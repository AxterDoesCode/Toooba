import MemoryTypes::*; // Import from RISCYOOO
import TlbTypes ::*;
import CCTypes ::*;
import FIFO::*;
import Fifos::*;
import Ehr::*;
import Vector::*;
import ConfigReg::*;
import LFSR::*;

import Types::*;
import RWBramCore::*;
import Prefetcher_intf::*;

typedef struct {
    reqT req;
    Line line;
} L1ToCDPT#(type reqT) deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
} NextCandT deriving (Bits, FShow, Eq);

module mkCDP(
    CacheLinePrefetcher#(reqT)
) provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr, size 8 for each FIFO
    SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // This is purely for $display
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP deqLineL1", $time);
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                nextCandidateBuffer.enqS[enqIdx].enq(
                    NextCandT{
                        paddr: getReqAddr(x.req), 
                        vaddr: x.line[i]});
                // Probably change logging here to just see the candidate vaddr -> candidate paddr?
                $display("%t AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", $time, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP reportIncomingCacheLine", $time);
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line);
        if (hitMiss == HIT) begin
            $display("%t AlexLog: prefetcher report HIT %h", $time, addr);
        end
        else begin
            $display("%t AlexLog: prefetcher report MISS %h", $time, addr);
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr; // Do I want some condition here?
        // Found a virtual address and need to translate it now,
        // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
        let x = nextCandidateBuffer.deqS[0].first;
        nextCandidateBuffer.deqS[0].deq;
        // Use the same VPN -> PPN, but get the offset of the candidate vaddr
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%t AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule

typedef struct {
    Bit#(16)       pcHash;
    LineDataOffset lineOffset;
} TrainingTableEntryT deriving (Bits, FShow, Eq);

typedef struct {
    reqT req;
    idxT ttIdx;
    Bool missedOnThisVaddr;
    LineDataOffset offset;
    Addr candVaddr; // The actual candidate vaddr (pointer value) found at this offset
} TrainingTableRespQT#(type reqT, type idxT) deriving (Bits, FShow, Eq);

// PC-offset confidence table entry: one 3-bit confidence counter per cache line offset (8 offsets)
typedef Vector#(8, Bit#(3)) PCOffsetConfT;

// Tag carried alongside each pcTable read request so the single response rule
// knows whether to do a confidence update (Training), a prefetch issue (PrefetchIssue),
// or a periodic confidence decay (Decay)
typedef union tagged {
    LineDataOffset      Training;      // offset whose counter to saturating-increment
    Tuple2#(Addr, Line) PrefetchIssue; // (load addr, cache line) to select prefetch target from
    void                Decay;         // decrement all counters in the selected entry by 1
} PCTableRdTagT deriving (Bits, FShow);

module mkCDPStateful#(
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT),

    NumAlias#(trainingTableIdxBits, TLog#(trainingTableSize)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),

    NumAlias#(pcTableIdxBits, TLog#(pcTableSize)),
    Alias#(pcTableIdxT, Bit#(pcTableIdxBits)),
    Alias#(ttRespQT, TrainingTableRespQT#(reqT, trainingTableIdxT)),

    Add#(a__, TLog#(trainingTableSize), 64),
    Add#(b__, TLog#(pcTableSize), 16),
    Add#(c__, TLog#(trainingTableSize), 33)

);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr, size 8 for each FIFO
    //SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    RWBramCore#(trainingTableIdxT, Maybe#(TrainingTableEntryT)) trainingTable <- mkRWBramCoreForwarded(); // Training table should be indexed by vaddr and value should contain the PC and offset within the line at that miss
    SupFifo#(8, 8, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(8, 8, trainingTableIdxT) ttRdReqSupFIFO <- mkSupFifo;

    // PC-offset confidence table: indexed by truncated pcHash, stores confidence per offset
    RWBramCore#(pcTableIdxT, Maybe#(PCOffsetConfT)) pcTable <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;

    // Incoming pcTable read requests
    // Do I want to make this FIFO an overflow fifo? Probably?
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    // Mirrors in-flight BRAM reads so pcTableResp knows what each response is for
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdTagT)) pcTableRdTagQ    <- mkFIFO;

    // Init registers
    Reg#(Bool) trainingTableInited <- mkConfigReg(False);
    Reg#(Bit#(trainingTableIdxBits)) trainingTableInitCount <- mkReg(0);
    Reg#(Bool) pcTableInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcTableInitCount <- mkReg(0);

    // Confidence decay: LFSR picks a random pcTable entry, counter controls frequency
    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    // Whether we have inited
    function Bool inited;
        //return ptrTableInited && trainingTableInited && tlbReqFreeQInited;
        return trainingTableInited && pcTableInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!trainingTableInited);
        trainingTable.wrReq(trainingTableInitCount, Invalid);
        if (trainingTableInitCount == ~0) begin
            trainingTableInited <= True;
            // Also seed the Lfsr here
            //trainingDecayLfsr.seed('h11);
            $display("%t AlexLog: Training table inited", $time);
        end
        trainingTableInitCount <= trainingTableInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processPcTableRdReq, pcTableResp" *)
    rule doPcTableInit(!pcTableInited);
        pcTable.wrReq(pcTableInitCount, Invalid);
        if (pcTableInitCount == ~0) begin
            pcTableInited <= True;
            decayLfsr.seed('hA5F1);
            $display("%t AlexLog: PC table inited", $time);
        end
        pcTableInitCount <= pcTableInitCount + 1;
    endrule
    
    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines; // Dequeue the incoming cache lines
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // Use this and index into the training table to see if it has been seen before, if so CRUD PC table entry
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP deqCacheLines", $time);
        // We want to fill the training table with potential vaddrs if the vaddr hasn't been seen before
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin // If it looks like a vaddr (in the same page)
                // XOR-fold the 33 meaningful SV39 bits (38:6) into trainingTableIdxBits
                // to spread the index more uniformly and reduce aliasing
                Bit#(39) vaddr39 = truncate(x.line[i]);
                Bit#(33) shifted = truncate(vaddr39 >> valueOf(LgLineSzBytes));
                trainingTableIdxT fold1 = truncate(shifted);
                trainingTableIdxT fold2 = truncate(shifted >> valueOf(trainingTableIdxBits));
                trainingTableIdxT fold3 = truncate(shifted >> (2 * valueOf(trainingTableIdxBits)));
                trainingTableIdxT idx   = fold1 ^ fold2 ^ fold3;
                Bool missedOnThisVaddr = (dataSel == fromInteger(i));
                if (missedOnThisVaddr)
                    $display("%t AlexLog: found a candidate vaddr that missed", $time);
                ttRespQ.enqS[enqIdx].enq(
                    TrainingTableRespQT{
                        req: x.req,
                        ttIdx: idx,
                        missedOnThisVaddr: missedOnThisVaddr,
                        offset: fromInteger(i),
                        candVaddr: x.line[i]});
                ttRdReqSupFIFO.enqS[enqIdx].enq(idx); // Since this can call multiple times per cycle, need to send it to a SupFIFO
                $display("%t AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", $time, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
        // One pcTable lookup per incoming line — if this PC already has high confidence
        // for some offset, issue a prefetch immediately without waiting for the next HIT
        if (getReqOp(x.req) == Ld) begin
            pcTableIdxT pctIdx = truncate(getPcHash(x.req) >> valueof(TSub#(16, pcTableIdxBits)));
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple2(getReqAddr(x.req), x.line)));
        end
    endrule

    rule processTtRdReq(inited);
        let idx = ttRdReqSupFIFO.deqS[0].first;
        ttRdReqSupFIFO.deqS[0].deq;
        trainingTable.rdReq(idx); // Sequeuntially queue the index
    endrule

    rule ttAccess(inited);
        let x = trainingTable.rdResp;
        trainingTable.deqRdResp;
        ttRespQT respQ = ttRespQ.deqS[0].first;
        ttRespQ.deqS[0].deq;
        // This if statement also needs to check if the BRAM table has been init with some values
        //if (trainingTable.rdRespValid && respQ.missedOnThisVaddr) begin // Vaddr already exists in the training table and the cache miss is for that specific vaddr
        if (x matches tagged Valid .ttRdResp) begin // Vaddr already exists in the training table and the cache miss is for that specific vaddr
            if (respQ.missedOnThisVaddr) begin
                let pctIdx = truncate(getPcHash(respQ.req) >> valueof(TSub#(16, pcTableIdxBits)));
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training ttRdResp.lineOffset));
            end
            // If the vaddr trainingTable entry already exists then no need to update
        end else begin // vaddr doesn't exist, create entry
            trainingTable.wrReq(respQ.ttIdx, Valid(TrainingTableEntryT {
                pcHash:     getPcHash(respQ.req),
                lineOffset: respQ.offset // Offset of where this vaddr in the line was found
            }));
            $display("%t AlexLog: Wrote to training table, idx: %d", $time, respQ.ttIdx);
        end
    endrule

    // Drains pcTableRdReqFIFO one entry at a time and issues the actual BRAM read,
    // keeping pcTableRdTagQ in sync so pcTableResp knows what each response is for
    rule processPcTableRdReq(inited);
        match {.pctIdx, .tag} = pcTableRdReqFIFO.first;
        pcTableRdReqFIFO.deq;
        pcTable.rdReq(pctIdx);
        pcTableRdTagQ.enq(tuple2(pctIdx, tag));
    endrule

    // Single consumer of pcTable.rdResp; dispatches on the tag to either update
    // confidence (Training) or issue a prefetch candidate (PrefetchIssue)
    rule pcTableResp(inited);
        let rdResp = pcTable.rdResp;
        pcTable.deqRdResp;
        match {.pctIdx, .tag} = pcTableRdTagQ.first;
        pcTableRdTagQ.deq;
        case (tag) matches
            tagged Training .offset: begin
                PCOffsetConfT curConf = fromMaybe(replicate(0), rdResp);
                Bit#(3) curVal = curConf[offset];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(update(curConf, offset, newVal)));
                $display("%t AlexLog: PC table updated, idx: %d, offset: %d, conf: %d -> %d", $time, pctIdx, offset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line}: begin
                if (rdResp matches tagged Valid .conf) begin
                    // Find highest-confidence offset; lowest index wins on tie
                    LineDataOffset bestOffset = 0;
                    Bool foundHighConf = False;
                    for (Integer i = 7; i >= 0; i = i - 1) begin
                        if (conf[i] >= 3) begin
                            bestOffset = fromInteger(i);
                            foundHighConf = True;
                        end
                    end
                    if (foundHighConf) begin
                        nextCandidateBuffer.enq(NextCandT{paddr: addr, vaddr: line[bestOffset]});
                        $display("%t AlexLog: CDP prefetch from familiar PC, offset: %d, paddr: %h, vaddr: %h", $time, bestOffset, addr, line[bestOffset]);
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .conf) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    pcTable.wrReq(pctIdx, Valid(map(satDec, conf)));
                    $display("%t AlexLog: CDP decay applied to pcTable idx: %d", $time, pctIdx);
                end
            end
        endcase
    endrule

    // Ticks every cycle regardless of FIFO state so decay timing is never distorted
    rule tickDecayCounter(inited);
        decayCounter <= (decayCounter == 0) ? fromInteger(valueOf(decayInterval)) : decayCounter - 1;
    endrule

    // Enqueues a decay read request when the counter expires; lower urgency than
    // tickDecayCounter so the counter always resets even if the FIFO is momentarily full
    (* descending_urgency = "issuePcTableDecay, tickDecayCounter" *)
    rule issuePcTableDecay(inited && decayCounter == 0);
        pcTableIdxT decayIdx = truncate(decayLfsr.value);
        decayLfsr.next;
        pcTableRdReqFIFO.enq(tuple2(decayIdx, tagged Decay));
    endrule

    //rule thing;
        // For that specific cache line fill -> the actual data being pulled needs to be checked if it is a candidate vaddr
        // If so the go into the training table -> if seen before -> update confidence on PC-offset table

        // For each candidate vaddr in cache line fill
        // If it doesn't exist in the training table create an entry
        // else it already exists AND it is the datasel (the actual data word requested in the miss) then update confidence
        // Impl:
            // Send off a read request to the training table
            // Read the responses, if it exists then check if the datasel thing we passed through in the side pipe is true
            // If it doesn't exist the send a write request to the training table

        // When we see a reportAccess to a specific PC, check the PC table and see if any offset has good confidence. Prefetch if so
    //endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP reportIncomingCacheLine", $time);
    endmethod

    // On a HIT, the line is already in cache so we can use its contents directly as prefetch targets.
    // MISSes are ignored here; training happens via reportIncomingCacheLine when the line arrives.
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line);
        if (hitMiss == HIT) begin
            pcTableIdxT pctIdx = truncate(pcHash >> valueof(TSub#(16, pcTableIdxBits)));
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple2(addr, line)));
        end
        $display("%t AlexLog: prefetcher report %s %h", $time, hitMiss == HIT ? "HIT" : "MISS", addr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr; // Do I want some condition here?
        // Found a virtual address and need to translate it now,
        // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        // Use the same VPN -> PPN, but get the offset of the candidate vaddr
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%t AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule

// ============================================================================
// mkCDPStatefulRelative
// Same as mkCDPStateful but trains on the offset of the candidate vaddr
// *relative* to the missed word position, so negative offsets are possible.
// ============================================================================

// Signed relative offset: candidate_position - miss_position, range -7..+7
typedef Int#(4) RelLineOffset;

// Confidence vector indexed by (relOffset + 7), covering offsets -7..+7 (15 slots)
typedef Vector#(15, Bit#(3)) PCRelOffsetConfT;

typedef union tagged {
    RelLineOffset        Training;      // relative offset whose counter to saturating-increment
    Tuple2#(Addr, Line)  PrefetchIssue; // (load addr, cache line) to select prefetch target from
    void                 Decay;         // decrement all counters in the selected entry by 1
} PCTableRdRelTagT deriving (Bits, FShow);

module mkCDPStatefulRelative#(
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT),

    NumAlias#(trainingTableIdxBits, TLog#(trainingTableSize)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),

    NumAlias#(pcTableIdxBits, TLog#(pcTableSize)),
    Alias#(pcTableIdxT, Bit#(pcTableIdxBits)),
    Alias#(ttRespQT, TrainingTableRespQT#(reqT, trainingTableIdxT)),

    Add#(a__, TLog#(trainingTableSize), 64),
    Add#(b__, TLog#(pcTableSize), 16),
    Add#(c__, TLog#(trainingTableSize), 33)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    RWBramCore#(trainingTableIdxT, Maybe#(TrainingTableEntryT)) trainingTable <- mkRWBramCoreForwarded();
    SupFifo#(8, 8, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(8, 8, trainingTableIdxT) ttRdReqSupFIFO <- mkSupFifo;

    // PC-relative-offset confidence table
    RWBramCore#(pcTableIdxT, Maybe#(PCRelOffsetConfT)) pcTable <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;

    // Init registers
    Reg#(Bool) trainingTableInited <- mkConfigReg(False);
    Reg#(Bit#(trainingTableIdxBits)) trainingTableInitCount <- mkReg(0);
    Reg#(Bool) pcTableInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcTableInitCount <- mkReg(0);

    // Confidence decay
    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bool inited;
        return trainingTableInited && pcTableInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!trainingTableInited);
        trainingTable.wrReq(trainingTableInitCount, Invalid);
        if (trainingTableInitCount == ~0) begin
            trainingTableInited <= True;
            $display("%t AlexLog: CDP Rel Training table inited", $time);
        end
        trainingTableInitCount <= trainingTableInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processPcTableRdReq, pcTableResp" *)
    rule doPcTableInit(!pcTableInited);
        pcTable.wrReq(pcTableInitCount, Invalid);
        if (pcTableInitCount == ~0) begin
            pcTableInited <= True;
            decayLfsr.seed('hA5F1);
            $display("%t AlexLog: CDP Rel PC table inited", $time);
        end
        pcTableInitCount <= pcTableInitCount + 1;
    endrule

    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req));
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP Rel deqCacheLines", $time);
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                // XOR-fold the 33 meaningful SV39 bits (38:6) into trainingTableIdxBits
                Bit#(39) vaddr39 = truncate(x.line[i]);
                Bit#(33) shifted = truncate(vaddr39 >> valueOf(LgLineSzBytes));
                trainingTableIdxT fold1 = truncate(shifted);
                trainingTableIdxT fold2 = truncate(shifted >> valueOf(trainingTableIdxBits));
                trainingTableIdxT fold3 = truncate(shifted >> (2 * valueOf(trainingTableIdxBits)));
                trainingTableIdxT idx   = fold1 ^ fold2 ^ fold3;
                Bool missedOnThisVaddr = (dataSel == fromInteger(i));
                if (missedOnThisVaddr)
                    $display("%t AlexLog: CDP Rel found a candidate vaddr that missed", $time);
                ttRespQ.enqS[enqIdx].enq(
                    TrainingTableRespQT{
                        req: x.req,
                        ttIdx: idx,
                        missedOnThisVaddr: missedOnThisVaddr,
                        offset: fromInteger(i),
                        candVaddr: x.line[i]});
                ttRdReqSupFIFO.enqS[enqIdx].enq(idx);
                $display("%t AlexLog: CDP Rel candidate vaddr found, offset: %d", $time, i);
                enqIdx = enqIdx + 1;
            end
        end
        // One pcTable lookup per incoming line — if this PC already has high confidence
        // for some offset, issue a prefetch immediately without waiting for the next HIT
        if (getReqOp(x.req) == Ld) begin
            pcTableIdxT pctIdx = truncate(getPcHash(x.req) >> valueof(TSub#(16, pcTableIdxBits)));
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple2(getReqAddr(x.req), x.line)));
        end
    endrule

    rule processTtRdReq(inited);
        let idx = ttRdReqSupFIFO.deqS[0].first;
        ttRdReqSupFIFO.deqS[0].deq;
        trainingTable.rdReq(idx);
    endrule

    rule ttAccess(inited);
        let x = trainingTable.rdResp;
        trainingTable.deqRdResp;
        ttRespQT respQ = ttRespQ.deqS[0].first;
        ttRespQ.deqS[0].deq;
        if (x matches tagged Valid .ttRdResp) begin
            if (respQ.missedOnThisVaddr) begin
                $display("%t AlexLog: CDP Rel PC table needs update", $time);
                let pctIdx = truncate(getPcHash(respQ.req) >> valueof(TSub#(16, pcTableIdxBits)));
                // Relative offset: where the pointer sat in the line vs where we missed
                LineDataOffset dataSel = getLineDataOffset(getReqAddr(respQ.req));
                RelLineOffset relOffset = unpack(zeroExtend(ttRdResp.lineOffset))
                                        - unpack(zeroExtend(dataSel));
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training relOffset));
            end
        end else begin
            trainingTable.wrReq(respQ.ttIdx, Valid(TrainingTableEntryT {
                pcHash:     getPcHash(respQ.req),
                lineOffset: respQ.offset
            }));
            $display("%t AlexLog: CDP Rel Wrote to training table, idx: %d", $time, respQ.ttIdx);
        end
    endrule

    rule processPcTableRdReq(inited);
        match {.pctIdx, .tag} = pcTableRdReqFIFO.first;
        pcTableRdReqFIFO.deq;
        pcTable.rdReq(pctIdx);
        pcTableRdTagQ.enq(tuple2(pctIdx, tag));
    endrule

    rule pcTableResp(inited);
        let rdResp = pcTable.rdResp;
        pcTable.deqRdResp;
        match {.pctIdx, .tag} = pcTableRdTagQ.first;
        pcTableRdTagQ.deq;
        case (tag) matches
            tagged Training .relOffset: begin
                PCRelOffsetConfT curConf = fromMaybe(replicate(0), rdResp);
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(update(curConf, vecIdx, newVal)));
                $display("%t AlexLog: CDP Rel PC table updated, idx: %d, relOffset: %d, conf: %d -> %d",
                         $time, pctIdx, relOffset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line}: begin
                if (rdResp matches tagged Valid .conf) begin
                    Int#(4) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    LineDataOffset bestOffset = 0;
                    Bool foundHighConf = False;
                    // Iterate high-to-low so lowest relative offset wins on tie
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(4) relOffset  = fromInteger(i - 7); // subtract at Integer level to stay in Int#(4) range
                        Int#(4) absTarget  = hitOffset + relOffset;
                        if (conf[fromInteger(i)] >= 3 &&& absTarget >= 0 &&& absTarget <= 7) begin
                            bestOffset = truncate(pack(absTarget));
                            foundHighConf = True;
                        end
                    end
                    if (foundHighConf) begin
                        nextCandidateBuffer.enq(NextCandT{paddr: addr, vaddr: line[bestOffset]});
                        $display("%t AlexLog: CDP Rel prefetch issued, paddr: %h, vaddr: %h",
                                 $time, addr, line[bestOffset]);
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .conf) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    pcTable.wrReq(pctIdx, Valid(map(satDec, conf)));
                    $display("%t AlexLog: CDP Rel decay applied to pcTable idx: %d", $time, pctIdx);
                end
            end
        endcase
    endrule

    rule tickDecayCounter(inited);
        decayCounter <= (decayCounter == 0) ? fromInteger(valueOf(decayInterval)) : decayCounter - 1;
    endrule

    (* descending_urgency = "issuePcTableDecay, tickDecayCounter" *)
    rule issuePcTableDecay(inited && decayCounter == 0);
        pcTableIdxT decayIdx = truncate(decayLfsr.value);
        decayLfsr.next;
        pcTableRdReqFIFO.enq(tuple2(decayIdx, tagged Decay));
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{req: req, line: line};
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP Rel reportIncomingCacheLine", $time);
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line);
        if (hitMiss == HIT) begin
            pcTableIdxT pctIdx = truncate(pcHash >> valueof(TSub#(16, pcTableIdxBits)));
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple2(addr, line)));
        end
        $display("%t AlexLog: CDP Rel prefetcher report %s %h", $time, hitMiss == HIT ? "HIT" : "MISS", addr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%t AlexLog: CDP Rel Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule
