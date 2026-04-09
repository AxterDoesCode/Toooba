import MemoryTypes::*; // Import from RISCYOOO
import TlbTypes ::*;
import CCTypes ::*;
import FIFO::*;
import Fifos::*;
import Ehr::*;
import Vector::*;
import ConfigReg::*;
import LFSR::*;
import ProcTypes::*;

import Types::*;
import RWBramCore::*;
import RWSetAssocBramCore::*;
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

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn);
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

// Signed relative offset: candidate_position - miss_position, range -7..+7
typedef Int#(4) RelLineOffset;

// Training table BRAM entry: valid bit + vaddr key (for isMatch) + training data
typedef struct {
    Bool          valid;
    Addr          storedVaddr; // key for set-associative tag match
    Bit#(16)      pcHash;
    RelLineOffset lineOffset;  // relative offset: candidate_pos - miss_pos
} TrainingTableEntryT deriving (Bits, FShow, Eq);

typedef struct {
    reqT req;
    idxT ttIdx;
    Bool missedOnThisVaddr;
    LineDataOffset offset;
    Addr candVaddr; // The actual candidate vaddr (pointer value) found at this offset
} TrainingTableRespQT#(type reqT, type idxT) deriving (Bits, FShow, Eq);

// ============================================================================
// mkCDPStatefulRelative
// Same as mkCDPStateful but trains on the offset of the candidate vaddr
// *relative* to the missed word position, so negative offsets are possible.
// Uses 4-way set-associative BRAMs (RWSetAssocBramCoreForwarded) for both
// the training table and PC table.
// ============================================================================

// Confidence vector indexed by (relOffset + 7), covering offsets -7..+7 (15 slots)
typedef Vector#(15, Bit#(3)) PCRelOffsetConfT;

typedef union tagged {
    RelLineOffset             Training;      // relative offset whose counter to saturating-increment
    Tuple3#(Addr, Line, Vpn)  PrefetchIssue; // (load addr, cache line, vpn) to select prefetch target from
    void                      Decay;         // decrement all counters in the selected entry by 1
} PCTableRdRelTagT deriving (Bits, FShow);

module mkCDPStatefulRelative#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____
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
    Add#(c__, TLog#(trainingTableSize), 33),
    Add#(1, d__, TDiv#(39, TLog#(trainingTableSize))),
    Add#(e__, 39, TMul#(TDiv#(39, TLog#(trainingTableSize)), TLog#(trainingTableSize))),
    Add#(1, f__, TDiv#(16, TLog#(pcTableSize))),
    Add#(g__, 16, TMul#(TDiv#(16, TLog#(pcTableSize)), TLog#(pcTableSize))),
    Add#(h__, matchBits, 27)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 4-way set-associative training table
    // addrT = trainingTableIdxT, wayT = Bit#(2), dataT = TrainingTableEntryT, tagT = Addr
    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(2), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    SupFifo#(8, 8, ttRespQT) ttRespQ <- mkSupFifo;
    // Carries (index, vaddr) — both needed by rdReq(addr, tag)
    SupFifo#(8, 8, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    // Flat PC confidence table
    RWBramCore#(pcTableIdxT, Maybe#(PCRelOffsetConfT)) pcTable <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;

    // TLB translation pipeline for prefetch candidates
    FIFO#(Addr) tlbReqFIFO <- mkSizedFIFO(16);        // decouples pcTableResp from TLB
    FIFO#(Addr) tlbPendingCandQ <- mkSizedFIFO(valueOf(LLCTlbReqNum)); // tracks in-flight vaddrs
    Reg#(LLCTlbReqIdx) tlbReqId <- mkReg(0);

    // Init: write unpack(0) (valid=False) to every (addr, way) pair for training table
    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 2))) ttInitCount <- mkReg(0);
    // Flat PC table init
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);

    // Confidence decay
    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bool inited;
        return ttInited && pcInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!ttInited);
        trainingTableIdxT addr = truncateLSB(ttInitCount);
        Bit#(2) way = truncate(ttInitCount);
        trainingTable.wrReq(addr, way, unpack(0));
        if (ttInitCount == maxBound) begin
            ttInited <= True;
            $display("%t AlexLog: CDP Rel Training table inited", $time);
        end
        ttInitCount <= ttInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processPcTableRdReq, pcTableResp" *)
    rule doPcTableInit(!pcInited);
        pcTable.wrReq(pcInitCount, Invalid);
        if (pcInitCount == ~0) begin
            pcInited <= True;
            decayLfsr.seed('hA5F1);
            $display("%t AlexLog: CDP Rel PC table inited", $time);
        end
        pcInitCount <= pcInitCount + 1;
    endrule

    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req));
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP Rel deqCacheLines", $time);
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper &&& getReqOp(x.req) == Ld) begin
                Bit#(39) vaddr39 = truncate(x.line[i]);
                trainingTableIdxT idx = hash(vaddr39);
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
                ttRdReqSupFIFO.enqS[enqIdx].enq(tuple2(idx, x.line[i]));
                $display("%t AlexLog: CDP Rel candidate vaddr found, offset: %d", $time, i);
                if (getVpn(x.line[i]) != getReqVpn(x.req))
                    $display("%t AlexLog: CDP Rel CROSS-PAGE candidate at offset %d: missVpn %h candVpn %h candVaddr %h",
                             $time, i, getReqVpn(x.req), getVpn(x.line[i]), x.line[i]);
                enqIdx = enqIdx + 1;
            end
        end
        // One pcTable lookup per incoming line
        if (getReqOp(x.req) == Ld) begin
            pcTableIdxT pctIdx = hash(getPcHash(x.req));
            pcTableRdReqFIFO.enq(tuple2(pctIdx,
                tagged PrefetchIssue tuple3(getReqAddr(x.req), x.line, getReqVpn(x.req))));
        end
    endrule

    rule processTtRdReq(inited);
        match {.idx, .vaddr} = ttRdReqSupFIFO.deqS[0].first;
        ttRdReqSupFIFO.deqS[0].deq;
        trainingTable.rdReq(idx, vaddr);
    endrule

    rule ttAccess(inited);
        let rdResp = trainingTable.rdResp;
        let rdRepl = trainingTable.rdRepl;
        trainingTable.deqRdResp;
        ttRespQT respQ = ttRespQ.deqS[0].first;
        ttRespQ.deqS[0].deq;
        if (rdResp matches tagged Valid {.hitWay, .ttRdResp}) begin
            // Key matched — no collision detection needed (isMatch handles it)
            if (respQ.missedOnThisVaddr) begin
                $display("%t AlexLog: CDP Rel PC table needs update", $time);
                pcTableIdxT pctIdx = hash(getPcHash(respQ.req));
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training ttRdResp.lineOffset));
            end
        end else begin
            // No matching entry — insert into replacement way
            LineDataOffset dataSel = getLineDataOffset(getReqAddr(respQ.req));
            RelLineOffset relOffset = unpack(zeroExtend(respQ.offset)) - unpack(zeroExtend(dataSel));
            trainingTable.wrReq(respQ.ttIdx, rdRepl, TrainingTableEntryT{
                valid:       True,
                storedVaddr: respQ.candVaddr,
                pcHash:      getPcHash(respQ.req),
                lineOffset:  relOffset
            });
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
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .conf) begin
                    Int#(4) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    LineDataOffset bestOffset = 0;
                    Bool foundHighConf = False;
                    // Iterate high-to-low so lowest relative offset wins on tie
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(4) relOffset  = fromInteger(i - 7);
                        Int#(4) absTarget  = hitOffset + relOffset;
                        if (conf[fromInteger(i)] >= 3 &&& absTarget >= 0 &&& absTarget <= 7) begin
                            bestOffset = truncate(pack(absTarget));
                            foundHighConf = True;
                        end
                    end
                    Addr candidate = line[bestOffset];
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                    Bool isValidVaddr = candUpper == addrUpper;
                    if (foundHighConf && isValidVaddr) begin
                        tlbReqFIFO.enq(candidate);
                        $display("%t AlexLog: CDP Rel queued TLB req for candidate vaddr %h", $time, candidate);
                    end
                    if (foundHighConf && !isValidVaddr) begin
                        $display("%t AlexLog: Invalid address at best offset");
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

    // Drain tlbReqFIFO and issue requests to the TLB
    rule processTlbReq;
        Addr candVaddr = tlbReqFIFO.first;
        tlbReqFIFO.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: tlbReqId});
        tlbPendingCandQ.enq(candVaddr);
        tlbReqId <= tlbReqId + 1;
        $display("%t AlexLog: CDP Rel TLB req sent for vaddr %h id %d", $time, candVaddr, tlbReqId);
    endrule

    // Consume TLB translation responses and enqueue to nextCandidateBuffer
    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        Addr candVaddr = tlbPendingCandQ.first;
        tlbPendingCandQ.deq;
        if (!resp.haveException) begin
            nextCandidateBuffer.enq(NextCandT{paddr: resp.paddr, vaddr: candVaddr});
            $display("%t AlexLog: CDP Rel TLB resp: vaddr %h -> paddr %h", $time, candVaddr, resp.paddr);
        end else begin
            $display("%t AlexLog: CDP Rel TLB resp: exception for vaddr %h, dropping prefetch", $time, candVaddr);
        end
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

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn);
        if (hitMiss == HIT) begin
            pcTableIdxT pctIdx = hash(pcHash);
            pcTableRdReqFIFO.enq(tuple2(pctIdx,
                tagged PrefetchIssue tuple3(addr, line, reqVpn)));
        end
        $display("%t AlexLog: CDP Rel prefetcher report %s %h", $time, hitMiss == HIT ? "HIT" : "MISS", addr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        // paddr is already the correct translated physical address from the TLB
        $display("%t AlexLog: CDP Rel Prefetch addr issued. paddr: %h | vaddr: %h", $time, x.paddr, x.vaddr);
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule
