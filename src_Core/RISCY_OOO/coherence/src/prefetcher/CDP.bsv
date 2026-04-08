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

// PC table BRAM entry: valid bit + pcHash key (for isMatch) + confidence vector
typedef struct {
    Bool             valid;
    Bit#(16)         pcHash; // key for set-associative tag match
    PCRelOffsetConfT conf;
} PCTableEntryT deriving (Bits, FShow, Eq);

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
    Add#(c__, TLog#(trainingTableSize), 33),
    Add#(1, d__, TDiv#(39, TLog#(trainingTableSize))),
    Add#(e__, 39, TMul#(TDiv#(39, TLog#(trainingTableSize)), TLog#(trainingTableSize))),
    Add#(1, f__, TDiv#(16, TLog#(pcTableSize))),
    Add#(g__, 16, TMul#(TDiv#(16, TLog#(pcTableSize)), TLog#(pcTableSize)))
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

    // 4-way set-associative PC confidence table
    // addrT = pcTableIdxT, wayT = Bit#(2), dataT = PCTableEntryT, tagT = Bit#(16)
    function Bool pcIsMatch(PCTableEntryT e, Bit#(16) tag) = e.valid && e.pcHash == tag;
    function Bool pcIsReplaceCandidate(PCTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(pcTableIdxT, Bit#(2), PCTableEntryT, Bit#(16)) pcTable
        <- mkRWSetAssocBramCoreForwarded(pcIsMatch, pcIsReplaceCandidate);

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    // Carries (pcHash key, index, tag) — pcHash key needed by rdReq(addr, tag)
    FIFO#(Tuple3#(Bit#(16), pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple3#(Bit#(16), pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;

    // Init: write unpack(0) (valid=False) to every (addr, way) pair
    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 2))) ttInitCount <- mkReg(0);
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(pcTableIdxBits, 2))) pcInitCount <- mkReg(0);

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
        pcTableIdxT addr = truncateLSB(pcInitCount);
        Bit#(2) way = truncate(pcInitCount);
        pcTable.wrReq(addr, way, unpack(0));
        if (pcInitCount == maxBound) begin
            pcInited <= True;
            $display("%t AlexLog: CDP Rel PC table inited", $time);
        end
        pcInitCount <= pcInitCount + 1;
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
                enqIdx = enqIdx + 1;
            end
        end
        // One pcTable lookup per incoming line
        if (getReqOp(x.req) == Ld) begin
            Bit#(16) pcKey = getPcHash(x.req);
            pcTableIdxT pctIdx = hash(pcKey);
            pcTableRdReqFIFO.enq(tuple3(pcKey, pctIdx,
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
                Bit#(16) pcKey = getPcHash(respQ.req);
                pcTableIdxT pctIdx = hash(pcKey);
                pcTableRdReqFIFO.enq(tuple3(pcKey, pctIdx, tagged Training ttRdResp.lineOffset));
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
        match {.pcKey, .pctIdx, .tag} = pcTableRdReqFIFO.first;
        pcTableRdReqFIFO.deq;
        pcTable.rdReq(pctIdx, pcKey);
        pcTableRdTagQ.enq(tuple3(pcKey, pctIdx, tag));
    endrule

    rule pcTableResp(inited);
        let rdResp = pcTable.rdResp;
        let rdRepl = pcTable.rdRepl;
        pcTable.deqRdResp;
        match {.pcKey, .pctIdx, .tag} = pcTableRdTagQ.first;
        pcTableRdTagQ.deq;
        case (tag) matches
            tagged Training .relOffset: begin
                PCRelOffsetConfT curConf = case (rdResp) matches
                    tagged Valid {.hitWay, .e}: e.conf;
                    default: replicate(0);
                endcase;
                Bit#(2) writeWay = case (rdResp) matches
                    tagged Valid {.hitWay, .*}: hitWay;
                    default: rdRepl;
                endcase;
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, writeWay, PCTableEntryT{
                    valid:  True,
                    pcHash: pcKey,
                    conf:   update(curConf, vecIdx, newVal)
                });
                $display("%t AlexLog: CDP Rel PC table updated, idx: %d, relOffset: %d, conf: %d -> %d",
                         $time, pctIdx, relOffset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid {.hitWay, .e}) begin
                    Int#(4) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    LineDataOffset bestOffset = 0;
                    Bool foundHighConf = False;
                    // Iterate high-to-low so lowest relative offset wins on tie
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(4) relOffset  = fromInteger(i - 7);
                        Int#(4) absTarget  = hitOffset + relOffset;
                        if (e.conf[fromInteger(i)] >= 3 &&& absTarget >= 0 &&& absTarget <= 7) begin
                            bestOffset = truncate(pack(absTarget));
                            foundHighConf = True;
                        end
                    end
                    Addr candidate = line[bestOffset];
                    Bool isValidVaddr = getVpn(line[bestOffset]) == reqVpn;
                    if (foundHighConf && isValidVaddr) begin
                        nextCandidateBuffer.enq(NextCandT{paddr: addr, vaddr: candidate});
                        $display("%t AlexLog: CDP Rel prefetch issued, paddr: %h, vaddr: %h", $time, addr, candidate);
                    end
                    if (foundHighConf && !isValidVaddr) begin
                        $display("%t AlexLog: Invalid address at best offset");
                    end
                end
            end
        endcase
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{req: req, line: line};
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP Rel reportIncomingCacheLine", $time);
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn);
        if (hitMiss == HIT) begin
            Bit#(16) pcKey = pcHash;
            pcTableIdxT pctIdx = hash(pcKey);
            pcTableRdReqFIFO.enq(tuple3(pcKey, pctIdx,
                tagged PrefetchIssue tuple3(addr, line, reqVpn)));
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
