// CDPBMAlignSuppConf.bsv -- BMAlignSupp + per-PC attribution gating.
// Layers a minimal "learn from outcomes" signal on top of the stateless
// BMAlignSupp detector (currently the 8-bench best at -0.01% vs NoPref).
//
// The hypothesis: BMAlignSupp is detection-bound. Treeadd issues 3788
// prefetches at 30.9% accuracy — the 2619 useless are timing-bound
// misses (line arrived early, evicted) or fundamentally-wrong pointers
// that the shape filter can't distinguish. A direct "was this prefetch
// useful" signal should let us suppress the 2+ loser PCs.
//
// Mechanism:
//   - Filter entry carries (lineAddr, pcHash) instead of just lineAddr.
//   - Per-PC 4-bit signed score (256 entries, hash-keyed).
//   - reportUsefulPrefetch(lineAddr) reads filter, bumps score +1 (sat +7).
//   - reportEviction(lineAddr) reads filter, bumps score -1 (sat -8).
//   - deqLineL1: if pc.score <= -2, SUPPRESS. Otherwise proceed as AlignSupp.
//   - Cold start: PC defaults to score=0, so first 2 useless events are
//     free (no suppression), giving each PC a chance to prove itself.

import MemoryTypes::*;
import TlbTypes ::*;
import CCTypes ::*;
import FIFO::*;
import Fifos::*;
import Vector::*;
import ConfigReg::*;
import ProcTypes::*;

import Types::*;
import RWBramCore::*;
import Prefetcher_intf::*;
import Cur_Cycle::*;
import CDP::*;

typedef struct {
    LineAddr lineAddr;
    Bit#(16) pcHash;
} BMAlignSuppConfFilterEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool routeLLC;
    Bit#(16) pcHash;
} NextCandAlignSuppConfT deriving (Bits, FShow, Eq);

module mkCDPBMAlignSuppConf#(
    TlbToPrefetcher toTlb,
    Parameter#(matchBits) _
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT),
    Add#(a__, matchBits, 27)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // Candidate now carries (vaddr, routeLLC, pcHash) so PC survives into issue.
    SupFifo#(8, 8, Tuple3#(Addr, Bool, Bit#(16))) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandAlignSuppConfT) nextCandidateBuffer <- mkOverflowBypassFifo;

    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr))     pendCandVaddr <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendRouteLLC  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bit#(16))) pendPcHash    <- replicateM(mkRegU);

    RWBramCore#(Bit#(10), Maybe#(BMAlignSuppConfFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    FIFO#(Tuple5#(Bit#(10), Addr, Addr, Bool, Bit#(16))) filterPendingQ <- mkFIFO;

    // Per-PC score. Starts at 0. Useful = +1 (sat +7), Evict = -1 (sat -8).
    // Gate: suppress if score <= -2.
    Vector#(256, Reg#(Int#(4))) pcScore <- replicateM(mkReg(0));

    // Useful-hit and eviction lookup queues.
    FIFO#(LineAddr) usefulHitQ      <- mkFIFO;
    FIFO#(LineAddr) evictionHitQ    <- mkFIFO;
    FIFO#(Tuple2#(Bit#(10), LineAddr)) attribLookupPendingQ <- mkFIFO;
    // Tag the pending lookup as +1 or -1.
    FIFO#(Bool) attribIsUseful <- mkFIFO;

    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(10)) filterInitCount <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    (* mutually_exclusive = "doFilterInit, processFilterResp, processAttribResp" *)
    rule doFilterInit(!filterInited);
        prefetchFilter.wrReq(filterInitCount, Invalid);
        if (filterInitCount == ~0) filterInited <= True;
        filterInitCount <= filterInitCount + 1;
    endrule

    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        if (tlbReqFreeQInitCount == ~0) tlbReqFreeQInited <= True;
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
    endrule

    function Bool isPtrShape(Addr w);
        Bool upperZero = (w[63:39] == 0);
        Bool aligned16 = (w[3:0] == 0);
        Bool nonNull   = (w != 0);
        return upperZero && aligned16 && nonNull;
    endfunction

    function Int#(4) satAdd(Int#(4) a, Int#(4) b);
        Int#(5) s = extend(a) + extend(b);
        if (s > 7) return 7;
        else if (s < -8) return -8;
        else return truncate(s);
    endfunction

    rule deqLineL1(filterInited && tlbReqFreeQInited);
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        Bit#(16) pc = getPcHash(x.req);
        Bit#(8)  pcIdx = hash(pc);
        Int#(4)  score = pcScore[pcIdx];

        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper && isPtrShape(x.line[i]))
                matchCount = matchCount + 1;
        end
        // PostConf gate: PC with demonstrated bad history (score <= -2) suppressed.
        Bool pcKill = score <= -2;
        Bool suppress = (matchCount >= 2) || pcKill;
        Integer enqIdx = 0;
        if (!suppress) begin
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
                if (candUpper == missUpper && isPtrShape(x.line[i])) begin
                    candFIFO.enqS[enqIdx].enq(tuple3(x.line[i], False, pc));
                    $display("%t AlexLog: CDP BMAlignSuppConf candidate offset: %d candVaddr: %h matchCount: %d pcHash: %h score: %d L1",
                        cur_cycle, i, x.line[i], matchCount, pc, score);
                    enqIdx = enqIdx + 1;
                end
            end
        end else begin
            $display("%t AlexLog: CDP BMAlignSuppConf SUPPRESS matchCount: %d pcHash: %h score: %d (%s)",
                cur_cycle, matchCount, pc, score, pcKill ? "pc-kill" : "multi-match");
        end
    endrule

    rule processTlbReq(filterInited && tlbReqFreeQInited);
        match {.candVaddr, .routeLLC, .pc} = candFIFO.deqS[0].first;
        candFIFO.deqS[0].deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id] <= candVaddr;
        pendRouteLLC[id]  <= routeLLC;
        pendPcHash[id]    <= pc;
    endrule

    rule processTlbResp(filterInited && tlbReqFreeQInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr = pendCandVaddr[id];
        Bool routeLLC = pendRouteLLC[id];
        Bit#(16) pc   = pendPcHash[id];
        tlbReqFreeQ.enq(id);
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple5(filterIdx, resp.paddr, candVaddr, routeLLC, pc));
        end else begin
            $display("%t AlexLog: CDP BMAlignSuppConf dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
                cur_cycle, candVaddr, resp.paddr, resp.haveException, paddrInMainMem);
        end
    endrule

    rule processFilterResp(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .paddr, .candVaddr, .routeLLC, .pc} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP BMAlignSuppConf filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMAlignSuppConfFilterEntryT{ lineAddr: lineAddr, pcHash: pc }));
            nextCandidateBuffer.enq(NextCandAlignSuppConfT{paddr: paddr, vaddr: candVaddr, routeLLC: routeLLC, pcHash: pc});
            $display("%t AlexLog: CDP BMAlignSuppConf filter MISS, issuing prefetch lineAddr %h pcHash: %h", cur_cycle, lineAddr, pc);
        end
    endrule

    // Attribution lookup: triggered on useful hit or eviction.
    // Reads filter to find the pcHash that originally issued this lineAddr.
    rule startAttribLookup_useful(filterInited);
        LineAddr lineAddr = usefulHitQ.first;
        usefulHitQ.deq;
        Bit#(10) filterIdx = hash(lineAddr);
        prefetchFilter.rdReq(filterIdx);
        attribLookupPendingQ.enq(tuple2(filterIdx, lineAddr));
        attribIsUseful.enq(True);
    endrule

    (* descending_urgency = "startAttribLookup_useful, startAttribLookup_evict" *)
    rule startAttribLookup_evict(filterInited);
        LineAddr lineAddr = evictionHitQ.first;
        evictionHitQ.deq;
        Bit#(10) filterIdx = hash(lineAddr);
        prefetchFilter.rdReq(filterIdx);
        attribLookupPendingQ.enq(tuple2(filterIdx, lineAddr));
        attribIsUseful.enq(False);
    endrule

    rule processAttribResp(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .lineAddr} = attribLookupPendingQ.first;
        attribLookupPendingQ.deq;
        Bool isUseful = attribIsUseful.first;
        attribIsUseful.deq;
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            Bit#(8) pcIdx = hash(fe.pcHash);
            Int#(4) oldScore = pcScore[pcIdx];
            Int#(4) newScore = satAdd(oldScore, isUseful ? 1 : -1);
            pcScore[pcIdx] <= newScore;
            $display("%t AlexLog: CDP BMAlignSuppConf %s lineAddr %h pcHash %h score %d -> %d",
                cur_cycle, isUseful ? "USEFUL" : "EVICTED", lineAddr, fe.pcHash, oldScore, newScore);
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        if (filterInited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            l1ToCDP.enq(L1ToCDPT{req: req, line: line});
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        evictionHitQ.enq(lineAddr);
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
        usefulHitQ.enq(lineAddr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: x.routeLLC,
            isNeighbourLine: False
        };
    endmethod
endmodule
