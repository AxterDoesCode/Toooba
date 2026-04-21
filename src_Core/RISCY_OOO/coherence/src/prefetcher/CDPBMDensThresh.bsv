// CDPBMDensThresh.bsv -- Variant BM-DensityThresh.
// Extends BMPolySupp-MB27 (current pure-bit-match best) with a per-PC
// reliability gate, to filter out single-match candidates from PCs that
// tend to produce NOISY (multi-match) lines.
//
// Observation (from BMPolySupp analysis on treeadd):
//   - Single-match (matchCount==1) candidates have only 10.9% useful hits.
//   - Even the "clean" single-match bucket has 90% false positives.
//   - To push past NoPref parity we must filter out the bad single-match
//     PCs, not just the noisy multi-match lines.
//
// Policy (BMPolySupp + PC gate):
//   - matchCount == 1:
//       * Update pcScore[PC] += 1 (cap at +7)
//       * If pcScore[PC] >= 0, ISSUE L1 prefetch (pass gate)
//       * Else SUPPRESS (PC is unreliable — mostly multi-match)
//   - matchCount >= 2:
//       * Update pcScore[PC] -= 2 (penalize 2x)
//       * SUPPRESS (same as BMPolySupp)
//   - matchCount == 0:
//       * no update, no issue
//
// New PCs start at +2 (optimistic cold-start: 2 free chances before being
// downgraded). Gate is "pcScore >= 0" so takes 2 bad events to silence a
// cold PC.
//
// State: 256-entry Int#(4) table, hash-keyed by pcHash. 1 KiB total.

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

typedef struct { LineAddr lineAddr; } BMDensThreshFilterEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool routeLLC;
} NextCandDensThreshT deriving (Bits, FShow, Eq);

module mkCDPBMDensThresh#(
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

    SupFifo#(8, 8, Tuple2#(Addr, Bool)) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandDensThreshT) nextCandidateBuffer <- mkOverflowBypassFifo;

    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendRouteLLC <- replicateM(mkRegU);

    RWBramCore#(Bit#(10), Maybe#(BMDensThreshFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    FIFO#(Tuple4#(Bit#(10), Addr, Addr, Bool)) filterPendingQ <- mkFIFO;

    // Per-PC reliability score. Positive = PC mostly produces single-match
    // (reliable pointer-chase). Negative = PC mostly produces multi-match
    // (noisy, likely split-pointer struct). Start optimistic at +2.
    Vector#(256, Reg#(Int#(4))) pcScore <- replicateM(mkReg(2));

    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(10)) filterInitCount <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    (* mutually_exclusive = "doFilterInit, processFilterResp" *)
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
        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper)
                matchCount = matchCount + 1;
        end
        Bit#(16) pc = getPcHash(x.req);
        Bit#(8)  pcIdx = hash(pc);
        Int#(4) oldScore = pcScore[pcIdx];

        // Update PC score based on match class.
        Int#(4) newScore = oldScore;
        if (matchCount == 1)      newScore = satAdd(oldScore,  1);
        else if (matchCount >= 2) newScore = satAdd(oldScore, -2);
        pcScore[pcIdx] <= newScore;

        // Multi-match lines always suppress (BMPolySupp policy).
        Bool suppressMulti = matchCount >= 2;
        // PC gate: suppress single-match from unreliable PCs.
        Bool suppressByPc  = (matchCount == 1) && (oldScore < 0);
        Bool suppress = suppressMulti || suppressByPc;

        Integer enqIdx = 0;
        if (!suppress) begin
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
                if (candUpper == missUpper) begin
                    candFIFO.enqS[enqIdx].enq(tuple2(x.line[i], False));
                    $display("%t AlexLog: CDP BMDensThresh candidate offset: %d candVaddr: %h matchCount: %d pcHash: %h pcScore: %d L1",
                        cur_cycle, i, x.line[i], matchCount, pc, oldScore);
                    enqIdx = enqIdx + 1;
                end
            end
        end else begin
            $display("%t AlexLog: CDP BMDensThresh SUPPRESS matchCount: %d pcHash: %h pcScore: %d (%s)",
                cur_cycle, matchCount, pc, oldScore,
                suppressByPc ? "pc-gate" : "multi-match");
        end
    endrule

    rule processTlbReq(filterInited && tlbReqFreeQInited);
        match {.candVaddr, .routeLLC} = candFIFO.deqS[0].first;
        candFIFO.deqS[0].deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id] <= candVaddr;
        pendRouteLLC[id] <= routeLLC;
    endrule

    rule processTlbResp(filterInited && tlbReqFreeQInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr = pendCandVaddr[id];
        Bool routeLLC = pendRouteLLC[id];
        tlbReqFreeQ.enq(id);
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple4(filterIdx, resp.paddr, candVaddr, routeLLC));
        end else begin
            $display("%t AlexLog: CDP BMDensThresh dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
                cur_cycle, candVaddr, resp.paddr, resp.haveException, paddrInMainMem);
        end
    endrule

    rule processFilterResp(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .paddr, .candVaddr, .routeLLC} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP BMDensThresh filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMDensThreshFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandDensThreshT{paddr: paddr, vaddr: candVaddr, routeLLC: routeLLC});
            $display("%t AlexLog: CDP BMDensThresh filter MISS, issuing prefetch lineAddr %h routeLLC: %b", cur_cycle, lineAddr, routeLLC);
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
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
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
