// CDPBitMatch.bsv -- Variant BM: clean bit-matching-only prefetcher.
// The reusable primitive from the original Cooksey et al. CDP paper is the
// "virtual-address recognition by bit matching": a word in a cache line is
// treated as a pointer candidate iff its upper matchBits bits equal the
// upper matchBits bits of the demand-load's VPN.
//
// This module implements ONLY that primitive + a small dedup filter:
//   - On cache-LINE-MISS for a Ld: scan the 8 words of the loaded line.
//   - For each word with matching upper-bits: issue a prefetch to the
//     target line iff the target's lineAddr is not already in the
//     1024-entry prefetch filter (dedup).
//   - No PC table, no training table, no per-(PC, relOff) conf.
//   - No utility feedback (reportUsefulPrefetch is ignored).
//
// Differences from the existing mkCDPNaive (in CDP.bsv):
//   - mkCDPNaive scans on EVERY load (hits and misses). Here we scan only
//     on misses — newly-fetched lines are where content is worth scanning.
//   - mkCDPNaive has no dedup filter, so recurring pointer words re-issue
//     prefetches indefinitely. Here a 1024-entry hash-keyed filter drops
//     duplicates.
//
// Intended as the CLEAN reference point for "how far does pure bit-matching
// get you?" — orthogonal to the PC/TT-learning variants (CDP-M, CDP-N, etc.).

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

typedef struct { LineAddr lineAddr; } BMPolyFilterEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool routeLLC;
} NextCandPolyT deriving (Bits, FShow, Eq);

module mkCDPBitMatchPoly#(
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

    // Candidate queue: up to 8 per line. Also carries routeLLC decision made
    // at scan time based on the per-line match count (1 match -> L1, >=2 -> LLC).
    SupFifo#(8, 8, Tuple2#(Addr, Bool)) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandPolyT) nextCandidateBuffer <- mkOverflowBypassFifo;

    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendRouteLLC <- replicateM(mkRegU);

    // 1024-entry dedup filter keyed by hash(lineAddr). Hash-based, so evicts
    // under pressure — good enough for "recently issued" dedup without the
    // cost of a full associative structure.
    RWBramCore#(Bit#(10), Maybe#(BMPolyFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    // Stash the full translated paddr+vaddr+routeLLC until the filter read returns.
    FIFO#(Tuple4#(Bit#(10), Addr, Addr, Bool)) filterPendingQ <- mkFIFO;

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

    rule deqLineL1(filterInited && tlbReqFreeQInited);
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        // Two-pass: count matches first, then route decision.
        // 1 match -> L1 (single pointer chase — likely correct).
        // >= 2 -> LLC (multi-candidate — probably "both children" or noise).
        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper)
                matchCount = matchCount + 1;
        end
        Bool routeLLC = matchCount >= 2;
        Integer enqIdx = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper) begin
                candFIFO.enqS[enqIdx].enq(tuple2(x.line[i], routeLLC));
                $display("%t AlexLog: CDP BitMatchPoly candidate offset: %d candVaddr: %h matchCount: %d routeLLC: %b",
                    cur_cycle, i, x.line[i], matchCount, routeLLC);
                enqIdx = enqIdx + 1;
            end
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
            $display("%t AlexLog: CDP BitMatchPoly dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
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
            $display("%t AlexLog: CDP BitMatchPoly filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMPolyFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandPolyT{paddr: paddr, vaddr: candVaddr, routeLLC: routeLLC});
            $display("%t AlexLog: CDP BitMatchPoly filter MISS, issuing prefetch lineAddr %h routeLLC: %b", cur_cycle, lineAddr, routeLLC);
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // Only scan on MISSES of Ld (not hits, not prefetches, not neighbour-chain).
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
