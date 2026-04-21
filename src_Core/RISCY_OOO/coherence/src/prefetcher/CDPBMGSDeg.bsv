// CDPBitMatchEarly.bsv -- Variant BM-EARLY: BM's bit-matching + stride-on-HIT.
// Motivation from parser-level analysis: on treeadd, 47% of BM+STRIDE's
// prefetches arrive AFTER the demand miss (`latePrefetch`=3840/8189). Those
// prefetches contribute zero. Root cause: miss-only scanning fires only
// after a miss, but by then the next demand for line+1 is already in
// flight. Issuing the stride-ahead from a demand HIT moves the prefetch
// creation ~hundreds of cycles earlier, giving it enough lead time to
// become either `demandOwned` (merged in-flight) or `usefulPrefetch`
// (fully-resident L1 hit).
//
// Policy:
//   - On MISS (Ld only): same as BM+STRIDE — scan loaded line for bit-match
//     candidates, AND emit line+1.
//   - On HIT (Ld only): emit line+1 stride prefetch. Dedup filter drops
//     duplicates so aggressively-repeated access patterns don't flood.
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

typedef struct { LineAddr lineAddr; } BMGSDegFilterEntryT deriving (Bits, FShow, Eq);

module mkCDPBMGSDeg#(
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

    // Candidate queue: up to 8 per line.
    SupFifo#(8, 8, Addr) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;

    // TLB request tracking: id-keyed register file so responses are paired
    // correctly even if the TLB returns them out of order. See the bug in
    // the original mkCDPNaive and early BM that used a FIFO — pre-fetched
    // paddr would be paired with the wrong candVaddr under out-of-order TLB
    // responses, leading to garbage prefetches and health/patricia crashes.
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);

    // 1024-entry dedup filter keyed by hash(lineAddr). Hash-based, so evicts
    // under pressure — good enough for "recently issued" dedup without the
    // cost of a full associative structure.
    RWBramCore#(Bit#(10), Maybe#(BMGSDegFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    // Stash the full translated paddr+vaddr until the filter read returns.
    FIFO#(Tuple3#(Bit#(10), Addr, Addr)) filterPendingQ <- mkFIFO;

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
        // BMGS-Deg: bit-matching is a CONTROL SIGNAL, not a prefetch source.
        // Count bit-matches in the loaded line; use the count to pick stride
        // degree. No bit-match candidates are themselves issued as prefetches;
        // only line+1..line+N where N depends on match count.
        //
        // 0 matches -> 0 stride prefetches (suppress — we're in a cold/leaf region)
        // 1 match   -> 1 stride (line+1)
        // 2 matches -> 2 stride (line+1, line+2)
        // 3 matches -> 3 stride (line+1, line+2, line+3)
        // 4+ matches -> 4 stride (capped at degree 4)
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper)
                matchCount = matchCount + 1;
        end
        // Clamp degree to [0, 4].
        Bit#(4) degree = (matchCount > 4) ? 4 : matchCount;
        Addr baseLine = getReqAddr(x.req) & 'hFFFF_FFFF_FFFF_FFC0;
        if (degree >= 1) candFIFO.enqS[0].enq(baseLine + 64);
        if (degree >= 2) candFIFO.enqS[1].enq(baseLine + 128);
        if (degree >= 3) candFIFO.enqS[2].enq(baseLine + 192);
        if (degree >= 4) candFIFO.enqS[3].enq(baseLine + 256);
        $display("%t AlexLog: CDP BMGSDeg matchCount: %d stride-degree: %d",
            cur_cycle, matchCount, degree);
    endrule

    rule processTlbReq(filterInited && tlbReqFreeQInited);
        Addr candVaddr = candFIFO.deqS[0].first;
        candFIFO.deqS[0].deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id] <= candVaddr;
    endrule

    rule processTlbResp(filterInited && tlbReqFreeQInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr = pendCandVaddr[id];
        tlbReqFreeQ.enq(id);
        // Main memory range on this Toooba config is 0x80000000 .. 0x90000000
        // (256MB). Prefetches outside are either MMIO (side-effects) or
        // unmapped (AXI DECERR). Drop them — this is the BM-v3 paddr gate.
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple3(filterIdx, resp.paddr, candVaddr));
        end else begin
            $display("%t AlexLog: CDP BMGSDeg dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
                cur_cycle, candVaddr, resp.paddr, resp.haveException, paddrInMainMem);
        end
    endrule

    rule processFilterResp(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .paddr, .candVaddr} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP BMGSDeg filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMGSDegFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandT{paddr: paddr, vaddr: candVaddr, isNeighbourLine: False});
            $display("%t AlexLog: CDP BMGSDeg filter MISS, issuing prefetch lineAddr %h", cur_cycle, lineAddr);
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // Only scan on MISSES of Ld (not hits, not prefetches, not neighbour-chain).
        if (filterInited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            l1ToCDP.enq(L1ToCDPT{req: req, line: line});
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        // Degree-2 stride on HIT: line+1 AND line+2.
        if (filterInited && tlbReqFreeQInited && hitMiss == HIT && op == Ld && !isPrefetch) begin
            Addr baseLine = addr & 'hFFFF_FFFF_FFFF_FFC0;
            candFIFO.enqS[0].enq(baseLine + 64);
            candFIFO.enqS[1].enq(baseLine + 128);
            $display("%t AlexLog: CDP BMGSDeg hit-stride line+1: %h line+2: %h (from addr %h)",
                cur_cycle, baseLine + 64, baseLine + 128, addr);
        end
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
            nextLevel: False,
            isNeighbourLine: False
        };
    endmethod
endmodule
