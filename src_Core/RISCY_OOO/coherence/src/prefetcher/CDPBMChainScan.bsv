// CDPBMChainScan.bsv -- BMAlignSupp + classical Cooksey depth-1 chain scan.
//
// Extends AlignSupp with the original Cooksey CDP paper's "depth-N"
// mechanism: when an AlignSupp-issued prefetch arrives at L1, re-scan
// its contents for more bit-match candidates. Depth-1 only: the
// chain-issued prefetches are marked isNeighbourLine=True so subsequent
// arrivals don't re-scan (preventing unbounded recursion / divergence).
//
// Trigger:
//   Demand miss (cRqIsPrefetch=False, wasMiss=True) → scan, emit as
//     isNeighbourLine=False (first-level prefetch)
//   Prefetch arrival (cRqIsPrefetch=True, wasNeighbourPrefetch=False) →
//     scan, emit as isNeighbourLine=True (chain prefetch, no further chain)
//   Chain prefetch arrival (cRqIsPrefetch=True, wasNeighbourPrefetch=True) →
//     ignored (terminates depth at 1)
//
// Scan logic: identical to AlignSupp — VPN-match at matchBits=27, plus
// pointer-shape filter (16-byte align, upper-25-bits-zero, non-null), plus
// multi-match suppress.

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

typedef struct { LineAddr lineAddr; } BMChainScanFilterEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool routeLLC;
    Bool isChain;   // True if emitted from chain scan (no further chaining)
} NextCandChainScanT deriving (Bits, FShow, Eq);

// Work item: a line to scan, plus the demand VPN to match against, plus
// whether this scan was triggered by demand (isChain=False) or by
// prefetch arrival (isChain=True).
typedef struct {
    Line  line;
    Vpn   vpn;
    Bool  isChain;
} ChainScanWorkT deriving (Bits, FShow, Eq);

module mkCDPBMChainScan#(
    TlbToPrefetcher toTlb,
    Parameter#(matchBits) _
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT),
    Add#(a__, matchBits, 27)
);

    FIFO#(ChainScanWorkT) scanWorkQ <- mkFIFO;

    // Candidate FIFO now carries (vaddr, routeLLC, isChain) so chain-scan-
    // issued candidates flow through with the chain flag.
    SupFifo#(8, 8, Tuple3#(Addr, Bool, Bool)) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandChainScanT) nextCandidateBuffer <- mkOverflowBypassFifo;

    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendRouteLLC <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendIsChain  <- replicateM(mkRegU);

    RWBramCore#(Bit#(10), Maybe#(BMChainScanFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    FIFO#(Tuple5#(Bit#(10), Addr, Addr, Bool, Bool)) filterPendingQ <- mkFIFO;

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

    function Bool isPtrShape(Addr w);
        Bool upperZero = (w[63:39] == 0);
        Bool aligned16 = (w[3:0] == 0);
        Bool nonNull   = (w != 0);
        return upperZero && aligned16 && nonNull;
    endfunction

    rule doScan(filterInited && tlbReqFreeQInited);
        ChainScanWorkT w = scanWorkQ.first;
        scanWorkQ.deq;
        Bit#(matchBits) missUpper = truncateLSB(w.vpn);

        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(w.line[i]));
            if (candUpper == missUpper && isPtrShape(w.line[i]))
                matchCount = matchCount + 1;
        end
        Bool suppress = matchCount >= 2;
        Integer enqIdx = 0;
        if (!suppress) begin
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(w.line[i]));
                if (candUpper == missUpper && isPtrShape(w.line[i])) begin
                    candFIFO.enqS[enqIdx].enq(tuple3(w.line[i], False, w.isChain));
                    $display("%t AlexLog: CDP BMChainScan candidate offset: %d candVaddr: %h matchCount: %d isChain: %b",
                        cur_cycle, i, w.line[i], matchCount, w.isChain);
                    enqIdx = enqIdx + 1;
                end
            end
        end else begin
            $display("%t AlexLog: CDP BMChainScan SUPPRESS matchCount: %d isChain: %b",
                cur_cycle, matchCount, w.isChain);
        end
    endrule

    rule processTlbReq(filterInited && tlbReqFreeQInited);
        match {.candVaddr, .routeLLC, .isChain} = candFIFO.deqS[0].first;
        candFIFO.deqS[0].deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id] <= candVaddr;
        pendRouteLLC[id] <= routeLLC;
        pendIsChain[id]  <= isChain;
    endrule

    rule processTlbResp(filterInited && tlbReqFreeQInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr = pendCandVaddr[id];
        Bool routeLLC  = pendRouteLLC[id];
        Bool isChain   = pendIsChain[id];
        tlbReqFreeQ.enq(id);
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple5(filterIdx, resp.paddr, candVaddr, routeLLC, isChain));
        end else begin
            $display("%t AlexLog: CDP BMChainScan dropped vaddr %h paddr %h (exc=%b mainMem=%b isChain=%b)",
                cur_cycle, candVaddr, resp.paddr, resp.haveException, paddrInMainMem, isChain);
        end
    endrule

    rule processFilterResp(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .paddr, .candVaddr, .routeLLC, .isChain} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP BMChainScan filter HIT, dropping lineAddr %h isChain=%b",
                cur_cycle, lineAddr, isChain);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMChainScanFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandChainScanT{paddr: paddr, vaddr: candVaddr, routeLLC: routeLLC, isChain: isChain});
            $display("%t AlexLog: CDP BMChainScan filter MISS, issuing prefetch lineAddr %h isChain=%b routeLLC: %b",
                cur_cycle, lineAddr, isChain, routeLLC);
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // Case 1: demand miss of Ld → scan and emit first-level candidates.
        if (filterInited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            scanWorkQ.enq(ChainScanWorkT{line: line, vpn: getReqVpn(req), isChain: False});
        end
        // Case 2: prefetch arrival (but NOT a chain prefetch) → re-scan for depth-1 chain.
        // wasMiss=True means the prefetch actually fetched a line; the line data is what we scan.
        // We exclude wasNeighbourPrefetch=True to prevent depth >= 2.
        else if (filterInited && cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            // For chain scan, we match against the prefetched line's OWN VPN
            // (the line contains pointers, and we want pointers to same page
            // as the prefetched line — this chases the chain forward).
            scanWorkQ.enq(ChainScanWorkT{line: line, vpn: getReqVpn(req), isChain: True});
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
            isNeighbourLine: x.isChain
        };
    endmethod
endmodule
