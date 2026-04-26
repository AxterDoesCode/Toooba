// SPPCooksey.bsv -- SPP (Signature Path Prefetcher) augmented with Cooksey
// bit-matching pointer discovery on demand-Ld L1 misses.
//
// Motivation: SPP learns delta patterns within 4 KB pages, plus (in the
// paper) cross-page bootstrapping via GHR. It does NOT look at cache-line
// DATA, so it cannot see that a line contains a pointer to an arbitrary
// page. Cooksey bit-matching (from the original Cooksey et al. CDP paper)
// does exactly that. The two mechanisms are orthogonal:
//   - SPP handles: strided arrays, same-page linked lists, delta-pattern
//     cross-page (via GHR).
//   - Cooksey handles: scattered pointer-chase across arbitrary pages,
//     discovered by scanning returned cache-line content.
//
// Fusion mechanism (v1 -- "Cooksey-on-miss"):
//   Every time reportIncomingCacheLine fires for a demand Ld L1 miss,
//   we stage the (reqVpn, line) into a scan queue. A scan rule iterates
//   over the 8 aligned 64-bit words in the line. Each word whose upper
//   matchBits agree with the demand's VPN AND whose low 3 bits are zero
//   (pointer-aligned) becomes a prefetch candidate. These are enqueued
//   into SPP's existing post-filter prefetch queue (bypassing SPP's
//   PrefetchFilter -- Cooksey candidates don't feed alpha).
//
// Reuses the submodules defined in SPP.bsv (Divider, PrefetchCalculator,
// SignatureTable, PatternTable, PrefetchFilter) verbatim.
//
// See cdp_experiments/SPP_Cooksey_design_2026-04-23.md for design
// rationale and rejected alternatives.

import Prefetcher_intf::*;
import Types::*;
import MemoryTypes::*;
import CCTypes::*;
import TlbTypes::*;
import ProcTypes::*;
import Vector::*;
import FIFO::*;
import Fifos::*;
import FIFOF::*;
import SpecialFIFOs::*;
import GetPut::*;
import RWBramCore::*;
import FixedPoint::*;
import ConfigReg::*;

// Import SPP to get Divider, PrefetchCalculator, SignatureTable,
// PatternTable, PrefetchFilter, and the Prob/Sig/Count/Delta typedefs.
import SPP::*;

module mkSPPCooksey#(
    TlbToPrefetcher toTlb
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT)
);
    // -------- SPP submodules (same config as mkSPP) ----------------
    Prob prefetchThreshold = 7'b0100000;   // ~0.25 in 7-bit fixed point
    Bool useFilter = True;
    String divTableFile = "";              // unused; inlined via include in SPP.bsv

    PrefetchCalculator#(8, 8) calculator <- mkPrefetchCalculator(prefetchThreshold, divTableFile);
    SignatureTable#(4, 64, 4) st <- mkSignatureTable;
    PatternTable#(512, 4) pt <- mkPatternTable;
    PrefetchFilter#(1024, 6, 8) filter <- mkPrefetchFilter;

    // Post-filter prefetch queue (LineAddrs ready to translate via TLB).
    Fifo#(16, LineAddr) addrToPrefetch <- mkOverflowBypassFifo;

    // Final output to L1 (after TLB translation + paddr gate).
    Fifo#(8, PendingPrefetch) nextCandidateBuffer <- mkOverflowBypassFifo;

    // TLB bookkeeping.
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(LineAddr)) pendLineAddr <- replicateM(mkRegU);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCnt <- mkReg(0);

    // -------- Cooksey scan state --------------------------------------
    // cookseyQ: (reqVpn, line) staged per demand-Ld L1 miss.
    Fifo#(16, Tuple2#(Vpn, Line)) cookseyQ <- mkOverflowBypassFifo;
    // Per-line scan state.
    Reg#(Vpn)       scanVpn    <- mkRegU;
    Reg#(Line)      scanLine   <- mkRegU;
    Reg#(Bit#(4))   scanIdx    <- mkReg(8);   // 8 = idle / done
    Reg#(Bool)      scanActive <- mkReg(False);

    // Cooksey config: require upper 16 bits of VPN to match, and low 3
    // bits of the candidate to be zero (aligned pointer). matchBits=16
    // gives a ~8 MB window (like H7's default), admitting cross-page
    // pointers within the benchmark's heap arena.
    Integer matchBits = 16;

    Bool verbose = False;

    // -------- TLB free-queue init -------------------------------------
    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCnt);
        if (tlbReqFreeQInitCnt == ~0) tlbReqFreeQInited <= True;
        tlbReqFreeQInitCnt <= tlbReqFreeQInitCnt + 1;
    endrule

    // -------- SPP internal pipeline (unchanged from mkSPP) ----------
    rule ptlFromStToPt;
        let ptl <- st.getPTLookupEntry;
        pt.doPTLookup(ptl);
    endrule

    rule ptuFromStToPt;
        let ptu <- st.getPTUpdateEntry;
        pt.doPTUpdate(ptu);
    endrule

    rule ptlFromCalcToPt;
        let ptl <- calculator.getPTLookupEntry;
        pt.doPTLookup(ptl);
    endrule

    rule pteFromPtToCalc;
        let {ptl, pte} <- pt.getPTEntry;
        Prob alpha = filter.getCurrAlpha;
        calculator.submitCandidates(ptl.addr, ptl.sig, alpha, ptl.currCumProb, pte.sigCount, pte.deltaCounts, ptl.depth);
    endrule

    rule pfAddrFromCalcToFilter;
        let lineAddr <- calculator.getNextPrefetchAddr;
        let depth <- calculator.getNextPrefetchAddrDepth;
        filter.canPrefetchReq(lineAddr);
    endrule

    rule getAddrFromFilter;
        let {canPrefetch, addr} <- filter.canPrefetchResp;
        if (canPrefetch || !useFilter) begin
            addrToPrefetch.enq(addr);
        end
    endrule

    // -------- Cooksey scan pipeline ---------------------------------
    // Pick up the next line to scan when idle.
    rule cookseyStartScan(!scanActive);
        match {.vpn, .line} = cookseyQ.first;
        cookseyQ.deq;
        scanVpn    <= vpn;
        scanLine   <= line;
        scanIdx    <= 0;
        scanActive <= True;
    endrule

    // Walk the 8 aligned 64-bit words, emit pointer candidates. One
    // candidate tested per cycle; scan completes in <= 8 cycles.
    // Scheduled lower than the SPP-side addrToPrefetch producer via
    // descending_urgency (see below) so SPP output wins when both fire.
    rule cookseyScanStep(scanActive && scanIdx < 8);
        Bit#(64) candidate = scanLine[scanIdx];
        Vpn candVpn = getVpn(candidate);

        // Cooksey: upper `matchBits` bits of the access VPN must equal
        // the upper bits of the candidate's VPN. We use matchBits=16 on
        // a 27-bit VPN, i.e. upper 16 bits must match; a ~8 MB region.
        Bit#(16) accessHi = truncateLSB(scanVpn);   // VPN is 27 bits; take top 16
        Bit#(16) candHi   = truncateLSB(candVpn);
        Bool shapeMatch = (accessHi == candHi)
                       && (candidate[3:0] == 4'b0)   // 16-byte-aligned pointer
                       && (candidate >= 'h1000);     // skip low pages / null
        if (shapeMatch) begin
            LineAddr candLineAddr = getLineAddr(candidate);
            addrToPrefetch.enq(candLineAddr);
            if (verbose) $display("%t SPP-Cooksey: scan word[%d]=%h matched, enq lineAddr %h",
                $time, scanIdx, candidate, candLineAddr);
        end

        if (scanIdx == 7) scanActive <= False;
        scanIdx <= scanIdx + 1;
    endrule

    // SPP-path filter output takes precedence over Cooksey-path scan
    // when both attempt to enq addrToPrefetch in the same cycle.
    (* descending_urgency = "getAddrFromFilter, cookseyScanStep" *)

    // -------- TLB translation -------------------------------------
    rule issueTlbReq(tlbReqFreeQInited);
        LineAddr lineAddr = addrToPrefetch.first;
        addrToPrefetch.deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        Addr vaddr = {lineAddr, 6'b0};
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: vaddr, id: id});
        pendLineAddr[id] <= lineAddr;
    endrule

    rule processTlbResp(tlbReqFreeQInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        LineAddr lineAddr = pendLineAddr[id];
        tlbReqFreeQ.enq(id);
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            Addr vaddr = {lineAddr, 6'b0};
            nextCandidateBuffer.enq(PendingPrefetch{
                addr: resp.paddr,
                vpn: getVpn(vaddr),
                nextLevel: False,
                isNeighbourLine: False
            });
        end
    endrule

    // -------- Methods --------------------------------------------

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss,
                               Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        // SPP trains on every non-prefetch L1 access (same as mkSPP).
        if (!isPrefetch) begin
            LineAddr lineAddr = getLineAddr(addr);
            st.reportAccess(lineAddr);
            filter.reportAccess(lineAddr, hitMiss);
        end
    endmethod

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // Cooksey fires only on demand Ld L1 misses -- the moment a
        // returned cache line's DATA first enters L1.
        if (getReqOp(req) == Ld
                && !cRqIsPrefetch
                && wasMiss
                && !wasNeighbourPrefetch) begin
            cookseyQ.enq(tuple2(getReqVpn(req), line));
        end
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        noAction;
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
        noAction;
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr();
        let p = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        return p;
    endmethod
endmodule
