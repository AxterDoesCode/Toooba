// CDPBMAlignSupp.bsv -- BMPolySupp + pointer-shape filters.
// Combines two proven mechanisms:
//   (a) BMPolySupp: multi-match lines (matchCount>=2) suppressed entirely;
//       single-match lines routed to L1.
//   (b) BMAligned: candidate word must be at least 16-byte aligned
//       (low 4 bits == 0). Heap objects from glibc malloc are 16-byte
//       aligned; random data rarely has exactly low 4 bits zero.
//
// Additionally apply a "valid SV39 vaddr" check: upper 25 bits (bits
// [63:39]) must be zero. Main-memory vaddrs/paddrs fit in 39 bits; a word
// with nonzero upper 25 bits is definitely data, not a pointer.
//
// Goal: tighten pointer detection beyond what matchBits=27 alone provides.
// Bit-match via VPN-match has ~2^-27 random-match probability; combining
// with 16-byte alignment adds ~2^-4; combining with upper-25-bits-zero
// adds ~2^-25. Combined detector false-positive rate is << 1 per billion
// random words.

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

typedef struct { LineAddr lineAddr; } BMAlignSuppFilterEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool routeLLC;
} NextCandAlignSuppT deriving (Bits, FShow, Eq);

module mkCDPBMAlignSupp#(
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

    Fifo#(16, NextCandAlignSuppT) nextCandidateBuffer <- mkOverflowBypassFifo;

    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendRouteLLC <- replicateM(mkRegU);

    RWBramCore#(Bit#(10), Maybe#(BMAlignSuppFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
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

    function Bool isPtrShape(Addr w);
        // Valid SV39 vaddr: upper 25 bits zero + low 4 bits zero + non-null.
        Bool upperZero = (w[63:39] == 0);
        Bool aligned16 = (w[3:0] == 0);
        Bool nonNull  = (w != 0);
        return upperZero && aligned16 && nonNull;
    endfunction

    rule deqLineL1(filterInited && tlbReqFreeQInited);
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        // Two-pass: first count matches that pass the pointer-shape gate.
        Bit#(4) matchCount = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper && isPtrShape(x.line[i]))
                matchCount = matchCount + 1;
        end
        // Multi-match under tight filter is still "split pointers" — suppress.
        Bool suppress = matchCount >= 2;
        Integer enqIdx = 0;
        if (!suppress) begin
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
                if (candUpper == missUpper && isPtrShape(x.line[i])) begin
                    candFIFO.enqS[enqIdx].enq(tuple2(x.line[i], False));
                    $display("%t AlexLog: CDP BMAlignSupp candidate offset: %d candVaddr: %h matchCount: %d L1",
                        cur_cycle, i, x.line[i], matchCount);
                    enqIdx = enqIdx + 1;
                end
            end
        end else begin
            $display("%t AlexLog: CDP BMAlignSupp SUPPRESS matchCount: %d (multi-match)",
                cur_cycle, matchCount);
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
            $display("%t AlexLog: CDP BMAlignSupp dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
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
            $display("%t AlexLog: CDP BMAlignSupp filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(BMAlignSuppFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandAlignSuppT{paddr: paddr, vaddr: candVaddr, routeLLC: routeLLC});
            $display("%t AlexLog: CDP BMAlignSupp filter MISS, issuing prefetch lineAddr %h routeLLC: %b", cur_cycle, lineAddr, routeLLC);
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
