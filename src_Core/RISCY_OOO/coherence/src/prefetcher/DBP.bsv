// DBP.bsv -- Dependence-Based Prefetcher (Roth/Moshovos/Sohi, ASPLOS '98)
//
// Faithful adaptation of the original DBP mechanism to Toooba's
// CacheLinePrefetcher interface. Learns producer-consumer dependences
// across load instructions: a load P is a producer for a load C if the
// value P loads is later used as C's effective address (possibly with a
// small offset, e.g. `p = p->next->left` gives offset=8). A correlation
// (P -> C, offset) is recorded in the Correlation Table (CT); when P
// subsequently loads a new value V, a prefetch for (V + offset) is
// issued on C's behalf.
//
// Two structures:
//   PPW (Potential Producer Window) -- 128-entry, direct-mapped
//     BRAM indexed by hash(value). Entry: {value, producerPC}.
//     Records recently-loaded values along with the load instruction
//     that produced them.
//   CT (Correlation Table) -- 256-entry, direct-mapped BRAM indexed
//     by hash(producerPC). Entry: {producerPC, consumerPC, offset}.
//     Records learned dependences.
//
// Pipelining -- three steps per reportIncomingCacheLine event:
//   (1) Consumer step: look up addr in PPW. If found with producer P',
//       insert correlation (P' -> pcHash, offset=addr-P'.value) in CT.
//   (2) Trigger step: look up pcHash in CT. If (pcHash -> C, off)
//       correlation exists, compute prefetchAddr = loadedValue + off
//       and enqueue for TLB translation + dedup + issue.
//   (3) Producer step: insert (loadedValue, pcHash) into PPW so that
//       future consumers of loadedValue can be detected.
//
// Toooba-specific adaptations (see cdp_experiments/DBP_design_plan_2026-04-22.md):
//   - Training fires only on demand Ld L1 MISSES via reportIncomingCacheLine
//     (matches existing CDP variant pattern). The paper trains on every
//     committed load, but Toooba's prefetcher interface doesn't see hits
//     cleanly; missing loads are where pointer-chase correlations matter
//     most.
//   - "Loaded value" is extracted deterministically from the returned line
//     using the load's line-offset: loadedValue = line[addr[5:3]].
//   - Prefetches fill L1 directly (no separate Prefetch Buffer); dedup
//     via a 1024-entry hash-keyed filter (reuse CDP BM pattern).
//   - No confidence gate and no dataflow cascade (prefetch-completion
//     does NOT re-probe CT) -- matches the paper's main-evaluation
//     configuration ("single-instance-ahead" throttling).
//   - incomingQ is mkOverflowBypassFifo: drop-on-full prevents
//     method-guard back-pressure into pipelineResp_cRq (the H7 lesson,
//     see memory bsv_method_guard_backpressure_lesson.md).

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
import CDP::*;   // reuse NextCandT

// Per-PPW slot state.
typedef struct {
    Bit#(64) value;
    Bit#(16) producerPC;
} PPWEntryT deriving (Bits, FShow, Eq);

// Per-CT slot state. Offset is a signed 13-bit field (+/- 4 KB around
// the producer's loaded value -- covers typical LDS node struct sizes).
typedef struct {
    Bit#(16) producerPC;
    Bit#(16) consumerPC;
    Int#(13) offset;
} CTEntryT deriving (Bits, FShow, Eq);

typedef struct { LineAddr lineAddr; } DBPFilterEntryT deriving (Bits, FShow, Eq);

module mkDBP#(
    TlbToPrefetcher toTlb
)(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz),
    FShow#(reqT),
    IsProcRq#(reqT)
);

    // ---- Staging FIFO (H7 lesson: non-blocking method enq) -----------
    // Tuple: (pcHash, loadAddr, line).
    Fifo#(32, Tuple3#(Bit#(16), Addr, Line)) incomingQ <- mkOverflowBypassFifo;

    // ---- Correlation structures ------------------------------------
    RWBramCore#(Bit#(7), Maybe#(PPWEntryT)) ppw <- mkRWBramCoreForwarded();
    RWBramCore#(Bit#(8), Maybe#(CTEntryT))  ct  <- mkRWBramCoreForwarded();

    // Staging between rdReq and rdResp of PPW/CT. Carries enough state
    // to perform all three pipeline steps once responses arrive.
    // Tuple: (pcHash, loadAddr, loadedValue).
    FIFO#(Tuple3#(Bit#(16), Addr, Bit#(64))) lookupPendingQ <- mkFIFO;

    // ---- Prefetch output path --------------------------------------
    FIFO#(Addr) candFIFO <- mkSizedFIFO(8);

    // TLB id-keyed slot vector (same pattern as CDPBitMatch -- avoids
    // the out-of-order-TLB-response bug the naive FIFO form suffered).
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr <- replicateM(mkRegU);

    // Dedup filter: 1024-entry hash-keyed; stores lineAddr so we can
    // verify the hash bucket actually held this line (not an alias).
    RWBramCore#(Bit#(10), Maybe#(DBPFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    FIFO#(Tuple3#(Bit#(10), Addr, Addr)) filterPendingQ <- mkFIFO;

    // External output to L1Bank.
    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;

    // ---- Init -------------------------------------------------------
    Reg#(Bool) ppwInited     <- mkConfigReg(False);
    Reg#(Bit#(7)) ppwInitCnt <- mkReg(0);
    Reg#(Bool) ctInited      <- mkConfigReg(False);
    Reg#(Bit#(8)) ctInitCnt  <- mkReg(0);
    Reg#(Bool) filterInited  <- mkConfigReg(False);
    Reg#(Bit#(10)) filterInitCnt <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCnt <- mkReg(0);

    (* mutually_exclusive = "doPpwInit, processLookups" *)
    rule doPpwInit(!ppwInited);
        ppw.wrReq(ppwInitCnt, Invalid);
        if (ppwInitCnt == ~0) ppwInited <= True;
        ppwInitCnt <= ppwInitCnt + 1;
    endrule

    (* mutually_exclusive = "doCtInit, processLookups" *)
    rule doCtInit(!ctInited);
        ct.wrReq(ctInitCnt, Invalid);
        if (ctInitCnt == ~0) ctInited <= True;
        ctInitCnt <= ctInitCnt + 1;
    endrule

    (* mutually_exclusive = "doFilterInit, processFilterResp" *)
    rule doFilterInit(!filterInited);
        prefetchFilter.wrReq(filterInitCnt, Invalid);
        if (filterInitCnt == ~0) filterInited <= True;
        filterInitCnt <= filterInitCnt + 1;
    endrule

    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCnt);
        if (tlbReqFreeQInitCnt == ~0) tlbReqFreeQInited <= True;
        tlbReqFreeQInitCnt <= tlbReqFreeQInitCnt + 1;
    endrule

    function Bool allInited = ppwInited && ctInited && filterInited && tlbReqFreeQInited;

    // ---- Pipeline: drainIncoming -> processLookups ----------------
    //
    // drainIncoming reads PPW and CT in parallel; processLookups consumes
    // the responses and performs all three DBP steps (consumer / trigger
    // / producer) with at most one BRAM write to each structure per event.

    rule drainIncoming(allInited);
        match {.pcHash, .loadAddr, .line} = incomingQ.first;
        incomingQ.deq;

        // Loaded value: the 64-bit word in the returned line at the
        // load's byte-offset. addr[5:3] picks one of the 8 aligned
        // 64-bit slots.
        Bit#(3) wordIdx = loadAddr[5:3];
        Bit#(64) loadedValue = line[wordIdx];

        // Issue reads.  PPW is keyed by hash(loadAddr): we're asking
        // "did any prior load produce this address value?"  CT is
        // keyed by hash(pcHash): "does this PC have a learned consumer?"
        Bit#(7) ppwKey = hash(loadAddr);
        Bit#(8) ctKey  = hash(pcHash);
        ppw.rdReq(ppwKey);
        ct.rdReq(ctKey);

        lookupPendingQ.enq(tuple3(pcHash, loadAddr, loadedValue));

        $display("%t AlexLog: DBP drainIncoming pcHash=%h addr=%h loadedVal=%h",
                 cur_cycle, pcHash, loadAddr, loadedValue);
    endrule

    rule processLookups(allInited);
        let ppwResp = ppw.rdResp;        ppw.deqRdResp;
        let ctResp  = ct.rdResp;         ct.deqRdResp;
        match {.pcHash, .loadAddr, .loadedValue} = lookupPendingQ.first;
        lookupPendingQ.deq;

        // Step 1 -- Consumer attribution.
        // If the current load's effective address matches a value
        // produced by an earlier load P (recorded in PPW), create the
        // correlation (P -> pcHash, offset = loadAddr - P.value) in CT.
        if (ppwResp matches tagged Valid .ppe
                &&& ppe.value == loadAddr
                &&& ppe.producerPC != pcHash
                // Offset must fit in Int#(13), i.e. |offset| < 4 KB, to
                // be a plausible struct-field access. Big differences
                // are spurious aliasing and are dropped.
                &&& ((loadAddr - ppe.value) < 'h1000 || (ppe.value - loadAddr) < 'h1000)) begin
            Int#(13) learnedOffset = unpack(truncate(pack(loadAddr - ppe.value)));
            Bit#(8) prodCtKey = hash(ppe.producerPC);
            ct.wrReq(prodCtKey, Valid(CTEntryT{
                producerPC: ppe.producerPC,
                consumerPC: pcHash,
                offset:     learnedOffset
            }));
            $display("%t AlexLog: DBP correlation-learned producer=%h consumer=%h offset=%d",
                     cur_cycle, ppe.producerPC, pcHash, learnedOffset);
        end

        // Step 2 -- Trigger.
        // If this load's PC is a known producer (hit in CT) with a
        // learned consumer, issue a prefetch for (loadedValue + offset).
        // The CT lookup was keyed by hash(pcHash), so we must verify
        // the slot's producerPC matches pcHash (hash aliasing).
        if (ctResp matches tagged Valid .cte
                &&& cte.producerPC == pcHash) begin
            // prefetchAddr = loadedValue + offset. Sign-extend offset
            // to 64 bits.
            Bit#(64) signedOff = signExtend(pack(cte.offset));
            Addr prefetchAddr = loadedValue + signedOff;
            // Plausibility: skip near-null pointers (top few pages).
            // Full address-range gating happens after TLB translation.
            if (prefetchAddr >= 'h1000) begin
                candFIFO.enq(prefetchAddr);
                $display("%t AlexLog: DBP trigger producer=%h consumer=%h loadedVal=%h off=%d prefetchAddr=%h",
                         cur_cycle, pcHash, cte.consumerPC, loadedValue, cte.offset, prefetchAddr);
            end
        end

        // Step 3 -- Producer update.
        // Insert (loadedValue, pcHash) so a future consumer whose
        // effective address == loadedValue can find this PC as its
        // producer.
        Bit#(7) valKey = hash(loadedValue);
        ppw.wrReq(valKey, Valid(PPWEntryT{
            value:      loadedValue,
            producerPC: pcHash
        }));
    endrule

    // ---- TLB translation + dedup + issue --------------------------
    rule processTlbReq(allInited);
        Addr candVaddr = candFIFO.first;
        candFIFO.deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id] <= candVaddr;
    endrule

    rule processTlbResp(allInited);
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr = pendCandVaddr[id];
        tlbReqFreeQ.enq(id);
        // Main memory range 0x80000000..0x90000000 (256 MB). Drop
        // translations outside (MMIO / unmapped / AXI DECERR).
        Bool paddrInMainMem = (resp.paddr >= 'h8000_0000) && (resp.paddr < 'h9000_0000);
        if (!resp.haveException && paddrInMainMem) begin
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple3(filterIdx, resp.paddr, candVaddr));
        end else begin
            $display("%t AlexLog: DBP dropped vaddr %h paddr %h (exc=%b mainMem=%b)",
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
            $display("%t AlexLog: DBP filter HIT, dropping lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(DBPFilterEntryT{ lineAddr: lineAddr }));
            nextCandidateBuffer.enq(NextCandT{paddr: paddr, vaddr: candVaddr, isNeighbourLine: False});
            $display("%t AlexLog: DBP filter MISS, issuing prefetch lineAddr %h", cur_cycle, lineAddr);
        end
    endrule

    // ---- Methods ---------------------------------------------------

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // Train + trigger only on demand Ld L1 misses.
        if (getReqOp(req) == Ld
                && !cRqIsPrefetch
                && wasMiss
                && !wasNeighbourPrefetch) begin
            incomingQ.enq(tuple3(getPcHash(req), getReqAddr(req), line));
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        noAction;
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        noAction;
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
        noAction;
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
