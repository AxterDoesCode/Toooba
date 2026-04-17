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
import Cur_Cycle::*;

typedef struct {
    reqT req;
    Line line;
} L1ToCDPT#(type reqT) deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool isNeighbourLine;
} NextCandT deriving (Bits, FShow, Eq);

module mkCDPNaive#(
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

    // Up to 8 candidates per cache line; one enqueue port per slot
    SupFifo#(8, 8, Addr) candFIFO <- mkSupFifo;

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;

    // TLB translation pipeline
    FIFO#(Addr) tlbPendingCandQ <- mkSizedFIFO(valueOf(LLCTlbReqNum));
    Reg#(LLCTlbReqIdx) tlbReqId <- mkReg(0);

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        $display("%0d AlexLog: CDP Naive deqLineL1", cur_cycle);
        Integer enqIdx = 0;
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
            if (candUpper == missUpper &&& getReqOp(x.req) == Ld) begin
                candFIFO.enqS[enqIdx].enq(x.line[i]);
                $display("%0d AlexLog: CDP Naive candidate vaddr offset: %d candVaddr: %h crossPage: %b",
                    cur_cycle, i, x.line[i], getVpn(x.line[i]) != getReqVpn(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    rule processTlbReq;
        Addr candVaddr = candFIFO.deqS[0].first;
        candFIFO.deqS[0].deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: tlbReqId});
        tlbPendingCandQ.enq(candVaddr);
        tlbReqId <= tlbReqId + 1;
        $display("%0d AlexLog: CDP Naive TLB req sent for vaddr %h id %d", cur_cycle, candVaddr, tlbReqId);
    endrule

    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        Addr candVaddr = tlbPendingCandQ.first;
        tlbPendingCandQ.deq;
        if (!resp.haveException) begin
            nextCandidateBuffer.enq(NextCandT{paddr: resp.paddr, vaddr: candVaddr, isNeighbourLine: False});
            $display("%0d AlexLog: CDP Naive TLB resp: vaddr %h -> paddr %h", cur_cycle, candVaddr, resp.paddr);
        end else begin
            $display("%0d AlexLog: CDP Naive TLB resp: exception for vaddr %h, dropping", cur_cycle, candVaddr);
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        l1ToCDP.enq(L1ToCDPT{req: req, line: line});
        $display("%0d AlexLog: CDP Naive reportIncomingCacheLine", cur_cycle);
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        noAction;
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch, Bool hitOnPrefetchedLine);
        $display("%0d AlexLog: CDP Naive prefetcher report %s addr %h", cur_cycle, hitMiss == HIT ? "HIT" : "MISS", addr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        $display("%0d AlexLog: CDP Naive Prefetch addr issued. paddr: %h | vaddr: %h", cur_cycle, x.paddr, x.vaddr);
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False,
            isNeighbourLine: False
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
    Bool isTrainingLookup; // True = miss-vaddr lookup (training trigger); False = candidate pointer lookup
    LineDataOffset offset;  // position of candidate in line (only meaningful when !isTrainingLookup)
    Addr candVaddr; // the address being looked up in the training table
} TrainingTableRespQT#(type reqT, type idxT) deriving (Bits, FShow, Eq);

// ============================================================================
// mkCDPStatefulRelative
// Same as mkCDPStateful but trains on the offset of the candidate vaddr
// *relative* to the missed word position, so negative offsets are possible.
// Uses 2-way set-associative BRAMs (RWSetAssocBramCoreForwarded) for both
// the training table and PC table.
// ============================================================================

// Per-offset training count indexed by (relOffset + 7), covering offsets -7..+7 (15 slots)
typedef Vector#(15, Bit#(4)) PCRelOffsetConfT;

typedef struct {
    Bit#(16)         pcHash;
    PCRelOffsetConfT cDelta; // per-offset training event count
    Bit#(4)          cSig;  // total training events for this PC
} PCTableEntryT deriving (Bits, FShow, Eq);

typedef union tagged {
    Tuple2#(Bit#(16), RelLineOffset) Training;      // (pcHash, relOffset) — pcHash carried so it survives into the write-back log
    Tuple3#(Addr, Line, Vpn)         PrefetchIssue; // (load addr, cache line, vpn) to select prefetch target from
    void                              Decay;         // decrement all counters in the selected entry by 1
} PCTableRdRelTagT deriving (Bits, FShow);

module mkCDPStatefulRelative#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____,
    Parameter#(confidenceThreshold) _____
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

    // 2-way set-associative training table
    // addrT = trainingTableIdxT, wayT = Bit#(1), dataT = TrainingTableEntryT, tagT = Addr
    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(1), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    // Slot 0: training trigger (hit-time from reportAccess OR miss-time from deqCacheLines — mutually exclusive)
    // Slots 1-8: candidate pointer lookups (from deqCacheLines)
    SupFifo#(16, 16, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(16, 16, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    // Flat PC confidence table
    RWBramCore#(pcTableIdxT, Maybe#(PCTableEntryT)) pcTable <- mkRWBramCoreForwarded();

    // 64-entry direct-mapped prefetch filter: avoids issuing duplicate prefetches for the same cache line
    RWBramCore#(Bit#(6), Maybe#(LineAddr)) prefetchFilter <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;
    // Filter pipeline: (filterIdx, candidate) queued after TLB resp, consumed by processFilterResp
    FIFO#(Tuple2#(Bit#(6), NextCandT)) filterPendingQ <- mkFIFO;
    // Eviction notifications from L1: clear filter entry for evicted prefetch lines
    FIFO#(LineAddr) evictionQ <- mkSizedFIFO(4);

    // TLB translation pipeline for prefetch candidates
    // Free-list of TLB request slot IDs: dequeue to get a slot before issuing, enqueue back on response.
    // This gives natural backpressure — processTlbReq blocks when all LLCTlbReqNum slots are in use,
    // preventing the monotonically-incrementing counter approach from aliasing in-flight requests.
    FIFO#(Tuple2#(Addr, Bool)) tlbReqFIFO <- mkSizedFIFO(4); // Tuple2 of Vaddr and isNeighbourLine
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendIsNeighbourLine <- replicateM(mkRegU);

    // Init: write unpack(0) (valid=False) to every (addr, way) pair for training table
    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 1))) ttInitCount <- mkReg(0);
    // Flat PC table init
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);
    // Prefetch filter init (64 entries)
    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(6)) filterInitCount <- mkReg(0);
    // TLB free-queue init
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    // Global prefetch accuracy counters for SPP-style confidence.
    // Initialized to 1 (neutral prior: 100% accuracy with low weight) so the
    // threshold check is active immediately without a cold-start deadlock.
    Reg#(Bit#(10)) cTotal  <- mkReg(1); // prefetches issued
    Reg#(Bit#(10)) cUseful <- mkReg(1); // demand hits on prefetched lines

    // Confidence decay
    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bit#(4) shrink1(Bit#(4) x) = x >> 1;

    function Bool inited;
        return ttInited && pcInited && filterInited && tlbReqFreeQInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!ttInited);
        trainingTableIdxT addr = truncateLSB(ttInitCount);
        Bit#(1) way = truncate(ttInitCount);
        trainingTable.wrReq(addr, way, unpack(0));
        if (ttInitCount == maxBound) begin
            ttInited <= True;
            $display("%0d AlexLog: CDP Rel Training table inited", cur_cycle);
        end
        ttInitCount <= ttInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processPcTableRdReq, pcTableResp" *)
    rule doPcTableInit(!pcInited);
        pcTable.wrReq(pcInitCount, Invalid);
        if (pcInitCount == ~0) begin
            pcInited <= True;
            decayLfsr.seed('hA5F1);
            $display("%0d AlexLog: CDP Rel PC table inited", cur_cycle);
        end
        pcInitCount <= pcInitCount + 1;
    endrule

    (* mutually_exclusive = "doFilterInit, processFilterResp, doEvictionClear" *)
    rule doFilterInit(!filterInited);
        prefetchFilter.wrReq(filterInitCount, Invalid);
        if (filterInitCount == ~0) begin
            filterInited <= True;
            $display("%0d AlexLog: CDP Rel prefetch filter inited", cur_cycle);
        end
        filterInitCount <= filterInitCount + 1;
    endrule

    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        if (tlbReqFreeQInitCount == ~0) begin
            tlbReqFreeQInited <= True;
            $display("%0d AlexLog: CDP Rel TLB free queue inited", cur_cycle);
        end
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
    endrule

    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req));
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        $display("%0d AlexLog: CDP Rel deqCacheLines", cur_cycle);
        if (getReqOp(x.req) == Ld) begin
            // Slot 0: training trigger — look up the virtual miss address in training table.
            // If this address was previously seen as a pointer in another cache line, we can
            // reinforce the PC table entry for the PC that originally stored it.
            Addr missVaddr = zeroExtend({pack(getReqVpn(x.req)), getPageOffset(getReqAddr(x.req))});
            Bit#(39) missVaddr39 = truncate(missVaddr);
            trainingTableIdxT missIdx = hash(missVaddr39);
            ttRespQ.enqS[0].enq(TrainingTableRespQT{
                req:              x.req,
                ttIdx:            missIdx,
                isTrainingLookup: True,
                offset:           dataSel,
                candVaddr:        missVaddr});
            ttRdReqSupFIFO.enqS[0].enq(tuple2(missIdx, missVaddr));
            // Slots 1..8: candidate pointer lookups — scan incoming line for pointer-like values
            Integer enqIdx = 1;
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
                if (candUpper == missUpper) begin
                    Bit#(39) vaddr39 = truncate(x.line[i]);
                    trainingTableIdxT idx = hash(vaddr39);
                    ttRespQ.enqS[enqIdx].enq(TrainingTableRespQT{
                        req:              x.req,
                        ttIdx:            idx,
                        isTrainingLookup: False,
                        offset:           fromInteger(i),
                        candVaddr:        x.line[i]});
                    ttRdReqSupFIFO.enqS[enqIdx].enq(tuple2(idx, x.line[i]));
                    LineDataOffset iOff = fromInteger(i);
                    RelLineOffset relOffset = unpack(zeroExtend(iOff)) - unpack(zeroExtend(dataSel));
                    $display("%0d AlexLog: CDP Rel candidate vaddr relOffset: %d pcHash: %h candVaddr: %h crossPage: %b",
                        cur_cycle, relOffset, getPcHash(x.req), x.line[i], getVpn(x.line[i]) != getReqVpn(x.req));
                    enqIdx = enqIdx + 1;
                end
            end
            // One pcTable lookup per incoming line (for prefetch issue on future hits)
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
        if (respQ.isTrainingLookup) begin
            // Training trigger: we looked up the virtual miss address in the training table.
            // A hit means this address was previously seen as a pointer value in another cache
            // line loaded by pcHash=ttRdResp.pcHash, at relative offset ttRdResp.lineOffset.
            // We reinforce that PC table entry now.
            if (rdResp matches tagged Valid {.hitWay, .ttRdResp}) begin
                pcTableIdxT pctIdx = hash(ttRdResp.pcHash);
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training tuple2(ttRdResp.pcHash, ttRdResp.lineOffset)));
                $display("%0d AlexLog: CDP Rel Training hit: missVaddr %h seen before by pcHash %h at relOffset %d",
                    cur_cycle, respQ.candVaddr, ttRdResp.pcHash, ttRdResp.lineOffset);
            end
            // Miss: this vaddr hasn't been seen as a pointer before — nothing to do
        end else begin
            // Candidate lookup: we looked up a pointer-like value from the incoming line.
            // Overwrite the current (pcHash, relOffset) context if the pcHash differs for the vaddr
            // overwriting on hit keeps the entry current if the same vaddr is later seen by a different load PC.
            LineDataOffset dataSel = getLineDataOffset(getReqAddr(respQ.req));
            RelLineOffset relOffset = unpack(zeroExtend(respQ.offset)) - unpack(zeroExtend(dataSel));
            TrainingTableEntryT newEntry = TrainingTableEntryT{
                valid:       True,
                storedVaddr: respQ.candVaddr,
                pcHash:      getPcHash(respQ.req),
                lineOffset:  relOffset
            };
            if (rdResp matches tagged Valid {.hitWay, .ttRdResp}) begin
                // Only overwrite if pcHash has changed — avoids a write when context is stable
                //if (ttRdResp.pcHash != getPcHash(respQ.req)) begin
                    trainingTable.wrReq(respQ.ttIdx, hitWay, newEntry);
                    $display("%0d AlexLog: CDP Rel Overwrote training table, idx: %d candVaddr: %h oldPcHash: %h newPcHash: %h relOffset: %d",
                        cur_cycle, respQ.ttIdx, respQ.candVaddr, ttRdResp.pcHash, getPcHash(respQ.req), relOffset);
            end else begin
                // New candidate — insert into replacement way
                trainingTable.wrReq(respQ.ttIdx, rdRepl, newEntry);
                $display("%0d AlexLog: CDP Rel Wrote to training table, idx: %d candVaddr: %h relOffset: %d",
                    cur_cycle, respQ.ttIdx, respQ.candVaddr, relOffset);
            end
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
            tagged Training {.pcHash, .relOffset}: begin
                // Collision detection — if stored pcHash differs, reset counters
                PCRelOffsetConfT curCDelta = replicate(0);
                Bit#(4) curCSig = 0;
                if (rdResp matches tagged Valid .e) begin
                    if (e.pcHash != pcHash) begin
                        $display("%0d AlexLog: CDP Rel PC table collision at idx: %d evicted pcHash: %h new pcHash: %h",
                            cur_cycle, pctIdx, e.pcHash, pcHash);
                    end else begin
                        curCDelta = e.cDelta;
                        curCSig   = e.cSig;
                    end
                end
                Bit#(4) vecIdx = pack(relOffset + 7);
                // Aging: when cSig is saturated, halve all counts to preserve ratios while making room
                Bool saturated = (curCSig == 15);
                PCRelOffsetConfT agedCDelta = saturated ? map(shrink1, curCDelta) : curCDelta;
                Bit#(4) agedCSig            = saturated ? (curCSig >> 1)         : curCSig;
                Bit#(4) curVal = agedCDelta[vecIdx];
                Bit#(4) newVal = (curVal == 15) ? 15 : curVal + 1;
                Bit#(4) newCSig = (agedCSig == 15) ? 15 : agedCSig + 1;
                pcTable.wrReq(pctIdx, Valid(PCTableEntryT{
                    pcHash: pcHash,
                    cDelta: update(agedCDelta, vecIdx, newVal),
                    cSig:   newCSig
                }));
                $display("%0d AlexLog: CDP Rel PC table updated, idx: %d pcHash: %h relOffset: %d cDelta: %d -> %d cSig: %d -> %d",
                         cur_cycle, pctIdx, pcHash, relOffset, curVal, newVal, curCSig, newCSig);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .entry) begin
                    // Use Int#(5) to avoid overflow: hitOffset (0-7) + relOffset (-7..+7) = -7..+14
                    // which exceeds Int#(4)'s range of -8..+7 for the positive end.
                    Int#(5) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    // Local confidence threshold: issue if cDelta[i]/cSig >= 1/confidenceThreshold
                    // Rearranged (no division): cDelta[i] * confidenceThreshold >= cSig
                    // cTotal/cUseful are still tracked for observability but not used in the check.
                    Bit#(32) threshDenom = fromInteger(valueOf(confidenceThreshold));
                    Bit#(32) cSig32      = extend(entry.cSig);
                    // Unified selection: best high-confidence offset wins regardless of whether
                    // absTarget falls within this cache line or in a neighbouring one.
                    // Iterate high-to-low so lowest relOffset wins on tie.
                    Bool foundHighConf = False;
                    Int#(5) bestAbsTarget = 0;
                    RelLineOffset bestRelOffset = 0;
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(5) relOffset = fromInteger(i - 7);
                        Int#(5) absTarget = hitOffset + relOffset;
                        Bit#(32) lhs = extend(entry.cDelta[fromInteger(i)]) * threshDenom;
                        if (entry.cSig > 0 && lhs >= cSig32) begin
                            bestAbsTarget  = absTarget;
                            bestRelOffset  = fromInteger(i - 7);
                            foundHighConf  = True;
                        end
                    end
                    if (!foundHighConf) begin
                        Bit#(4) maxDelta = 0;
                        for (Integer i = 0; i < 15; i = i + 1)
                            if (entry.cDelta[fromInteger(i)] > maxDelta) maxDelta = entry.cDelta[fromInteger(i)];
                        $display("%0d AlexLog: CDP Rel no high-conf offset: pcHash %h maxCDelta %d cSig %d",
                            cur_cycle, entry.pcHash, maxDelta, entry.cSig);
                    end
                    if (foundHighConf) begin
                        Bit#(4) bestIdx = pack(bestRelOffset + 7);
                        Bool isNeighbour = !(bestAbsTarget >= 0 &&& bestAbsTarget <= 7);
                        $display("%0d AlexLog: CDP Rel prefetch decision: pcHash %h relOffset %d cDelta %d cSig %d isNeighbour %b",
                            cur_cycle, entry.pcHash, bestRelOffset, entry.cDelta[bestIdx], entry.cSig, isNeighbour);
                        if (!isNeighbour) begin
                            // In-bounds: chase the pointer value stored at that word
                            LineDataOffset targetOff = truncate(pack(bestAbsTarget));
                            Addr candidate = line[targetOff];
                            Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                            if (candUpper == addrUpper) begin
                                tlbReqFIFO.enq(tuple2(candidate, False));
                                $display("%0d AlexLog: CDP Rel queued TLB req for candidate vaddr %h pcHash %h relOffset %d",
                                    cur_cycle, candidate, entry.pcHash, bestRelOffset);
                            end else begin
                                $display("%0d AlexLog: CDP Rel skipped invalid vaddr at relOffset %d pcHash %h",
                                    cur_cycle, bestRelOffset, entry.pcHash);
                            end
                        end else begin
                            // Out-of-bounds: pointer lives in the neighbouring cache line, prefetch that line
                            Bit#(TSub#(PageOffsetSz, LgLineSzBytes)) lineInPage = truncateLSB(getPageOffset(addr));
                            Bit#(LgLineSzBytes) lineByteOff = 0;
                            Addr curLineVbase = zeroExtend({pack(reqVpn), lineInPage, lineByteOff});
                            Bool isPrev = bestAbsTarget < 0;
                            Addr neighLineVaddr = isPrev ? curLineVbase - fromInteger(valueOf(TExp#(LgLineSzBytes)))
                                                         : curLineVbase + fromInteger(valueOf(TExp#(LgLineSzBytes)));
                            // Compute exact word vaddr within the neighbouring line.
                            // Int#(5) avoids overflow so isPrev is always correct.
                            // prev: absTarget in -7..-1 → wordInNeigh = absTarget+8, range 1..7
                            // next: absTarget in 8..14  → wordInNeigh = absTarget-8, range 0..6
                            Bit#(5) absTargetBits = pack(bestAbsTarget);
                            Bit#(3) wordInNeigh = isPrev ? truncate(absTargetBits + 8)
                                                         : truncate(absTargetBits - 8);
                            Addr neighWordVaddr = neighLineVaddr + zeroExtend({wordInNeigh, 3'b0});
                            tlbReqFIFO.enq(tuple2(neighWordVaddr, True));
                            $display("%0d AlexLog: CDP Rel queued TLB req for %s line word vaddr %h (word %d) pcHash %h relOffset %d",
                                cur_cycle, isPrev ? "prev" : "next", neighWordVaddr, wordInNeigh, entry.pcHash, bestRelOffset);
                        end
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .entry) begin
                    // Right-shift preserves cDelta/cSig ratios while aging the entry
                    pcTable.wrReq(pctIdx, Valid(PCTableEntryT{
                        pcHash: entry.pcHash,
                        cDelta: map(shrink1, entry.cDelta),
                        cSig:   entry.cSig >> 1
                    }));
                    $display("%0d AlexLog: CDP Rel decay applied to pcTable idx: %d pcHash: %h", cur_cycle, pctIdx, entry.pcHash);
                end
            end
        endcase
    endrule

    // Drain tlbReqFIFO and issue requests to the TLB.
    // Dequeue a free slot ID — blocks naturally if all LLCTlbReqNum slots are in use.
    rule processTlbReq;
        match {.candVaddr, .isNeighbourLine} = tlbReqFIFO.first;
        tlbReqFIFO.deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id]       <= candVaddr;
        pendIsNeighbourLine[id] <= isNeighbourLine;
        $display("%0d AlexLog: CDP Rel TLB req sent for vaddr %h id %d", cur_cycle, candVaddr, id);
    endrule

    // Stage 1: TLB response → read prefetch filter (1-cycle BRAM latency)
    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr       = pendCandVaddr[id];
        Bool isNeighbourLine = pendIsNeighbourLine[id];
        tlbReqFreeQ.enq(id); // return slot to free list
        if (!resp.haveException) begin
            NextCandT cand = NextCandT{paddr: resp.paddr, vaddr: candVaddr, isNeighbourLine: isNeighbourLine};
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(6) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple2(filterIdx, cand));
            $display("%0d AlexLog: CDP Rel TLB resp: vaddr %h -> paddr %h lineAddr %h", cur_cycle, candVaddr, resp.paddr, lineAddr);
        end else begin
            $display("%0d AlexLog: CDP Rel TLB resp: exception for vaddr %h, dropping prefetch", cur_cycle, candVaddr);
        end
    endrule

    // Stage 2: filter check → issue prefetch or drop duplicate
    (* descending_urgency = "doEvictionClear, processFilterResp" *)
    rule processFilterResp(inited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .cand} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(cand.paddr);
        if (rdResp matches tagged Valid .storedAddr &&& storedAddr == lineAddr) begin
            $display("%0d AlexLog: CDP Rel filter HIT: dropped duplicate prefetch for lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(lineAddr));
            nextCandidateBuffer.enq(cand);
            $display("%0d AlexLog: CDP Rel filter MISS: issuing prefetch for lineAddr %h", cur_cycle, lineAddr);
        end
    endrule

    // Clear filter entry when a prefetched line is evicted from L1
    rule doEvictionClear(filterInited);
        LineAddr lineAddr = evictionQ.first;
        evictionQ.deq;
        Bit#(6) filterIdx = hash(lineAddr);
        prefetchFilter.wrReq(filterIdx, Invalid);
        $display("%0d AlexLog: CDP Rel filter eviction clear: lineAddr %h idx %d", cur_cycle, lineAddr, filterIdx);
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

   method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        // On demand miss cache fill
        if (inited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            let tmp = L1ToCDPT{req: req, line: line};
            l1ToCDP.enq(tmp);
            $display("%0d AlexLog: CDP Rel reportIncomingCacheLine", cur_cycle);
        end else if ( // On demand hit (we have seen the cache line before so don't need to inspect all of the candidate vaddrs)
        inited &&
        getReqOp(req) == Ld &&
        !wasMiss &&
        !cRqIsPrefetch &&
        !wasNeighbourPrefetch
        ) begin
            let reqVpn = getReqVpn(req);
            pcTableIdxT pctIdx = hash(getPcHash(req));
            // AlexNote: Fairly certain this FIFO can trigger on the same cycle as the deqCacheLines rule?
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple3(getReqAddr(req), line, reqVpn)));
            // Training trigger (improvement 1): look up the hit vaddr in training table.
            // Covers the case where the working set is warm and all accesses are hits
            // without this, no training trigger ever fires since reportIncomingCacheLine
            // is only called on demand miss fills.
            Addr hitVaddr = zeroExtend({pack(reqVpn), getPageOffset(getReqAddr(req))});
            Bit#(39) hitVaddr39 = truncate(hitVaddr);
            trainingTableIdxT hitIdx = hash(hitVaddr39);
            // Shares slot 0 with deqCacheLines miss-time training trigger which should be mutually exclusive, 
            ttRespQ.enqS[0].enq(TrainingTableRespQT{
                req:              unpack(0), // req unused in isTrainingLookup=True path
                ttIdx:            hitIdx,
                isTrainingLookup: True,
                offset:           0,
                candVaddr:        hitVaddr});
            ttRdReqSupFIFO.enqS[0].enq(tuple2(hitIdx, hitVaddr));
        end else if ( // Neighbour-line prefetch returned a HIT: check the specific word we targeted.
        // If the neighbour line was a miss (not already in cache), the prefetch was too early
        // and any chained pointer prefetch would likely also be evicted before use — drop it.
        inited &&
        getReqOp(req) == Ld &&
        cRqIsPrefetch &&
        wasNeighbourPrefetch &&
        !wasMiss // AlexNote: Maybe toggle inbetween these
        ) begin
            // req.addr is the word-level paddr we sent to the TLB, so getLineDataOffset
            // recovers the exact word index within this cache line.
            LineDataOffset wordOff = getLineDataOffset(getReqAddr(req));
            Addr candidate = line[wordOff];
            Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
            Bit#(matchBits) addrUpper = truncateLSB(getReqVpn(req));
            if (candUpper == addrUpper) begin
                tlbReqFIFO.enq(tuple2(candidate, False));
                $display("%0d AlexLog: CDP Rel neighbour chain: word %d candidate vaddr %h queued for TLB", cur_cycle, wordOff, candidate);
            end else begin
                $display("%0d AlexLog: CDP Rel neighbour chain: word %d vaddr %h failed VPN check, dropping", cur_cycle, wordOff, candidate);
            end
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch, Bool hitOnPrefetchedLine);
        if (hitOnPrefetchedLine) begin
            cUseful <= (cUseful == maxBound) ? cUseful : cUseful + 1;
            $display("%0d AlexLog: CDP Rel useful prefetch hit addr %h cUseful %d", cur_cycle, addr, cUseful + 1);
        end
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        evictionQ.enq(lineAddr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        cTotal <= (cTotal == maxBound) ? cTotal : cTotal + 1;
        // paddr is already the correct translated physical address from the TLB
        $display("%0d AlexLog: CDP Rel Prefetch addr issued. lineAddr: %h | paddr: %h | vaddr: %h cTotal %d cUseful %d", cur_cycle, getLineAddr(x.paddr), x.paddr, x.vaddr, cTotal + 1, cUseful);
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False,
            isNeighbourLine: x.isNeighbourLine // prev/next line prefetch issuance ( we have an offset at the vaddr of the neighbour that we want to "chain" on)
        };
    endmethod
endmodule
