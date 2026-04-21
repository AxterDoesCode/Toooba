// CDPPPFRoute.bsv -- Variant N: PPF-gated ROUTING (not suppression).
// Same attribution machinery as Variant M (256-entry signed-4-bit perceptron
// keyed by hash(pcHash) XOR relOff+7, 4096-entry attribTable), but the
// perceptron weight is used to pick routing instead of suppressing prefetches.
//
// Issue policy: always issue (no binary drop).
// Routing policy: weight >= threshold -> L1 (reap hit-latency on proven
//   useful patterns); weight < threshold -> LLC (still warms LLC for the
//   eventual demand miss, but does NOT pollute L1).
// Attribution: same as M. Useful-hit bumps +1, useless-evict bumps -1.
//
// Why this instead of M: Variant B (route-all-to-LLC) won treeadd +7.01%
// but crushed patricia -6.35%. Per-PC adaptive routing (E/E3/E4) was too
// noisy at per-PC granularity. M's per-(PC, relOff) perceptron is finer-
// grained but we burned its signal on binary suppression. By using the
// same signal for ROUTING instead, we keep useful prefetches (just in LLC
// when the pattern is not trusted), preserving patricia-style benefits
// while protecting L1 from treeadd-style pollution.
//
// Motivation: Variant H (kill-switch) uses the same 1024-entry prefetch filter
// for TWO jobs -- dedup (drop re-issued prefetches) AND attribution (map
// evicted prefetched-lineAddr back to the pcHash that issued it). Under heavy
// prefetch load, filter entries are hash-evicted by NEWER prefetches before
// the CORRESPONDING cache eviction fires, so useless events fail to attribute.
// Logs showed useless bumps ~1/3 to ~1/5 of real evict-without-use events.
// H compensated by amplifying each attributed bump by 3; Variant J eliminates
// the bias instead.
//
// Design: keep the 1024-entry filter for dedup (unchanged). Add a SECOND
// 4096-entry table (`attribTable`) keyed by hash(lineAddr), storing pcHash +
// punishable. Written on every issued prefetch (same moment as filter write).
// Read on:
//   - cache eviction (reportEviction)  -> AccUseless(pcHash)
//   - demand-hit on prefetched line (reportUsefulPrefetch) -> AccUseful(pcHash)
// Size rationale: 4096 >> 1024 means far fewer collisions, so the attribution
// entry is much more likely to still be valid when eviction fires. 4k entries
// * (LineAddr + 16b pcHash + 1b punishable) ~= 50 bits * 4k = 25KB.
//
// Kill-switch logic identical to H's ratio gate. `AccUseless` bumps by 1 (no
// amplification) -- if the attribution is now accurate, we don't need to lie.

import MemoryTypes::*;
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
import CDP::*;

// PC-table entry — same as baseline CDP (no per-PC kill-switch). The
// perceptron replaces the kill-switch gate; see the weight register-file
// declared in the module.
typedef struct {
    Bit#(16)         pcHash;
    PCRelOffsetConfT conf;
} PCTablePPFRouteEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool isNeighbourLine;
    Bool routeLLC;
} NextCandPPFRouteT deriving (Bits, FShow, Eq);

// Dedup filter entry: minimal.
typedef struct { LineAddr lineAddr; } PPFRouteFilterEntryT deriving (Bits, FShow, Eq);

// Attribution-table entry: also stores the relOffset the decision used, so
// useful/useless events can reward/punish the EXACT perceptron weight that
// produced the issue.
typedef struct {
    LineAddr     lineAddr;
    Bit#(16)     pcHash;
    RelLineOffset relOffset;     // rel offset from decision time (not line delta)
    Bool         punishable;
} PPFRouteAttribEntryT deriving (Bits, FShow, Eq);

// Perceptron updates happen in-line via register-file, not through the pcTable
// pipeline, so the tag set stays the same as the baseline CDP (no AccUseful/
// AccUseless in the pcTable pipeline).
typedef union tagged {
    Tuple2#(Bit#(16), RelLineOffset) Training;
    Tuple3#(Addr, Line, Vpn)         PrefetchIssue;
    void                             Decay;
} PCTableRdPPFRouteTagT deriving (Bits, FShow);

module mkCDPStatefulRelativePPFRoute#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____,
    Parameter#(confidenceThreshold) _____,
    Parameter#(killThreshold) ______
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

    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(1), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    SupFifo#(16, 16, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(16, 16, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    RWBramCore#(pcTableIdxT, Maybe#(PCTablePPFRouteEntryT)) pcTable <- mkRWBramCoreForwarded();
    // Dedup filter -- 1024 entries (Bit#(10)) as before.
    RWBramCore#(Bit#(10), Maybe#(PPFRouteFilterEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
    // Attribution table -- 4096 entries (Bit#(12)), independent of the filter.
    RWBramCore#(Bit#(12), Maybe#(PPFRouteAttribEntryT)) attribTable <- mkRWBramCoreForwarded();

    // Perceptron weight table: 256 signed 4-bit weights, indexed by
    // hash(pcHash)[7:0] XOR zeroExt(relOff+7). Allows per-(PC, relOff) gating
    // where CDP's existing conf table only goes UP — perceptron weights can
    // also go NEGATIVE based on useful/useless attribution.
    Vector#(256, Reg#(Int#(4))) perceptron <- replicateM(mkReg(0));

    Fifo#(16, NextCandPPFRouteT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdPPFRouteTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdPPFRouteTagT)) pcTableRdTagQ    <- mkFIFO;
    FIFO#(Tuple4#(Bit#(10), NextCandPPFRouteT, Bit#(16), RelLineOffset)) filterPendingQ <- mkFIFO;
    FIFO#(LineAddr) evictionQ <- mkSizedFIFO(4);
    FIFO#(Tuple2#(Bit#(12), LineAddr)) evictionPendingQ <- mkSizedFIFO(4);
    FIFO#(LineAddr) usefulHitQ <- mkSizedFIFO(4);
    FIFO#(Tuple2#(Bit#(12), LineAddr)) usefulHitPendingQ <- mkSizedFIFO(4);

    FIFO#(Tuple7#(Addr, Bool, Bool, Bit#(16), Bool, Bool, RelLineOffset)) tlbReqFIFO <- mkSizedFIFO(4);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr))          pendCandVaddr        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))          pendIsNeighbourLine  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))          pendCrossPage        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bit#(16)))      pendPcHash           <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))          pendPunishable       <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))          pendRouteLLC         <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(RelLineOffset)) pendRelOffset        <- replicateM(mkRegU);

    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 1))) ttInitCount <- mkReg(0);
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);
    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(10)) filterInitCount <- mkReg(0);
    Reg#(Bool) attribInited <- mkConfigReg(False);
    Reg#(Bit#(12)) attribInitCount <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bool inited;
        return ttInited && pcInited && filterInited && attribInited && tlbReqFreeQInited;
    endfunction

    // Perceptron helpers
    function Bit#(8) perceptronIdx(Bit#(16) pcHash, RelLineOffset relOff);
        Bit#(16) h = hash(pcHash);
        Bit#(8) relBits = zeroExtend(pack(relOff + 7));  // relOff+7 in 0..14
        return truncate(h) ^ relBits;
    endfunction
    function Bool perceptronVote(Bit#(16) pcHash, RelLineOffset relOff);
        Int#(4) threshold = fromInteger(valueOf(killThreshold));
        return perceptron[perceptronIdx(pcHash, relOff)] >= threshold;
    endfunction
    function Int#(4) satAdd(Int#(4) w, Int#(4) delta);
        Int#(5) sum = signExtend(w) + signExtend(delta);
        if (sum > 7) return 7;
        else if (sum < -8) return -8;
        else return truncate(sum);
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!ttInited);
        trainingTableIdxT addr = truncateLSB(ttInitCount);
        Bit#(1) way = truncate(ttInitCount);
        trainingTable.wrReq(addr, way, unpack(0));
        if (ttInitCount == maxBound) begin ttInited <= True; decayLfsr.seed('hA5F1); end
        ttInitCount <= ttInitCount + 1;
    endrule

    (* mutually_exclusive = "doPcTableInit, processPcTableRdReq, pcTableResp" *)
    rule doPcTableInit(!pcInited);
        pcTable.wrReq(pcInitCount, Invalid);
        if (pcInitCount == ~0) pcInited <= True;
        pcInitCount <= pcInitCount + 1;
    endrule

    (* mutually_exclusive = "doFilterInit, processFilterResp" *)
    rule doFilterInit(!filterInited);
        prefetchFilter.wrReq(filterInitCount, Invalid);
        if (filterInitCount == ~0) filterInited <= True;
        filterInitCount <= filterInitCount + 1;
    endrule

    (* mutually_exclusive = "doAttribInit, finishEviction, finishUsefulLookup" *)
    rule doAttribInit(!attribInited);
        attribTable.wrReq(attribInitCount, Invalid);
        if (attribInitCount == ~0) attribInited <= True;
        attribInitCount <= attribInitCount + 1;
    endrule

    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        if (tlbReqFreeQInitCount == ~0) tlbReqFreeQInited <= True;
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
    endrule

    (* descending_urgency = "deqCacheLines, processTtRdReq, ttAccess" *)
    rule deqCacheLines;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req));
        l1ToCDP.deq;
        Bit#(matchBits) missUpper = truncateLSB(getReqVpn(x.req));
        if (getReqOp(x.req) == Ld) begin
            Addr missVaddr = zeroExtend({pack(getReqVpn(x.req)), getPageOffset(getReqAddr(x.req))});
            Bit#(39) missVaddr39 = truncate(missVaddr);
            trainingTableIdxT missIdx = hash(missVaddr39);
            ttRespQ.enqS[0].enq(TrainingTableRespQT{
                req: x.req, ttIdx: missIdx, isTrainingLookup: True,
                offset: dataSel, candVaddr: missVaddr});
            ttRdReqSupFIFO.enqS[0].enq(tuple2(missIdx, missVaddr));
            Integer enqIdx = 1;
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(matchBits) candUpper = truncateLSB(getVpn(x.line[i]));
                if (candUpper == missUpper) begin
                    Bit#(39) vaddr39 = truncate(x.line[i]);
                    trainingTableIdxT idx = hash(vaddr39);
                    ttRespQ.enqS[enqIdx].enq(TrainingTableRespQT{
                        req: x.req, ttIdx: idx, isTrainingLookup: False,
                        offset: fromInteger(i), candVaddr: x.line[i]});
                    ttRdReqSupFIFO.enqS[enqIdx].enq(tuple2(idx, x.line[i]));
                    enqIdx = enqIdx + 1;
                end
            end
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
            if (rdResp matches tagged Valid {.hitWay, .ttRdResp}) begin
                pcTableIdxT pctIdx = hash(ttRdResp.pcHash);
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training tuple2(ttRdResp.pcHash, ttRdResp.lineOffset)));
            end
        end else begin
            LineDataOffset dataSel = getLineDataOffset(getReqAddr(respQ.req));
            RelLineOffset relOffset = unpack(zeroExtend(respQ.offset)) - unpack(zeroExtend(dataSel));
            TrainingTableEntryT newEntry = TrainingTableEntryT{
                valid: True, storedVaddr: respQ.candVaddr,
                pcHash: getPcHash(respQ.req), lineOffset: relOffset };
            if (rdResp matches tagged Valid {.hitWay, .ttRdResp})
                trainingTable.wrReq(respQ.ttIdx, hitWay, newEntry);
            else
                trainingTable.wrReq(respQ.ttIdx, rdRepl, newEntry);
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
                PCRelOffsetConfT curConf = replicate(0);
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash)
                    curConf = e.conf;
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(PCTablePPFRouteEntryT{
                    pcHash: pcHash,
                    conf: update(curConf, vecIdx, newVal)}));
                $display("%t AlexLog: CDP PPFRoute PC table updated, idx: %d pcHash: %h relOffset: %d conf: %d -> %d",
                         cur_cycle, pctIdx, pcHash, relOffset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .entry) begin
                    Int#(5) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    Bit#(3) threshold = fromInteger(valueOf(confidenceThreshold));
                    Bool foundHighConf = False;
                    Int#(5) bestAbsTarget = 0;
                    RelLineOffset bestRelOffset = 0;
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(5) relOffset = fromInteger(i - 7);
                        Int#(5) absTarget = hitOffset + relOffset;
                        if (entry.conf[fromInteger(i)] >= threshold) begin
                            bestAbsTarget = absTarget;
                            bestRelOffset = fromInteger(i - 7);
                            foundHighConf = True;
                        end
                    end
                    if (foundHighConf) begin
                        // Route-not-suppress: trusted (weight >= threshold) -> L1; untrusted -> LLC.
                        // Always issue (no drop).
                        Bool trusted = perceptronVote(entry.pcHash, bestRelOffset);
                        Bool routeLLC = !trusted;
                        Int#(4) w = perceptron[perceptronIdx(entry.pcHash, bestRelOffset)];
                        $display("%t AlexLog: CDP PPFRoute prefetch decision: pcHash %h relOffset %d weight %d route %s",
                            cur_cycle, entry.pcHash, bestRelOffset, w,
                            routeLLC ? "LLC" : "L1");
                        if (bestAbsTarget >= 0 &&& bestAbsTarget <= 7) begin
                            LineDataOffset targetOff = truncate(pack(bestAbsTarget));
                            Addr candidate = line[targetOff];
                            Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                            if (candUpper == addrUpper)
                                tlbReqFIFO.enq(tuple7(candidate, False, getVpn(candidate) != reqVpn,
                                                       entry.pcHash, True, routeLLC, bestRelOffset));
                        end else begin
                            Bit#(TSub#(PageOffsetSz, LgLineSzBytes)) lineInPage = truncateLSB(getPageOffset(addr));
                            Bit#(LgLineSzBytes) lineByteOff = 0;
                            Addr curLineVbase = zeroExtend({pack(reqVpn), lineInPage, lineByteOff});
                            Bool isPrev = bestAbsTarget < 0;
                            Addr neighLineVaddr = isPrev ? curLineVbase - fromInteger(valueOf(TExp#(LgLineSzBytes)))
                                                         : curLineVbase + fromInteger(valueOf(TExp#(LgLineSzBytes)));
                            Bit#(5) absTargetBits = pack(bestAbsTarget);
                            Bit#(3) wordInNeigh = isPrev ? truncate(absTargetBits + 8)
                                                         : truncate(absTargetBits - 8);
                            Addr neighWordVaddr = neighLineVaddr + zeroExtend({wordInNeigh, 3'b0});
                            tlbReqFIFO.enq(tuple7(neighWordVaddr, True, getVpn(neighWordVaddr) != reqVpn,
                                                   entry.pcHash, True, routeLLC, bestRelOffset));
                        end
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .entry) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    pcTable.wrReq(pctIdx, Valid(PCTablePPFRouteEntryT{
                        pcHash: entry.pcHash, conf: map(satDec, entry.conf)}));
                end
            end
        endcase
    endrule

    rule processTlbReq;
        match {.candVaddr, .isNeighbourLine, .crossPage, .pcH, .punish, .rlLLC, .relOff} = tlbReqFIFO.first;
        tlbReqFIFO.deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id]       <= candVaddr;
        pendIsNeighbourLine[id] <= isNeighbourLine;
        pendCrossPage[id]       <= crossPage;
        pendPcHash[id]          <= pcH;
        pendPunishable[id]      <= punish;
        pendRouteLLC[id]        <= rlLLC;
        pendRelOffset[id]       <= relOff;
    endrule

    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr       = pendCandVaddr[id];
        Bool isNeighbourLine = pendIsNeighbourLine[id];
        Bit#(16) pcH         = pendPcHash[id];
        Bool rlLLC           = pendRouteLLC[id];
        RelLineOffset relOff = pendRelOffset[id];
        tlbReqFreeQ.enq(id);
        if (!resp.haveException) begin
            NextCandPPFRouteT cand = NextCandPPFRouteT{
                paddr: resp.paddr, vaddr: candVaddr,
                isNeighbourLine: isNeighbourLine, routeLLC: rlLLC };
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple4(filterIdx, cand, pcH, relOff));
        end
    endrule

    rule processFilterResp(inited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .cand, .pcH, .relOff} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(cand.paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP PPFRoute filter HIT: dropped duplicate prefetch for lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(PPFRouteFilterEntryT{ lineAddr: lineAddr }));
            Bit#(12) attribIdx = hash(lineAddr);
            attribTable.wrReq(attribIdx, Valid(PPFRouteAttribEntryT{
                lineAddr: lineAddr, pcHash: pcH, relOffset: relOff, punishable: True }));
            nextCandidateBuffer.enq(cand);
            $display("%t AlexLog: CDP PPFRoute filter MISS: issuing prefetch for lineAddr %h pcHash %h relOff %d",
                cur_cycle, lineAddr, pcH, relOff);
        end
    endrule

    rule startEviction(attribInited);
        LineAddr lineAddr = evictionQ.first;
        evictionQ.deq;
        Bit#(12) attribIdx = hash(lineAddr);
        attribTable.rdReq(attribIdx);
        evictionPendingQ.enq(tuple2(attribIdx, lineAddr));
    endrule

    rule finishEviction(attribInited);
        let rdResp = attribTable.rdResp;
        attribTable.deqRdResp;
        match {.attribIdx, .lineAddr} = evictionPendingQ.first;
        evictionPendingQ.deq;
        if (rdResp matches tagged Valid .ae &&& ae.lineAddr == lineAddr) begin
            if (ae.punishable) begin
                Bit#(8) pIdx = perceptronIdx(ae.pcHash, ae.relOffset);
                Int#(4) w = perceptron[pIdx];
                Int#(4) wNew = satAdd(w, -1);
                perceptron[pIdx] <= wNew;
                $display("%t AlexLog: CDP PPFRoute useless bump: lineAddr %h pcHash %h relOff %d w %d -> %d",
                    cur_cycle, lineAddr, ae.pcHash, ae.relOffset, w, wNew);
            end
            attribTable.wrReq(attribIdx, Invalid);
        end
    endrule

    rule startUsefulLookup(attribInited);
        LineAddr lineAddr = usefulHitQ.first;
        usefulHitQ.deq;
        Bit#(12) attribIdx = hash(lineAddr);
        attribTable.rdReq(attribIdx);
        usefulHitPendingQ.enq(tuple2(attribIdx, lineAddr));
    endrule

    rule finishUsefulLookup(attribInited);
        let rdResp = attribTable.rdResp;
        attribTable.deqRdResp;
        match {.attribIdx, .lineAddr} = usefulHitPendingQ.first;
        usefulHitPendingQ.deq;
        if (rdResp matches tagged Valid .ae &&& ae.lineAddr == lineAddr &&& ae.punishable) begin
            Bit#(8) pIdx = perceptronIdx(ae.pcHash, ae.relOffset);
            Int#(4) w = perceptron[pIdx];
            Int#(4) wNew = satAdd(w, 1);
            perceptron[pIdx] <= wNew;
            $display("%t AlexLog: CDP PPFRoute useful bump: lineAddr %h pcHash %h relOff %d w %d -> %d",
                cur_cycle, lineAddr, ae.pcHash, ae.relOffset, w, wNew);
        end
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
        if (inited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            let tmp = L1ToCDPT{req: req, line: line};
            l1ToCDP.enq(tmp);
        end else if (inited && getReqOp(req) == Ld && !wasMiss && !cRqIsPrefetch && !wasNeighbourPrefetch) begin
            let reqVpn = getReqVpn(req);
            pcTableIdxT pctIdx = hash(getPcHash(req));
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged PrefetchIssue tuple3(getReqAddr(req), line, reqVpn)));
            Addr hitVaddr = zeroExtend({pack(reqVpn), getPageOffset(getReqAddr(req))});
            Bit#(39) hitVaddr39 = truncate(hitVaddr);
            trainingTableIdxT hitIdx = hash(hitVaddr39);
            ttRespQ.enqS[0].enq(TrainingTableRespQT{
                req: unpack(0), ttIdx: hitIdx, isTrainingLookup: True,
                offset: 0, candVaddr: hitVaddr});
            ttRdReqSupFIFO.enqS[0].enq(tuple2(hitIdx, hitVaddr));
        end else if (inited && getReqOp(req) == Ld && cRqIsPrefetch && wasNeighbourPrefetch && !wasMiss) begin
            LineDataOffset wordOff = getLineDataOffset(getReqAddr(req));
            Addr candidate = line[wordOff];
            Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
            Bit#(matchBits) addrUpper = truncateLSB(getReqVpn(req));
            if (candUpper == addrUpper)
                // Neighbour-chain prefetch: not attributable to a single decision,
                // pass relOffset=0 and punishable=False so the perceptron won't train on it.
                tlbReqFIFO.enq(tuple7(candidate, False, getVpn(candidate) != getReqVpn(req),
                                      16'h0, False, False, 0));
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        evictionQ.enq(lineAddr);
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
        usefulHitQ.enq(lineAddr);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        $display("%t AlexLog: CDP PPFRoute prefetch issued. lineAddr: %h",
            cur_cycle, getLineAddr(x.paddr));
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: x.routeLLC,
            isNeighbourLine: x.isNeighbourLine
        };
    endmethod
endmodule
