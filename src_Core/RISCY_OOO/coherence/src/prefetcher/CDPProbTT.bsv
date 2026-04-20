// CDPProbTT.bsv — Variant F: probabilistic training-table overwrite.
//
// Identical to mkCDPStatefulRelative except for the TT-HIT branch in ttAccess:
// when an existing TT entry already maps the candidate vaddr to some stored
// (pcHash, relOffset), the baseline unconditionally overwrites with the new
// scanning PC's triple. That discards potentially-useful training context.
//
// This variant accepts the overwrite only with a low probability (default
// 1/16 ≈ 6.25%). The LFSR-gated flip lets an established PC's entry persist
// across many scans by other PCs, so the "original owner" of a candidate has
// more chances to fire the Training trigger before losing its slot.
//
// Motivation (2026-04-20): root-cause analysis shows the 4 losing benchmarks
// (em3d, health, treeadd, voronoi) all feature scattered prefetch decisions
// across many PCs (47 PCs for health, 67 for voronoi) — the TT is churning.
// Patricia (25 concentrated PCs) was the sole winner; its TT churn is low.
// Preserving established entries should narrow the scatter-PC accuracy gap
// without harming patricia's already-stable state.
//
// Only the HIT-overwrite path is probabilistic. The MISS-insert path (new
// vaddr evicting an unused replacement slot via rdRepl) stays deterministic —
// that's how the TT fills in the first place.

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

module mkCDPStatefulRelativeProbTT#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____,
    Parameter#(confidenceThreshold) _____,
    Parameter#(ttOverwriteNum) ______,     // numerator of overwrite probability
    Parameter#(ttOverwriteDenom) _______   // denominator (power of 2) — prob = num/denom
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
    Add#(h__, matchBits, 27),
    // Needed to truncate(ttOverwriteLfsr.value) down to TLog#(ttOverwriteDenom) bits.
    Add#(i__, TLog#(ttOverwriteDenom), 16)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(1), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    SupFifo#(16, 16, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(16, 16, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    RWBramCore#(pcTableIdxT, Maybe#(PCTableEntryT)) pcTable <- mkRWBramCoreForwarded();
    RWBramCore#(Bit#(8), Maybe#(LineAddr)) prefetchFilter <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;
    FIFO#(Tuple2#(Bit#(8), NextCandT)) filterPendingQ <- mkFIFO;
    FIFO#(LineAddr) evictionQ <- mkSizedFIFO(4);

    FIFO#(Tuple3#(Addr, Bool, Bool)) tlbReqFIFO <- mkSizedFIFO(4);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr)) pendCandVaddr  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendIsNeighbourLine <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendCrossPage <- replicateM(mkRegU);

    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 1))) ttInitCount <- mkReg(0);
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);
    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(8)) filterInitCount <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    // Independent LFSR for TT overwrite decisions — separate seed so it doesn't
    // correlate with decay LFSR.
    LFSR#(Bit#(16)) ttOverwriteLfsr <- mkLFSR_16;
    Reg#(Bool) ttLfsrSeeded <- mkConfigReg(False);

    function Bool inited;
        return ttInited && pcInited && filterInited && tlbReqFreeQInited;
    endfunction

    rule seedTtLfsr(!ttLfsrSeeded);
        ttOverwriteLfsr.seed('h137F);
        ttLfsrSeeded <= True;
    endrule

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

    (* mutually_exclusive = "doFilterInit, processFilterResp, doEvictionClear" *)
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

    // ** KEY DIFFERENCE vs baseline: TT-HIT overwrite is gated by an LFSR coin flip. **
    rule ttAccess(inited);
        let rdResp = trainingTable.rdResp;
        let rdRepl = trainingTable.rdRepl;
        trainingTable.deqRdResp;
        ttRespQT respQ = ttRespQ.deqS[0].first;
        ttRespQ.deqS[0].deq;
        ttOverwriteLfsr.next;
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
            if (rdResp matches tagged Valid {.hitWay, .ttRdResp}) begin
                // Probabilistic overwrite. Accept iff LFSR sample < ttOverwriteNum.
                // With ttOverwriteDenom=16 a ttOverwriteNum=1 gives ~6.25%.
                Bit#(TLog#(ttOverwriteDenom)) lfsrBits = truncate(ttOverwriteLfsr.value);
                Bool acceptOverwrite = (lfsrBits < fromInteger(valueOf(ttOverwriteNum)));
                if (acceptOverwrite) begin
                    trainingTable.wrReq(respQ.ttIdx, hitWay, newEntry);
                    $display("%t AlexLog: CDP ProbTT Overwrote training table (acc), idx: %d candVaddr: %h oldPcHash: %h newPcHash: %h relOffset: %d",
                        cur_cycle, respQ.ttIdx, respQ.candVaddr, ttRdResp.pcHash, getPcHash(respQ.req), relOffset);
                end else begin
                    $display("%t AlexLog: CDP ProbTT Overwrote training table (kept), idx: %d candVaddr: %h oldPcHash: %h newPcHash: %h",
                        cur_cycle, respQ.ttIdx, respQ.candVaddr, ttRdResp.pcHash, getPcHash(respQ.req));
                end
            end else begin
                // MISS-insert: deterministic (this is how the TT fills up in the first place).
                trainingTable.wrReq(respQ.ttIdx, rdRepl, newEntry);
                $display("%t AlexLog: CDP ProbTT Wrote to training table, idx: %d candVaddr: %h relOffset: %d",
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
                PCRelOffsetConfT curConf = replicate(0);
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) curConf = e.conf;
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(PCTableEntryT{pcHash: pcHash, conf: update(curConf, vecIdx, newVal)}));
                $display("%t AlexLog: CDP ProbTT PC table updated, idx: %d pcHash: %h relOffset: %d conf: %d -> %d",
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
                        Bit#(4) bestIdx = pack(bestRelOffset + 7);
                        $display("%t AlexLog: CDP ProbTT prefetch decision: pcHash %h relOffset %d conf %d",
                            cur_cycle, entry.pcHash, bestRelOffset, entry.conf[bestIdx]);
                        if (bestAbsTarget >= 0 &&& bestAbsTarget <= 7) begin
                            LineDataOffset targetOff = truncate(pack(bestAbsTarget));
                            Addr candidate = line[targetOff];
                            Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                            if (candUpper == addrUpper)
                                tlbReqFIFO.enq(tuple3(candidate, False, getVpn(candidate) != reqVpn));
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
                            tlbReqFIFO.enq(tuple3(neighWordVaddr, True, getVpn(neighWordVaddr) != reqVpn));
                        end
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .entry) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    pcTable.wrReq(pctIdx, Valid(PCTableEntryT{pcHash: entry.pcHash, conf: map(satDec, entry.conf)}));
                end
            end
        endcase
    endrule

    rule processTlbReq;
        match {.candVaddr, .isNeighbourLine, .crossPage} = tlbReqFIFO.first;
        tlbReqFIFO.deq;
        LLCTlbReqIdx id = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: id});
        pendCandVaddr[id]       <= candVaddr;
        pendIsNeighbourLine[id] <= isNeighbourLine;
        pendCrossPage[id]       <= crossPage;
    endrule

    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr       = pendCandVaddr[id];
        Bool isNeighbourLine = pendIsNeighbourLine[id];
        tlbReqFreeQ.enq(id);
        if (!resp.haveException) begin
            NextCandT cand = NextCandT{paddr: resp.paddr, vaddr: candVaddr, isNeighbourLine: isNeighbourLine};
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(8) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple2(filterIdx, cand));
        end
    endrule

    (* descending_urgency = "doEvictionClear, processFilterResp" *)
    rule processFilterResp(inited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .cand} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(cand.paddr);
        if (rdResp matches tagged Valid .storedAddr &&& storedAddr == lineAddr) begin
            $display("%t AlexLog: CDP ProbTT filter HIT: dropped duplicate prefetch for lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(lineAddr));
            nextCandidateBuffer.enq(cand);
            $display("%t AlexLog: CDP ProbTT filter MISS: issuing prefetch for lineAddr %h", cur_cycle, lineAddr);
        end
    endrule

    rule doEvictionClear(filterInited);
        LineAddr lineAddr = evictionQ.first;
        evictionQ.deq;
        Bit#(8) filterIdx = hash(lineAddr);
        prefetchFilter.wrReq(filterIdx, Invalid);
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
                tlbReqFIFO.enq(tuple3(candidate, False, getVpn(candidate) != getReqVpn(req)));
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
    endmethod

    method Action reportEviction(LineAddr lineAddr);
        evictionQ.enq(lineAddr);
    endmethod

    method Action reportUsefulPrefetch(LineAddr lineAddr);
        noAction;
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        return PendingPrefetch {
            addr: x.paddr, vpn: getVpn(x.vaddr),
            nextLevel: False, isNeighbourLine: x.isNeighbourLine };
    endmethod
endmodule
