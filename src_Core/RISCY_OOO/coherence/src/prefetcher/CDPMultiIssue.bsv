// CDPMultiIssue.bsv — Variant C: multi-offset (top-2) issue CDP.
//
// Identical to mkCDPStatefulRelative except the selection step in the
// PrefetchIssue branch of pcTableResp finds the TOP-2 highest-confidence
// offsets above threshold, emits the best immediately via tlbReqFIFO, and
// defers the second-best into a pendingSecondIssueReg. A new drain rule
// forwards the deferred second to tlbReqFIFO on the next cycle.
//
// Motivation: the Olden treeadd and voronoi benchmarks store both child
// pointers (left, right) in the same cache line at predictable relative
// offsets (treeadd: word 1 and word 2; voronoi: word 3 and word 4). The
// baseline CDP sees both during candidate-scan but emits only one prefetch
// per decision — with a 2-ported issue we could cover both children per
// parent miss for roughly 2× coverage on these LDS workloads.
//
// Design notes: previous attempt at this used an Ehr register + a nested
// function to centralise the "in-bounds vs neighbour" tuple computation;
// combined with the existing Training/PrefetchIssue case split that caused
// bsc elaboration to explode past 20 minutes. This version uses a plain
// Reg (not Ehr) for the pending slot, mutex-scheduled writes between
// pcTableResp and drainSecondIssue (pcTableResp wins on conflict — a new
// second overwrites a pending second that hadn't drained yet), and
// inlined tuple construction to avoid nested functions entirely.

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

module mkCDPStatefulRelativeMultiIssue#(
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

    // tlbReqFIFO is a 2-port SupFifo so pcTableResp can enq the best offset on
    // port 0 and the second offset on port 1 in the same rule firing — no need
    // for a separate drain rule (which was the source of BSC scheduling grief
    // in earlier attempts). processTlbReq dequeues via port 0 only.
    SupFifo#(2, 2, Tuple3#(Addr, Bool, Bool)) tlbReqFIFO <- mkSupFifo;
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

    function Bool inited;
        return ttInited && pcInited && filterInited && tlbReqFreeQInited;
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
                req:              x.req, ttIdx: missIdx, isTrainingLookup: True,
                offset:           dataSel, candVaddr: missVaddr});
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
                    LineDataOffset iOff = fromInteger(i);
                    RelLineOffset relOffset = unpack(zeroExtend(iOff)) - unpack(zeroExtend(dataSel));
                    $display("%t AlexLog: CDP Multi candidate vaddr relOffset: %d pcHash: %h candVaddr: %h crossPage: %b",
                        cur_cycle, relOffset, getPcHash(x.req), x.line[i], getVpn(x.line[i]) != getReqVpn(x.req));
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

    // ** KEY DIFFERENCE: finds top-2 high-conf offsets and emits BOTH. **
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
                $display("%t AlexLog: CDP Multi PC table updated, idx: %d pcHash: %h relOffset: %d conf: %d -> %d",
                         cur_cycle, pctIdx, pcHash, relOffset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .entry) begin
                    Int#(5) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    Bit#(3) threshold = fromInteger(valueOf(confidenceThreshold));
                    // Find TOP-2 highest-confidence offsets above threshold via TWO
                    // sequential passes. A single pass with nested if/else promotion
                    // caused BSC to OOM (125GB) during static-unroll path enumeration
                    // — the nested branches create exponentially many code paths across
                    // 15 loop iterations. Each pass below has a single-branch body, so
                    // BSC elaboration matches the baseline's cost.
                    //
                    // Pass 1 finds the best slot. Pass 2 finds the best slot excluding
                    // bestIdx. Ties resolve to highest relOffset (iteration order).
                    Bool    haveBest = False;
                    Bit#(3) bestConf = 0;
                    Int#(5) bestAbsT = 0;
                    Bit#(4) bestIdx  = 0;
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(5) relOff = fromInteger(i - 7);
                        Int#(5) absT   = hitOffset + relOff;
                        Bit#(3) c      = entry.conf[fromInteger(i)];
                        if (c >= threshold && c > bestConf) begin
                            haveBest = True;
                            bestConf = c;
                            bestAbsT = absT;
                            bestIdx  = fromInteger(i);
                        end
                    end
                    Bool    haveSecond = False;
                    Bit#(3) secondConf = 0;
                    Int#(5) secondAbsT = 0;
                    Bit#(4) secondIdx  = 0;
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(5) relOff = fromInteger(i - 7);
                        Int#(5) absT   = hitOffset + relOff;
                        Bit#(3) c      = entry.conf[fromInteger(i)];
                        if (c >= threshold && c > secondConf && fromInteger(i) != bestIdx) begin
                            haveSecond = True;
                            secondConf = c;
                            secondAbsT = absT;
                            secondIdx  = fromInteger(i);
                        end
                    end
                    if (!haveBest) begin
                        Bit#(3) maxConf = 0;
                        for (Integer i = 0; i < 15; i = i + 1)
                            if (entry.conf[fromInteger(i)] > maxConf) maxConf = entry.conf[fromInteger(i)];
                        $display("%t AlexLog: CDP Multi no high-conf offset: pcHash %h maxConf %d",
                            cur_cycle, entry.pcHash, maxConf);
                    end
                    if (haveBest) begin
                        RelLineOffset bestRelOff = unpack(bestIdx) - 7;
                        Bool isNeigh = !(bestAbsT >= 0 &&& bestAbsT <= 7);
                        $display("%t AlexLog: CDP Multi prefetch decision: pcHash %h relOffset %d conf %d isNeighbour %b",
                            cur_cycle, entry.pcHash, bestRelOff, bestConf, isNeigh);
                        // Emit best via SupFifo port 0 --------------------------------------
                        if (bestAbsT >= 0 &&& bestAbsT <= 7) begin
                            LineDataOffset targetOff = truncate(pack(bestAbsT));
                            Addr candidate = line[targetOff];
                            if (truncateLSB(getVpn(candidate)) == addrUpper)
                                tlbReqFIFO.enqS[0].enq(tuple3(candidate, False, getVpn(candidate) != reqVpn));
                        end else begin
                            Bit#(TSub#(PageOffsetSz, LgLineSzBytes)) lineInPage = truncateLSB(getPageOffset(addr));
                            Bit#(LgLineSzBytes) lineByteOff = 0;
                            Addr curLineVbase = zeroExtend({pack(reqVpn), lineInPage, lineByteOff});
                            Bool isPrev = bestAbsT < 0;
                            Addr neighLineVaddr = isPrev ? curLineVbase - fromInteger(valueOf(TExp#(LgLineSzBytes)))
                                                         : curLineVbase + fromInteger(valueOf(TExp#(LgLineSzBytes)));
                            Bit#(5) absTBits = pack(bestAbsT);
                            Bit#(3) wordInNeigh = isPrev ? truncate(absTBits + 8)
                                                         : truncate(absTBits - 8);
                            Addr neighWordVaddr = neighLineVaddr + zeroExtend({wordInNeigh, 3'b0});
                            tlbReqFIFO.enqS[0].enq(tuple3(neighWordVaddr, True, getVpn(neighWordVaddr) != reqVpn));
                        end
                        // Emit second via SupFifo port 1 in the SAME rule firing — no
                        // separate drain rule needed. Port-independent enq avoids the
                        // BSC scheduling grief we hit with a single-port FIFO + drainer.
                        if (haveSecond) begin
                            RelLineOffset secondRelOff = unpack(secondIdx) - 7;
                            $display("%t AlexLog: CDP Multi second-offset: pcHash %h relOffset %d conf %d",
                                cur_cycle, entry.pcHash, secondRelOff, secondConf);
                            if (secondAbsT >= 0 &&& secondAbsT <= 7) begin
                                LineDataOffset sTargetOff = truncate(pack(secondAbsT));
                                Addr sCandidate = line[sTargetOff];
                                Bit#(matchBits) sCandUpper = truncateLSB(getVpn(sCandidate));
                                if (sCandUpper == addrUpper)
                                    tlbReqFIFO.enqS[1].enq(tuple3(sCandidate, False, getVpn(sCandidate) != reqVpn));
                            end else begin
                                Bit#(TSub#(PageOffsetSz, LgLineSzBytes)) sLineInPage = truncateLSB(getPageOffset(addr));
                                Bit#(LgLineSzBytes) sLineByteOff = 0;
                                Addr sCurLineVbase = zeroExtend({pack(reqVpn), sLineInPage, sLineByteOff});
                                Bool sIsPrev = secondAbsT < 0;
                                Addr sNeighLineVaddr = sIsPrev ? sCurLineVbase - fromInteger(valueOf(TExp#(LgLineSzBytes)))
                                                               : sCurLineVbase + fromInteger(valueOf(TExp#(LgLineSzBytes)));
                                Bit#(5) sAbsTBits = pack(secondAbsT);
                                Bit#(3) sWordInNeigh = sIsPrev ? truncate(sAbsTBits + 8)
                                                               : truncate(sAbsTBits - 8);
                                Addr sNeighWordVaddr = sNeighLineVaddr + zeroExtend({sWordInNeigh, 3'b0});
                                tlbReqFIFO.enqS[1].enq(tuple3(sNeighWordVaddr, True, getVpn(sNeighWordVaddr) != reqVpn));
                            end
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
        match {.candVaddr, .isNeighbourLine, .crossPage} = tlbReqFIFO.deqS[0].first;
        tlbReqFIFO.deqS[0].deq;
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
            $display("%t AlexLog: CDP Multi filter HIT: dropped duplicate prefetch for lineAddr %h", cur_cycle, lineAddr);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(lineAddr));
            nextCandidateBuffer.enq(cand);
            $display("%t AlexLog: CDP Multi filter MISS: issuing prefetch for lineAddr %h", cur_cycle, lineAddr);
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
                tlbReqFIFO.enqS[0].enq(tuple3(candidate, False, getVpn(candidate) != getReqVpn(req)));
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
        $display("%t AlexLog: CDP Multi Prefetch addr issued. lineAddr: %h", cur_cycle, getLineAddr(x.paddr));
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False,
            isNeighbourLine: x.isNeighbourLine
        };
    endmethod
endmodule
