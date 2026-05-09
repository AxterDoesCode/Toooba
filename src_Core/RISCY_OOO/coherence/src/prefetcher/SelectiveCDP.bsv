
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

typedef Vector#(15, Bit#(2)) PCRelOffsetConf2BitT;

typedef struct {
    Bit#(16)             pcHash;
    PCRelOffsetConf2BitT conf;
    Bit#(4)              usefulCount;
    Bit#(4)              uselessCount;
} PCTableAcc2BitEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool isNeighbourLine;
    Bool routeLLC;
} NextCandAdaptT deriving (Bits, FShow, Eq);

typedef struct {
    Bit#(16) addrTag;
    Bit#(16) pcHash;
    Bool     punishable;
} FilterAccHashedEntryT deriving (Bits, FShow, Eq);

function Bit#(16) tagOfLineAddr(LineAddr a);
    Bit#(16) s0 = a[25:10];
    Bit#(16) s1 = a[41:26];
    Bit#(16) s2 = zeroExtend(a[57:42]);
    return s0 ^ s1 ^ s2;
endfunction

typedef union tagged {
    Tuple2#(Bit#(16), RelLineOffset) Training;
    Tuple3#(Addr, Line, Vpn)         PrefetchIssue;
    Bit#(16)                          AccUseful;
    Bit#(16)                          AccUseless;
    void                              Decay;
} PCTableRdAdaptTagT deriving (Bits, FShow);

typedef enum {
    EvIgnore,
    EvDemandLdMiss,
    EvDemandLdHit,
    EvNeighbourChain
} CDPIncomingBranchT deriving (Bits, FShow, Eq);

module mkSelectiveCDP#(
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

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkSizedFIFO(8);

    Fifo#(32, Tuple3#(CDPIncomingBranchT, reqT, Line)) incomingQ <- mkOverflowBypassFifo;

    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(1), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    SupFifo#(16, 16, ttRespQT) ttRespQ <- mkSupFifo;
    SupFifo#(16, 16, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    RWBramCore#(pcTableIdxT, Maybe#(PCTableAcc2BitEntryT)) pcTable <- mkRWBramCoreForwarded();
    RWBramCore#(Bit#(10), Maybe#(FilterAccHashedEntryT)) prefetchFilter <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandAdaptT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdAdaptTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdAdaptTagT)) pcTableRdTagQ    <- mkFIFO;
    FIFO#(Tuple3#(Bit#(10), NextCandAdaptT, Bit#(16))) filterPendingQ <- mkFIFO;
    FIFO#(LineAddr) evictionQ <- mkSizedFIFO(4);
    FIFO#(Tuple2#(Bit#(10), LineAddr)) evictionPendingQ <- mkSizedFIFO(4);
    FIFO#(LineAddr) usefulHitQ <- mkSizedFIFO(4);
    FIFO#(Tuple2#(Bit#(10), LineAddr)) usefulHitPendingQ <- mkSizedFIFO(4);

    FIFO#(Tuple6#(Addr, Bool, Bool, Bit#(16), Bool, Bool)) tlbReqFIFO <- mkSizedFIFO(4);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr))     pendCandVaddr        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendIsNeighbourLine  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendCrossPage        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bit#(16))) pendPcHash           <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendPunishable       <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendRouteLLC         <- replicateM(mkRegU);

    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 1))) ttInitCount <- mkReg(0);
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);
    Reg#(Bool) filterInited <- mkConfigReg(False);
    Reg#(Bit#(10)) filterInitCount <- mkReg(0);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);

    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bool inited;
        return ttInited && pcInited && filterInited && tlbReqFreeQInited;
    endfunction

    function Bool shouldIssue(Bit#(4) uf, Bit#(4) us);
        Bit#(4) threshold = fromInteger(valueOf(killThreshold));
        Bool chronic = (us >= threshold) && (us > uf);
        return !chronic;
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

    (* mutually_exclusive = "doFilterInit, processFilterResp, finishEviction, finishUsefulLookup" *)
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
                PCRelOffsetConf2BitT curConf = replicate(0);
                Bit#(4) curUseful = 0, curUseless = 0;
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) begin
                    curConf = e.conf;
                    curUseful = e.usefulCount;
                    curUseless = e.uselessCount;
                end
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(2) curVal = curConf[vecIdx];
                Bit#(2) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(PCTableAcc2BitEntryT{
                    pcHash: pcHash,
                    conf: update(curConf, vecIdx, newVal),
                    usefulCount: curUseful,
                    uselessCount: curUseless}));
                $display("%t AlexLog: CDP Kill PC table updated, idx: %d pcHash: %h relOffset: %d conf: %d -> %d uf: %d us: %d",
                         cur_cycle, pctIdx, pcHash, relOffset, curVal, newVal, curUseful, curUseless);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .entry) begin
                    Int#(5) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    Bit#(2) threshold = fromInteger(valueOf(confidenceThreshold));
                    Bool foundHighConf = False;
                    Int#(5) bestAbsTarget = 0;
                    RelLineOffset bestRelOffset = 0;
                    Bit#(2) bestConf = 0;
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(5) relOffset = fromInteger(i - 7);
                        Int#(5) absTarget = hitOffset + relOffset;
                        Bit#(2) thisConf = entry.conf[fromInteger(i)];
                        if (thisConf >= threshold && thisConf > bestConf) begin
                            bestAbsTarget = absTarget;
                            bestRelOffset = fromInteger(i - 7);
                            bestConf = thisConf;
                            foundHighConf = True;
                        end
                    end
                    if (foundHighConf) begin
                        Bool okToIssue = shouldIssue(entry.usefulCount, entry.uselessCount);
                        Bool isNeigh = !(bestAbsTarget >= 0 && bestAbsTarget <= 7);
                        Bit#(4) bestVecIdx = pack(bestRelOffset + 7);
                        Bit#(2) bestConf = entry.conf[bestVecIdx];
                        $display("%t AlexLog: CDP Rel prefetch decision: pcHash %h relOffset %d conf %d isNeighbour %b uf %d us %d %s",
                            cur_cycle, entry.pcHash, bestRelOffset, bestConf, isNeigh,
                            entry.usefulCount, entry.uselessCount,
                            okToIssue ? "ISSUE" : "SUPPRESSED");
                        if (okToIssue) begin
                            if (bestAbsTarget >= 0 &&& bestAbsTarget <= 7) begin
                                LineDataOffset targetOff = truncate(pack(bestAbsTarget));
                                Addr candidate = line[targetOff];
                                Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                                if (candUpper == addrUpper)
                                    tlbReqFIFO.enq(tuple6(candidate, False, getVpn(candidate) != reqVpn,
                                                           entry.pcHash, True, False));
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
                                tlbReqFIFO.enq(tuple6(neighWordVaddr, True, getVpn(neighWordVaddr) != reqVpn,
                                                       entry.pcHash, True, False));
                            end
                        end
                    end
                end
            end
            tagged AccUseful .pcHash: begin
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) begin
                    Bit#(4) newUf = (e.usefulCount == maxBound) ? maxBound : e.usefulCount + 1;
                    pcTable.wrReq(pctIdx, Valid(PCTableAcc2BitEntryT{
                        pcHash: e.pcHash, conf: e.conf,
                        usefulCount: newUf, uselessCount: e.uselessCount}));
                    $display("%t AlexLog: CDP Kill acc useful bump, idx: %d pcHash: %h uf: %d -> %d",
                        cur_cycle, pctIdx, pcHash, e.usefulCount, newUf);
                end
            end
            tagged AccUseless .pcHash: begin
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) begin
                    Bit#(5) amplified = zeroExtend(e.uselessCount) + 3;
                    Bit#(4) newUs = (amplified >= 15) ? 15 : truncate(amplified);
                    pcTable.wrReq(pctIdx, Valid(PCTableAcc2BitEntryT{
                        pcHash: e.pcHash, conf: e.conf,
                        usefulCount: e.usefulCount, uselessCount: newUs}));
                    $display("%t AlexLog: CDP Kill acc useless bump, idx: %d pcHash: %h us: %d -> %d",
                        cur_cycle, pctIdx, pcHash, e.uselessCount, newUs);
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .entry) begin
                    function Bit#(2) satDec(Bit#(2) x) = (x == 0) ? 0 : x - 1;
                    Bit#(4) decayUf = (entry.usefulCount > 0) ? entry.usefulCount - 1 : 0;
                    Bit#(4) decayUs = (entry.uselessCount > 0) ? entry.uselessCount - 1 : 0;
                    pcTable.wrReq(pctIdx, Valid(PCTableAcc2BitEntryT{
                        pcHash: entry.pcHash, conf: map(satDec, entry.conf),
                        usefulCount: decayUf, uselessCount: decayUs}));
                end
            end
        endcase
    endrule

    rule processTlbReq;
        match {.candVaddr, .isNeighbourLine, .crossPage, .pcH, .punish, .rlLLC} = tlbReqFIFO.first;
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
    endrule

    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        LLCTlbReqIdx id = resp.id;
        Addr candVaddr       = pendCandVaddr[id];
        Bool isNeighbourLine = pendIsNeighbourLine[id];
        Bool crossPage       = pendCrossPage[id];
        Bit#(16) pcH         = pendPcHash[id];
        Bool rlLLC           = pendRouteLLC[id];
        tlbReqFreeQ.enq(id);
        if (!resp.haveException) begin
            NextCandAdaptT cand = NextCandAdaptT{
                paddr: resp.paddr, vaddr: candVaddr,
                isNeighbourLine: isNeighbourLine, routeLLC: rlLLC };
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            $display("%0d AlexLog: CDP Rel TLB resp: vaddr %h -> paddr %h lineAddr %h crossPage %b",
                cur_cycle, candVaddr, resp.paddr, lineAddr, crossPage);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple3(filterIdx, cand, pcH));
        end else begin
            $display("%t AlexLog: CDP Rel TLB resp: exception for vaddr %h, dropping prefetch",
                cur_cycle, candVaddr);
        end
    endrule

    (* descending_urgency = "finishEviction, processFilterResp" *)
    rule processFilterResp(inited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .cand, .pcH} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(cand.paddr);
        Bit#(16) addrTag = tagOfLineAddr(lineAddr);
        if (rdResp matches tagged Valid .fe &&& fe.addrTag == addrTag) begin
            $display("%t AlexLog: CDP Rel filter HIT: dropped duplicate prefetch for lineAddr %h tag %h", cur_cycle, lineAddr, addrTag);
        end else begin
            prefetchFilter.wrReq(filterIdx, Valid(FilterAccHashedEntryT{
                addrTag: addrTag, pcHash: pcH, punishable: True }));
            nextCandidateBuffer.enq(cand);
            $display("%t AlexLog: CDP Rel filter MISS: issuing prefetch for lineAddr %h tag %h pcHash %h isNeighbour %b route %s",
                cur_cycle, lineAddr, addrTag, pcH, cand.isNeighbourLine, cand.routeLLC ? "LLC" : "L1");
        end
    endrule

    rule startEviction(filterInited);
        LineAddr lineAddr = evictionQ.first;
        evictionQ.deq;
        Bit#(10) filterIdx = hash(lineAddr);
        prefetchFilter.rdReq(filterIdx);
        evictionPendingQ.enq(tuple2(filterIdx, lineAddr));
    endrule

    rule finishEviction(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .lineAddr} = evictionPendingQ.first;
        evictionPendingQ.deq;
        if (rdResp matches tagged Valid .fe &&& fe.addrTag == tagOfLineAddr(lineAddr)) begin
            if (fe.punishable) begin
                pcTableIdxT pctIdx = hash(fe.pcHash);
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged AccUseless fe.pcHash));
                $display("%t AlexLog: CDP Kill useless evict: lineAddr %h pcHash %h",
                    cur_cycle, lineAddr, fe.pcHash);
            end
        end
        prefetchFilter.wrReq(filterIdx, Invalid);
    endrule

    rule startUsefulLookup(filterInited);
        LineAddr lineAddr = usefulHitQ.first;
        usefulHitQ.deq;
        Bit#(10) filterIdx = hash(lineAddr);
        prefetchFilter.rdReq(filterIdx);
        usefulHitPendingQ.enq(tuple2(filterIdx, lineAddr));
    endrule

    rule finishUsefulLookup(filterInited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .lineAddr} = usefulHitPendingQ.first;
        usefulHitPendingQ.deq;
        if (rdResp matches tagged Valid .fe &&& fe.addrTag == tagOfLineAddr(lineAddr) &&& fe.punishable) begin
            pcTableIdxT pctIdx = hash(fe.pcHash);
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged AccUseful fe.pcHash));
            $display("%t AlexLog: CDP Kill useful hit: lineAddr %h pcHash %h",
                cur_cycle, lineAddr, fe.pcHash);
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

    rule drainIncomingEvents;
        match {.branch, .req, .line} = incomingQ.first;
        incomingQ.deq;
        case (branch)
            EvDemandLdMiss: begin
                let tmp = L1ToCDPT{req: req, line: line};
                l1ToCDP.enq(tmp);
            end
            EvDemandLdHit: begin
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
            end
            EvNeighbourChain: begin
                LineDataOffset wordOff = getLineDataOffset(getReqAddr(req));
                Addr candidate = line[wordOff];
                Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                Bit#(matchBits) addrUpper = truncateLSB(getReqVpn(req));
                if (candUpper == addrUpper) begin
                    $display("%0d AlexLog: CDP Rel neighbour chain: word %d candidate vaddr %h queued for TLB",
                        cur_cycle, wordOff, candidate);
                    tlbReqFIFO.enq(tuple6(candidate, False, getVpn(candidate) != getReqVpn(req),
                                          16'h0, False, False));
                end else begin
                    $display("%0d AlexLog: CDP Rel neighbour chain: word %d vaddr %h failed VPN check, dropping",
                        cur_cycle, wordOff, candidate);
                end
            end
            EvIgnore: noAction;
        endcase
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line, Bool cRqIsPrefetch, Bool wasMiss, Bool wasNeighbourPrefetch);
        CDPIncomingBranchT branch = EvIgnore;
        if (inited && getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch) begin
            branch = EvDemandLdMiss;
        end else if (inited && getReqOp(req) == Ld && !wasMiss && !cRqIsPrefetch && !wasNeighbourPrefetch) begin
            branch = EvDemandLdHit;
        end else if (inited && getReqOp(req) == Ld && cRqIsPrefetch && wasNeighbourPrefetch) begin
            branch = EvNeighbourChain;
        end
        incomingQ.enq(tuple3(branch, req, line));
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
        $display("%t AlexLog: CDP Kill Prefetch addr issued. lineAddr: %h route %s",
            cur_cycle, getLineAddr(x.paddr), x.routeLLC ? "LLC" : "L1");
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: x.routeLLC,
            isNeighbourLine: x.isNeighbourLine
        };
    endmethod
endmodule
