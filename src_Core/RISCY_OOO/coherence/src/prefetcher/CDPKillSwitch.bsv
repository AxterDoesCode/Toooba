// CDPKillSwitch.bsv — Variant H: do-no-harm CDP via per-PC blacklist.
//
// Problem: Variant B (LLC-routed) helps some benchmarks but not treeadd — even
// LLC prefetches consume DRAM/bandwidth, and treeadd's mis-targeted prefetches
// still cost cycles via LLC contention even without L1 pollution. Variant E
// (adaptive L1/LLC routing) can't fully fix this because LLC is not "free"
// — the ONLY actually-harmless action for a proven-bad PC is to issue
// nothing at all.
//
// Design: each PC-table entry carries a small (4-bit) uselessCount. Once a
// PC accumulates `killThreshold` useless attributions (eviction of
// wasPrefetch=True line before any demand touched it), ALL further prefetches
// from that PC are suppressed — not LLC-routed, just dropped. Good PCs that
// keep delivering useful hits never accumulate enough useless to trip. Patricia
// should therefore stay L1-prefetched; treeadd / em3d / voronoi / health PCs
// that are mis-targeting should self-silence.
//
// The useful counter is tracked too but NOT used for the gate — it's there for
// logging / diagnostics and in case we want to add a forgiveness policy later
// (e.g. reset uselessCount when useful reaches some level).
//
// The useless counter is known to be biased LOW (filter entries lose
// attribution when they're hash-evicted by newer prefetches before the
// delayed eviction fires). So killThreshold should be set fairly low —
// something like 3 — because each observed useless event implies many more
// un-attributed ones in reality.

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

// Extended PC-table entry with per-PC accuracy counters.
typedef struct {
    Bit#(16)         pcHash;
    PCRelOffsetConfT conf;
    Bit#(4)          usefulCount;   // saturating at 15
    Bit#(4)          uselessCount;  // saturating at 15
} PCTableAccEntryT deriving (Bits, FShow, Eq);

// Decision output carries the routing choice so getNextPrefetchAddr can
// set PendingPrefetch.nextLevel appropriately.
typedef struct {
    Addr paddr;
    Addr vaddr;
    Bool isNeighbourLine;
    Bool routeLLC;                  // True → nextLevel=True (LLC), False → L1
} NextCandAdaptT deriving (Bits, FShow, Eq);

// Filter entry extended with pcHash so eviction can charge the right PC.
typedef struct {
    LineAddr lineAddr;
    Bit#(16) pcHash;
    Bool     punishable;            // False for neighbour-chain entries (no clean attribution)
} FilterAccEntryT deriving (Bits, FShow, Eq);

typedef union tagged {
    Tuple2#(Bit#(16), RelLineOffset) Training;
    Tuple3#(Addr, Line, Vpn)         PrefetchIssue;
    Bit#(16)                          AccUseful;    // (pcHash) — bump usefulCount
    Bit#(16)                          AccUseless;   // (pcHash) — bump uselessCount
    void                              Decay;
} PCTableRdAdaptTagT deriving (Bits, FShow);

module mkCDPStatefulRelativeKillSwitch#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____,
    Parameter#(confidenceThreshold) _____,
    Parameter#(killThreshold) ______  // % threshold (out of 16) for L1-routing
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

    RWBramCore#(pcTableIdxT, Maybe#(PCTableAccEntryT)) pcTable <- mkRWBramCoreForwarded();
    RWBramCore#(Bit#(10), Maybe#(FilterAccEntryT)) prefetchFilter <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandAdaptT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdAdaptTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdAdaptTagT)) pcTableRdTagQ    <- mkFIFO;
    // Filter pipeline: (filterIdx, candidate, pcHashOfOrigin) after TLB resp.
    FIFO#(Tuple3#(Bit#(10), NextCandAdaptT, Bit#(16))) filterPendingQ <- mkFIFO;
    FIFO#(LineAddr) evictionQ <- mkSizedFIFO(4);
    // Split eviction pipeline so we can read the filter before invalidating.
    FIFO#(Tuple2#(Bit#(10), LineAddr)) evictionPendingQ <- mkSizedFIFO(4);
    // Useful-hit lookup pipeline: reportUsefulPrefetch() enqs lineAddr,
    // startUsefulLookup reads the filter, finishUsefulLookup on match charges
    // the owning PC's usefulCount via an AccUseful tag.
    FIFO#(LineAddr) usefulHitQ <- mkSizedFIFO(4);
    FIFO#(Tuple2#(Bit#(10), LineAddr)) usefulHitPendingQ <- mkSizedFIFO(4);

    // tlbReqFIFO payload: (vaddr, isNeighbour, crossPage, pcHashOfOrigin, punishable, routeLLC)
    FIFO#(Tuple6#(Addr, Bool, Bool, Bit#(16), Bool, Bool)) tlbReqFIFO <- mkSizedFIFO(4);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    Vector#(LLCTlbReqNum, Reg#(Addr))     pendCandVaddr        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendIsNeighbourLine  <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendCrossPage        <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bit#(16))) pendPcHash           <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool))     pendPunishable       <- replicateM(mkRegU);
    // Accuracy decision for this prefetch, captured at decision time so it
    // flows to the filter and ultimately to getNextPrefetchAddr's routing choice.
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

    // Kill-switch gate: once uselessCount hits killThreshold, ALL further
    // prefetches from that PC are suppressed — the harshest possible response
    // to a proven-bad predictor. Because the useless counter is biased low
    // (filter entries get hash-evicted before delayed useless events attribute),
    // a small killThreshold (~3) already reflects many more real useless
    // events. Good PCs whose prefetches keep delivering useful hits rarely
    // accumulate useless events anyway.
    // Ratio-based gate. Blacklist only when a PC has both (a) enough useless
    // evidence to be statistically meaningful (us >= killThreshold), AND
    // (b) more useless events than useful — "not mostly good". A PC with a
    // strong useful record tolerates some noise. A PC with no wins doesn't.
    // The `us > uf` half comparison naturally protects patricia (whose useful
    // counters saturate) and punishes treeadd/em3d PCs that never deliver.
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
                PCRelOffsetConfT curConf = replicate(0);
                Bit#(4) curUseful = 0, curUseless = 0;
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) begin
                    curConf = e.conf;
                    curUseful = e.usefulCount;
                    curUseless = e.uselessCount;
                end
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(PCTableAccEntryT{
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
                        // ** Kill-switch gate. Once uselessCount hits killThreshold this PC
                        //    issues NO further prefetches — not LLC-routed, just suppressed. **
                        Bool okToIssue = shouldIssue(entry.usefulCount, entry.uselessCount);
                        $display("%t AlexLog: CDP Kill prefetch decision: pcHash %h relOffset %d uf %d us %d %s",
                            cur_cycle, entry.pcHash, bestRelOffset, entry.usefulCount, entry.uselessCount,
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
                    pcTable.wrReq(pctIdx, Valid(PCTableAccEntryT{
                        pcHash: e.pcHash, conf: e.conf,
                        usefulCount: newUf, uselessCount: e.uselessCount}));
                    $display("%t AlexLog: CDP Kill acc useful bump, idx: %d pcHash: %h uf: %d -> %d",
                        cur_cycle, pctIdx, pcHash, e.usefulCount, newUf);
                end
            end
            tagged AccUseless .pcHash: begin
                if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash) begin
                    // Amplify: bump useless by 3 per attributed event. The filter
                    // captures only ~1 in 3-5 real useless events (delayed eviction
                    // loses to hash-collision invalidation); scaling up compensates.
                    Bit#(5) amplified = zeroExtend(e.uselessCount) + 3;
                    Bit#(4) newUs = (amplified >= 15) ? 15 : truncate(amplified);
                    pcTable.wrReq(pctIdx, Valid(PCTableAccEntryT{
                        pcHash: e.pcHash, conf: e.conf,
                        usefulCount: e.usefulCount, uselessCount: newUs}));
                    $display("%t AlexLog: CDP Kill acc useless bump, idx: %d pcHash: %h us: %d -> %d",
                        cur_cycle, pctIdx, pcHash, e.uselessCount, newUs);
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .entry) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    // Also softly decay accuracy counters (half-rate — every 2nd decay).
                    Bit#(4) decayUf = (entry.usefulCount > 0) ? entry.usefulCount - 1 : 0;
                    Bit#(4) decayUs = (entry.uselessCount > 0) ? entry.uselessCount - 1 : 0;
                    pcTable.wrReq(pctIdx, Valid(PCTableAccEntryT{
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
        Bit#(16) pcH         = pendPcHash[id];
        Bool rlLLC           = pendRouteLLC[id];
        tlbReqFreeQ.enq(id);
        if (!resp.haveException) begin
            NextCandAdaptT cand = NextCandAdaptT{
                paddr: resp.paddr, vaddr: candVaddr,
                isNeighbourLine: isNeighbourLine, routeLLC: rlLLC };
            LineAddr lineAddr = getLineAddr(resp.paddr);
            Bit#(10) filterIdx = hash(lineAddr);
            prefetchFilter.rdReq(filterIdx);
            filterPendingQ.enq(tuple3(filterIdx, cand, pcH));
        end
    endrule

    (* descending_urgency = "finishEviction, processFilterResp" *)
    rule processFilterResp(inited);
        let rdResp = prefetchFilter.rdResp;
        prefetchFilter.deqRdResp;
        match {.filterIdx, .cand, .pcH} = filterPendingQ.first;
        filterPendingQ.deq;
        LineAddr lineAddr = getLineAddr(cand.paddr);
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            $display("%t AlexLog: CDP Kill filter HIT: dropped duplicate prefetch for lineAddr %h", cur_cycle, lineAddr);
        end else begin
            // Write provenance and issue. The routing-to-LLC decision will be
            // made in getNextPrefetchAddr by re-reading the PC table — but since
            // this would add round-trip cost, we instead store a simple heuristic
            // here: if the filter just evicted a prior useless prefetch on this
            // PC, route LLC; else route L1.
            // Simpler first-cut: always trust the PC-table's accuracy decision we
            // made at prefetch-decision time. That was routed via pendRouteLLC.
            prefetchFilter.wrReq(filterIdx, Valid(FilterAccEntryT{
                lineAddr: lineAddr, pcHash: pcH, punishable: True }));
            nextCandidateBuffer.enq(cand);
            $display("%t AlexLog: CDP Kill filter MISS: issuing prefetch for lineAddr %h pcHash %h route %s",
                cur_cycle, lineAddr, pcH, cand.routeLLC ? "LLC" : "L1");
        end
    endrule

    // Eviction handling: split to read filter before invalidating. On a match,
    // look up which pcHash owned this prefetch and charge it with "uselessCount++".
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
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr) begin
            if (fe.punishable) begin
                pcTableIdxT pctIdx = hash(fe.pcHash);
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged AccUseless fe.pcHash));
                $display("%t AlexLog: CDP Kill useless evict: lineAddr %h pcHash %h",
                    cur_cycle, lineAddr, fe.pcHash);
            end
        end
        prefetchFilter.wrReq(filterIdx, Invalid);
    endrule

    // Useful-hit feedback: reportUsefulPrefetch() is invoked by L1Bank when a
    // demand load hits a wasPrefetch=True line. We look up the filter entry for
    // that lineAddr to find the originating pcHash, then enqueue an AccUseful
    // bump for that PC. If the filter entry is stale / lineAddr mismatch
    // (hash collision with a newer prefetch) we silently skip the bump.
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
        if (rdResp matches tagged Valid .fe &&& fe.lineAddr == lineAddr &&& fe.punishable) begin
            pcTableIdxT pctIdx = hash(fe.pcHash);
            pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged AccUseful fe.pcHash));
            $display("%t AlexLog: CDP Kill useful hit: lineAddr %h pcHash %h",
                cur_cycle, lineAddr, fe.pcHash);
        end
        // Note: we don't invalidate the filter entry on useful hit — L1Bank
        // will eventually evict the line anyway, clearing wasPrefetch; leaving
        // the filter entry lets subsequent re-prefetches dedup correctly.
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
                // Neighbour-chain prefetch — no attributable PC, route to L1 by default.
                tlbReqFIFO.enq(tuple6(candidate, False, getVpn(candidate) != getReqVpn(req),
                                      16'h0, False, False));
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
