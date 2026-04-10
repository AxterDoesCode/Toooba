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
} NextCandT deriving (Bits, FShow, Eq);

module mkCDP(
    CacheLinePrefetcher#(reqT)
) provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr, size 8 for each FIFO
    SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // This is purely for $display
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%0d AlexLog: CDP deqLineL1", cur_cycle);
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                nextCandidateBuffer.enqS[enqIdx].enq(
                    NextCandT{
                        paddr: getReqAddr(x.req), 
                        vaddr: x.line[i]});
                // Probably change logging here to just see the candidate vaddr -> candidate paddr?
                $display("%0d AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", cur_cycle, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    method Action reportIncomingCacheLine(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%0d AlexLog: CDP reportIncomingCacheLine", cur_cycle);
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        if (hitMiss == HIT) begin
            $display("%0d AlexLog: prefetcher report HIT %h", cur_cycle, addr);
        end
        else begin
            $display("%0d AlexLog: prefetcher report MISS %h", cur_cycle, addr);
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr; // Do I want some condition here?
        // Found a virtual address and need to translate it now,
        // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
        let x = nextCandidateBuffer.deqS[0].first;
        nextCandidateBuffer.deqS[0].deq;
        // Use the same VPN -> PPN, but get the offset of the candidate vaddr
        Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
        $display("%0d AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", cur_cycle, nextAddr, x.vaddr);
        return PendingPrefetch {
            addr: nextAddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
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
// Uses 4-way set-associative BRAMs (RWSetAssocBramCoreForwarded) for both
// the training table and PC table.
// ============================================================================

// Confidence vector indexed by (relOffset + 7), covering offsets -7..+7 (15 slots)
typedef Vector#(15, Bit#(3)) PCRelOffsetConfT;

typedef union tagged {
    RelLineOffset             Training;      // relative offset whose counter to saturating-increment
    Tuple3#(Addr, Line, Vpn)  PrefetchIssue; // (load addr, cache line, vpn) to select prefetch target from
    void                      Decay;         // decrement all counters in the selected entry by 1
} PCTableRdRelTagT deriving (Bits, FShow);

module mkCDPStatefulRelative#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____
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

    // 4-way set-associative training table
    // addrT = trainingTableIdxT, wayT = Bit#(2), dataT = TrainingTableEntryT, tagT = Addr
    function Bool ttIsMatch(TrainingTableEntryT e, Addr tag) = e.valid && e.storedVaddr == tag;
    function Bool ttIsReplaceCandidate(TrainingTableEntryT e) = !e.valid;
    RWSetAssocBramCore#(trainingTableIdxT, Bit#(2), TrainingTableEntryT, Addr) trainingTable
        <- mkRWSetAssocBramCoreForwarded(ttIsMatch, ttIsReplaceCandidate);

    SupFifo#(16, 9, ttRespQT) ttRespQ <- mkSupFifo;
    // Carries (index, vaddr) — both needed by rdReq(addr, tag)
    SupFifo#(16, 9, Tuple2#(trainingTableIdxT, Addr)) ttRdReqSupFIFO <- mkSupFifo;

    // Flat PC confidence table
    RWBramCore#(pcTableIdxT, Maybe#(PCRelOffsetConfT)) pcTable <- mkRWBramCoreForwarded();

    Fifo#(16, NextCandT) nextCandidateBuffer <- mkOverflowBypassFifo;
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdReqFIFO <- mkSizedFIFO(64);
    FIFO#(Tuple2#(pcTableIdxT, PCTableRdRelTagT)) pcTableRdTagQ    <- mkFIFO;

    // TLB translation pipeline for prefetch candidates
    FIFO#(Addr) tlbReqFIFO <- mkSizedFIFO(16);        // decouples pcTableResp from TLB
    FIFO#(Addr) tlbPendingCandQ <- mkSizedFIFO(valueOf(LLCTlbReqNum)); // tracks in-flight vaddrs
    Reg#(LLCTlbReqIdx) tlbReqId <- mkReg(0);

    // Init: write unpack(0) (valid=False) to every (addr, way) pair for training table
    Reg#(Bool) ttInited <- mkConfigReg(False);
    Reg#(Bit#(TAdd#(trainingTableIdxBits, 2))) ttInitCount <- mkReg(0);
    // Flat PC table init
    Reg#(Bool) pcInited <- mkConfigReg(False);
    Reg#(Bit#(pcTableIdxBits)) pcInitCount <- mkReg(0);

    // Confidence decay
    LFSR#(Bit#(16)) decayLfsr <- mkLFSR_16;
    Reg#(Bit#(32))  decayCounter <- mkReg(fromInteger(valueOf(decayInterval)));

    function Bool inited;
        return ttInited && pcInited;
    endfunction

    (* mutually_exclusive = "doTrainingTableInit, processTtRdReq, ttAccess" *)
    rule doTrainingTableInit(!ttInited);
        trainingTableIdxT addr = truncateLSB(ttInitCount);
        Bit#(2) way = truncate(ttInitCount);
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
                pcTableRdReqFIFO.enq(tuple2(pctIdx, tagged Training ttRdResp.lineOffset));
                $display("%0d AlexLog: CDP Rel Training hit: missVaddr %h seen before by pcHash %h at relOffset %d",
                    cur_cycle, respQ.candVaddr, ttRdResp.pcHash, ttRdResp.lineOffset);
            end
            // Miss: this vaddr hasn't been seen as a pointer before — nothing to do
        end else begin
            // Candidate lookup: we looked up a pointer-like value from the incoming line.
            // Always write the current (pcHash, relOffset) context — overwriting on hit keeps
            // the entry current if the same vaddr is later seen by a different load PC.
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
                if (ttRdResp.pcHash != getPcHash(respQ.req)) begin
                    trainingTable.wrReq(respQ.ttIdx, hitWay, newEntry);
                    $display("%0d AlexLog: CDP Rel Overwrote training table, idx: %d candVaddr: %h oldPcHash: %h newPcHash: %h relOffset: %d",
                        cur_cycle, respQ.ttIdx, respQ.candVaddr, ttRdResp.pcHash, getPcHash(respQ.req), relOffset);
                end
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
            tagged Training .relOffset: begin
                PCRelOffsetConfT curConf = fromMaybe(replicate(0), rdResp);
                Bit#(4) vecIdx = pack(relOffset + 7);
                Bit#(3) curVal = curConf[vecIdx];
                Bit#(3) newVal = (curVal == maxBound) ? maxBound : curVal + 1;
                pcTable.wrReq(pctIdx, Valid(update(curConf, vecIdx, newVal)));
                $display("%0d AlexLog: CDP Rel PC table updated, idx: %d, relOffset: %d, conf: %d -> %d",
                         cur_cycle, pctIdx, relOffset, curVal, newVal);
            end
            tagged PrefetchIssue {.addr, .line, .reqVpn}: begin
                if (rdResp matches tagged Valid .conf) begin
                    Int#(4) hitOffset = unpack(zeroExtend(getLineDataOffset(addr)));
                    LineDataOffset bestOffset = 0;
                    Bool foundHighConf = False;
                    // Iterate high-to-low so lowest relative offset wins on tie
                    for (Integer i = 14; i >= 0; i = i - 1) begin
                        Int#(4) relOffset  = fromInteger(i - 7);
                        Int#(4) absTarget  = hitOffset + relOffset;
                        if (conf[fromInteger(i)] >= 3 &&& absTarget >= 0 &&& absTarget <= 7) begin
                            bestOffset = truncate(pack(absTarget));
                            foundHighConf = True;
                        end
                    end
                    Addr candidate = line[bestOffset];
                    Bit#(matchBits) addrUpper = truncateLSB(reqVpn);
                    Bit#(matchBits) candUpper = truncateLSB(getVpn(candidate));
                    Bool isValidVaddr = candUpper == addrUpper;
                    if (foundHighConf && isValidVaddr) begin
                        tlbReqFIFO.enq(candidate);
                        $display("%0d AlexLog: CDP Rel queued TLB req for candidate vaddr %h", cur_cycle, candidate);
                    end
                    if (foundHighConf && !isValidVaddr) begin
                        $display("%0d AlexLog: CDP Rel Invalid address at best offset");
                    end
                end
            end
            tagged Decay: begin
                if (rdResp matches tagged Valid .conf) begin
                    function Bit#(3) satDec(Bit#(3) x) = (x == 0) ? 0 : x - 1;
                    pcTable.wrReq(pctIdx, Valid(map(satDec, conf)));
                    $display("%0d AlexLog: CDP Rel decay applied to pcTable idx: %d", cur_cycle, pctIdx);
                end
            end
        endcase
    endrule

    // Drain tlbReqFIFO and issue requests to the TLB
    rule processTlbReq;
        Addr candVaddr = tlbReqFIFO.first;
        tlbReqFIFO.deq;
        toTlb.prefetcherReq(PrefetcherReqToTlb{vaddr: candVaddr, id: tlbReqId});
        tlbPendingCandQ.enq(candVaddr);
        tlbReqId <= tlbReqId + 1;
        $display("%0d AlexLog: CDP Rel TLB req sent for vaddr %h id %d", cur_cycle, candVaddr, tlbReqId);
    endrule

    // Consume TLB translation responses and enqueue to nextCandidateBuffer
    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        Addr candVaddr = tlbPendingCandQ.first;
        tlbPendingCandQ.deq;
        if (!resp.haveException) begin
            nextCandidateBuffer.enq(NextCandT{paddr: resp.paddr, vaddr: candVaddr});
            $display("%0d AlexLog: CDP Rel TLB resp: vaddr %h -> paddr %h", cur_cycle, candVaddr, resp.paddr);
        end else begin
            $display("%0d AlexLog: CDP Rel TLB resp: exception for vaddr %h, dropping prefetch", cur_cycle, candVaddr);
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

    method Action reportIncomingCacheLine(reqT req, Line line);
        if (inited) begin
            let tmp = L1ToCDPT{req: req, line: line};
            l1ToCDP.enq(tmp);
            $display("%0d AlexLog: CDP Rel reportIncomingCacheLine", cur_cycle);
        end
    endmethod

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        if (inited && op == Ld) begin
            // This rule does work only on HIT loads currently because we detect miss loads on the cache line fill from L2 with reportIncomingCacheLine
            // In L1Bank we currently only reportAccess on demand (not prefetch)
            if (hitMiss == HIT) begin
                pcTableIdxT pctIdx = hash(pcHash);
                pcTableRdReqFIFO.enq(tuple2(pctIdx,
                    tagged PrefetchIssue tuple3(addr, line, reqVpn)));
                $display("%0d AlexLog: CDP Rel prefetcher report %s addr %h pcHash %h", cur_cycle, hitMiss == HIT ? "HIT" : "MISS", addr, pcHash);
            end
            //$display("%0d AlexLog: CDP Rel prefetcher report %s %h", cur_cycle, hitMiss == HIT ? "HIT" : "MISS", addr);
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = nextCandidateBuffer.first;
        nextCandidateBuffer.deq;
        // paddr is already the correct translated physical address from the TLB
        $display("%0d AlexLog: CDP Rel Prefetch addr issued. lineAddr: %h | paddr: %h | vaddr: %h", cur_cycle, getLineAddr(x.paddr), x.paddr, x.vaddr);
        return PendingPrefetch {
            addr: x.paddr,
            vpn: getVpn(x.vaddr),
            nextLevel: False
        };
    endmethod
endmodule
