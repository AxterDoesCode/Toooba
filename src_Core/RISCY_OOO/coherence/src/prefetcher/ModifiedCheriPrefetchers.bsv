// Copyright (c) 2024 Karlis Susters 
// Copyright (c) 2025 Louis Hobson
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Prefetcher_intf::*;
import Types::*;
import CacheUtils::*;
import CCTypes::*;
import ISA_Decls   :: *;
import ProcTypes::*;
import Vector::*;
import FIFO::*;
import Fifos::*;
import FIFOF::*;
import SpecialFIFOs :: *;
import Ehr::*;
import GetPut::*;
import RWBramCore::*;
import RWBramCoreSequential::*;
import ConfigReg::*;
import SpecialRegs::*;
import CHERICap::*;
import CHERICC_Fat::*;
import PerformanceMonitor::*;
import MemoryTypes::*;
import TlbTypes::*;

`define VERBOSE True

typedef enum {
  NOTUSED = 3'd0, USED0 = 3'd1, USED1 = 3'd2, USED2 = 3'd3, USED3 = 3'd4
} LineState deriving (Bits, Eq, FShow);

//Indexed by hash of bounds length and offset
typedef struct {
    Bit#(tagBits) tag;
    LineState state;
    Bit#(24) lastUsedOffset;
} PtrTableEntry #(numeric type tagBits) deriving (Bits, Eq, FShow);

//Indexed by virtual address
typedef struct {
    Bit#(tagBits) tag;
    Bit#(ptrTableIdxTagBits) ptrTableIdxTag;
    Bit#(24) pointerOffset;
} TrainingTableEntry#(numeric type tagBits, numeric type ptrTableIdxTagBits) deriving (Bits, Eq, FShow);

module mkCapPtrPrefetcherNonPC#(
    TlbToPrefetcher toTlb, 
    Parameter#(maxCapSizeToTrack) _,
    Parameter#(ptrTableSize) __, 
    Parameter#(trainingTableSize) ___, 
    Parameter#(inverseDecayChance) ____,
    Parameter#(onlyOnMiss) _____,
    Parameter#(onlyExactCap) ______
)(CheriPrefetcher) provisos (
    NumAlias#(ptrTableTagBits, 16),
    NumAlias#(trainingTableTagBits, 16),
    NumAlias#(ptrTableIdxBits, TLog#(ptrTableSize)),
    NumAlias#(ptrTableIdxTagBits, TAdd#(ptrTableIdxBits, ptrTableTagBits)),
    NumAlias#(trainingTableIdxBits, TLog#(trainingTableSize)),
    NumAlias#(trainingTableIdxTagBits, TAdd#(trainingTableIdxBits, trainingTableTagBits)),
    Alias#(ptrTableIdxT, Bit#(ptrTableIdxBits)),
    Alias#(ptrTableIdxTagT, Bit#(ptrTableIdxTagBits)),
    Alias#(ptrTableTagT, Bit#(ptrTableTagBits)),
    Alias#(ptrTableEntryT, PtrTableEntry#(ptrTableTagBits)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),
    Alias#(trainingTableIdxTagT, Bit#(trainingTableIdxTagBits)),
    Alias#(trainingTableTagT, Bit#(trainingTableTagBits)),
    Alias#(trainingTableEntryT, TrainingTableEntry#(trainingTableTagBits, ptrTableIdxTagBits)),
    Alias#(potentialPrefetchT, Tuple3#(ptrTableIdxTagT, CapPipe, Bool)),

    Add#(a__, 60, TMul#(TDiv#(60, TAdd#(TLog#(ptrTableSize), 16)), TAdd#(TLog#(ptrTableSize), 16))),
    Add#(1, b__, TDiv#(64, TAdd#(TLog#(ptrTableSize), 16))),
    Add#(c__, TAdd#(TLog#(trainingTableSize), 16), 64),
    Add#(1, d__, TDiv#(58, TAdd#(TLog#(trainingTableSize), 16))),
    Add#(1, l__, TDiv#(64, TAdd#(TLog#(trainingTableSize), 16))),
    Add#(k__, 64, TMul#(TDiv#(64, TAdd#(TLog#(trainingTableSize), 16)), TAdd#(TLog#(trainingTableSize), 16))),
    Add#(e__, 58, TMul#(TDiv#(58, TAdd#(TLog#(trainingTableSize), 16)), TAdd#(TLog#(trainingTableSize), 16))),
    Add#(g__, 64, TMul#(TDiv#(64, TAdd#(14, TLog#(ptrTableSize))), TAdd#(14, TLog#(ptrTableSize)))),
    Add#(i__, 58, TMul#(TDiv#(58, TAdd#(14, TLog#(ptrTableSize))), TAdd#(14, TLog#(ptrTableSize)))),
    Add#(1, f__, TDiv#(58, TAdd#(14, TLog#(ptrTableSize)))),
    Add#(1, j__, TDiv#(64, TAdd#(14, TLog#(ptrTableSize)))),
    Add#(h__, 2, TLog#(ptrTableSize)),
    Add#(TLog#(ptrTableSize), m__, 48),
    Add#(p__, TLog#(ptrTableSize), 60),
    Add#(1, n__, TDiv#(64, TLog#(ptrTableSize))),
    Add#(o__, 64, TMul#(TDiv#(64, TLog#(ptrTableSize)), TLog#(ptrTableSize))),
    Add#(q__, TAdd#(TLog#(ptrTableSize), 16), 60),
    Add#(r__, TLog#(TDiv#(maxCapSizeToTrack, 64)), 58)
);
    Array #(Reg #(EventsPrefetcher)) perf_events <- mkDRegOR (5, unpack (0));
    RWBramCoreSequential#(ptrTableIdxBits, ptrTableEntryT, 4) pt <- mkRWBramCoreSequential();
    RWBramCore#(trainingTableIdxT, trainingTableEntryT) tt <- mkRWBramCore();
    Fifo#(8, Tuple2#(trainingTableIdxTagT, Bit#(24))) ttLookupQueue <- mkOverflowBypassFifo;
    Fifo#(1, Tuple2#(trainingTableIdxTagT, Bit#(24))) ttLookupQueueReading <- mkPipelineFifo;
    Fifo#(4, trainingTableIdxT) wipeTtEntry <- mkOverflowBypassFifo;
    Fifo#(4, Tuple2#(trainingTableIdxT, trainingTableEntryT)) installTtEntry <- mkOverflowBypassFifo;
    Fifo#(8, Tuple2#(ptrTableIdxTagT, Bit#(24))) ptUpgradeQueue <- mkOverflowBypassFifo;
    Fifo#(1, Tuple2#(ptrTableIdxTagT, Bit#(24))) ptUpgradeQueueReading <- mkPipelineFifo;

    Fifo#(8, Vector#(4, potentialPrefetchT)) ptLookupQueue <- mkOverflowBypassFifo;
    Fifo#(1, Vector#(4, potentialPrefetchT)) ptLookupQueueReading <- mkPipelineFifo;
    Reg#(Vector#(4, Bool)) ptLookupUsedEntry <- mkReg(replicate(False));

    Fifo#(32, PendingPrefetch) tlbLookupQueue <- mkOverflowPipelineFifo;
    Fifo#(16, PendingPrefetch) prefetchQueue <- mkOverflowBypassFifo;
    Reg#(Bit#(8)) randomCounter <- mkConfigReg(0);
    Reg#(LineAddr) lastLookupLineAddr <- mkReg(0);
    Reg#(trainingTableIdxTagT) lastMatchedTit <- mkReg(0);

    
    function ptrTableIdxTagT getIdxTag(Addr boundsLength, Addr boundsOffset, Addr boundsVirtBase);
        //boundsOffset should be an offset of a cap, so 16 byte aligned, so drop its lowest 4 bits
        //but also, need lowest 2 bits to be sequential and determined by boundsOffset
         //{hash(boundsLength) ^ hash(boundsOffset[63:6]), boundsOffset[5:4]};
        ptrTableIdxT lenHash = hash(boundsLength) ^ hash(boundsVirtBase);
        return truncate(extend(lenHash) + boundsOffset[63:4]);
    endfunction

    function trainingTableIdxTagT getTrainingIdxTag(Addr vaddr, Addr boundsVirtBase, Addr boundsLength) =
        hash(boundsVirtBase ^ boundsLength);
        //hash(getLineAddr(vaddr));

    function LineState upgrade(LineState st) = 
        case (st)
            NOTUSED: USED0;
            USED0: USED1;
            USED1: USED2;
            USED2: USED3;
            USED3: USED3;
        endcase;

    function LineState downgrade(LineState st) =
        case (st)
            NOTUSED: NOTUSED;
            USED0: NOTUSED;
            USED1: USED0;
            USED2: USED1;
            USED3: USED2;
        endcase;

    rule incrRandomCounter;
        if (randomCounter == fromInteger(valueof(inverseDecayChance))-1)
            randomCounter <= 0;
        else
            randomCounter <= randomCounter + 1;
    endrule

    rule doInstallTtEntry;
        let {tIdx, te} = installTtEntry.first;
        installTtEntry.deq;
        tt.wrReq(tIdx, te);
    endrule
    
    (* descending_urgency = "doInstallTtEntry, doWipeTtEntry" *)
    rule doWipeTtEntry;
        let tIdx = wipeTtEntry.first;
        wipeTtEntry.deq;
        trainingTableEntryT te = unpack(0);
        tt.wrReq(tIdx, te);
    endrule

    rule doTtLookupPtr;
        let {tit, boundsOffset} = ttLookupQueue.first;
        ttLookupQueue.deq;
        tt.rdReq(truncate(tit));
        ttLookupQueueReading.enq(tuple2(tit, boundsOffset));
    endrule

    rule processTtRead;
        let {tit, boundsOffset} = ttLookupQueueReading.first;
        ttLookupQueueReading.deq;
        trainingTableTagT tTag = truncateLSB(tit);
        trainingTableIdxT tIdx = truncate(tit);
        tt.deqRdResp;
        let te = tt.rdResp;
        Bit#(24) offsetOffset = boundsOffset - te.pointerOffset;
        if (te.tag == tTag && lastMatchedTit != tit) begin
            //Match -- upgrade ptrTable
            if (`VERBOSE) $display("%t Prefetcher training table match! Will upgrade ptr table pit %h", $time, te.ptrTableIdxTag);
            ptUpgradeQueue.enq(tuple2(te.ptrTableIdxTag, offsetOffset));
            EventsPrefetcher evt = unpack(0);
            evt.evt_0 = 1;
            perf_events[0] <= evt;
            wipeTtEntry.enq(tIdx);
            lastMatchedTit <= tit;
        end
        else begin
            if (`VERBOSE) $display("%t Prefetcher training table mismatch! table %h now %h", $time, te.tag, tTag);
        end
    endrule

    rule doPtReadForUpgrade;
        if (`VERBOSE) $display("%t Prefetcher doPtReadForUpgrade", $time);
        let {pit, offsetOffset} = ptUpgradeQueue.first;
        ptUpgradeQueue.deq;
        ptUpgradeQueueReading.enq(tuple2(pit, offsetOffset));
        pt.rdReq(truncate(pit));
    endrule

    rule processPtReadUpgrade;
        let pteVec = pt.rdResp;
        let pte = pteVec[0];
        pt.deqRdResp;
        let {pit, offsetOffset} = ptUpgradeQueueReading.first;
        ptUpgradeQueueReading.deq;
        if (pte.tag == truncateLSB(pit)) begin
            if (pte.lastUsedOffset == offsetOffset)
                pte.state = upgrade(pte.state);
            pte.lastUsedOffset = offsetOffset;
            if (`VERBOSE) $display("%t Prefetcher processPtReadUpgrade hit pit %h set lastUsedOffset %d to %d, changed state to ", $time, pit, pte.lastUsedOffset, offsetOffset, fshow(pte.state));
            /*
            EventsPrefetcher evt = unpack(0);
            evt.evt_1 = 1;
            perf_events[1] <= evt;
            */
        end
        else begin
            pte.state = USED1;
            pte.tag = truncateLSB(pit);
            pte.lastUsedOffset = offsetOffset;
            if (`VERBOSE) $display("%t Prefetcher processPtReadUpgrade miss pit %h set lastUsedOffset %d to %d, changed state to ", $time, pit, pte.lastUsedOffset, offsetOffset, fshow(pte.state));
        end
        pt.wrReq(truncate(pit), pte);
    endrule

    (* descending_urgency = "doPtReadForUpgrade, doPtReadForLookup" *)
    rule doPtReadForLookup;
        $display("%t Prefetcher doPtReadForLookup", $time);
        let pitVec = ptLookupQueue.first;
        ptLookupQueue.deq;
        ptLookupQueueReading.enq(pitVec);
        pt.rdReq(truncate(tpl_1(pitVec[0])));

        /*
        EventsPrefetcher evt = unpack(0);
        evt.evt_2 = 1;
        perf_events[2] <= evt;
        */
    endrule

    //usedPrefetch, entry from pt, pit, capValid
    function Bool canPrefetch(Tuple4#(Bool, ptrTableEntryT, ptrTableIdxTagT, Bool) pte) = 
        !tpl_1(pte) && 
        tpl_4(pte) &&
        tpl_2(pte).tag == truncateLSB(tpl_3(pte)) && 
        (tpl_2(pte).state == USED2 || tpl_2(pte).state == USED3);


    function Bool canDoAnyPrefetch;
        let pteVec = pt.rdResp;
        let ppVec = ptLookupQueueReading.first;
        return any(canPrefetch, zip4(ptLookupUsedEntry, pteVec, map(tpl_1, ppVec), map(tpl_3, ppVec)));
    endfunction

    rule deqPtRdResp if (!canDoAnyPrefetch);
        $display("%t Prefetcher deqPtRdResp", $time, fshow(ptLookupQueueReading.first), fshow(pt.rdResp), fshow (ptLookupUsedEntry));
        pt.deqRdResp;
        ptLookupQueueReading.deq;
        ptLookupUsedEntry <= replicate(False);
    endrule

    (* descending_urgency = "deqPtRdResp, processPtReadForLookup" *)
    rule processPtReadForLookup;
        //downgrade pte with some chance
        let ppVec = ptLookupQueueReading.first;
        let pteVec = pt.rdResp;
        if (`VERBOSE) $display("%t Prefetcher processPtReadForLookup ", $time, fshow(ptLookupUsedEntry), fshow(pteVec));
        let prefetchIdx = findIndex(canPrefetch, zip4(ptLookupUsedEntry, pteVec, map(tpl_1, ppVec), map(tpl_3, ppVec)));
        if (prefetchIdx matches tagged Valid .idx) begin
            ptLookupUsedEntry[idx] <= True;
            let pte = pteVec[idx];
            let pit = tpl_1(ppVec[idx]);
            let cap = tpl_2(ppVec[idx]);
            Bit#(24) offset = truncate(getOffset(cap)) + pte.lastUsedOffset;
            cap = setOffset(cap, extend(offset)).value;
            if (isInBounds(cap, False)) begin
                if (`VERBOSE) $display("%t Prefetcher processPtReadForLookup canprefetch pit %h table tag %h read tag %h target vaddr %h offset %h", $time, pit, pte.tag, ptrTableTagT'{truncateLSB(pit)}, getAddr(cap), offset);
                tlbLookupQueue.enq(PendingPrefetch {
                    addr: ?,
                    cap: cap,
                    nextLevel: False,
                    auxData: NoPrefetchAuxData
                });
                if (randomCounter == 0) begin
                    pte.state = downgrade(pte.state);
                    pt.wrReq(truncate(pit), pte);
                    if (`VERBOSE) $display("%t Prefetcher processPtReadForLookup %h downgrading to ", $time, pit, fshow(pte.state));
                end
                EventsPrefetcher evt = unpack(0);
                evt.evt_1 = 1;
                /*
                if (offset <= 64) begin
                    evt.evt_2 = 1;
                end
                */
                perf_events[2] <= evt;
            end else begin
                if (`VERBOSE) $display("%t Prefetcher processPtReadForLookup %h out of bounds base %h length %h offset %h (original offset %h pTable offset %h)", $time, pit, getBase(cap), getLength(cap), offset, getOffset(tpl_2(ppVec[idx])), pte.lastUsedOffset);
                pte.state = downgrade(pte.state);
                pt.wrReq(truncate(pit), pte);
            end
        end
    endrule
        
        /*
    rule doTlbLookup;
        let prefetch = tlbLookupQueue.first;
        tlbLookupQueue.deq;
        toTlb.prefetcherReq(prefetch);
    endrule

    rule getTlbResp;
        let resp = toTlb.prefetcherResp;
        toTlb.deqPrefetcherResp;
        if (`VERBOSE) $display("%t Prefetcher got TLB response: ", $time, fshow(resp));
            if (!resp.haveException && resp.prefetch.addr != 0) begin
                prefetchQueue.enq(resp.prefetch);
            // EventsPrefetcher evt = unpack(0);
            // evt.evt_3 = 1;
            // perf_events[3] <= evt;
        end
    endrule
    */
    

    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        //Lookup addr in training table, if get a hit, update ptrTable
        if (!isPrefetch && (memOp == Ld || memOp == St) && boundsLength <= fromInteger(valueOf(maxCapSizeToTrack))) begin
            Addr vaddr = boundsVirtBase + boundsOffset;
            trainingTableIdxTagT tit = getTrainingIdxTag(vaddr, boundsVirtBase, boundsLength);
            Bit#(24) usedOffset = truncate(boundsOffset);
            if (`VERBOSE) $display("%t Prefetcher reportAccess %h offset %h boundslen %d lineoffset %d tit %h", $time, addr, boundsOffset, boundsLength, usedOffset, tit, fshow(hitMiss));
            ttLookupQueue.enq(tuple2(tit, usedOffset));
        end
    endmethod

    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (memOp == Ld && boundsLength <= fromInteger(valueOf(maxCapSizeToTrack)) && boundsLength >= 16) begin
            $display ("%t Prefetcher reportCacheDataArrival wasMiss %d wasPrefetch %d access addr %h boundslen %d offset %h pcHash deadbeef ", 
                $time, 
                wasMiss, 
                wasPrefetch, 
                addr, 
                boundsLength, 
                boundsOffset, 
                fshow(lineWithTags)
            );

            //Add accessed cap to training table in case we dereference it later.
            if (addr[3:0] == 0) begin
                //addr targeted a multiple of 16 bytes -- so potentially a capability
                let offset = getLineMemDataOffset(addr);
                MemTaggedData d = getTaggedDataAt(lineWithTags, offset);
                CapPipe cap = fromMem(unpack(pack(d)));
                if (d.tag && boundsVirtBase != getBase(cap)) begin
                    //install ptr addr of cap in training table
                    ptrTableIdxTagT pit = getIdxTag(boundsLength, boundsOffset, boundsVirtBase);
                    trainingTableIdxTagT tit = getTrainingIdxTag(getAddr(cap), saturating_truncate(getBase(cap)), saturating_truncate(getLength(cap)));
                    trainingTableTagT tTag = truncateLSB(tit);
                    trainingTableIdxT tIdx = truncate(tit);
                    trainingTableEntryT te;
                    if (`VERBOSE) $display("%t Prefetcher reportDataArrival adding training table entry! access addr %h boundslen %d offset %h prefetch %b pcHash deadbeef ptraddress %h ptrbase %h ptrlength %d tit %h pit %h", 
                        $time, addr, boundsLength, boundsOffset, wasPrefetch, getAddr(cap), getBase(cap), getLength(cap), tit, pit, " ptrperms ", fshow(getHardPerms(cap)));
                    te.tag = tTag;
                    te.ptrTableIdxTag = pit;
                    te.pointerOffset = truncate(getOffset(cap));
                    installTtEntry.enq(tuple2(tIdx, te));
                    tt.wrReq(tIdx, te);
                    EventsPrefetcher evt = unpack(0);
                    evt.evt_4 = 1;
                    if (boundsVirtBase != getBase(cap)) begin
                        //evt.evt_2 = 1;
                    end
                    perf_events[4] <= evt;
                end
            end

            //Previous condition was wasMiss && !wasPrefetch
            if (valueOf(onlyOnMiss)==0 || wasMiss) begin
                //TODO prevent runaway prefetching
                //Queue caps here for lookup in ptr table
                //Only do so on a cache miss to prevent too many prefetches
                Vector#(4, potentialPrefetchT) v;
                Bool foundOneCap = False;
                Addr clineStartOffset = (boundsOffset-extend(addr[5:0]));
                if (valueOf(onlyExactCap) != 0) begin
                    MemTaggedData d = getTaggedDataAt(lineWithTags, getLineMemDataOffset(addr));
                    CapPipe cap = fromMem(unpack(pack(d)));
                    ptrTableIdxTagT pit = getIdxTag(boundsLength, boundsOffset, boundsVirtBase);
                    v[0] = tuple3(pit, cap, d.tag);
                    for (Integer i = 1; i < 4; i = i + 1) v[i] = tuple3(?, ?, False);
                    foundOneCap = d.tag;
                end else begin
                    for (Integer i = 0; i < 4; i = i + 1) begin
                        MemTaggedData d = getTaggedDataAt(lineWithTags, fromInteger(i));
                        CapPipe cap = fromMem(unpack(pack(d)));
                        ptrTableIdxTagT pit = getIdxTag(boundsLength, clineStartOffset+fromInteger(i)*16, boundsVirtBase);
                        Bool lowerBoundOk = (boundsOffset >> 4) + fromInteger(i) >= extend(addr[5:4]);
                        Bool upperBoundOk = (boundsOffset >> 4) + fromInteger(i+1) <= extend(addr[5:4]) + (boundsLength >> 4);
                        Bool goodCap = d.tag && lowerBoundOk && upperBoundOk;
                        v[i] = tuple3(pit, cap, goodCap);
                        foundOneCap = foundOneCap || goodCap;
                    end
                end
                if (foundOneCap) begin
                    if (`VERBOSE) $display("%t Prefetcher reportDataArrival addr %h prefetech %b adding %d caps for prefetch lookups (clinestartoffset %h)", 
                        $time, addr, wasPrefetch, countElem(True, map(tpl_3, v)), clineStartOffset, fshow(v));
                    ptLookupQueue.enq(v);
                    EventsPrefetcher evt = unpack(0);
                    evt.evt_3 = 1;
                    if (wasPrefetch) begin
                        evt.evt_2 = 1;
                    end
                    perf_events[3] <= evt;
                    lastLookupLineAddr <= getLineAddr(addr);
                end
            end
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        if (`VERBOSE) $display("%t Prefetcher getNextPrefetchAddr %h", $time, prefetchQueue.first);
        prefetchQueue.deq;
        return prefetchQueue.first;
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData if (False);
        return ?;
    endmethod

    method Action sendBroadcastData(PrefetcherBroadcastData data);
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return perf_events[0];
    endmethod
`endif

endmodule