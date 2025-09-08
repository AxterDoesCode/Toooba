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
import TlbTypes::*;
import MemoryTypes::*;
import ISA_Decls   :: *;
import ProcTypes::*;
import Vector::*;
import FIFO::*;
import Fifos::*;
import RWBramCore::*;
import RWSetAssocBramCore::*;
import CHERICap::*;
import CHERICC_Fat::*;
import LFSR::*;
import PerformanceMonitor::*;
import Ehr::*;
import ConfigReg::*;
import DReg::*;

`include "div_table_4x4to7.bsvi"



/* ================================================================
 * ======== Data Structures =======================================
 * ================================================================
 */



/* L1 pointer table entry.
 * Indexed by bounds length and pointer offset in bounds.
 * Counts how regularly observed capabilities are actually dereferenced,
 * producing a confidence value.
 */
typedef struct {
    Bit#(ptTagBits) tag;
    Bit#(TSub#(confBits, 1)) nSeen;
    Bit#(confBits) nFetched;
    Bit#(capOffsetBits) bestOffset;
} CapChaserL1PtEntry#(
    numeric type ptTagBits, 
    numeric type confBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* For upgrading/downgrading the L1 pointer table confidence */
typedef struct {
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bool upgrade;
    Bit#(capOffsetBits) accessOffset;
} CapChaserL1PtUpDowngrade#(
    numeric type ptIdxTagBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* LL pointer table entry.
 * We only need a pre-computed fixpoint confidence value.
 */
typedef struct {
    Bit#(ptTagBits) tag;
    Bit#(fixPointConfBits) confidence;
    Bit#(capOffsetBits) bestOffset;
} CapChaserLLPtEntry#(
    numeric type ptTagBits,
    numeric type fixPointConfBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* L1 Training table entry.
 * Indexed by boundsVirtBase and boundsLength.
 * Used to look for an access into a particular capability.
 * Also serves as the filter table for the L1.
 */
typedef struct {
    Bit#(ttTagBits) tag;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bool trained;
    Bool filter;
} CapChaserL1TtEntry#(
    numeric type ttTagBits, 
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* For training table updates */
typedef struct {
    Bit#(ttIdxTagBits) trainingTableIdxTag;
    Bit#(capOffsetBits) accessOffset;  
} CapChaserL1TtUpdate#(
    numeric type ttIdxTagBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* For prefetching and training */
typedef struct {
    CapPipe cap;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bit#(ttIdxTagBits) trainingTableIdxTag;
    Bool sizeMatch;
    Bool demanded;
} CapChaserL1ObservedCap#(
    numeric type ptIdxTagBits,
    numeric type ttIdxTagBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

typedef struct {
    Vector#(4, Maybe#(CapChaserL1ObservedCap#(ptIdxTagBits, ttIdxTagBits, capOffsetBits))) caps;
    Bool train;
    Bool missed;
    Maybe#(CapChaserAuxDataT) auxData;
} CapChaserL1ObservedCLine#(
    numeric type ptIdxTagBits,
    numeric type ttIdxTagBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* In the LL, we only need to do pointer table lookups.
 * An observed CLine is just a vector of observed caps.
 */
typedef struct {
    CapPipe cap;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bool sizeMatch;
    Bool demanded;
} CapChaserLLObservedCap#(
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

typedef struct {
    Vector#(4, Maybe#(CapChaserLLObservedCap#(ptIdxTagBits))) caps;
    Maybe#(CapChaserAuxDataT) auxData;
} CapChaserLLObservedCLine#(
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* For undecided prefetches in the L1 after looking up in the pointer table */
typedef struct {
    CapPipe cap;
    Bool missedL1;
    Bit#(confBits) nSeen;
    Bit#(confBits) nFetched;
    Maybe#(CapChaserAuxDataT) auxData;
} CapChaserL1CandidatePrefetch#(
    numeric type confBits
) deriving (Bits, Eq, FShow);

typedef struct {
    CapPipe cap;
    Bool missedL1;
    Bit#(fixPointConfBits) confidence;
    Maybe#(CapChaserAuxDataT) auxData;
} CapChaserL1ConfidencePrefetch#(
    numeric type fixPointConfBits
) deriving (Bits, Eq, FShow);

/* For preparing broadcast messages to the LL cache */
typedef struct {
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bit#(ptWayBits) ptrTableWay;
    Bit#(confBits) nFetched;
    Bit#(capOffsetBits) bestOffset;
} CapChaserL1BroadcastPrep#(
    numeric type ptIdxTagBits,
    numeric type ptWayBits,
    numeric type confBits,
    numeric type capOffsetBits
) deriving (Bits, Eq, FShow);

/* For undecided prefetches in the L2 after looking up in the pointer table.
 * Compared to the L1, the division has already happened.
 */
typedef struct {
    CapPipe cap;
    Bit#(fixPointConfBits) confidence;
    Maybe#(CapChaserAuxDataT) auxData;
} CapChaserLLCandidatePrefetch#(
    numeric type fixPointConfBits
) deriving (Bits, Eq, FShow);



/* ================================================================
 * ======== L1 CapChaser ==========================================
 * ================================================================
 */



module mkL1CapChaserPrefetcher#(
    TlbToPrefetcher toTlb, 
    Parameter#(maxCapSizeToTrack) _,
    Parameter#(ptrTableSize) __, 
    Parameter#(trainingTableSize) ___,
    Parameter#(l1OnlyMode) ____,
    Parameter#(trainingDecayCycles) _____,
    Parameter#(useFiltering) ______
)(CheriPrefetcher) provisos (
    // The number of sets in the pointer table is the size divided by ways
    NumAlias#(ptrTableWays, 2),
    NumAlias#(ptrTableSets, TDiv#(ptrTableSize, ptrTableWays)),
    // The tables are indexed by hashes, so access is already inexact.
    // Choose how much tag to store to tradeoff storage vs accuracy.
    NumAlias#(ptrTableTagBits, 4),
    NumAlias#(ptrTableIdxBits, TLog#(ptrTableSets)),
    NumAlias#(ptrTableIdxTagBits, TAdd#(ptrTableIdxBits, ptrTableTagBits)),
    NumAlias#(ptrTableWayBits, TLog#(ptrTableWays)),
    NumAlias#(trainingTableTagBits, 8),
    NumAlias#(trainingTableIdxBits, TLog#(trainingTableSize)),
    NumAlias#(trainingTableIdxTagBits, TAdd#(trainingTableIdxBits, trainingTableTagBits)),
    // The following provisos are needed for hashing to work
    Add#(a__, AddrSz, TMul#(TDiv#(AddrSz, trainingTableIdxTagBits), trainingTableIdxTagBits)),
    Add#(b__, AddrSz, TMul#(TDiv#(AddrSz, ptrTableIdxTagBits), ptrTableIdxTagBits)),
    Add#(1, c__, TDiv#(AddrSz, trainingTableIdxTagBits)),
    Add#(1, d__, TDiv#(AddrSz, ptrTableIdxTagBits)),

    // 2-4 confidence bits are sensible
    // Regardless, needs to be less bits than the LFSR for RNG
    NumAlias#(ptrTableConfBits, 4),  

    // The number of bits for the fixed point confidence divide
    // You can't just change this number. It is hard coded in the division table
    // and in PrefetchAuxData of PendingPrefetch.
    NumAlias#(fixPointConfBits, 7),
    
    // Index/tag types
    Alias#(ptrTableIdxT, Bit#(ptrTableIdxBits)),
    Alias#(ptrTableTagT, Bit#(ptrTableTagBits)),
    Alias#(ptrTableIdxTagT, Bit#(ptrTableIdxTagBits)),
    Alias#(ptrTableWayT, Bit#(ptrTableWayBits)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),
    Alias#(trainingTableTagT, Bit#(trainingTableTagBits)),
    Alias#(trainingTableIdxTagT, Bit#(trainingTableIdxTagBits)),
    
    // Bits required to represent offsets
    NumAlias#(lgMaxCapSizeToTrack, TLog#(maxCapSizeToTrack)),
    NumAlias#(capOffsetBits, TSub#(lgMaxCapSizeToTrack, 4)),

    // Fifo types
    Alias#(observedCapT, CapChaserL1ObservedCap#(ptrTableIdxTagBits, trainingTableIdxTagBits, capOffsetBits)),
    Alias#(observedCLineT, CapChaserL1ObservedCLine#(ptrTableIdxTagBits, trainingTableIdxTagBits, capOffsetBits)),
    Alias#(candidatePrefetchT, CapChaserL1CandidatePrefetch#(ptrTableConfBits)),
    Alias#(confidencePrefetchT, CapChaserL1ConfidencePrefetch#(fixPointConfBits)),
    Alias#(broadcastPrepT, CapChaserL1BroadcastPrep#(ptrTableIdxTagBits, ptrTableWayBits, ptrTableConfBits, capOffsetBits)),
    Alias#(trainingTableUpdateT, CapChaserL1TtUpdate#(trainingTableIdxTagBits, capOffsetBits)),

    // Entry types
    Alias#(ptrTableEntryT, Maybe#(CapChaserL1PtEntry#(ptrTableTagBits, ptrTableConfBits, capOffsetBits))),
    Alias#(trainingTableEntryT, Maybe#(CapChaserL1TtEntry#(trainingTableTagBits, ptrTableIdxTagBits))),

    // UpDowngrade type
    Alias#(ptUpDowngradeT, CapChaserL1PtUpDowngrade#(ptrTableIdxTagBits, capOffsetBits)),

    // Training decay counter reset value
    NumAlias#(trainingDecayReset, TSub#(trainingDecayCycles, 1)),
    Add#(1, g__, trainingDecayCycles),

    // Ugh
    Add#(h__, 6, TMax#(TAdd#(TLog#(maxCapSizeToTrack), 1), 7)),
    Add#(i__, TMax#(TAdd#(TLog#(maxCapSizeToTrack), 1), 7), 64),
    Add#(j__, TSub#(TLog#(maxCapSizeToTrack), 4), 64),

    // Something to do with NumAlias#(capOffsetBits, TSub#(lgMaxCapSizeToTrack, 4))... go figure
    Add#(3, k__, TLog#(maxCapSizeToTrack)),

    // Because of random number generation for training table decay
    Add#(l__, trainingTableIdxBits, 16),

    // Because CapChaserTrainingDataT has fixed size for ptIdxTag :(
    Log#(ptrTableSize, 8),
    Log#(maxCapSizeToTrack, 9),
    Add#(m__, 7, ptrTableIdxTagBits)
);
    Bool verbose = True;

    // Training table
    RWBramCore#(trainingTableIdxT, trainingTableEntryT) trainingTable <- mkRWBramCoreForwarded();

    // Pointer table
    function Bool isPtrTableMatch(ptrTableEntryT entry, ptrTableTagT tag);
        return (entry matches tagged Valid .e ? e.tag == tag : False); 
    endfunction
    function Bool isPtrTableReplaceCandidate(ptrTableEntryT entry);
        return !isValid(entry);
    endfunction
    RWSetAssocBramCore#(ptrTableIdxT, ptrTableWayT, ptrTableEntryT, ptrTableTagT) ptrTable 
        <- mkRWSetAssocBramCoreForwarded(isPtrTableMatch, isPtrTableReplaceCandidate);

    // Queues for training table lookups 
    // ttLookupQ can be bypass: doTtLookup just initiates a table lookup.
    Fifo#(8, trainingTableUpdateT) ttLookupQ <- mkOverflowBypassFifo; 
    Fifo#(1, trainingTableUpdateT) ttLookupRespQ <- mkPipelineFifo;

    // Queues for pointer table access updates 
    Fifo#(8, ptUpDowngradeT) ptUpDowngradeQ <- mkOverflowPipelineFifo;
    Fifo#(1, ptUpDowngradeT) ptUpDowngradeRespQ <- mkPipelineFifo;

    // Queues for observed capabilities
    // observedCLineQ can probably get away with being bypass..? It's also on the critical path for prefetching.
    Fifo#(8, observedCLineT) observedCLineQ <- mkOverflowPipelineFifo;
    Fifo#(1, UInt#(2)) observedCapRespQ <- mkPipelineFifo;
    Reg#(Vector#(4, Bool)) unprocessedObservedCap <- mkConfigReg(replicate(True));

    // Tlb lookup and prefetch queues
    // candidateQ can't really be bypass: when dequeued, it sends a TLB request, which is a quite heavy operation. 
    // prefetchQ is probably fine to be bypass, however.
    Fifo#(8, candidatePrefetchT) candidateQ <- mkOverflowPipelineFifo;
    Fifo#(1, confidencePrefetchT) multiplyQ <- mkPipelineFifo;
    Fifo#(1, confidencePrefetchT) tlbRequestQ <- mkPipelineFifo;
    Fifo#(16, PendingPrefetch) prefetchQ <- mkOverflowBypassFifo;

    // Queue for preparing and sending broadcasts
    Fifo#(1, broadcastPrepT) broadcastPrepQ <- mkPipelineFifo;
    Fifo#(8, PrefetcherBroadcastData) broadcastQ <- mkOverflowPipelineFifo;

    // Registers for pending TLB requests
    Vector#(LLCTlbReqNum, Reg#(CapChaserAuxDataT)) pendAuxData <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(Bool)) pendL1Confidence <- replicateM(mkRegU);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    
    // Init registers 
    Reg#(Bool) ptrTableInited <- mkConfigReg(False);
    Reg#(Bool) trainingTableInited <- mkConfigReg(False);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);
    Reg#(Bit#(TAdd#(ptrTableIdxBits, ptrTableWayBits))) ptrTableInitCount <- mkReg(0);
    Reg#(Bit#(trainingTableIdxBits)) trainingTableInitCount <- mkReg(0);

    // Decay counter register
    Reg#(Bit#(TLog#(trainingDecayCycles))) trainingDecayCounter <- mkReg(0);
    Fifo#(1, trainingTableIdxT) ttDecayRespQ <- mkPipelineFifo;
    LFSR#(Bit#(16)) trainingDecayLfsr <- mkLFSR_16;

    // There are generally lots of successive accesses to the same capability or cache line.
    // Remember the last accessed capability and last cache line seen loaded.
    // Don't add to queues when we see a repeat.
    Reg#(LineAddr) lastLineLoaded <- mkRegU;
    Reg#(Bool) lastLineLoadedWasDemanded <- mkReg(False);
    Reg#(trainingTableIdxTagT) lastCapAccessed <- mkRegU;

    // We will discard observed prefetches when they have a successor, because it probably means that
    // they were late and we should instead use the demand access for prefetching.
    // Remember whether we are expecting a successor
    Reg#(Bool) expectingSuccessor <- mkDReg(False);


    // Hashing functions to produce the index/tags 
    function ptrTableIdxTagT getPtrTableIdxTag(Addr boundsOffset, Addr boundsLength);
        Addr hashLength = {boundsLength[3:0], truncateLSB(boundsLength)};
        return hash((boundsOffset >> 4) ^ hashLength);
    endfunction
    function trainingTableIdxTagT getTrainingTableIdxTag(Addr boundsLength, Addr boundsVirtBase);
        let bvb = boundsVirtBase >> 4;
        // Shift an additional two bits: the virtual base may be consistently aligned
        // This assumes there could be cache line sized consistent alignment
        // If there is lower-granuality consistent alignment then the training table will be underutilised (this is really not ideal)
        // If there is high-granuality consistent alignment (16-byte) then there will be some aliasing (this is fine really)
        Addr hashBvb = {bvb[1:0], truncateLSB(bvb)};
        Addr hashLength = {boundsLength[3:0], truncateLSB(boundsLength)};
        return hash(hashBvb ^ hashLength);
    endfunction
    
    // Confidence-checking functions
    function Bool isL1LevelConfidence(Bit#(fixPointConfBits) fixpoint);
        return fixpoint[6:5] == 2'b11; // >= 75% 
    endfunction
    function Bool isL2LevelConfidence(Bit#(fixPointConfBits) fixpoint);
        return fixpoint[6:5] != 0; // >= 25%
    endfunction

    // Whether we have inited
    function Bool inited;
        return ptrTableInited && trainingTableInited && tlbReqFreeQInited;
    endfunction

    // Function to get the next observed cap in queue
    function Bool isDemanded(Maybe#(observedCapT) cap);
        return (cap matches tagged Valid .c ? c.demanded : False);
    endfunction
    function nextObservedCapIdx;
        if (observedCLineQ.notEmpty) begin
            if (findIndex(id, zipWith(\&& , map(isDemanded, observedCLineQ.first.caps), unprocessedObservedCap)) matches tagged Valid .idx) begin
                return Valid(idx);
            end else begin
                return findIndex(id, zipWith(\&& , map(isValid, observedCLineQ.first.caps), unprocessedObservedCap));
            end
        end else begin
            return Invalid;
        end
    endfunction


    /* Init the prefetcher */
    // All occur after a training table read (except for init)
    (* mutually_exclusive = "doTrainingTableInit, processObservedCapLookup, decayTrainingTableResp, processTtLookup" *)
    rule doTrainingTableInit(!trainingTableInited);
        trainingTable.wrReq(trainingTableInitCount, Invalid);
        if (trainingTableInitCount == ~0) begin
            trainingTableInited <= True;
            // Also seed the Lfsr here
            trainingDecayLfsr.seed('h11);
        end
        trainingTableInitCount <= trainingTableInitCount + 1;
    endrule
    // All occur after a pointer table read (except for init)
    (* mutually_exclusive = "doPtrTableInit, processObservedCapLookup, processPtUpDowngrade" *)
    rule doPtrTableInit(!ptrTableInited);
        ptrTable.wrReq(truncateLSB(ptrTableInitCount), truncate(ptrTableInitCount), Invalid);
        if (ptrTableInitCount == ~0) begin
            ptrTableInited <= True;
        end
        ptrTableInitCount <= ptrTableInitCount + 1;
    endrule
    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        if (tlbReqFreeQInitCount == ~0) begin
            tlbReqFreeQInited <= True;
        end
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
    endrule

    /* Get closer to decaying the training table */
    rule decayTrainingTableCounter(trainingDecayCounter != 0);
        trainingDecayCounter <= trainingDecayCounter - 1;
    endrule

    /* Do a lookup for a training table decay.
     * This implicity conflicts with doTtLookup, so make doTtLookup more urgent.
     */
    (* descending_urgency = "doTtLookup, decayTrainingTableLookup" *)
    (* descending_urgency = "doObservedCapLookup, decayTrainingTableLookup" *)
    rule decayTrainingTableLookup(inited && trainingDecayCounter == 0);
        trainingTableIdxT tIdx = truncate(trainingDecayLfsr.value >> 4);
        trainingDecayLfsr.next;
        trainingTable.rdReq(tIdx);
        ttDecayRespQ.enq(tIdx);
        trainingDecayCounter <= fromInteger(valueOf(trainingDecayReset));
    endrule

    rule decayTrainingTableResp;
        let tIdx = ttDecayRespQ.first;
        ttDecayRespQ.deq;
        // If we hit a valid entry, check whether it's been used for training and send a downgrade if not.
        // Then make sure that the entry is invalidated.
        if (trainingTable.rdResp matches tagged Valid .entry) begin
            if (!entry.trained) begin
                ptUpDowngradeQ.enq(CapChaserL1PtUpDowngrade{
                    ptrTableIdxTag: entry.ptrTableIdxTag,
                    upgrade: False,
                    accessOffset: ?
                });
            end
            trainingTable.wrReq(tIdx, Invalid);
            if (verbose) $display("%t CapChaser L1 decay hit: ttIdxTag: 0x%h, ptIdxTag: 0x%h, trained: %b, filter %b", $time, {entry.tag, tIdx}, entry.ptrTableIdxTag, entry.trained, entry.filter);
        end else begin
            if (verbose) $display("%t CapChaser L1 decay miss", $time);
        end
        trainingTable.deqRdResp;
    endrule

    /* Lookup in training table for an accessed capabilitiy.
     * Prefer to process observed cache lines first.
     */
    (* descending_urgency = "doObservedCapLookup, doTtLookup" *)
    rule doTtLookup(inited);
        let ttUpdate = ttLookupQ.first;
        ttLookupQ.deq;
        ttLookupRespQ.enq(ttUpdate);
        trainingTable.rdReq(truncate(ttUpdate.trainingTableIdxTag));
    endrule

    /* Response from training table for looking up an accessed capability */
    rule processTtLookup;
        let ttUpdate = ttLookupRespQ.first;
        ttLookupRespQ.deq;
        trainingTableTagT tTag = truncateLSB(ttUpdate.trainingTableIdxTag);
        trainingTableIdxT tIdx = truncate(ttUpdate.trainingTableIdxTag);

        // This rule should never fire when a read response is available from an observed cap lookup
        doAssert(!observedCapRespQ.notEmpty, "processTtLookup fired while observedCapRespQ is non empty");
        // Check whether we found a valid entry in the training table
        if (trainingTable.rdResp matches tagged Valid .entry &&& entry.tag == tTag) begin
            // If not trained, queue an upgrade in the pointer table.
            // Then mark the training table entry as trained and good for filtering.
            if (!entry.trained) begin
                ptUpDowngradeQ.enq(CapChaserL1PtUpDowngrade{
                    ptrTableIdxTag: entry.ptrTableIdxTag,
                    upgrade: True,
                    accessOffset: ttUpdate.accessOffset 
                });
            end
            trainingTable.wrReq(tIdx, Valid(CapChaserL1TtEntry {
                tag: entry.tag,
                ptrTableIdxTag: entry.ptrTableIdxTag,
                trained: True,
                filter: True
            }));

            // Print that we hit the training table
            if (verbose) $display("%t CapChaser L1 training hit: ttIdxTag: 0x%h, ptIdxTag: 0x%h", $time, ttUpdate.trainingTableIdxTag, entry.ptrTableIdxTag);
        end else begin
            // Print that we missed the training table
            if (verbose) $display("%t CapChaser L1 training miss: ttIdxTag: 0x%h", $time, ttUpdate.trainingTableIdxTag);
        end
        trainingTable.deqRdResp;
    endrule

    /* Process the next observed cap at the front of the queue */
    rule doObservedCapLookup(nextObservedCapIdx matches tagged Valid .idx);
        let observedCLine = observedCLineQ.first;
        let observedCap = fromMaybe(?, observedCLine.caps[idx]);
        unprocessedObservedCap[idx] <= False;
        // Firstly, read to the training table. We need to do this because:
        // - If we are training, we need to see if we are about to evict an unobserved entry (hence need to update confidence), and
        // - We use the training table as a filter table (therefore do the read regardless of observedCLine.train).
        trainingTable.rdReq(truncate(observedCap.trainingTableIdxTag));
        // Also read from the pointer table, so we can maybe perform a prefetch
        ptrTable.rdReq(truncate(observedCap.ptrTableIdxTag), truncateLSB(observedCap.ptrTableIdxTag));
        // Queue up the observed cap ready for the read responses
        observedCapRespQ.enq(idx);
    endrule

    /* Dequeue observed CLine when there are none left */
    rule deqObservedCLine(!isValid(nextObservedCapIdx));
        observedCLineQ.deq;
        unprocessedObservedCap <= replicate(True);
    endrule

    /* Process the read response from observed capabilities */
    rule processObservedCapLookup;
        let capIdx = observedCapRespQ.first;
        let observedCLine = observedCLineQ.first;
        let observedCap = fromMaybe(?, observedCLine.caps[capIdx]);
        trainingTableIdxT tIdx = truncate(observedCap.trainingTableIdxTag);
        trainingTableTagT tTag = truncateLSB(observedCap.trainingTableIdxTag);
        observedCapRespQ.deq;

        // This rule should not fire when there is another read response from either table cause by another rule
        doAssert(!ttLookupRespQ.notEmpty, "processObservedCapLookup fired while ttLookupRespQ is non empty");
        doAssert(!ptUpDowngradeRespQ.notEmpty, "processObservedCapLookup fired while ttLookupptUpDowngradeRespQRespQ is non empty");

        // We're about to evict a valid training table entry
        // If that's not a duplicate of the line we're about to add, then we need to downgrade confidence
        Bool filterPrefetch = False;
        Bool untrainedHit = False;
        if (trainingTable.rdResp matches tagged Valid .entry) begin
            if (entry.tag != tTag && !entry.trained) begin
                // Queue a condifence downgrade
                ptUpDowngradeQ.enq(CapChaserL1PtUpDowngrade{
                    ptrTableIdxTag: entry.ptrTableIdxTag,
                    upgrade: False,
                    accessOffset: ?
                });
                // Print that we're evicting an unobserved entry
                if (verbose) $display("%t CapChaser L1 unobserved tt eviction: ttIdxTag: 0x%h, ptIdxTag: 0x%h", 
                    $time, 
                    {entry.tag, tIdx}, 
                    entry.ptrTableIdxTag
                );
            end
            // Filter out the prefetch if we have an exact match in the training table, and that entry is either
            // already prefetched (i.e. we've already chased it) or has been observed (we're late).
            // Don't apply this filter to a demanded cache line. The filter bit won't be set if valueOf(useFiltering)==0.
            filterPrefetch = entry.tag == tTag && entry.filter && !observedCap.demanded;
            untrainedHit = entry.tag == tTag && !entry.trained;
        end
        trainingTable.deqRdResp;

        // If the cache line is to be prefetched on, check if we hit the pointer table.
        // Also check that we hit (i.e. tag matches), we are not filtered out by the training table, 
        // and we have some chance of prefetching.
        if (ptrTable.rdResp matches tagged Valid {.way, tagged Valid .entry} &&& !filterPrefetch && entry.nSeen != 0) begin
            // Check the pointer table and fill in the prefetch offset.
            // If we see two capabilities of the same size, then we're probably seeing a chain of the same datastructure,
            // so access the capability at the same offset as we just used.
            // If it's a different size, we'll either use the offset we found in memory, or one where
            // we know that there's a capability.
            CapPipe prefetchCap = (observedCap.sizeMatch ? observedCap.cap : setOffset(observedCap.cap, extend(entry.bestOffset << 4)).value);
            // Simply add as a candidate prefetch
            // We can't really do the division on this clock cycle
            candidateQ.enq(CapChaserL1CandidatePrefetch{
                cap: prefetchCap,
                missedL1: observedCLine.missed,
                nSeen: {1'b1, entry.nSeen},
                nFetched: (observedCap.demanded ? ~0 : entry.nFetched),
                auxData: observedCLine.auxData
            });
        end
        ptrTable.deqRdResp;

        // Write to the training table
        trainingTable.wrReq(tIdx, Valid (CapChaserL1TtEntry {
            tag: tTag,
            ptrTableIdxTag: observedCap.ptrTableIdxTag,
            trained: (untrainedHit ? False : !observedCLine.train),
            filter: valueOf(useFiltering)!=0 && (filterPrefetch || observedCap.demanded)
        }));

        // Print that we observed a capability and are trying to prefetch
        if (verbose) $display("%t CapChaser L1 observed cap vbase: 0x%h, offset: 0x%h, length: 0x%h, ptIdxTag: 0x%h, ttIdxTag: 0x%h, train: %b, missed: %b, filter: %b, sizeMatch: %b, demanded: %b",
            $time,
            getBase(observedCap.cap),
            getOffset(observedCap.cap),
            getLength(observedCap.cap),
            observedCap.ptrTableIdxTag,
            observedCap.trainingTableIdxTag,
            observedCLine.train,
            observedCLine.missed,
            filterPrefetch,
            observedCap.sizeMatch,
            observedCap.demanded
        );
    endrule

    /* Process a candidate prefetch by performing confidence division. */
    (* descending_urgency = "doConfidenceMultiply, processCandidatePrefetch" *)
    rule processCandidatePrefetch;
        let candidate = candidateQ.first;
        candidateQ.deq;

        // Perform confidence division
        CapChaserL1ConfidencePrefetch#(fixPointConfBits) confCandidate = CapChaserL1ConfidencePrefetch {
            cap: candidate.cap,
            missedL1: candidate.missedL1,
            confidence: readDivtable4x4to7({candidate.nFetched, candidate.nSeen}),
            auxData: candidate.auxData
        };

        // Either perform confidence multiplication, or send straight to the TLB
        if (isValid(candidate.auxData)) begin
            multiplyQ.enq(confCandidate);
        end else begin
            tlbRequestQ.enq(confCandidate);
        end
      
        if (verbose) $display("%t CapChaser L1 candidate prefetch: auxData: ", 
            $time, 
            fshow(candidate.auxData),
            ", cap: ",
            fshow(candidate.cap)
        );
    endrule

    /* Do a confidence multiplication */
    rule doConfidenceMultiply;
        let candidate = multiplyQ.first;
        multiplyQ.deq;
        if (candidate.auxData matches tagged Valid .auxData) begin
            candidate.confidence = (pack(unsignedMul(unpack(candidate.confidence), unpack(auxData.confidence))))[13:7];
        end else begin
            doAssert(False, "Attempted to do confidence multiply without prefetch aux data");
        end
        tlbRequestQ.enq(candidate);
    endrule

    /* The confidence is ready, so either discard the candidate prefetch or send a TLB request */
    rule doTlbRequest;
        let candidate = tlbRequestQ.first;
        tlbRequestQ.deq;

        // Get the confidence level
        let l1Confidence = isL1LevelConfidence(candidate.confidence);
        let l2Confidence = isL2LevelConfidence(candidate.confidence);

        if (// We need to have at least L2 confidence level
            l2Confidence &&
            // If we are in split mode, and we missed the L1, then only issue if we have L1-level confidence
            (valueOf(l1OnlyMode)!=0 || !candidate.missedL1 || l1Confidence)
        ) begin
            // Set up a TLB request.
            let tlbReqIdx = tlbReqFreeQ.first;
            tlbReqFreeQ.deq;

            // Send the TLB request
            toTlb.prefetcherReq(PrefetcherReqToTlb {
                cap: candidate.cap,
                id: tlbReqIdx
            });

            // Save the aux data
            pendL1Confidence[tlbReqIdx] <= l1Confidence;
            pendAuxData[tlbReqIdx] <= CapChaserAuxDataT {
                confidence: candidate.confidence
            `ifdef CAP_CHASER_COUNT_DEPTH
                , depth: (candidate.auxData matches tagged Valid .auxData ? auxData.depth + 1 : 0)
            `endif
            };

            if (verbose) $display("%t CapChaser L1 TLB request: confidence: %b, l1Conf: %b, l2Conf: %b", 
                $time, 
                candidate.confidence,
                isL1LevelConfidence(candidate.confidence),
                isL2LevelConfidence(candidate.confidence),
            `ifdef CAP_CHASER_COUNT_DEPTH
                ", depth: ", (pcandidate.auxData matches tagged Valid .auxData ? auxData.depth + 1 : 0),
            `endif
                ", cap: ", fshow(candidate.cap)
            );
        end
        
    endrule

    /* Handle a TLB reponse */
    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        let tlbReqIdx = resp.id;
        toTlb.deqPrefetcherResp;

        if (// Check TLB permissions 
            !resp.haveException && 
            resp.permsCheckPass && 
            resp.paddr != 0
        ) begin
            prefetchQ.enq(PendingPrefetch {
                addr: resp.paddr,
                cap: resp.cap,
                nextLevel: !pendL1Confidence[tlbReqIdx],
                auxData: CapChaserAuxData(pendAuxData[tlbReqIdx])
            });
        end
        
        tlbReqFreeQ.enq(tlbReqIdx);

        if (verbose) $display("%t CapChaser L1 TLB response: exception: %b, perms: %b, confidence: %b",
            $time, 
            resp.haveException,
            resp.permsCheckPass,
            pendAuxData[tlbReqIdx].confidence
        `ifdef CAP_CHASER_COUNT_DEPTH
          , ", depth: ", pendAuxData[tlbReqIdx].depth
        `endif
        );
    endrule

    /* Do a lookup for PT upgrade/downgrade requests */
    rule doPtLookupForUpDowngrade(inited && !isValid(nextObservedCapIdx));
        let upDowngrade = ptUpDowngradeQ.first;
        ptUpDowngradeQ.deq;
        ptrTable.rdReq(truncate(upDowngrade.ptrTableIdxTag), truncateLSB(upDowngrade.ptrTableIdxTag));
        ptUpDowngradeRespQ.enq(upDowngrade);
    endrule

    /* Perform PT confidence upgrade/downgrades */
    rule processPtUpDowngrade;
        let upDowngrade = ptUpDowngradeRespQ.first;
        ptUpDowngradeRespQ.deq;

        // This rule should never fire when a read response is available from an observed cap lookup
        doAssert(!observedCapRespQ.notEmpty, "processPtUpDowngrade fired while observedCapRespQ is non empty");

        // If the PT lookup hit, update the counters and potentially the confidence
        if (ptrTable.rdResp matches tagged Valid {.way, tagged Valid .entry}) begin
            let nSeen = entry.nSeen + 1;
            // Shift nFetched if we just looped the counter back to 0
            let nFetched = (entry.nSeen == ~0 ? (entry.nFetched >> 1) : entry.nFetched) + (upDowngrade.upgrade ? 1 : 0); 
            // Get the best offset for when we aren't chaining identical capability sizes
            let bestOffset = (upDowngrade.upgrade ? upDowngrade.accessOffset : entry.bestOffset);
            // Inform the LL cache if we have just saturated the counter
            if (nSeen == ~0 && valueOf(l1OnlyMode)==0) begin
                broadcastPrepQ.enq(CapChaserL1BroadcastPrep {
                    ptrTableIdxTag: upDowngrade.ptrTableIdxTag,
                    ptrTableWay: way,
                    nFetched: nFetched,
                    bestOffset: bestOffset
                });
            end
            // Delete the entry if we no longer have any confidence.
            if (nFetched == 0) begin
                ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), way, Invalid);
                if (verbose) $display("%t CapChaser L1 removing pt entry: ptIdxTag: 0x%h", 
                    $time, 
                    upDowngrade.ptrTableIdxTag
                );
            end else begin 
                ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), way, Valid(CapChaserL1PtEntry {
                    tag: truncateLSB(upDowngrade.ptrTableIdxTag),
                    nSeen: nSeen,
                    nFetched: nFetched,
                    bestOffset: bestOffset
                }));
                if (verbose) $display("%t CapChaser L1 updating confidence: ptIdxTag: 0x%h, ptWay: %d, upgrade: %b, nseen: %d, nfetched: %d, bestOffset: %d", 
                    $time, 
                    upDowngrade.ptrTableIdxTag,
                    way,
                    upDowngrade.upgrade,
                    {1'b1, nSeen},
                    nFetched,
                    bestOffset
                );
            end
        end else if (upDowngrade.upgrade) begin 
            ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), ptrTable.rdRepl, Valid(CapChaserL1PtEntry {
                tag: truncateLSB(upDowngrade.ptrTableIdxTag),
                nSeen: 1,
                nFetched: 1,
                bestOffset: upDowngrade.accessOffset
            }));
            // Print that we're inserting a new pointer table entry
            if (verbose) $display("%t CapChaser L1 inserting new pt entry: ptIdxTag: 0x%h, ptWay: %d", 
                $time, 
                upDowngrade.ptrTableIdxTag,
                ptrTable.rdRepl
            );
        end
        ptrTable.deqRdResp;
    endrule

    /* Do the division for a broadcast message to the LL cache.
     * broadcastPrepQ will never be queued to if we are solely operating in the L1.
     */
    rule prepareBroadcast;
        let broadcastPrep = broadcastPrepQ.first;
        broadcastPrepQ.deq;
        let confidence = readDivtable4x4to7({broadcastPrep.nFetched, 4'b1111});
        broadcastQ.enq(CapChaserTrainingData (CapChaserTrainingDataT {
            ptrTableIdx: truncate(broadcastPrep.ptrTableIdxTag),
            ptrTableTag: truncateLSB(broadcastPrep.ptrTableIdxTag),
            ptrTableWay: broadcastPrep.ptrTableWay,
            confidence: confidence,
            bestOffset: broadcastPrep.bestOffset
        }));
        if (verbose) $display("%t CapChaser L1 prepared broadcast: ptIdxTag: 0x%h, ptWay: %d, confidence: %b, bestOffset: %d",
            $time,
            broadcastPrep.ptrTableIdxTag,
            broadcastPrep.ptrTableWay,
            confidence,
            broadcastPrep.bestOffset
        );
    endrule

    /* Upon access, check whether we just accessed an entry in the training table.
     * We want to only include demand access here, as we're checking if our prefetcher will be accurate.
     * We don't care if it's a store or a load: the line needs to be in the cache either way.
     */
    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (inited &&
            memOp == Ld &&
            !isPrefetch && 
            boundsLength >= 16 && 
            boundsLength <= fromInteger(valueOf(maxCapSizeToTrack))
        ) begin
            let tit = getTrainingTableIdxTag(boundsLength, boundsVirtBase);
            // Filter out accesses to the same capability
            if (tit != lastCapAccessed) begin
                lastCapAccessed <= tit;
                ttLookupQ.enq(CapChaserL1TtUpdate {
                    trainingTableIdxTag: tit,
                    accessOffset: truncate(boundsOffset >> 4)
                });
                if (verbose) $display("%t CapChaser L1 reportAccess vbase: 0x%h, offset: 0x%h, length: 0x%h, ttIdxTag: 0x%h",
                    $time,
                    boundsVirtBase,
                    boundsOffset,
                    boundsLength,
                    tit
                );
            end
        end
    endmethod

    /* Upon data arrival, perform two actions for each pointer in the cache line:
     * - Add the capability to the training table.'
     *   Although the demand access is probably for a specific capability in the line, 
     *   we want to use the confidence in the context of prefetch chaining, where we are
     *   no longer loading specific addresses, rather cache lines as a whole. Therefore, learn
     *   confidence about the whole line, ignoring the specific address used.
     * - Lookup each capability in the pointer table.
     */
    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        // Always specify that we're expecting a successor
        expectingSuccessor <= hasSuccessor;
        // Now actually process the data arrival
        if (inited &&
            (valueOf(l1OnlyMode) != 0 || !wasNextLevel) && 
            memOp == Ld && 
            boundsLength >= 16 && 
            boundsLength <= fromInteger(valueOf(maxCapSizeToTrack)) &&
            (getLineAddr(addr) != lastLineLoaded || (!wasPrefetch && !lastLineLoadedWasDemanded)) &&
            // If this is a prefetch with a successor, it's _probably_ a late prefetch.
            // Drop the prefetch and wait for the demand hit on the next cycle.
            (!wasPrefetch || !hasSuccessor)
        ) begin
            // Remember that we loaded this line
            lastLineLoaded <= getLineAddr(addr);
            lastLineLoadedWasDemanded <= !wasPrefetch;
            // Get relevant aux data
            let auxData = case (prefetchAuxData) matches 
                tagged CapChaserAuxData .d: Valid(d);
                tagged CapChaserAllInAuxData .d: Valid(d);
                default: Invalid;
            endcase;
            // Fill observedCLine with the capabilities in this cache line
            observedCLineT observedCLine;
            // Only train on non-CapChaser loads into the cache (includes demand loads and loads from other prefetchers).
            // We compound the confidence of chained loads, so we don't want to incorporate it into our baseline confidence.
            observedCLine.train = !isValid(auxData);
            // Remember if we missed: don't prefetch to L2 if in split mode.
            // We can consider ourselves as having missed if this is a successor request.
            observedCLine.missed = wasMiss || expectingSuccessor;
            observedCLine.auxData = auxData;
            for (Integer i = 0; i < 4; i = i + 1) begin
                // Get the i'th capability (might not exist) from the cache line
                MemTaggedData d = getTaggedDataAt(lineWithTags, fromInteger(i));
                CapPipe cap = fromMem(unpack(pack(d)));
                // Calculate the offset of this cap (may underflow, but we will detect that)
                // Why TMax#(TAdd#(capOffsetBits, 1), 7)?
                // We need an extra bit on top of capOffsetBits to detect overflow,
                // but we need at 7 bits so we have a whole cache line's leeway.
                Bit#(TMax#(TAdd#(lgMaxCapSizeToTrack, 1), 7)) atOffset = truncate(boundsOffset) - extend(addr[5:0]) + (fromInteger(i) << 4);
                // Get the index/tag pairs
                ptrTableIdxTagT pit = getPtrTableIdxTag(extend(atOffset), boundsLength);
                trainingTableIdxTagT tit = getTrainingTableIdxTag(saturating_truncate(getLength(cap)), getBase(cap));
                // Get the capability we should prefetch
                // If we see two capabilities of the same size, then we're probably seeing a chain of the same datastructure,
                // so access the capability at the same offset as we just used.
                // If it's a different size, we'll either use the offset we found in memory, or one where
                // we know that there's a capability.
                Bool sizeMatch = extend(boundsLength) == getLength(cap);
                CapPipe prefetchCap = (sizeMatch ? setOffset(cap, extend(atOffset)).value : cap);
                // Get whether this exact capability has been demanded.
                // It will then be prioritised by the prefetcher (and be given high confidence).
                Bool demanded = !wasPrefetch && (addr[5:3] == fromInteger(i*2));
                // We are interested in this capability if
                // - It is tagged (obviously), and
                // - It's size is within maxCapSizeToTrack, and
                // - It doesn't point to itself, and
                // - It is within the bounds of the capability used to access it.
                if (d.tag && 
                    getLength(cap) <= fromInteger(valueOf(maxCapSizeToTrack)) && 
                    extend(boundsVirtBase) != getBase(cap) && 
                    atOffset < truncate(boundsLength) 
                ) begin
                    observedCLine.caps[i] = Valid (CapChaserL1ObservedCap {
                        cap: prefetchCap,
                        ptrTableIdxTag: pit,
                        trainingTableIdxTag: tit,
                        sizeMatch: sizeMatch,
                        demanded: demanded
                    });
                end else begin
                    observedCLine.caps[i] = Invalid;
                end
            end
            // Print that we saw a capability
            if (verbose) $display("%t CapChaser L1 reportCacheDataArrival wasMiss: %b, wasPrefetch: %b, vbase: 0x%h, offset: 0x%h, length: 0x%h, train: %b, observedCLine: ",
                $time,
                wasMiss,
                wasPrefetch,
                boundsVirtBase,
                boundsOffset,
                boundsLength,
                observedCLine.train,
                fshow(observedCLine)
            );
            // Send off the observed caps for training and prefetching, if there are any
            if (any(isValid, observedCLine.caps)) begin
                observedCLineQ.enq(observedCLine);
            end
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = prefetchQ.first;
        prefetchQ.deq;
        return x;
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData;
        broadcastQ.deq;
        return broadcastQ.first;
    endmethod

    /* We don't expect to receive any broadcasts */
    method Action sendBroadcastData(PrefetcherBroadcastData data);
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events() = unpack(0);
`endif
endmodule



/* ================================================================
 * ======== LL CapChaser ==========================================
 * ================================================================
 */



module mkLLCapChaserPrefetcher#(
    TlbToPrefetcher toTlb, 
    Parameter#(maxCapSizeToTrack) _,
    Parameter#(ptrTableSize) __
)(CheriPrefetcher) provisos (
    // We only have a pointer table in the L2 cache
    NumAlias#(ptrTableWays, 2),
    NumAlias#(ptrTableSets, TDiv#(ptrTableSize, ptrTableWays)),
    NumAlias#(ptrTableTagBits, 4),
    NumAlias#(ptrTableIdxBits, TLog#(ptrTableSets)),
    NumAlias#(ptrTableIdxTagBits, TAdd#(ptrTableIdxBits, ptrTableTagBits)),
    NumAlias#(ptrTableWayBits, TLog#(ptrTableWays)),
    Add#(a__, AddrSz, TMul#(TDiv#(AddrSz, ptrTableIdxTagBits), ptrTableIdxTagBits)),
    Add#(1, b__, TDiv#(AddrSz, ptrTableIdxTagBits)),

    // Need to have the same fixed point float confidence bits as the L1
    NumAlias#(fixPointConfBits, 7),
    
    // Index/tag types
    Alias#(ptrTableIdxT, Bit#(ptrTableIdxBits)),
    Alias#(ptrTableTagT, Bit#(ptrTableTagBits)),
    Alias#(ptrTableIdxTagT, Bit#(ptrTableIdxTagBits)),
    Alias#(ptrTableWayT, Bit#(ptrTableWayBits)),

    // Bits required to represent offsets
    NumAlias#(lgMaxCapSizeToTrack, TLog#(maxCapSizeToTrack)),
    NumAlias#(capOffsetBits, TSub#(lgMaxCapSizeToTrack, 4)),

    // Fifo types
    NumAlias#(lgMaxCapSizeToTrack, TLog#(maxCapSizeToTrack)),
    Alias#(observedCapT, CapChaserLLObservedCap#(ptrTableIdxTagBits)),
    Alias#(observedCLineT, CapChaserLLObservedCLine#(ptrTableIdxTagBits)),
    Alias#(candidatePrefetchT, CapChaserLLCandidatePrefetch#(fixPointConfBits)),

    // Entry types
    // We only have a pointer table in the LL cache.
    Alias#(ptrTableEntryT, Maybe#(CapChaserLLPtEntry#(ptrTableTagBits, fixPointConfBits, capOffsetBits))),

    // Set-associative pointer table
    //NumAlias#(ptrTableWays, 4),
    //Add#(e__, TLog#(ptrTableWays), TLog#(ptrTableSize)),    

    // As in the L1
    Add#(h__, 6, TMax#(TAdd#(TLog#(maxCapSizeToTrack), 1), 7)),
    Add#(i__, TMax#(TAdd#(TLog#(maxCapSizeToTrack), 1), 7), 64),
    //Add#(ptrTableIdxBits, j__, 8),
    Add#(k__, TSub#(TLog#(maxCapSizeToTrack), 4), 64),

    // Beause of PrefetcherBroadcastData having fixed sizes
    Log#(maxCapSizeToTrack, 9),
    Log#(ptrTableSets, 7)
);
    Bool verbose = True;

    // Pointer table
    function Bool isPtrTableMatch(ptrTableEntryT entry, ptrTableTagT tag);
        return (entry matches tagged Valid .e ? e.tag == tag : False); 
    endfunction
    function Bool isPtrTableReplaceCandidate(ptrTableEntryT entry);
        return !isValid(entry);
    endfunction
    RWSetAssocBramCore#(ptrTableIdxT, ptrTableWayT, ptrTableEntryT, ptrTableTagT) ptrTable 
        <- mkRWSetAssocBramCoreForwarded(isPtrTableMatch, isPtrTableReplaceCandidate);

    // Queues for observed capabilities
    Fifo#(8, observedCLineT) observedCLineQ <- mkOverflowPipelineFifo;
    Fifo#(1, UInt#(2)) observedCapRespQ <- mkPipelineFifo;
    Reg#(Vector#(4, Bool)) unprocessedObservedCap <- mkConfigReg(replicate(True));

    // Tlb lookup and prefetch queues
    Fifo#(8, candidatePrefetchT) candidateQ <- mkOverflowPipelineFifo;
    Fifo#(1, candidatePrefetchT) tlbRequestQ <- mkPipelineFifo;
    Fifo#(16, PendingPrefetch) prefetchQ <- mkOverflowBypassFifo;

    // Registers for pending TLB requests
    // The confidence is ready a cycle after sending the TLB request, so we don't
    // need to flag whether it's ready or not.
    Vector#(LLCTlbReqNum, Reg#(CapChaserAuxDataT)) pendAuxData <- replicateM(mkRegU);
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) tlbReqFreeQ <- mkBypassFifo;
    
    // Init registers 
    Reg#(Bool) ptrTableInited <- mkConfigReg(False);
    Reg#(Bool) tlbReqFreeQInited <- mkConfigReg(False);
    Reg#(LLCTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);
    Reg#(Bit#(TAdd#(ptrTableIdxBits, ptrTableWayBits))) ptrTableInitCount <- mkReg(0);

    // We don't need to remember the last accessed capability in the L2: we're not doing any training.
    Reg#(LineAddr) lastLineLoaded <- mkRegU;
    Reg#(Bool) lastLineLoadedWasDemanded <- mkReg(False);

    // Hashing function to produce the index/tag the pointer table
    // Needs to be the same as the L1, obviously
    function ptrTableIdxTagT getPtrTableIdxTag(Addr boundsOffset, Addr boundsLength);
        return hash((boundsOffset >> 4) ^ (boundsLength >> 4) ^ boundsLength);
    endfunction

    // We only need to check L2 confidence here
    function Bool isL2LevelConfidence(Bit#(fixPointConfBits) fixpoint);
        return fixpoint[6:5] != 0; // 25%
    endfunction

    // Whether we have inited
    function Bool inited;
        return ptrTableInited && tlbReqFreeQInited;
    endfunction

    // Function to get the next observed cap in queue
    function Bool isDemanded(Maybe#(observedCapT) cap);
        return (cap matches tagged Valid .c ? c.demanded : False);
    endfunction
    function nextObservedCapIdx;
        if (observedCLineQ.notEmpty) begin
            if (findIndex(id, zipWith(\&& , map(isDemanded, observedCLineQ.first.caps), unprocessedObservedCap)) matches tagged Valid .idx) begin
                return Valid(idx);
            end else begin
                return findIndex(id, zipWith(\&& , map(isValid, observedCLineQ.first.caps), unprocessedObservedCap));
            end
        end else begin
            return Invalid;
        end
    endfunction

    /* Init the prefetcher */
    (* mutually_exclusive = "doPtrTableInit, processObservedCapLookup" *)
    rule doPtrTableInit(!ptrTableInited);
        ptrTable.wrReq(truncateLSB(ptrTableInitCount), truncate(ptrTableInitCount), Invalid);
        if (ptrTableInitCount == ~0) begin
            ptrTableInited <= True;
        end
        ptrTableInitCount <= ptrTableInitCount + 1;
    endrule
    (* mutually_exclusive = "doTlbReqFreeQInit, processTlbResp" *)
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        if (tlbReqFreeQInitCount == ~0) begin
            tlbReqFreeQInited <= True;
        end
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
    endrule

    /* Process the next observed cap at the front of the queue */
    rule doObservedCapLookup(nextObservedCapIdx matches tagged Valid .idx);
        let observedCLine = observedCLineQ.first;
        let observedCap = fromMaybe(?, observedCLine.caps[idx]);
        unprocessedObservedCap[idx] <= False;
        // Unconditionally read from the pointer table: we already filtered out requests we don't want
        // to prefetch from.
        ptrTable.rdReq(truncate(observedCap.ptrTableIdxTag), truncateLSB(observedCap.ptrTableIdxTag));
        observedCapRespQ.enq(idx);
    endrule

    /* Dequeue observed CLine when there are none left */
    rule deqObservedCLine(!isValid(nextObservedCapIdx));
        observedCLineQ.deq;
        unprocessedObservedCap <= replicate(True);
    endrule

    /* Process the read response from observed capabilities */
    rule processObservedCapLookup;
        let capIdx = observedCapRespQ.first;
        let observedCLine = observedCLineQ.first;
        let observedCap = fromMaybe(?, observedCLine.caps[capIdx]);
        observedCapRespQ.deq;

        if (ptrTable.rdResp matches tagged Valid {.way, tagged Valid .entry} &&& entry.confidence != 0) begin
            CapPipe prefetchCap = (observedCap.sizeMatch ? observedCap.cap : setOffset(observedCap.cap, extend(entry.bestOffset << 4)).value);
            candidateQ.enq(CapChaserLLCandidatePrefetch{
                cap: prefetchCap,
                confidence: (observedCap.demanded ? ~0 : entry.confidence),
                auxData: observedCLine.auxData
            });
        end
        ptrTable.deqRdResp;

        // Print that we observed a capability and are trying to prefetch
        if (verbose) $display("%t CapChaser LL observed cap vbase: 0x%h, offset: 0x%h, length: 0x%h, ptIdxTag: 0x%h, sizeMatch: %b, demanded: %b",
            $time,
            getBase(observedCap.cap),
            getOffset(observedCap.cap),
            getLength(observedCap.cap),
            observedCap.ptrTableIdxTag,
            observedCap.sizeMatch,
            observedCap.demanded
        );
    endrule

    /* Process a candidate prefetch by performing confidence multiplication. */
    rule processCandidatePrefetch;
        let candidate = candidateQ.first;
        candidateQ.deq;

        // Perform confidence multiplication
        tlbRequestQ.enq(CapChaserLLCandidatePrefetch {
            cap: candidate.cap,
            confidence: (candidate.auxData matches tagged Valid .auxData 
                ? (pack(unsignedMul(unpack(candidate.confidence) , unpack(auxData.confidence))))[13:7]
                : candidate.confidence
            ),
            auxData: candidate.auxData
        });
      
        if (verbose) $display("%t CapChaser LL candidate prefetch: auxData: ", 
            $time, 
            fshow(candidate.auxData),
            ", cap: ",
            fshow(candidate.cap)
        );
    endrule

    /* The confidence is ready, so either discard the candidate prefetch or send a TLB request */
    rule doTlbRequest;
        let candidate = tlbRequestQ.first;
        tlbRequestQ.deq;

        // Check confidence
        if (isL2LevelConfidence(candidate.confidence)) begin
            // Set up a TLB request.
            let tlbReqIdx = tlbReqFreeQ.first;
            tlbReqFreeQ.deq;

            // Send the TLB request
            toTlb.prefetcherReq(PrefetcherReqToTlb {
                cap: candidate.cap,
                id: tlbReqIdx
            });

            // Save the aux data
            pendAuxData[tlbReqIdx] <= CapChaserAuxDataT {
                confidence: candidate.confidence
            `ifdef CAP_CHASER_COUNT_DEPTH
                , depth: (candidate.auxData matches tagged Valid .auxData ? auxData.depth + 1 : 0)
            `endif
            };

            if (verbose) $display("%t CapChaser LL TLB request: confidence: %b",
                $time, 
                candidate.confidence,
            `ifdef CAP_CHASER_COUNT_DEPTH
                ", depth: ", (pcandidate.auxData matches tagged Valid .auxData ? auxData.depth + 1 : 0),
            `endif
                ", cap: ", fshow(candidate.cap)
            );
        end        
    endrule

    /* Handle a TLB reponse */
    rule processTlbResp;
        let resp = toTlb.prefetcherResp;
        let tlbReqIdx = resp.id;
        toTlb.deqPrefetcherResp;
        
        if (!resp.haveException && resp.permsCheckPass && resp.paddr != 0) begin
            prefetchQ.enq(PendingPrefetch {
                addr: resp.paddr,
                cap: resp.cap,
                nextLevel: False,
                auxData: CapChaserAuxData(pendAuxData[tlbReqIdx])
            });
        end
        tlbReqFreeQ.enq(tlbReqIdx);

        if (verbose) $display("%t CapChaser LL TLB response: exception: %b, perms: %b, confidence: %b",
            $time, 
            resp.haveException,
            resp.permsCheckPass,
            pendAuxData[tlbReqIdx].confidence,
        `ifdef CAP_CHASER_COUNT_DEPTH
          , ", depth: ", pendAuxData[tlbReqIdx].depth
        `endif
            ", cap: ", fshow(resp.cap)
        );
    endrule

    /* Do nothing upon access: the L1 prefetcher does the training */
    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    endmethod

    /* Upon data arrival, we do prefetching the same as in the L1 prefetcher. 
     * We don't, however, need to do any training.
     */
    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (inited && 
            memOp == Ld && 
            boundsLength >= 16 && 
            boundsLength <= fromInteger(valueOf(maxCapSizeToTrack)) && 
            (getLineAddr(addr) != lastLineLoaded || (!wasPrefetch && !lastLineLoadedWasDemanded)) &&
            // If this is a prefetch with a successor, it's _probably_ a late prefetch.
            // Drop the prefetch and wait for the demand hit on the next cycle.
            (!wasPrefetch || !hasSuccessor)
        ) begin
            lastLineLoaded <= getLineAddr(addr);
            lastLineLoadedWasDemanded <= !wasPrefetch;
            let auxData = case (prefetchAuxData) matches 
                tagged CapChaserAuxData .d: Valid(d);
                tagged CapChaserAllInAuxData .d: Valid(d);
                default: Invalid;
            endcase;
            observedCLineT observedCLine;
            observedCLine.auxData = auxData;
            for (Integer i = 0; i < 4; i = i + 1) begin
                MemTaggedData d = getTaggedDataAt(lineWithTags, fromInteger(i));
                CapPipe cap = fromMem(unpack(pack(d)));
                Bit#(TMax#(TAdd#(lgMaxCapSizeToTrack, 1), 7)) atOffset = truncate(boundsOffset) - extend(addr[5:0]) + (fromInteger(i) << 4);
                ptrTableIdxTagT pit = getPtrTableIdxTag(extend(atOffset), boundsLength);
                Bool sizeMatch = extend(boundsLength) == getLength(cap);
                CapPipe prefetchCap = (sizeMatch ? setOffset(cap, extend(atOffset)).value : cap);
                Bool demanded = !wasPrefetch && (addr[5:3] == fromInteger(i*2));
                if (d.tag && 
                    getLength(cap) <= fromInteger(valueOf(maxCapSizeToTrack)) && 
                    extend(boundsVirtBase) != getBase(cap) && 
                    atOffset < truncate(boundsLength) 
                ) begin
                    observedCLine.caps[i] = Valid (CapChaserLLObservedCap {
                        cap: prefetchCap,
                        ptrTableIdxTag: pit,
                        sizeMatch: sizeMatch,
                        demanded: demanded
                    });
                end else begin
                    observedCLine.caps[i] = Invalid;
                end
            end
            // Print that we saw a capability
            if (verbose) $display("%t CapChaser LL reportCacheDataArrival wasPrefetch: %b, vbase: 0x%h, offset: 0x%h, length: 0x%h, observedCLine: ",
                $time,
                wasPrefetch,
                boundsVirtBase,
                boundsOffset,
                boundsLength,
                fshow(observedCLine)
            );
            // Send off the observed caps for training and prefetching, if there are any
            if (any(isValid, observedCLine.caps)) begin
                observedCLineQ.enq(observedCLine);
            end
        end
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x = prefetchQ.first;
        prefetchQ.deq;
        return x;
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData if (False);
        return ?;
    endmethod

    /* If we receive a CapChaser broadcastg message, add to the pointer table */
    method Action sendBroadcastData(PrefetcherBroadcastData data);
        // Ignore if we're not inited
        if (data matches tagged CapChaserTrainingData .ptrTableEntry &&& inited) begin
            if (ptrTableEntry.confidence != 0) begin
                ptrTable.wrReq(ptrTableEntry.ptrTableIdx, ptrTableEntry.ptrTableWay, Valid (CapChaserLLPtEntry {
                    tag: ptrTableEntry.ptrTableTag,
                    confidence: ptrTableEntry.confidence,
                    bestOffset: ptrTableEntry.bestOffset
                }));
                if (verbose) $display("%t CapChaser LL updating pt entry: ptIdxTag: 0x%h, ptWay: %d, confidence: %b, bestOffset: %d",
                    $time,
                    {ptrTableEntry.ptrTableTag, ptrTableEntry.ptrTableIdx},
                    ptrTableEntry.ptrTableWay,
                    ptrTableEntry.confidence,
                    ptrTableEntry.bestOffset
                );
            end else begin
                ptrTable.wrReq(ptrTableEntry.ptrTableIdx, ptrTableEntry.ptrTableWay, Invalid);
                if (verbose) $display("%t CapChaser LL erasing pt entry: ptIdxTag: 0x%h, ptWay", 
                    $time, 
                    {ptrTableEntry.ptrTableTag, ptrTableEntry.ptrTableIdx},
                    ptrTableEntry.ptrTableWay
                );
            end
        end
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events() = unpack(0);
`endif

endmodule



/* ================================================================
 * ======== AllInCap2 =============================================
 * ================================================================
 */



module mkCapChaserAllInPrefetcher#(
        Parameter#(maxCapSizeToPrefetch) _,
        Parameter#(onDemandHit) __,
        Parameter#(onDemandMiss) ___,
        Parameter#(onPrefetchHit) ____,
        Parameter#(onPrefetchMiss) _____
)(CheriPrefetcher) provisos (
    /* Assume 4KB pages */
    NumAlias#(pageIndexBits, 12),
    Alias#(pageAddressT, Bit#(TSub#(AddrSz, pageIndexBits))),
    Alias#(pageIndexT, Bit#(pageIndexBits)),

    // For confidence calculation
    NumAlias#(prefetchHitCheckBits, TSub#(TMax#(1, onPrefetchHit), 1)),
    NumAlias#(prefetchMissCheckBits, TSub#(TMax#(1, onPrefetchMiss), 1)),

    // Provisos for the above
    Add#(prefetchHitCheckBits, a__, 7),
    Add#(prefetchMissCheckBits, b__, 7)
);
    Bool verbose = True;

    Reg#(LineAddr) origLineAddr <- mkConfigRegU;
    Reg#(LineAddr) stopLineAddr <- mkConfigReg(0);
    // Use EHRs so that a new prefetch overrules an ongoing prefetch
    Ehr#(2, Addr) nextPrefetchAddr <- mkEhr(0);
    Reg#(Addr) nextPrefetchAddr_ongoing = nextPrefetchAddr[0];
    Reg#(Addr) nextPrefetchAddr_new = nextPrefetchAddr[1];
    Ehr#(2, CapPipe) prefetchCap <- mkEhr(?);
    Reg#(CapPipe) prefetchCap_ongoing = prefetchCap[0];
    Reg#(CapPipe) prefetchCap_new = prefetchCap[1];
    Reg#(PrefetchAuxData) auxData <- mkConfigRegU;
    
    Reg#(Addr) prevBaseAddr1 <- mkRegU;
    Reg#(Addr) prevBaseAddr2 <- mkRegU;

    Fifo#(8, PendingPrefetch) prefetchQ <- mkOverflowBypassFifo;

    function Bool activateOnPrefetchHit(PrefetchAuxData auxData);
        if (valueOf(onPrefetchHit)==0) begin
            return False;
        end else if (auxData matches tagged CapChaserAuxData .d) begin
            Bit#(prefetchHitCheckBits) check = truncateLSB(d.confidence);
            return (valueOf(onPrefetchHit)==1) || (check == ~0);
        end else begin
            return False;
        end
    endfunction
    function Bool activateOnPrefetchMiss(PrefetchAuxData auxData);
        if (valueOf(onPrefetchMiss)==0) begin
            return False;
        end else if (auxData matches tagged CapChaserAuxData .d) begin
            Bit#(prefetchMissCheckBits) check = truncateLSB(d.confidence);
            return (valueOf(onPrefetchMiss)==1) || (check == ~0);
        end else begin
            return False;
        end
    endfunction

    rule produceNextPrefetch(getLineAddr(nextPrefetchAddr_ongoing) <= stopLineAddr);
        if (verbose) $display("%t AllInCap produceNextPrefetch: addr: 0x%h, cap: ",
            $time, 
            nextPrefetchAddr_ongoing,
            fshow(prefetchCap_ongoing)
        );
        // The amount to skip by for the next prefetch
        Addr skipAmount = 64;
        if (getLineAddr(nextPrefetchAddr_ongoing) + 1 == origLineAddr) begin
            skipAmount = 128;
        end
        // Increase by the skip amount
        nextPrefetchAddr_ongoing <= nextPrefetchAddr_ongoing + skipAmount;
        prefetchCap_ongoing <= incOffset(prefetchCap_ongoing, skipAmount).value;
        // Issue a prefetch
        prefetchQ.enq(PendingPrefetch {
            addr: nextPrefetchAddr_ongoing,
            cap: prefetchCap_ongoing,
            nextLevel: False,
            auxData: auxData
        });
    endrule

    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (
            // Prefetch on hit/miss to a demand/prefetch access depending on configuration
            (isPrefetch
                ? (hitMiss == HIT ? activateOnPrefetchHit(prefetchAuxData) : activateOnPrefetchMiss(prefetchAuxData))
                : (hitMiss == HIT ? valueOf(onDemandHit)!=0 : valueOf(onDemandMiss)!=0)
            ) &&
            // Only prefetch on loads with appropriate bounds
            memOp == Ld && boundsLength != 0 && boundsLength <= fromInteger(valueof(maxCapSizeToPrefetch)) &&
            // Not an access for the current, most recent, or previous prefetch
            boundsVirtBase != prevBaseAddr1 && boundsVirtBase != prevBaseAddr2 &&
            // Did not originate from this prefetcher
            !(prefetchAuxData matches tagged CapChaserAllInAuxData .* ? True : prefetchAuxData == CapChaserAllInEmpty)
        ) begin
            if (verbose) $display("%t AllInCap reportAccess: addr: 0x%h, hit: %b, isPrefetch: %b, boundsBase: 0x%h, boundsOffset: 0x%h, boundsLength: 0x%h",
                $time, 
                addr,
                hitMiss == HIT,
                isPrefetch,
                boundsVirtBase,
                boundsOffset,
                boundsLength
            );

            // Get the physical bounds base and top
            Addr boundsBase = addr-boundsOffset;
            Addr boundsTop = boundsBase+boundsLength-1;
            // Get base, access, and top page addresses
            pageAddressT basePage = truncateLSB(boundsBase);
            pageAddressT addrPage = truncateLSB(addr);
            pageAddressT topPage = truncateLSB(boundsTop);
            // If the access is in a different page to the base/top, clamp to only prefetch within this page
            Addr offset = 0;
            if (basePage != addrPage) begin
                pageIndexT pageIdx = truncate(addr);
                offset = boundsOffset - extend(pageIdx);
                boundsBase = Addr'{addrPage, 0};
            end
            if (topPage != addrPage) begin
                boundsTop = Addr'{addrPage, ~0};
            end
            // If the access was for the first cache line of the capability, skip straight to the second
            if (getLineAddr(boundsBase) == getLineAddr(addr)) begin
                boundsBase = boundsBase + 64;
                offset = offset + 64;
            end
            // Set prefetch registers
            nextPrefetchAddr_new <= boundsBase;
            stopLineAddr <= getLineAddr(boundsTop);
            origLineAddr <= getLineAddr(addr);
            // Keep any aux data from CapChaser to avoid infinite prefetch chaining
            auxData <= (prefetchAuxData matches tagged CapChaserAuxData .auxData ? CapChaserAllInAuxData(auxData) : CapChaserAllInEmpty);

            // Create a capability for the prefetches
            CapPipe cap = almightyCap;
            let cap1 = setAddr(cap, boundsVirtBase);
            let cap2 = setBounds(cap1.value, boundsLength);
            let cap3 = setOffset(cap2.value, offset);
            prefetchCap_new <= cap3.value;

            // Remember the last base address we prefetched on
            prevBaseAddr2 <= prevBaseAddr1;
            prevBaseAddr1 <= boundsVirtBase;
        end
    endmethod

    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        prefetchQ.deq;
        return prefetchQ.first;
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData if (False);
        return ?;
    endmethod

    method Action sendBroadcastData(PrefetcherBroadcastData data);
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events() = unpack(0);
`endif

endmodule