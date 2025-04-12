// Copyright (c) 2024 Karlis Susters 
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
import CHERICap::*;
import CHERICC_Fat::*;
import LFSR::*;
import PerformanceMonitor::*;

`include "div_table_4x4to7.bsvi"

/* Pointer table entry.
 * Indexed by bounds length and pointer offset in bounds.
 * Counts how regularly observed capabilities are actually dereferenced,
 * producing a confidence value.
 */
typedef struct {
    Bit#(ptTagBits) tag;
    Bit#(TSub#(confBits, 1)) nSeen;
    Bit#(confBits) nFetched;
} CapChaserPtEntry#(
    numeric type ptTagBits, 
    numeric type confBits
) deriving (Bits, Eq, FShow);

/* Training table entry.
 * Indexed by boundsVirtBase and boundsLength.
 * Used to look for an access into a particular capability.
 * Also serves as the filter table for the L1.
 */
typedef struct {
    Bit#(ttTagBits) tag;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bool prefetched;
    Bool observed;
} CapChaserTtEntry#(
    numeric type ttTagBits, 
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* For inserting into the training table */
typedef struct {
    CapPipe cap;
    Bit#(ttIdxTagBits) trainingTableIdxTag;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
} CapChaserL1ObservedCap#(
    numeric type ttIdxTagBits,
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

typedef struct {
    Vector#(4, Maybe#(CapChaserL1ObservedCap#(ttIdxTagBits, ptIdxTagBits))) caps;
    Bool prefetch;
} CapChaserL1ObservedCLine#(
    numeric type ttIdxTagBits,
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* In the LL, we only need to do pointer table lookups.
 * An observed CLine is just a vector of observed caps.
 */
typedef struct {
    CapPipe cap;
    Bit#(ptIdxTagBits) ptrTableIdxTag;
} CapChaserLLObservedCap#(
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

typedef struct {
    Vector#(4, Maybe#(CapChaserLLObservedCap#(ptIdxTagBits))) caps;
} CapChaserLLObservedCLine#(
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* For upgrading the pointer table confidence */
typedef struct {
    Bit#(ptIdxTagBits) ptrTableIdxTag;
    Bool upgrade;
} CapChaserPtUpDowngrade#(
    numeric type ptIdxTagBits
) deriving (Bits, Eq, FShow);

/* For undecided prefetches after looking up in the pointer table */
typedef struct {
    CapPipe cap;
    Bit#(confBits) nSeen;
    Bit#(confBits) nFetched;
    PrefetchAuxData auxData;
} CapChaserCandidatePrefetch#(
    numeric type confBits
) deriving (Bits, Eq, FShow);

module mkL1CapChaserPrefetcher#(
    TlbToPrefetcher toTlb, 
    Parameter#(maxCapSizeToTrack) _,
    Parameter#(ptrTableSize) __, 
    Parameter#(trainingTableSize) ___
)(CheriPrefetcher) provisos (
    // The tables are indexed by hashes, so access is already inexact.
    // Choose how much tag to store to tradeoff storage vs accuracy.
    NumAlias#(ptrTableTagBits, 16),
    NumAlias#(ptrTableIdxBits, TLog#(ptrTableSize)),
    NumAlias#(ptrTableIdxTagBits, TAdd#(ptrTableIdxBits, ptrTableTagBits)),
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
    Add#(ptrTableConfBits, e__, 8), 
    Add#(2, f__, ptrTableConfBits),

    // The number of bits for the fixed point confidence divide
    // You can't just change this number. It is hard coded in the division table
    // and in PrefetchAuxData of PendingPrefetch.
    NumAlias#(fixPointConfBits, 7),
    
    // Index/tag types
    Alias#(ptrTableIdxT, Bit#(ptrTableIdxBits)),
    Alias#(ptrTableTagT, Bit#(ptrTableTagBits)),
    Alias#(ptrTableIdxTagT, Bit#(ptrTableIdxTagBits)),
    Alias#(trainingTableIdxT, Bit#(trainingTableIdxBits)),
    Alias#(trainingTableTagT, Bit#(trainingTableTagBits)),
    Alias#(trainingTableIdxTagT, Bit#(trainingTableIdxTagBits)),

    // Fifo types
    NumAlias#(lgMaxCapSizeToTrack, TLog#(maxCapSizeToTrack)),
    Alias#(observedCapT, CapChaserL1ObservedCap#(trainingTableIdxTagBits, ptrTableIdxTagBits)),
    Alias#(observedCLineT, CapChaserL1ObservedCLine#(trainingTableIdxTagBits, ptrTableIdxTagBits)),
    Alias#(candidatePrefetchT, CapChaserCandidatePrefetch#(ptrTableConfBits)),

    // Entry types
    // The L1 CapChaser learns confidence and can issue prefetches, so need both
    // training confidence bits and issue confidence bits.
    Alias#(ptrTableEntryT, Maybe#(CapChaserPtEntry#(ptrTableTagBits, ptrTableConfBits))),
    Alias#(trainingTableEntryT, Maybe#(CapChaserTtEntry#(trainingTableTagBits, ptrTableIdxTagBits))),

    // UpDowngrade type
    Alias#(upDowngradeT, CapChaserPtUpDowngrade#(ptrTableIdxTagBits)),

    // Set-associative pointer table
    //NumAlias#(ptrTableWays, 4),
    //Add#(e__, TLog#(ptrTableWays), TLog#(ptrTableSize)),    

    // maxCapSizeToTrack should be at least the size of a capability and no larger than the entire address space
    Add#(TLog#(maxCapSizeToTrack), g__, 63),
    Add#(5, h__, TLog#(maxCapSizeToTrack))
);
    Bool verbose = True;

    // Training table
    RWBramCore#(trainingTableIdxT, trainingTableEntryT) trainingTable <- mkRWBramCoreForwarded();

    // Pointer table
    RWBramCore#(ptrTableIdxT, ptrTableEntryT) ptrTable <- mkRWBramCoreForwarded();

    // Queues for training table lookups 
    Fifo#(8, trainingTableIdxTagT) ttLookupQ <- mkOverflowPipelineFifo;
    Fifo#(1, trainingTableIdxTagT) ttLookupRespQ <- mkPipelineFifo;

    // Queues for pointer table access updates 
    Fifo#(8, upDowngradeT) ptUpDowngradeQ <- mkOverflowPipelineFifo;
    Fifo#(1, upDowngradeT) ptUpDowngradeRespQ <- mkPipelineFifo;

    // Queues for observed capabilities
    Fifo#(8, observedCLineT) observedCLineQ <- mkOverflowPipelineFifo;
    Fifo#(1, observedCapT) observedCapRespQ <- mkPipelineFifo;
    Reg#(Vector#(4, Bool)) unprocessedObservedCap <- mkReg(replicate(True));

    // Tlb lookup and prefetch queues
    Fifo#(8, candidatePrefetchT) candidateQ <- mkOverflowPipelineFifo;
    Fifo#(1, PrefetcherTlbReqIdx) confidenceMultQ <- mkPipelineFifo;
    Fifo#(8, PendingPrefetch) tlbLookupQ <- mkOverflowPipelineFifo;
    Fifo#(16, PendingPrefetch) prefetchQ <- mkOverflowPipelineFifo;

    // Registers for pending TLB requests
    Vector#(PrefetcherTlbReqNum, Reg#(Bool)) pendConfidenceReady <- replicateM(mkRegU);
    Vector#(PrefetcherTlbReqNum, Reg#(Bit#(fixPointConfBits))) pendConfidence <- replicateM(mkRegU);
    Vector#(PrefetcherTlbReqNum, Reg#(PrefetchAuxData)) pendAuxData <- replicateM(mkRegU);
    Fifo#(PrefetcherTlbReqNum, PrefetcherTlbReqIdx) tlbReqFreeQ <- mkCFFifo;
    
    // Init registers 
    Reg#(Bool) bramInited <- mkReg(False);
    Reg#(Bool) tlbReqFreeQInited <- mkReg(False);
    Reg#(PrefetcherTlbReqIdx) tlbReqFreeQInitCount <- mkReg(0);
    Reg#(Bit#(TMax#(ptrTableIdxBits, trainingTableIdxBits))) bramInitCount <- mkReg(0);

    // Latency-saving signal that doObservedCapLookup is actually busy.
    // It might just be dequeuing, in which case other rules can fire.
    RWire#(void) observedCLineBusy <- mkRWire;

    // Hashing functions to produce the index/tags for training and pointer tables
    function ptrTableIdxTagT getPtrTableIdxTag(Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase);
        return hash((boundsOffset >> 4) ^ boundsLength ^ (boundsLength << valueOf(lgMaxCapSizeToTrack)));
    endfunction
    function trainingTableIdxTagT getTrainingTableIdxTag(Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase);
        let bvb = boundsVirtBase >> 4;
        // Shift an additional two bits: the virtual base may be consistently aligned
        // This assumes there could be cache line sized consistent alignment
        Addr hashBvb = {bvb[1:0], truncateLSB(bvb)};
        return hash(hashBvb ^ boundsLength ^ (boundsLength << valueOf(lgMaxCapSizeToTrack)));
    endfunction

    // Confidence-checking functions
    function Bool isL1LevelConfidence(Bit#(fixPointConfBits) fixpoint);
        return fixpoint[7:3] == ~0; // 93.75% 
    endfunction
    function Bool isL2LevelConfidence(Bit#(fixPointConfBits) fixpoint);
        return fixpoint[7:6] != 0; // 25%
    endfunction

    // Whether we have inited
    function Bool inited;
        return bramInited && tlbReqFreeQInited;
    endfunction

    /* Init the prefetcher */
    rule doBramInit(!bramInited);
        trainingTable.wrReq(truncate(bramInitCount), Invalid);
        ptrTable.wrReq(truncate(bramInitCount), Invalid);
        bramInitCount <= bramInitCount + 1;
        if (bramInitCount == ~0) begin
            bramInited <= True;
        end
    endrule
    rule doTlbReqFreeQInit(!tlbReqFreeQInited);
        tlbReqFreeQ.enq(tlbReqFreeQInitCount);
        tlbReqFreeQInitCount <= tlbReqFreeQInitCount + 1;
        if (tlbReqFreeQInitCount == ~0) begin
            tlbReqFreeQInited <= True;
        end
    endrule

    /* Lookup in training table for an accessed capabilitiy.
     * Prefer to process observed cache lines first.
     */
    (* conflict_free = "doTtLookup, doObservedCapLookup" *)
    rule doTtLookup(!isValid(observedCLineBusy.wget) && inited);
        let tit = ttLookupQ.first;
        ttLookupQ.deq;
        ttLookupRespQ.enq(tit);
        trainingTable.rdReq(truncate(tit));
    endrule

    /* Response from training table for looking up an accessed capability */
    rule processTtLookup;
        let tit = ttLookupRespQ.first;
        ttLookupRespQ.deq;
        trainingTableTagT tTag = truncateLSB(tit);
        trainingTableIdxT tIdx = truncate(tit);

        // This rule should never fire when a read response is available from an observed cap lookup
        doAssert(!observedCapRespQ.notEmpty, "processTtLookup fired while observedCapRespQ is non empty");
        // Check whether we found a valid entry in the training table
        if (trainingTable.rdResp matches tagged Valid .entry &&& entry.tag == tTag && !entry.observed) begin
            // Queue an upgrade in the pointer table and mark the training table entry as observed
            ptUpDowngradeQ.enq(CapChaserPtUpDowngrade{
                ptrTableIdxTag: entry.ptrTableIdxTag,
                upgrade: True
            });
            trainingTable.wrReq(tIdx, Valid(CapChaserTtEntry {
                tag: entry.tag,
                ptrTableIdxTag: entry.ptrTableIdxTag,
                prefetched: entry.prefetched,
                observed: True
            }));

            // Print that we hit the training table
            if (verbose) $display("%t CapChaser training hit: ttIdxTag: 0x%h, ptIdxTag: 0x%h", $time, tit, entry.ptrTableIdxTag);
        end else begin
            // Print that we missed the training table
            if (verbose) $display("%t CapChaser training miss: ttIdxTag: 0x%h", $time, tit);
        end
        trainingTable.deqRdResp;
    endrule

    /* Process the next observed cap at the front of the queue */
    rule doObservedCapLookup(inited);
        let observedCLine = observedCLineQ.first;
        let nextCapIdx = findIndex(id, zipWith(\&& , map(isValid, observedCLine.caps), unprocessedObservedCap));
        if (nextCapIdx matches tagged Valid .idx) begin
            let observedCap = fromMaybe(?, observedCLine.caps[idx]);
            observedCLineBusy.wset(?);
            unprocessedObservedCap[idx] <= False;
            // Firstly, read to the training table to see if we are about to evict a good entry.
            // This is what let's us learn confidence.
            trainingTable.rdReq(truncate(observedCap.trainingTableIdxTag));
            // Also read from the pointer table, so we can maybe perform a prefetch
            if (observedCLine.prefetch) begin
                ptrTable.rdReq(truncate(observedCap.ptrTableIdxTag));
            end
            // Queue up the observed cap ready for the read responses
            observedCapRespQ.enq(observedCap);
        end else begin
            // There is no next observed cap, so dequeue
            observedCLineQ.deq;
            unprocessedObservedCap <= replicate(True);
        end
    endrule

    /* Process the read response from observed capabilities */
    rule processObservedCapLookup;
        let observedCLine = observedCLineQ.first;
        let observedCap = observedCapRespQ.first;
        trainingTableIdxT tIdx = truncate(observedCap.trainingTableIdxTag);
        trainingTableTagT tTag = truncateLSB(observedCap.trainingTableIdxTag);
        ptrTableTagT pTag = truncateLSB(observedCap.ptrTableIdxTag);
        observedCapRespQ.deq;

        // Print that we observed a capability and are trying to prefetch
        if (verbose) $display("%t CapChaser observed cap vbase: 0x%h, offset: 0x%h, length: 0x%h, ptIdxTag: 0x%h, ttIdxTag: 0x%h",
            $time,
            getBase(observedCap.cap),
            getOffset(observedCap.cap),
            getLength(observedCap.cap),
            observedCap.ptrTableIdxTag,
            observedCap.trainingTableIdxTag
        );

        // This rule should not fire when there is a read response from accessing a capability
        doAssert(!ttLookupRespQ.notEmpty, "processObservedCapLookup fired while ttLookupRespQ is non empty");

        // We're about to evict a valid training table entry
        // If that's not a duplicate of the line we're about to add, then we need to downgrade confidence
        Bool filterPrefetch = False;
        if (trainingTable.rdResp matches tagged Valid .entry) begin
            if (!entry.observed && entry.tag != tTag) begin
                // Queue a condifence downgrade
                ptUpDowngradeQ.enq(CapChaserPtUpDowngrade{
                    ptrTableIdxTag: entry.ptrTableIdxTag,
                    upgrade: False
                });
                // Print that we're evicting an unobserved entry
                if (verbose) $display("%t CapChaser unobserved tt eviction: ttIdxTag: 0x%h, ptIdxTag: 0x%h", 
                    $time, 
                    observedCap.trainingTableIdxTag, 
                    entry.ptrTableIdxTag
                );
            end
            if (entry.tag == tTag) begin
                filterPrefetch = entry.prefetched;
            end
        end
        trainingTable.deqRdResp;

        // If the cache line is to be prefetched on, check if we hit the pointer table
        // If we hit (i.e. tag matches), and the we are not filtered out by the training table, 
        // and we have non-zero confidence, then create a candidate prefetch.
        Bool prefetched = filterPrefetch;
        if (observedCLine.prefetch) begin
            if (ptrTable.rdResp matches tagged Valid .entry &&& entry.tag == pTag && !filterPrefetch && entry.nSeen != 0) begin
                prefetched = True;
                // Simply add as a candidate prefetch
                // We can't really do the division on this clock cycle
                candidateQ.enq(CapChaserCandidatePrefetch{
                    cap: observedCap.cap,
                    nSeen: {1'b1, entry.nSeen},
                    nFetched: entry.nFetched,
                    auxData: NoPrefetcherAuxData
                });
            end
            ptrTable.deqRdResp;
        end

        // Write to the training table
        // Remember whether we issued a prefetch so we can use the training table as a filter
        trainingTable.wrReq(tIdx, Valid (CapChaserTtEntry {
            tag: tTag,
            ptrTableIdxTag: observedCap.ptrTableIdxTag,
            prefetched: prefetched,
            observed: False
        }));
    endrule

    /* Process a candidate prefetch.
     * Access the TLB and perform the confidence division.
     */
    (* conflict_free = "processCandidatePrefetch, doConfidenceMultiply" *)
    rule processCandidatePrefetch;
        let candidate = candidateQ.first;
        candidateQ.deq;

        // Set up a TLB request.
        // The confidence is ready on the next cycle if this is the first prefetch in a chain
        // i.e. we don't need to perform a multiplication.
        let tlbReqIdx = tlbReqFreeQ.first;
        tlbReqFreeQ.deq;
        if (candidate.auxData matches tagged CapChaserConfidence .*) begin
            pendConfidenceReady[tlbReqIdx] <= False;
            confidenceMultQ.enq(tlbReqIdx);
        end else begin
            pendConfidenceReady[tlbReqIdx] <= True;
        end
        pendConfidence[tlbReqIdx] <= readDivtable4x4to7({candidate.nFetched, candidate.nSeen});
        pendAuxData[tlbReqIdx] <= candidate.auxData;

        // Send the TLB request
        toTlb.prefetcherReq(PrefetcherReqToTlb {
            cap: candidate.cap,
            id: tlbReqIdx
        });
    endrule

    /* Do a confidence multiplication */
    rule doConfidenceMultiply;
        let tlbReqIdx = confidenceMultQ.first;    
        confidenceMultQ.deq;
        if (pendAuxData[tlbReqIdx] matches tagged CapChaserConfidence .confidence) begin
            pendConfidence[tlbReqIdx] <= (pack(unsignedMul(unpack(pendConfidence[tlbReqIdx]) , unpack(confidence))))[13:7];
            pendConfidenceReady[tlbReqIdx] <= True;
        end else begin
            doAssert(False, "Attempted to do confidence multiply without prefetch aux data");
        end
    endrule

    /* Handle a TLB reponse, but only if the confidence is ready */
    rule processTlbResp(pendConfidenceReady[toTlb.prefetcherResp.id]);
        let resp = toTlb.prefetcherResp;
        let tlbReqIdx = resp.id;
        toTlb.deqPrefetcherResp;
        if (verbose) $display("%t CapChaser TLB response: exception: %b, perms: %b, confidence: %b, cap: ", 
            $time, 
            resp.haveException,
            resp.permsCheckPass,
            pendConfidence[tlbReqIdx],
            resp.cap
        );
        if (!resp.haveException && resp.permsCheckPass && resp.paddr != 0 && isL2LevelConfidence(pendConfidence[tlbReqIdx])) begin
            prefetchQ.enq(PendingPrefetch {
                addr: resp.paddr,
                cap: resp.cap,
                nextLevel: isL1LevelConfidence(pendConfidence[tlbReqIdx]),
                auxData: CapChaserConfidence(pendConfidence[tlbReqIdx])
            });
        end
        tlbReqFreeQ.enq(tlbReqIdx);
    endrule

    /* Do a lookup for PT upgrade/downgrade requests */
    (* conflict_free = "doPtLookupForUpDowngrade, doObservedCapLookup" *)
    rule doPtLookupForUpDowngrade(!isValid(observedCLineBusy.wget) && inited);
        let upDowngrade = ptUpDowngradeQ.first;
        ptUpDowngradeQ.deq;
        ptrTable.rdReq(truncate(upDowngrade.ptrTableIdxTag));
        ptUpDowngradeRespQ.enq(upDowngrade);
    endrule

    /* Actually perform PT confidence upgrade/downgrades */
    rule processPtUpDowngrade;
        let upDowngrade = ptUpDowngradeRespQ.first;
        ptUpDowngradeRespQ.deq;

        // This rule should never fire when a read response is available from an observed cap lookup
        doAssert(!observedCapRespQ.notEmpty, "processPtUpDowngrade fired while observedCapRespQ is non empty");

        // If the PT lookup hit, update the counters and potentially the confidence
        if (ptrTable.rdResp matches tagged Valid .entry) begin
            let nSeen = entry.nSeen + 1;
            let nFetched = entry.nFetched + (upDowngrade.upgrade ? 1 : 0); 
            // Right-shift nFetched when saturated
            if (entry.nSeen == ~0) begin
                nFetched = (entry.nFetched >> 1) + (upDowngrade.upgrade ? 1 : 0);
            end 
            // Delete the entry if we no longer have confidence
            if (nFetched == 0) begin
                ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), Invalid);
                if (verbose) $display("%t CapChaser removing pt entry: ptIdxTag: 0x%h", 
                    $time, 
                    upDowngrade.ptrTableIdxTag
                );
            end else begin 
                ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), Valid(CapChaserPtEntry {
                    tag: truncateLSB(upDowngrade.ptrTableIdxTag),
                    nSeen: nSeen,
                    nFetched: nFetched
                }));
                if (verbose) $display("%t CapChaser updating confidence: ptIdxTag: 0x%h, upgrade: %b, nseen: %d, nfetched: %d", 
                    $time, 
                    upDowngrade.ptrTableIdxTag,
                    upDowngrade.upgrade,
                    nSeen,
                    {1'b1, nFetched}
                );
            end
        end else if (upDowngrade.upgrade) begin 
            ptrTable.wrReq(truncate(upDowngrade.ptrTableIdxTag), Valid(CapChaserPtEntry {
                tag: truncateLSB(upDowngrade.ptrTableIdxTag),
                nSeen: 1,
                nFetched: 1
            }));
            // Print that we're inserting a new pointer table entry
            if (verbose) $display("%t CapChaser inserting new pt entry: ptIdxTag: 0x%h", 
                $time, 
                upDowngrade.ptrTableIdxTag
            );
        end
        ptrTable.deqRdResp;
    endrule

    /* Upon access, check whether we just accessed an entry in the training table.
     * We want to only include demand access here, as we're checking if our prefetcher will be accurate.
     * We don't care if it's a store or a load: the line needs to be in the cache either way.
     */
    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (!isPrefetch && boundsLength <= fromInteger(valueOf(maxCapSizeToTrack))) begin
            let tit = getTrainingTableIdxTag(boundsOffset, boundsLength, boundsVirtBase);
            ttLookupQ.enq(tit);

            // Print that we accessed a capability and are doing a TT lookup
            if (verbose) $display("%t CapChaser reportAccess vbase: 0x%h, offset: 0x%h, length: 0x%h, ttIdxTag: 0x%h",
                $time,
                boundsVirtBase,
                boundsOffset,
                boundsLength,
                tit
            );
        end
    endmethod

    /* Upon data arrival, perform two actions for each pointer in the cache line:
     * - Add the capability to the training table.'
     *   Although the demand access is probably for a specific capability in the line, 
     *   we want to use the confidence in the context of prefetch chaining, where we are
     *   no longer loading specific addresses, rather cache lines as a whole. Therefore, learn
     *   confidence about the whole line, ignoring the specific address used.
     * - Lookup the capability in the pointer table.
     *   We only want to do this on a hit, as the L2 will start prefetching on a miss.
     */
    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (memOp == Ld && boundsLength <= fromInteger(valueOf(maxCapSizeToTrack))) begin
            // Fill observedCLine with the capabilities in this cache line
            observedCLineT observedCLine;
            observedCLine.prefetch = !wasMiss;
            for (Integer i = 0; i < 4; i = i + 1) begin
                // Get the i'th capability (might not exist) from the cache line
                MemTaggedData d = getTaggedDataAt(lineWithTags, fromInteger(i));
                CapPipe cap = fromMem(unpack(pack(d)));
                // Calculate the offset of this cap (may underflow, but we will detect that)
                Bit#(TAdd#(lgMaxCapSizeToTrack, 1)) capOffset = truncate(boundsOffset) - extend(addr[5:0]) + (fromInteger(i) << 4);
                // Get the training and pointer table index/tag pairs
                trainingTableIdxTagT tit = getTrainingTableIdxTag(
                    getOffset(cap), saturating_truncate(getLength(cap)), saturating_truncate(getBase(cap))
                );
                ptrTableIdxTagT pit = getPtrTableIdxTag(
                    extend(capOffset), boundsLength, boundsVirtBase
                );
                // We are interested in this capability if
                // - It is tagged (obviously), and
                // - It has the same bounds size as the capability used to access it, and
                // - It is within the bounds of the capability used to access it.
                if (d.tag && extend(boundsLength) == getLength(cap) && extend(capOffset)+16 <= boundsLength) begin
                    observedCLine.caps[i] = Valid (CapChaserL1ObservedCap {
                        cap: setOffset(cap, extend(capOffset)).value,
                        trainingTableIdxTag: tit,
                        ptrTableIdxTag: pit
                    });
                end else begin
                    observedCLine.caps[i] = Invalid;
                end
            end
            // Print that we saw a capability
            if (verbose) $display("%t CapChaser reportCacheDataArrival wasPrefetch: %b, vbase: 0x%h, offset: 0x%h, length: 0x%h, observedCLine: ",
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

endmodule


module mkAllInCapPrefetcher2#(
        Parameter#(maxCapSizeToPrefetch) _,
        Parameter#(onDemandHit) __,
        Parameter#(onPrefetchHit) ___
)(CheriPrefetcher) provisos (
    /* Assume 4KB pages */
    NumAlias#(pageIndexBits, 6),
    Alias#(pageAddressT, Bit#(TSub#(LineAddrSz, pageIndexBits)))
);
    Reg#(Addr) nextPrefetchAddr <- mkReg(0);
    Reg#(LineAddr) origLineAddr <- mkReg(?);
    Reg#(Addr) stopPrefetchAddr <- mkReg(0);
    Reg#(CapPipe) prefetchCap <- mkReg(?);

    rule skipOriginalMiss if (getLineAddr(nextPrefetchAddr) == origLineAddr);
        nextPrefetchAddr <= nextPrefetchAddr + 64;
    endrule

    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (
            // Prefetch on any miss, or a hit depending on configuration
            (hitMiss == MISS || (isPrefetch && valueOf(onDemandHit)!=0) || (!isPrefetch && valueOf(onPrefetchHit) != 0)) &&
            // Only prefetch on loads with appropriate bounds
            memOp == Ld && boundsLength != 0 && boundsLength <= fromInteger(valueof(maxCapSizeToPrefetch)) &&
            // Not an access for the current or last prefetch
            boundsVirtBase != getBase(prefetchCap)
        ) begin
            // Get the physical bounds base and top
            Addr boundsBase = addr-boundsOffset;
            Addr boundsTop = addr+(boundsLength-boundsOffset-1);
            // Get base, access, and top page addresses
            pageAddressT basePage = truncateLSB(boundsBase);
            pageAddressT addrPage = truncateLSB(addr);
            pageAddressT topPage = truncateLSB(boundsTop);
            // If the access is in a different page to the base/top, clamp to only prefetch within this page
            if (basePage != addrPage) begin
                boundsBase = Addr'{addrPage, 0};
            end
            if (topPage != addrPage) begin
                boundsTop = Addr'{addrPage+1, 0};
            end
            // Set prefetch registers
            nextPrefetchAddr <= boundsBase;
            stopPrefetchAddr <= boundsTop;
            origLineAddr <= getLineAddr(addr);

            // Create a capability for the prefetches
            CapPipe cap = almightyCap;
            let cap1 = setAddr(cap, boundsVirtBase);
            let cap2 = setBounds(cap1.value, boundsLength);
            prefetchCap <= cap2.value;
        end
    endmethod

    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, 
        Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    endmethod

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr if (nextPrefetchAddr < stopPrefetchAddr && getLineAddr(nextPrefetchAddr) != origLineAddr);
        // Increase by a full cache line
        nextPrefetchAddr <= nextPrefetchAddr + 64;
        prefetchCap <= modifyOffset(prefetchCap, 64, True).value;
        // Issue a prefetch
        return PendingPrefetch {
            addr: nextPrefetchAddr,
            cap: prefetchCap,
            nextLevel: False,
            auxData: NoPrefetcherAuxData
        };
    endmethod

endmodule