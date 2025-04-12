// Copyright (c) 2023 Karlis Susters 
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
import ProcTypes::*;
import Vector::*;
import FIFO::*;
import Fifos::*;
import FIFOF::*;
import SpecialFIFOs :: *;
import GetPut::*;
import RWBramCore::*;
import FixedPoint::*;
import SpecialRegs::*;

`include "div_table_4x4to7.bsvi"

interface Divider;
    method Action doDiv1(Bit#(4) a, Bit#(4) b);
    method Action doDiv2(Bit#(4) a, Bit#(4) b);
    method Bit#(7) getDiv1Res;
    method Bit#(7) getDiv2Res;
    method Action deqDiv1Res;
    method Action deqDiv2Res;
endinterface

module mkDivider#(String divTableFile)(Divider);
    FIFOF#(Bit#(7)) div1Res <- mkPipelineFIFOF;
    FIFOF#(Bit#(7)) div2Res <- mkPipelineFIFOF;

    method Action doDiv1(Bit#(4) a, Bit#(4) b);
        Bit#(8) addr = {a, b};
        Bit#(7) divres = readDivtable4x4to7(addr);
        div1Res.enq(divres);
    endmethod

    method Action doDiv2(Bit#(4) a, Bit#(4) b);
        Bit#(8) addr = {a, b};
        Bit#(7) divres = readDivtable4x4to7(addr);
        div2Res.enq(divres);
    endmethod

    method Bit#(7) getDiv1Res;
        return div1Res.first;
    endmethod
    
    method Bit#(7) getDiv2Res;
        return div2Res.first;
    endmethod

    method Action deqDiv1Res;
        div1Res.deq;
    endmethod

    method Action deqDiv2Res;
        div2Res.deq;
    endmethod
endmodule

typedef Bit#(4) Count;
typedef Bit#(12) Sig;
typedef Bit#(7) Prob;
typedef Bit#(7) Delta;

function Action probWrite(String prefix, Prob p) =
    action
    Bit#(8) x = {1'b0, p};
    FixedPoint#(1,7) z = unpack(x);
    $write("%t ", $time);
    $write(prefix);
    fxptWrite(4, z);
    $write("\n");
    endaction;

typedef struct {
    Prob alphaXCumProb;
    Vector#(4, Delta) deltas;
    LineAddr currAddr;
    Sig sig;
    Bit#(8) depth;
} Stage1Out deriving (Bits, FShow);

typedef struct {
    Vector#(4, Prob) candidates;
    Vector#(4, Delta) deltas;
    LineAddr currAddr;
    Sig sig;
    Bit#(8) depth;
} Stage2Out deriving (Bits, FShow);

typedef struct {
    Vector#(4, Prob) candidates;
    Vector#(4, Bool) canPrefetch;
    Vector#(4, Delta) deltas;
    LineAddr currAddr;
    Sig sig;
    Bit#(8) depth;
} Stage3Out deriving (Bits, FShow);

typedef struct {
    Delta delta;
    Count count;
} DeltaEntry deriving (Bits, FShow, Eq);

typedef struct {
    Sig sig;
    LineAddr addr;
    Prob currCumProb;
    Bit#(8) depth;
} PTLookupEntry deriving (Bits, FShow, Eq);

function Sig updateSig (Sig sig, Delta delta)  =
    (sig << 3) ^ extend(delta);

interface PrefetchCalculator#(numeric type pfQueueSize, numeric type lookupQueueSize);
    method Action submitCandidates(LineAddr currAddr, Sig sig, Prob alpha, Prob currCumProb, Count sigCount, Vector#(4, DeltaEntry) deltaCounts, Bit#(8) depth);
    method ActionValue#(PTLookupEntry) getPTLookupEntry;
    method ActionValue#(LineAddr) getNextPrefetchAddr;
    method ActionValue#(Bit#(8)) getNextPrefetchAddrDepth;
endinterface

module mkPrefetchCalculator#(Prob threshold, String divTableFile)
(PrefetchCalculator#(pfQueueSize, lookupQueueSize));

    function Prob multProb (Prob a, Prob b) = (pack(unsignedMul(unpack(a) , unpack(b))))[13:7];
    FIFO#(Stage1Out) stage1Out <- mkFIFO;
    FIFO#(Stage2Out) stage2Out <- mkFIFO;
    FIFO#(Stage3Out) stage3Out <- mkBypassFIFO;
    Fifo#(pfQueueSize, LineAddr) pfQueue <- mkOverflowBypassFifo;
    Fifo#(pfQueueSize, Bit#(8)) pfDepthQueue <- mkOverflowBypassFifo;
    Fifo#(lookupQueueSize, PTLookupEntry) lookupQueue <- mkOverflowBypassFifo;
    //Each divider supports two concurrent divisions. Implemented with BRAM
    Divider div1 <- mkDivider(divTableFile);
    Divider div2 <- mkDivider(divTableFile);
    Vector#(4, Reg#(Bool)) stage4IssuedPrefetch <- replicateM(mkReg(False));

    Bool verbose = False;
    Bool extraVerbose = False;

    rule stage2;
        Stage1Out s = stage1Out.first;
        stage1Out.deq;
        Vector#(4, Prob) candidates;
        //if (verbose) probWrite("pfCalculator:stage2 alphaXCumProb ", s.alphaXCumProb);
        //if (verbose) $display("%t pfCalculator:stage2 divResults: {%h, %h, %h, %h}", $time, div1.getDiv1Res, div1.getDiv2Res, div2.getDiv1Res, div2.getDiv2Res);
        //if (verbose) probWrite("pfCalculator:stage2 div0 ", div1.getDiv1Res);
        //if (verbose) probWrite("pfCalculator:stage2 div1 ", div1.getDiv2Res);
        //if (verbose) probWrite("pfCalculator:stage2 div2 ", div2.getDiv1Res);
        //if (verbose) probWrite("pfCalculator:stage2 div3 ", div2.getDiv2Res);
        div1.deqDiv1Res;
        div1.deqDiv2Res;
        div2.deqDiv1Res;
        div2.deqDiv2Res;
        candidates[0] = multProb(div1.getDiv1Res, s.alphaXCumProb);
        candidates[1] = multProb(div1.getDiv2Res, s.alphaXCumProb);
        candidates[2] = multProb(div2.getDiv1Res, s.alphaXCumProb);
        candidates[3] = multProb(div2.getDiv2Res, s.alphaXCumProb);
        if (extraVerbose) probWrite("pfCalculator:stage2 candidates[0] ", candidates[0]);
        if (extraVerbose) probWrite("pfCalculator:stage2 candidates[1] ", candidates[1]);
        if (extraVerbose) probWrite("pfCalculator:stage2 candidates[2] ", candidates[2]);
        if (extraVerbose) probWrite("pfCalculator:stage2 candidates[3] ", candidates[3]);
        Stage2Out s2 = Stage2Out {
            candidates:candidates, 
            deltas:s.deltas, 
            currAddr:s.currAddr,
            sig:s.sig,
            depth:s.depth};
        //if (verbose) $display("%t pfCalculator:", $time, fshow(s2));
        stage2Out.enq(s2);
    endrule

    rule stage3;
        Stage2Out s = stage2Out.first;
        Vector#(4, Bool) canPrefetch;
        canPrefetch[0] = s.candidates[0] >= threshold;
        canPrefetch[1] = s.candidates[1] >= threshold;
        canPrefetch[2] = s.candidates[2] >= threshold;
        canPrefetch[3] = s.candidates[3] >= threshold;
        stage2Out.deq;
        Stage3Out s3 = Stage3Out {
            candidates:s.candidates, 
            deltas:s.deltas, 
            currAddr:s.currAddr, 
            canPrefetch:canPrefetch,
            sig:s.sig,
            depth:s.depth};
        //if (verbose) $display("%t pfCalculator:", $time, fshow(s3));
        stage3Out.enq(s3);
    endrule

    function LineAddr addDelta(LineAddr addr, Delta d) = 
        addr + (d[6] == 0 ? extend(d[5:0]) : -extend(d[5:0]));

    function Bit#(2) maxInVec(Vector#(4, Prob) vec);
        Prob maxVal = 0;
        
        Bit#(2) maxIndex1 = (vec[0] >= vec[1]) ? 0 : 1;
        Bit#(2) maxIndex2 = (vec[2] >= vec[3]) ? 2 : 3;
        return (vec[maxIndex1] >= vec[maxIndex2]) ? maxIndex1 : maxIndex2;
    endfunction

    rule stage4;
        Stage3Out s = stage3Out.first;
        if (s.canPrefetch[0] && !stage4IssuedPrefetch[0]) begin
            LineAddr nextAddr = addDelta(s.currAddr, s.deltas[0]);
            if (verbose) $display("%t pfCalculator:stage4 pfQueue.enq %h (entry 0) with confidence 0.%b", $time, Addr'{nextAddr, 0}, s.candidates[0]);
            pfQueue.enq(nextAddr);
            pfDepthQueue.enq(s.depth);
            stage4IssuedPrefetch[0] <= True;
        end
        else if (s.canPrefetch[1] && stage4IssuedPrefetch[1] == False) begin
            LineAddr nextAddr = addDelta(s.currAddr, s.deltas[1]);
            if (verbose) $display("%t pfCalculator:stage4 pfQueue.enq %h (entry 1) with confidence 0.%b", $time, Addr'{nextAddr, 0}, s.candidates[1]);
            pfQueue.enq(nextAddr);
            pfDepthQueue.enq(s.depth);
            stage4IssuedPrefetch[1] <= True;
        end
        else if (s.canPrefetch[2] && stage4IssuedPrefetch[2] == False) begin
            LineAddr nextAddr = addDelta(s.currAddr, s.deltas[2]);
            if (verbose) $display("%t pfCalculator:stage4 pfQueue.enq %h (entry 2) with confidence 0.%b", $time, Addr'{nextAddr, 0}, s.candidates[2]);
            pfQueue.enq(nextAddr);
            pfDepthQueue.enq(s.depth);
            stage4IssuedPrefetch[2] <= True;
        end
        else if (s.canPrefetch[3] && stage4IssuedPrefetch[3] == False) begin
            LineAddr nextAddr = addDelta(s.currAddr, s.deltas[3]);
            if (verbose) $display("%t pfCalculator:stage4 pfQueue.enq %h (entry 3) with confidence 0.%b", $time, Addr'{nextAddr, 0}, s.candidates[3]);
            pfQueue.enq(nextAddr);
            pfDepthQueue.enq(s.depth);
            stage4IssuedPrefetch[3] <= True;
        end
        else begin
            // Have issued all prefetches. Find maximum of all candidate probs, 
            // make sure it is above threshold (canPrefetch holds), 
            // and send it for further lookups in PT.
            Bit#(2) maxIdx = maxInVec(s.candidates);
            PTLookupEntry ptl = PTLookupEntry {
                addr: addDelta(s.currAddr, s.deltas[maxIdx]),
                currCumProb: s.candidates[maxIdx],
                sig: updateSig(s.sig,  s.deltas[maxIdx]),
                depth: s.depth + 1
            };
            if (stage4IssuedPrefetch[0] || stage4IssuedPrefetch[1] || 
                stage4IssuedPrefetch[2] || stage4IssuedPrefetch[3]) begin
                if (verbose) $display("%t pfCalculator:stage4 lookupQueue.enq addr %x ", $time, Addr'{ptl.addr, 0}, fshow(ptl));
                lookupQueue.enq(ptl);
            end
            writeVReg(stage4IssuedPrefetch, replicate(False));
            stage3Out.deq;
        end
    endrule

    method Action submitCandidates(
            LineAddr currAddr, Sig sig, Prob alpha, 
            Prob currCumProb, 
            Count sigCount, Vector#(4, DeltaEntry) deltaCounts, Bit#(8) depth);
        //if (verbose) probWrite("pfCalculator:submitCandidates alpha: ", alpha);
        //if (verbose) probWrite("pfCalculator:submitCandidates currCumProb: ", currCumProb);
        //if (verbose) $display("%t pfCalculator:submitCandidates deltaCounts ", $time, fshow(deltaCounts));
        //if (verbose) $display("%t pfCalculator:submitCandidates sigCount %h", $time, sigCount);
        div1.doDiv1(deltaCounts[0].count, sigCount);
        div1.doDiv2(deltaCounts[1].count, sigCount);
        div2.doDiv1(deltaCounts[2].count, sigCount);
        div2.doDiv2(deltaCounts[3].count, sigCount);
        Prob alphaXCumProb = (depth == 0) ? currCumProb : multProb(currCumProb, alpha);
        Vector#(4, Delta) deltas;
        deltas[0] = deltaCounts[0].delta;
        deltas[1] = deltaCounts[1].delta;
        deltas[2] = deltaCounts[2].delta;
        deltas[3] = deltaCounts[3].delta;
        Stage1Out s = Stage1Out {
            alphaXCumProb: alphaXCumProb, 
            deltas: deltas, 
            currAddr: currAddr,
            sig: sig,
            depth: depth};

        //if (verbose) $display("%t pfCalculator:submitCandidates ", $time, fshow(s));
        stage1Out.enq(s);
    endmethod
    method ActionValue#(PTLookupEntry) getPTLookupEntry;
        lookupQueue.deq;
        return lookupQueue.first;
    endmethod
    method ActionValue#(LineAddr) getNextPrefetchAddr;
        pfQueue.deq;
        return pfQueue.first;
    endmethod
    method ActionValue#(Bit#(8)) getNextPrefetchAddrDepth;
        pfDepthQueue.deq;
        return pfDepthQueue.first;
    endmethod
endmodule

typedef struct {
    Sig oldSig;
    Delta observedDelta;
} PTUpdateEntry deriving (Bits, FShow);

// The padding here is used only because in simulation BRAMs are intiialized as 10101..
// And I want the 'valid' of all entries to be initialized to 0. 
// So, 'valid' must be on an odd bit, and the length of STEntry must be even.
typedef struct {
    Bit#(padBits) pad;
    Bit#(tagBits) tag;
    Bit#(pageIndexBits) lastOffset;
    Sig signature;
    Bit#(lruBits) lru;
    Bool valid;
} STEntry#(numeric type padBits, numeric type pageIndexBits, numeric type tagBits, numeric type lruBits) deriving (Bits, FShow);


interface SignatureTable#(numeric type outputQueueSize, numeric type tableSets, numeric type tableWays);
    method Action reportAccess (LineAddr addr);
    method ActionValue#(PTLookupEntry) getPTLookupEntry;
    method ActionValue#(PTUpdateEntry) getPTUpdateEntry;
endinterface

module mkSignatureTable(SignatureTable#(outputQueueSize, tableSets, tableWays)) provisos
(
    NumAlias#(pageIndexBits, 6), //4k pages
    NumAlias#(tagBits, 16),
    Log#(tableWays, tableWayBits),
    Log#(tableSets, tableIndexBits),
    Alias#(pageAddressT, Bit#(TSub#(LineAddrSz, pageIndexBits))),
    Alias#(pageOffsetT, Bit#(pageIndexBits)),
    Alias#(tableIndexT, Bit#(tableIndexBits)),
    Alias#(tableTagT, Bit#(tagBits)),
    NumAlias#(padBits, TSub#(1, TSub#(TMul#(TDiv#(tableWayBits, 2), 2), tableWayBits))), //padBits is 1 if lruBits is even
    Alias#(stEntryT, STEntry#(padBits, pageIndexBits, tagBits, tableWayBits)),
    Add#(a__, tableIndexBits, 58),
    Add#(c__, tableIndexBits, 52),
    Add#(1, b__, tableWays)
);
    Fifo#(outputQueueSize, PTLookupEntry) ptlQueue <- mkOverflowPipelineFifo;
    Fifo#(outputQueueSize, PTUpdateEntry) ptuQueue <- mkOverflowPipelineFifo;
    FIFO#(LineAddr) addrForRdReq <- mkFIFO;
    RWBramCore#(tableIndexT, Vector#(tableWays, stEntryT)) st <- mkRWBramCoreForwarded();

    Bool verbose = False;
    Bool extraVerbose = False;

    function Maybe#(UInt#(tableWayBits)) getTagMatchWay (Vector#(tableWays, stEntryT) entries, tableTagT tag);
        function Bool isMatch (stEntryT entry);
            return entry.valid && entry.tag == tag;
        endfunction
        return findIndex(isMatch, entries);
    endfunction

    function UInt#(tableWayBits) getReplaceWay (Vector#(tableWays, stEntryT) entries);
        function Bool isInvalid (stEntryT entry);
            return !entry.valid;
        endfunction
        let f = findIndex(isInvalid, entries);
        if ( f matches tagged Valid .idx ) begin
            return idx;
        end
        else begin
            function Bool findLruIndex(stEntryT entry);
                Bit#(tableWayBits) target = fromInteger(valueOf(tableWays) - 1);
                return entry.lru == target;
            endfunction
            let x = findIndex(findLruIndex, entries);
            if (x matches tagged Valid .idx) begin
                return idx;
            end
            else begin
                //doAssert(false, "LRU couldn't find index!");
                return 0;
            end
        end
    endfunction

    function Delta calculateDelta(pageOffsetT curr, pageOffsetT prev);
        if (curr >= prev)
            return {1'b0, curr-prev};
        else 
            return {1'b1, prev-curr};
    endfunction

    rule processStRead;
        st.deqRdResp;
        addrForRdReq.deq;

        let addr = addrForRdReq.first;
        pageAddressT pa = truncateLSB(addr);
        pageOffsetT po = truncate(addr);
        tableIndexT idx = truncate(pa);
        tableTagT tag = pa[(valueOf(tableIndexBits)+valueOf(tagBits)-1):valueOf(tableIndexBits)];

        Vector#(tableWays, stEntryT) entries = st.rdResp;
        if (extraVerbose) $display("%t signatureTable:initial entries ", $time, fshow(entries));
        UInt#(tableWayBits) entryWay;
        let x = getTagMatchWay(entries, tag);
        stEntryT entry;
        if (x matches tagged Valid .way) begin
            entryWay = way;
            entry = entries[way];
            Delta delta = calculateDelta(po, entry.lastOffset);
            if (extraVerbose) $display("%t signatureTable:processStRead addr:%x found matching way %d, entry: ", 
                    $time, addr, way, fshow(entry));
            if (delta != 0) begin
                PTUpdateEntry ptu;
                ptu.oldSig = entry.signature;
                ptu.observedDelta = delta;
                if (extraVerbose) $display("%t signatureTable:processStRead create PTU: ", $time, fshow(ptu));
                ptuQueue.enq(ptu);

                PTLookupEntry ptl;
                ptl.sig = updateSig(entry.signature, delta);
                ptl.addr = addrForRdReq.first;
                ptl.currCumProb = 7'b1111111;
                ptl.depth = 0;
                if (extraVerbose) $display("%t signatureTable:processStRead create PTL: ", $time, fshow(ptl));
                ptlQueue.enq(ptl);

                entry.lastOffset = po;
                entry.signature = updateSig(entry.signature, delta);
            end
            entry.lru = 0;
        end
        else begin
            entryWay = getReplaceWay(entries);
            if (extraVerbose) $display("%t signatureTable:processStRead addr:%x replacing way %d ", $time, addr, entryWay);
            entry.valid = True;
            entry.tag = tag;
            entry.lastOffset = po;
            entry.signature = 0;
            entry.lru = 0;
            entry.pad = 0;
        end
        Bit#(tableWayBits) originalLru = entries[entryWay].valid ? 
                entries[entryWay].lru : fromInteger(valueof(tableWays) - 1);
        function stEntryT updateOtherLRUs(stEntryT ste);
            if (ste.lru < originalLru) ste.lru = ste.lru + 1;
            return ste;
        endfunction
        let newEntries = map(updateOtherLRUs, entries);
        newEntries[entryWay] = entry;
        if (extraVerbose) $display("%t signatureTable:processStRead newEntries (after LRU update) ", $time, fshow(newEntries));
        st.wrReq(idx, newEntries);
    endrule

    method Action reportAccess(LineAddr addr);
        addrForRdReq.enq(addr);
        pageAddressT pa = truncateLSB(addr);
        pageOffsetT po = truncate(addr);
        tableIndexT idx = truncate(pa);
        if (extraVerbose) $display("%t signatureTable:reportAccess %x, sending rdReq with idx:%x", $time, addr, idx);
        st.rdReq(idx);
    endmethod

    method ActionValue#(PTLookupEntry) getPTLookupEntry;
        if (extraVerbose) $display("%t signatureTable:getPTLookupEntry returning", $time, fshow(ptlQueue.first));
        ptlQueue.deq;
        return ptlQueue.first;
    endmethod
    method ActionValue#(PTUpdateEntry) getPTUpdateEntry;
        if (extraVerbose) $display("%t signatureTable:getPTUpdateEntry returning", $time, fshow(ptuQueue.first));
        ptuQueue.deq;
        return ptuQueue.first;
    endmethod
endmodule

typedef struct {
    Count sigCount;
    Vector#(4, DeltaEntry) deltaCounts;
    Bit#(1) pad;
    Bool initialized;
} PTEntry deriving (Bits, FShow);


interface PatternTable#(numeric type numEntries, numeric type inputFifoSize);
    method ActionValue#(Tuple2#(PTLookupEntry, PTEntry)) getPTEntry;
    method Action doPTLookup(PTLookupEntry ptl);
    method Action doPTUpdate(PTUpdateEntry ptu);
endinterface

module mkPatternTable(PatternTable#(numEntries, inputFifoSize)) provisos
    (Log#(numEntries, indexBits),
    Alias#(tableIndexT, Bit#(indexBits)),
    Add#(a__, indexBits, 12),
    NumAlias#(countMaxVal, TSub#(TExp#(4),1))
    );
    FIFO#(PTLookupEntry) ptlFifo_afterRead <- mkFIFO;
    FIFO#(PTUpdateEntry) ptuFifo_afterRead <- mkFIFO;

    Fifo#(inputFifoSize, PTLookupEntry) ptlFifo <- mkOverflowBypassFifo;
    Fifo#(inputFifoSize, PTUpdateEntry) ptuFifo <- mkOverflowBypassFifo;

    RWBramCore#(tableIndexT, PTEntry) pt <- mkRWBramCoreForwarded();
    
    Bool verbose = False;
    Bool extraVerbose = False;
    
    function Maybe#(UInt#(2)) getDeltaMatchingIdx (Vector#(4, DeltaEntry) entries, Delta delta);
        function Bool isMatch (DeltaEntry entry);
            return entry.delta == delta;
        endfunction
        return findIndex(isMatch, entries);
    endfunction

    function Bit#(2) getReplaceIdx (Vector#(4, DeltaEntry) entries);
        Bit#(2) minIndex1 = (entries[0].count > entries[1].count) ? 1 : 0;
        Bit#(2) minIndex2 = (entries[2].count > entries[3].count) ? 3 : 2;
        return (entries[minIndex1].count > entries[minIndex2].count) ? 
            minIndex2 : minIndex1;
    endfunction

    rule processPTUpdate;
        ptuFifo_afterRead.deq;
        pt.deqRdResp;
        PTUpdateEntry ptu = ptuFifo_afterRead.first;
        PTEntry pte = pt.rdResp;
        if (extraVerbose) $display("%t patternTable:processPTUpdate found entry", $time, fshow(pte));
        if (!pte.initialized) begin
            pte.sigCount = 0;
            pte.deltaCounts = unpack(0);
            pte.initialized = True;
        end

        if (pte.sigCount == fromInteger(valueOf(countMaxVal)))  begin
            pte.sigCount = (fromInteger(valueOf(countMaxVal)) >> 1) + 1;
            pte.deltaCounts[0].count = pte.deltaCounts[0].count >> 1;
            pte.deltaCounts[1].count = pte.deltaCounts[1].count >> 1;
            pte.deltaCounts[2].count = pte.deltaCounts[2].count >> 1;
            pte.deltaCounts[3].count = pte.deltaCounts[3].count >> 1;
        end
        else begin
            pte.sigCount = pte.sigCount + 1;
        end

        let x = getDeltaMatchingIdx(pte.deltaCounts, ptu.observedDelta);
        if (x matches tagged Valid .idx) begin
            pte.deltaCounts[idx].count = pte.deltaCounts[idx].count + 1;
        end
        else begin
            let replaceIdx = getReplaceIdx(pte.deltaCounts);
            pte.deltaCounts[replaceIdx].delta = ptu.observedDelta;
            pte.deltaCounts[replaceIdx].count = 1;
        end
        if (verbose) $display("%t patternTable:processPTUpdate updated ", $time, fshow(pte));

        tableIndexT tableIdx = truncate(ptu.oldSig);
        pt.wrReq(tableIdx, pte);
    endrule

    rule doPTReadForLookup; 
        ptlFifo.deq;
        tableIndexT idx = truncate(ptlFifo.first.sig);
        if (extraVerbose) $display("%t patternTable:doPTReadForLookup idx %h", $time, idx);
        ptlFifo_afterRead.enq(ptlFifo.first);
        pt.rdReq(idx);
    endrule

    (* descending_urgency = "doPTReadForUpdate, doPTReadForLookup" *)
    rule doPTReadForUpdate;
        ptuFifo.deq;
        tableIndexT idx = truncate(ptuFifo.first.oldSig);
        if (extraVerbose) $display("%t patternTable:doPTReadForUpdate idx %h", $time, idx);
        ptuFifo_afterRead.enq(ptuFifo.first);
        pt.rdReq(idx);
    endrule

    rule discardUninitializedPTE if (!pt.rdResp.initialized);
        if (extraVerbose) $display("%t patternTable:discardUninitializedPTE ", $time, fshow(ptlFifo_afterRead.first), fshow(pt.rdResp));
        ptlFifo_afterRead.deq;
        pt.deqRdResp;
    endrule

    method ActionValue#(Tuple2#(PTLookupEntry, PTEntry)) getPTEntry() if (pt.rdResp.initialized);
        if (verbose) $display("%t patternTable:getPTEntry ", $time, fshow(ptlFifo_afterRead.first), fshow(pt.rdResp));
        ptlFifo_afterRead.deq;
        pt.deqRdResp;
        return tuple2(ptlFifo_afterRead.first, pt.rdResp);
    endmethod

    method Action doPTLookup(PTLookupEntry ptl);
        ptlFifo.enq(ptl);
    endmethod
    
    method Action doPTUpdate(PTUpdateEntry ptu);
        ptuFifo.enq(ptu);
    endmethod
endmodule

interface PrefetchFilter#(numeric type numEntries, numeric type pfCounterBits, 
    numeric type queueSize);
    method Action canPrefetchReq(LineAddr addr);
    method ActionValue#(Tuple2#(Bool, LineAddr)) canPrefetchResp();
    method Action reportAccess(LineAddr addr, HitOrMiss hitMiss); 
    method Prob getCurrAlpha();
endinterface

typedef struct {
    tagT tag;
    Bool useful;
    Bool valid;
} FilterEntry#(type tagT) deriving (Bits, FShow);

module mkPrefetchFilter(PrefetchFilter#(numEntries, pfCounterBits, queueSize)) provisos
    (
    NumAlias#(idxBits, TLog#(numEntries)),
    Alias#(tableIdxT, Bit#(idxBits)),
    Alias#(tagT, Bit#(6)),
    Alias#(filterEntryT, FilterEntry#(tagT)),
    Alias#(countT, Bit#(pfCounterBits)),
    NumAlias#(maxCounterValue, TSub#(TExp#(pfCounterBits), 1)),
    Add#(a__, TLog#(numEntries), 58),
    Add#(pfCounterBits, b__, 7)
    );

    RWBramCore#(tableIdxT, filterEntryT) filterTable <- mkRWBramCoreForwarded;
    Reg#(countT) pfTotal <- mkReg(0);
    Reg#(countT) pfUseful <- mkReg(0);
    Reg#(Prob) currAlpha <- mkReg(7'b1100000);

    Fifo#(1, LineAddr) pfReqFifo_afterRead <- mkPipelineFifo;
    Fifo#(queueSize, LineAddr) pfReqFifo <- mkOverflowBypassFifo;

    Fifo#(1, Tuple3#(tagT, tableIdxT, HitOrMiss)) reportFifo_afterRead <- mkPipelineFifo;
    Fifo#(queueSize, Tuple2#(LineAddr, HitOrMiss)) reportFifo <- mkOverflowBypassFifo;

    Bool verbose = False;
    Bool extraVerbose = False;

    function Prob getNewAlpha();
        //Assume pfTotal is maxCounterValue + 1
        //Do pfUseful / pfTotal. Essentially we interpret pfUseful as a fixed point fraction, and 
        //just extend it to width of a Prob (7 bits).
        Prob fraction = {pfUseful, 0};
        return fraction;

    endfunction

    (* descending_urgency = "reportAccessRd, canPrefetchRd" *)
    rule canPrefetchRd;
        pfReqFifo.deq;
        let addr = pfReqFifo.first;
        tableIdxT idx = truncate(addr);
        tagT tag = addr[valueOf(idxBits)+6-1:valueOf(idxBits)];
        pfReqFifo_afterRead.enq(addr);
        filterTable.rdReq(idx);
    endrule

    (* descending_urgency = "reportAccessRd, canPrefetchRd" *)
    rule reportAccessRd;
        reportFifo.deq;
        let {addr, hm} = reportFifo.first;
        tableIdxT idx = truncate(addr);
        tagT tag = addr[valueOf(idxBits)+6-1:valueOf(idxBits)];
        reportFifo_afterRead.enq(tuple3(tag, idx, hm));
        filterTable.rdReq(idx);
    endrule

    rule reportAccessProcess;
        filterEntryT entry = filterTable.rdResp;
        filterTable.deqRdResp;
        let {tag, idx, hm} = reportFifo_afterRead.first;
        reportFifo_afterRead.deq;
        if (entry.valid && !entry.useful && hm == HIT && entry.tag == tag)  begin
            //This condition is just to keep the counters 'canonical'. If we allow pfUseful
            //to exceed pfTotal, we can't update alpha when pfTotal hits counterMaxVal.
            if (pfUseful < pfTotal) begin 
                if (pfUseful == fromInteger(valueOf(maxCounterValue))) begin
                    pfUseful <= (pfUseful >> 1) + 1;
                    pfTotal <= pfTotal >> 1;
                end
                else begin
                    pfUseful <= pfUseful + 1; 
                end
            end
            if (extraVerbose) $display(
                "%t PrefetchFilter:reportAccessProcess found a useful prefetch, previous pfUseful/pfTotal = %d/%d", $time, pfUseful, pfTotal);
            entry.useful = True;
        end
        else begin 
            // Insert the demand request into the filter, so we dont prefetch it later
            // set useful to True so we don't count it as a useful prefetch later
            // Even if the tag is a mismatch, and there is a potential prefetch here still waiting to be used, 
            // we have to evict it, and effectively mark it as not useful. Otherwise, prefetches might hang around for 
            // too long in the filter and eventually all get marked as useful by an accidental 
            // tag match from a different address
            if (extraVerbose) $display(
                "%t PrefetchFilter:reportAccessProcess adding demand request into filter", $time);
            entry.valid = True;
            entry.useful = True; 
            entry.tag = tag;
        end
        filterTable.wrReq(idx, entry);
    endrule
    
    method Action canPrefetchReq(LineAddr addr);
        pfReqFifo.enq(addr);
    endmethod

    method ActionValue#(Tuple2#(Bool, LineAddr)) canPrefetchResp;
        filterEntryT entry = filterTable.rdResp;
        filterTable.deqRdResp;
        pfReqFifo_afterRead.deq;
        let addr = pfReqFifo_afterRead.first;
        tableIdxT idx = truncate(addr);
        tagT tag = addr[valueOf(idxBits)+6-1:valueOf(idxBits)];
        if (entry.valid && entry.tag == tag) begin 
            if (extraVerbose) $display("%t PrefetchFilter:canPrefetchResp returning False", $time);
            return tuple2(False, addr); //Do not prefetch
        end
        else begin
            entry.valid = True;
            entry.useful = False;
            entry.tag = tag;
            if (pfTotal == fromInteger(valueOf(maxCounterValue))) begin
                pfTotal <= (pfTotal >> 1) + 1; //Assume we'll issue the prefetch
                pfUseful <= pfUseful >> 1;
                currAlpha <= getNewAlpha();
                if (verbose) $display("%t PrefetchFilter:canPrefetchResp updating alpha to %b", $time, getNewAlpha());
            end
            else 
                pfTotal <= pfTotal + 1;
            if (extraVerbose) $display("%t PrefetchFilter:canPrefetchResp returning True, adding to filter, previous pfUseful/pfTotal: %d/%d", $time, pfUseful, pfTotal);
            filterTable.wrReq(idx, entry);
            return tuple2(True, addr);
        end
    endmethod

    method Action reportAccess(LineAddr addr, HitOrMiss hitMiss); 
        //If no entry, insert entry with valid = 1, useful = 1
        //If find tag matching entry with valid = 1, useful = 1, do nothing
        //If find tag matching entry with valid = 1, useful = 0, increment pfUseful
        if (verbose) $display("%t PrefetchFilter:pfUseful: %d pfTotal: %d alpha: %d", $time, pfUseful, pfTotal, currAlpha);
        if (extraVerbose) $display("%t PrefetchFilter:reportAccess %x", $time, addr, fshow(hitMiss));
        reportFifo.enq(tuple2(addr, hitMiss));
    endmethod

    method Prob getCurrAlpha;
        return currAlpha; 
    endmethod
endmodule


module mkSignaturePathPrefetcher#(String divTableFile, Parameter#(stSets) _, 
        Parameter#(stWays) __, Parameter#(ptEntries) ___, Prob prefetchThreshold, Bool useFilter)(Prefetcher) 
provisos(
Add#(a__, TLog#(ptEntries), 12),
Add#(b__, TLog#(stSets), 58),
Add#(c__, TLog#(stSets), 52),
Add#(1, d__, stWays)
);
    PrefetchCalculator#(8, 8) calculator <- mkPrefetchCalculator(prefetchThreshold, divTableFile);
    SignatureTable#(4, stSets, stWays) st <- mkSignatureTable;
    PatternTable#(ptEntries, 4) pt <- mkPatternTable;
    PrefetchFilter#(1024, 6, 8) filter <- mkPrefetchFilter;
    Fifo#(8, LineAddr) addrToPrefetch <- mkOverflowBypassFifo;
    Array #(Reg #(EventsPrefetcher)) perf_events <- mkDRegOR (3, unpack (0));

    Bool verbose = False;

    rule ptlFromStToPt;
        let ptl <- st.getPTLookupEntry;
        pt.doPTLookup(ptl);
    endrule

    rule ptuFromStToPt;
        let ptu <- st.getPTUpdateEntry;
        pt.doPTUpdate(ptu);
    endrule

    rule ptlFromCalcToPt;
        let ptl <- calculator.getPTLookupEntry;
        pt.doPTLookup(ptl);
    endrule

    rule pteFromPtToCalc;
        let {ptl, pte} <- pt.getPTEntry;
        Prob alpha = filter.getCurrAlpha;
        calculator.submitCandidates(ptl.addr, ptl.sig, alpha, ptl.currCumProb, pte.sigCount, pte.deltaCounts, ptl.depth);
    endrule
    
    rule pfAddrFromCalcToFilter;
        let lineAddr <- calculator.getNextPrefetchAddr;
        let depth <- calculator.getNextPrefetchAddrDepth;
        EventsPrefetcher evt = unpack(0);
        evt.evt_0 = extend(filter.getCurrAlpha);
        if (depth >= 2) begin
            evt.evt_1 = 1;
        end
        evt.evt_2 = 1;
        evt.evt_3 = extend(depth);
        perf_events[1] <= evt;
        filter.canPrefetchReq(lineAddr);
    endrule

    rule getAddrToPrefetch;
        let {canPrefetch, addr} <- filter.canPrefetchResp;
        if (canPrefetch || !useFilter) begin
            addrToPrefetch.enq(addr);
        end
    endrule

    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        if (verbose) $display("%t Prefetcher:reportAccess %x", $time, addr);
        st.reportAccess(truncateLSB(addr));
        filter.reportAccess(truncateLSB(addr), hitMiss);
    endmethod

    method ActionValue#(Addr) getNextPrefetchAddr();
        EventsPrefetcher evt = unpack(0);
        evt.evt_4 = 1;
        perf_events[2] <= evt;
        let lineAddr = addrToPrefetch.first;
        addrToPrefetch.deq;
        if (verbose) $display("%t Prefetcher:getNextPrefetchAddr %x", $time, Addr'{lineAddr, '0});
        return {lineAddr, '0};
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
    EventsPrefetcher evt;
    evt.evt_0 = perf_events[0].evt_0;
    evt.evt_1 = perf_events[0].evt_1;
    evt.evt_2 = perf_events[0].evt_2;
    evt.evt_3 = perf_events[0].evt_3;
    evt.evt_4 = perf_events[0].evt_4;
    return evt;
    endmethod
`endif
endmodule