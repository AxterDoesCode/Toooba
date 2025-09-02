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
import SpecialRegs::*;

`define VERBOSE False

module mkBlockPrefetcher#(Parameter#(numLinesEachWay) _)(Prefetcher) provisos (
    Alias#(lineCountT, Bit#(TLog#(TAdd#(numLinesEachWay, 1)))),
    Add#(a__, TLog#(TAdd#(numLinesEachWay, 1)), 58)
);
    Reg#(Bool) nextIsForward <- mkReg(?);
    Reg#(LineAddr) prefetchAround <- mkReg(?);
    Reg#(lineCountT) linesEachWayPrefetched <- mkReg(fromInteger(valueOf(numLinesEachWay)));
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        if (hitMiss == MISS) begin
            if (`VERBOSE) $display("%t Prefetcher report MISS %h", $time, addr);
            nextIsForward <= True;
            prefetchAround <= getLineAddr(addr);
            linesEachWayPrefetched <= 0;
        end
        else 
            if (`VERBOSE) $display("%t Prefetcher report HIT %h", $time, addr);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (linesEachWayPrefetched != fromInteger(valueOf(numLinesEachWay)));
        nextIsForward <= !nextIsForward;
        if (nextIsForward) begin
            Addr retAddr = {prefetchAround + (extend(linesEachWayPrefetched)+1), 0};
            if (`VERBOSE) $display("%t Prefetcher getNextPrefetchAddr requesting forward %h", $time, retAddr);
            return retAddr;
        end
        else begin
            Addr retAddr = {prefetchAround - (extend(linesEachWayPrefetched)+1), 0};
            if (`VERBOSE) $display("%t Prefetcher getNextPrefetchAddr requesting backward %h", $time, retAddr);
            linesEachWayPrefetched <= linesEachWayPrefetched + 1;
            return retAddr;
        end
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif

endmodule

typedef enum {
  EMPTY = 2'b00, INIT = 2'b01, TRANSIENT = 2'b10, STEADY = 2'b11
} StrideState deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(12) lastAddr; 
    Bit#(13) stride;
    StrideState state;
    Bit#(4) cLinesPrefetched; //Stores how many cache lines have been prefetched for this instruction
} StrideEntry deriving (Bits, Eq, FShow);

module mkStridePCPrefetcher#(Parameter#(strideTableSize) _, Parameter#(cLinesAheadToPrefetch) __)(PCPrefetcher)
provisos(
    Alias#(strideTableIndexT, Bit#(TLog#(strideTableSize))),
    Add#(a__, TLog#(strideTableSize), 16)
    );
    RWBramCore#(strideTableIndexT, StrideEntry) strideTable <- mkRWBramCoreForwarded;
    FIFOF#(Tuple3#(Addr, Bit#(16), HitOrMiss)) memAccesses <- mkSizedBypassFIFOF(8);
    Reg#(Tuple3#(Addr, Bit#(16), HitOrMiss)) rdRespEntry <- mkReg(?);

    Fifo#(8, Addr) addrToPrefetch <- mkOverflowPipelineFifo;
    FIFO#(Tuple3#(StrideEntry, Addr, Bit#(16))) strideEntryForPrefetch <- mkBypassFIFO();
    Reg#(Maybe#(Bit#(4))) cLinesPrefetchedLatest <- mkReg(Invalid);
    PulseWire holdReadReq <- mkPulseWire;

    rule sendReadReq if (!holdReadReq);
        match {.addr, .pcHash, .hitMiss} = memAccesses.first;
        if (`VERBOSE) $display("%t Sending read req for %h!", $time, pcHash);
        strideTable.rdReq(truncate(pcHash));
        rdRespEntry <= memAccesses.first;
        memAccesses.deq;
    endrule


    rule updateStrideEntry;
        //Find slot in vector
        //if miss and slot empty
        //if slot init, put address, stride and move to transit
        //if slot transit or steady, verify stride, and move to steady
        //    also put last_prefetched
        //if stride wrong, move to transit
        match {.addr, .pcHash, .hitMiss} = rdRespEntry;
        strideTableIndexT index = truncate(pcHash);
        StrideEntry se = strideTable.rdResp;
        strideTable.deqRdResp;
        StrideEntry seNext = se;
        Bit#(13) observedStride = {1'b0, addr[11:0]} - {1'b0, se.lastAddr};
        if (`VERBOSE) $writeh("%t Stride Prefetcher updateStrideEntry ", $time,
            fshow(hitMiss), " ", addr,
            ". Entry ", index, " state is ", fshow(se.state), "\n");
        if (se.state == EMPTY) begin
            if (hitMiss == MISS) begin 
                seNext.lastAddr = truncate(addr);
                seNext.state = INIT;
                if (`VERBOSE) $display(", allocate entry");
            end
            else begin
                if (`VERBOSE) $display(", ignore");
            end
        end 
        else if (se.state == INIT && observedStride != 0) begin
            seNext.stride = observedStride;
            seNext.state = TRANSIENT;
            seNext.lastAddr = truncate(addr);
            if (`VERBOSE) $display(", set stride to %h", seNext.stride);
        end
        else if ((se.state == TRANSIENT || se.state == STEADY) && observedStride != 0) begin
            if (observedStride == se.stride) begin
                if (se.state == TRANSIENT) begin
                    //Here we transition from TRANSIENT to STEADY, so init this field
                    seNext.cLinesPrefetched = 0;
                end
                else begin
                    //state == STEADY
                    if (se.lastAddr[11:6] != addr[11:6]) begin
                        //This means we have crossed a cache line since last access
                        seNext.cLinesPrefetched = 
                            (se.cLinesPrefetched == 0) ? 0 : se.cLinesPrefetched - 1;
                    end
                end
                seNext.state = STEADY;
                seNext.lastAddr = truncate(addr);
                if (`VERBOSE) $display(", stride %h is confirmed!", seNext.stride);
            end
            else begin
                seNext.state = TRANSIENT;
                seNext.stride = observedStride;
                seNext.lastAddr = truncate(addr);
                if (`VERBOSE) $display(", old stride is broken! New stride: %h", seNext.stride);
            end
        end
        else
            if (`VERBOSE) $display("");
        
        strideEntryForPrefetch.enq(tuple3(seNext, addr, pcHash));
    endrule

    rule createPrefetchRequests;
        match {.se, .addr, .pcHash} = strideEntryForPrefetch.first;
        //If this rule is looping, then we'll have a valid cLinesPrefetchedLatest
        Bit#(4) cLinesPrefetched = fromMaybe(se.cLinesPrefetched, cLinesPrefetchedLatest);

        if (se.state == STEADY && 
            cLinesPrefetched != 
            fromInteger(valueof(cLinesAheadToPrefetch))) begin
            //can prefetch
            
            Bit#(13) strideToUse;
            Bit#(13) cLineSize = fromInteger(valueof(DataSz));
            if (se.stride[12] == 1 && se.stride > -cLineSize) begin
                //stride is negative and jumps less than one cline
                strideToUse = -cLineSize;
            end
            else if (se.stride[12] == 0 && se.stride < cLineSize) begin
                //stride is positive and jumps less than one cline
                strideToUse = cLineSize;
            end 
            else begin
                strideToUse = se.stride;
            end

            let reqAddr = addr + 
                (signExtend(strideToUse) * zeroExtend(cLinesPrefetched + 1));

            addrToPrefetch.enq(reqAddr);
            // We will still be processing this StrideEntry next cycle, 
            // so hold off any potential read requests until we do a writeback
            holdReadReq.send();
            cLinesPrefetchedLatest <= Valid(cLinesPrefetched + 1);
            if (`VERBOSE) $display("%t Stride Prefetcher getNextPrefetchAddr requesting %h for entry %h", $time, reqAddr, pcHash[7:0]);
        end
        else begin
            //cant prefetch
            if (`VERBOSE) $display("%t Stride Prefetcher no possible prefetch for entry %h", $time, strideTableIndexT'(truncate(pcHash)));
            strideEntryForPrefetch.deq;
            se.cLinesPrefetched = cLinesPrefetched;
            cLinesPrefetchedLatest <= Invalid;
            strideTable.wrReq(truncate(pcHash), se);
        end
    endrule

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        memAccesses.enq(tuple3 (addr, pcHash, hitMiss));
    endmethod

    method ActionValue#(Addr) getNextPrefetchAddr;
        addrToPrefetch.deq;
        return addrToPrefetch.first;
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif

endmodule

typedef enum {
  INIT = 2'd0, TRANSIENT = 2'd1, STEADY = 2'd2, NO_PRED = 2'd3
} StrideState2 deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(12) lastAddr; 
    Int#(12) stride;
    Bit#(4) cLinesPrefetched; //Stores how many cache lines have been prefetched for this instruction
    StrideState2 state;
} StrideEntry2 deriving (Bits, Eq, FShow);

module mkStride2PCPrefetcher#(Parameter#(strideTableSize) _, Parameter#(cLinesAheadToPrefetch) __)(PCPrefetcher)
provisos(
    Alias#(strideTableIndexT, Bit#(TLog#(strideTableSize))),
    Add#(a__, TLog#(strideTableSize), 16)
    );
    RWBramCore#(strideTableIndexT, StrideEntry2) strideTable <- mkRWBramCoreForwarded;
    FIFOF#(Tuple3#(Addr, Bit#(16), HitOrMiss)) memAccesses <- mkSizedBypassFIFOF(8);
    Reg#(Tuple3#(Addr, Bit#(16), HitOrMiss)) rdRespEntry <- mkReg(?);

    Fifo#(8, Addr) addrToPrefetch <- mkOverflowPipelineFifo;
    FIFO#(Tuple3#(StrideEntry2, Addr, Bit#(16))) strideEntryForPrefetch <- mkBypassFIFO();
    Reg#(Maybe#(Bit#(4))) cLinesPrefetchedLatest <- mkReg(?);
    PulseWire holdReadReq <- mkPulseWire;
`ifdef PERFORMANCE_MONITORING
    Array #(Reg #(EventsPrefetcher)) perf_events <- mkDRegOR (3, unpack (0));
`endif

    rule sendReadReq if (!holdReadReq);
        match {.addr, .pcHash, .hitMiss} = memAccesses.first;
        if (`VERBOSE) $display("%t Sending read req for %h!", $time, pcHash);
        strideTable.rdReq(truncate(pcHash));
        rdRespEntry <= memAccesses.first;
        memAccesses.deq;
    endrule


    rule updateStrideEntry;
        //Find slot in vector
        //if miss and slot empty
        //if slot init, put address, stride and move to transit
        //if slot transit or steady, verify stride, and move to steady
        //    also put last_prefetched
        //if stride wrong, move to transit
        match {.addr, .pcHash, .hitMiss} = rdRespEntry;
        strideTableIndexT index = truncate(pcHash);
        StrideEntry2 se = strideTable.rdResp;
        strideTable.deqRdResp;
        StrideEntry2 seNext = se;
        Int#(12) observedStride = unpack(addr[11:0] - se.lastAddr);
        if (`VERBOSE) $display("%t Stride Prefetcher updateStrideEntry ", $time,
            fshow(hitMiss), " ", addr,
            ". Entry ", index, " state is ", fshow(se.state), "\n");
        if (se.state == INIT && observedStride != 0) begin
            if (se.stride == observedStride) begin
                //fast track to steady
                seNext.state = STEADY;
                if (`VERBOSE) $display(", stride matches so fast track back to STEADY");
            end
            else begin
                seNext.stride = observedStride;
                seNext.state = TRANSIENT;
                if (`VERBOSE) $display(", stride doesn't match, so set to %h", seNext.stride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else if (se.state == TRANSIENT && observedStride != 0) begin
            if (observedStride == se.stride) begin
                //stride confimed, move to steady
                seNext.cLinesPrefetched = 0;
                seNext.state = STEADY;
                if (`VERBOSE) $display(", stride %h is confirmed!", seNext.stride);
            end
            else begin
                //We're seeing random accesses, go to no pred
                seNext.state = NO_PRED;
                seNext.stride = observedStride;
                if (`VERBOSE) $display(", we have a random stride (%h), go to NO_PRED", seNext.stride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else if (se.state == STEADY && observedStride != 0) begin
            if (observedStride == se.stride) begin
                if (se.lastAddr[11:6] != addr[11:6]) begin
                    //This means we have crossed a cache line since last access
                    seNext.cLinesPrefetched = 
                        (se.cLinesPrefetched == 0) ? 0 : se.cLinesPrefetched - 1;
                end
                if (`VERBOSE) $display(", stride %h stays confirmed!", seNext.stride);
            end
            else begin
                //We jump to some other random location, so reset number of lines prefetched
                seNext.cLinesPrefetched = 0;
                seNext.state = INIT;
                if (`VERBOSE) $display(", random jump (%x)! Move to INIT, don't reset stride", observedStride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else if (se.state == NO_PRED && observedStride != 0) begin
            if (observedStride == se.stride) begin
                seNext.state = TRANSIENT;
                if (`VERBOSE) $display(", have repeated stride: %h, move to TRANSIENT", seNext.stride);
            end
            else begin
                seNext.stride = observedStride;
                if (`VERBOSE) $display(", have random stride: %h", seNext.stride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else
            if (`VERBOSE) $display("");
        
        strideEntryForPrefetch.enq(tuple3(seNext, addr, pcHash));
    endrule

    rule createPrefetchRequests;
        match {.se, .addr, .pcHash} = strideEntryForPrefetch.first;
        //If this rule is looping, then we'll have a valid cLinesPrefetchedLatest
        Bit#(4) cLinesPrefetched = fromMaybe(se.cLinesPrefetched, cLinesPrefetchedLatest);

        Int#(16) cLineSize = fromInteger(valueof(DataSz));
        Int#(16) strideToUse = signExtend(se.stride);
        if (abs(strideToUse) < cLineSize) begin
            strideToUse = (strideToUse < 0) ? -cLineSize : cLineSize; 
        end
        Bit#(16) jumpDist = pack(strideToUse) * zeroExtend(cLinesPrefetched+1);
        let reqAddr = addr + signExtend(jumpDist);

        if (se.state == STEADY && 
            cLinesPrefetched != 
            fromInteger(valueof(cLinesAheadToPrefetch)) &&
            reqAddr[63:12] == addr[63:12] //Check if same page
        ) begin
            //can prefetch

            addrToPrefetch.enq(reqAddr);
`ifdef PERFORMANCE_MONITORING
            EventsPrefetcher evt = unpack(0);
            evt.evt_2 = 1;
            if (se.stride < 'd64) begin
                evt.evt_3 = 1;
            end
            perf_events[0] <= evt;
`endif
            // We will still be processing this StrideEntry next cycle, 
            // so hold off any potential read requests until we do a writeback
            holdReadReq.send();
            cLinesPrefetchedLatest <= Valid(cLinesPrefetched + 1);
            if (`VERBOSE) $display("%t Stride Prefetcher getNextPrefetchAddr requesting %h for entry %h", $time, reqAddr, pcHash[7:0]);
        end
        else begin
            //cant prefetch
            if (`VERBOSE) $display("%t Stride Prefetcher no possible prefetch for entry %h", $time, strideTableIndexT'(truncate(pcHash)));
            strideEntryForPrefetch.deq;
            se.cLinesPrefetched = cLinesPrefetched;
            cLinesPrefetchedLatest <= Invalid;
            strideTable.wrReq(truncate(pcHash), se);
        end
    endrule

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        Bit#(16) pch = {8'h0, pcHash[15:8] ^ pcHash[7:0]};
        memAccesses.enq(tuple3 (addr, pcHash, hitMiss));
    endmethod

    method ActionValue#(Addr) getNextPrefetchAddr;
        addrToPrefetch.deq;
        return addrToPrefetch.first;
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        let evt = EventsPrefetcher {
            evt_0: (!memAccesses.notFull) ? 1 : 0,
            evt_1: (!addrToPrefetch.notFull) ? 1 : 0,
            evt_2: perf_events[0].evt_2,
            evt_3: perf_events[0].evt_3,
            evt_4: 0
        };
        return evt;
    endmethod
`endif

endmodule

typedef struct {
    Addr lastAddr; 
    Int#(13) stride;
    Bit#(2) confidence;
} SimpleStrideEntry deriving (Bits, Eq, FShow);

//Reasonable parameter values:
//strideTableSize = 512
//cLinesAheadToPrefetch = 2
//minConfidenceToPrefetch = 2
module mkSimpleStridePCPrefetcher#(Parameter#(strideTableSize) _, Parameter#(cLinesAheadToPrefetch) __, Parameter#(minConfidenceToPrefetch) ___)(PCPrefetcher)
provisos(
    Alias#(strideTableIndexT, Bit#(TLog#(strideTableSize))),
    Add#(a__, TLog#(strideTableSize), 16)
    );
    Vector#(strideTableSize, Reg#(SimpleStrideEntry)) strideTable <- replicateM(mkReg(unpack(0)));

    Reg#(Addr) addrToPrefetch <- mkReg(0);
    Reg#(Int#(13)) strideToPrefetch <- mkReg(0);
    Ehr#(2, Bit#(3)) prefetchesIssued <- mkEhr(fromInteger(valueOf(cLinesAheadToPrefetch)));

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        if (`VERBOSE) $display("%t reportAccess %x %x", $time, addr, pcHash);
        strideTableIndexT idx = truncate(pcHash);
        SimpleStrideEntry entry = strideTable[idx];
        Int#(13) calc_stride = unpack(truncate(addr - entry.lastAddr));
        entry.lastAddr = addr;
        if (calc_stride == entry.stride) begin
            if (entry.confidence != 2'd3) begin
                entry.confidence = entry.confidence + 1;
            end
        end
        else begin
            if (entry.confidence > 0) begin
                entry.confidence = entry.confidence - 1;
            end
            if (entry.confidence < fromInteger(valueOf(minConfidenceToPrefetch))) begin
                entry.stride = calc_stride;
                entry.confidence = 0;
            end
        end
        
        if (entry.confidence >= fromInteger(valueOf(minConfidenceToPrefetch))) begin
            prefetchesIssued[1] <= 0;
            addrToPrefetch <= addr;
            strideToPrefetch <= entry.stride;
        end
        strideTable[idx] <= entry;
    endmethod

    method ActionValue#(Addr) getNextPrefetchAddr 
            if (prefetchesIssued[0] < fromInteger(valueOf(cLinesAheadToPrefetch)));
        
        Int#(13) strideToUse = strideToPrefetch;
        Int#(13) cLineSize = fromInteger(valueof(DataSz));
        if (abs(strideToPrefetch) < cLineSize) begin
            strideToUse = (strideToPrefetch < 0) ? -cLineSize : cLineSize;
        end

        prefetchesIssued[0] <= prefetchesIssued[0] + 1; 
        let reqAddr = addrToPrefetch + 
            (pack(signExtend(strideToUse)) * zeroExtend(prefetchesIssued[0] + 1));

        check(reqAddr[63:12] == addrToPrefetch[63:12]);
        if (`VERBOSE) $display("%t getNextPrefetchAddr returning %x", $time, reqAddr);
        return reqAddr;
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif

endmodule

typedef enum {
    EMPTY = 3'd0, INIT = 3'd1, TRANSIENT = 3'd2, STEADY1 = 3'd3, 
    STEADY2 = 3'd4, STEADY3 = 3'd5, STEADY4 = 4'd6, STEADYLAST = 3'd7
} StrideStateAdaptive deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(12) lastAddr; 
    Bit#(13) stride;
    StrideStateAdaptive state;
    Bit#(4) cLinesPrefetched; //Stores how many cache lines have been prefetched for this instruction
} StrideEntryAdaptive deriving (Bits, Eq, FShow);

module mkStrideAdaptivePCPrefetcher#(
    Parameter#(strideTableSize) _, 
    Parameter#(cLinesPrefetchMin) __,
    Parameter#(cLinesSmallStridePrefetchMax) ___,
    Parameter#(cLinesBigStridePrefetchMax) ____
    )(PCPrefetcher)
provisos(
    Alias#(strideTableIndexT, Bit#(TLog#(strideTableSize))),
    Add#(a__, TLog#(strideTableSize), 16)
    );
    RWBramCore#(strideTableIndexT, StrideEntryAdaptive) strideTable <- mkRWBramCoreForwarded;
    FIFOF#(Tuple3#(Addr, Bit#(16), HitOrMiss)) memAccesses <- mkSizedBypassFIFOF(8);
    Reg#(Tuple3#(Addr, Bit#(16), HitOrMiss)) rdRespEntry <- mkReg(?);

    Fifo#(8, Addr) addrToPrefetch <- mkOverflowPipelineFifo;
    FIFO#(Tuple3#(StrideEntryAdaptive, Addr, Bit#(16))) strideEntryForPrefetch <- mkBypassFIFO();
    Reg#(Maybe#(Bit#(4))) cLinesPrefetchedLatest <- mkReg(?);
    PulseWire holdReadReq <- mkPulseWire;

    function StrideStateAdaptive incrementSteady(StrideStateAdaptive state);
        case (state)
            STEADY1: return STEADY2;
            STEADY2: return STEADY3; 
            STEADY3: return STEADY4; 
            STEADY4: return STEADYLAST; 
            STEADYLAST: return STEADYLAST; 
            default: return STEADY1;
        endcase
    endfunction

    function Bool stateAtLeastSteady(StrideStateAdaptive state);
        return (state == STEADY1 ||
                state == STEADY2 ||
                state == STEADY3 ||
                state == STEADY4 ||
                state == STEADYLAST);
    endfunction

    function Bit#(4) cLinesAheadToPrefetch(StrideStateAdaptive state, Bit#(13) stride);
        let absStride = abs(stride);
        if (absStride <= 8) begin
            if (state == STEADY4 || state == STEADYLAST) begin
                return fromInteger(valueof(cLinesSmallStridePrefetchMax));
            end
            else begin
                return fromInteger(valueof(cLinesPrefetchMin));
            end
        end
        else begin
            //big strides
            if (state == STEADYLAST) begin
                return fromInteger(valueof(cLinesBigStridePrefetchMax));
            end
            else if (state == STEADY3 || state == STEADY4) begin
                return fromInteger(valueof(cLinesBigStridePrefetchMax))-1;
            end
            else begin
                return fromInteger(valueof(cLinesPrefetchMin));
            end
        end
    endfunction

    rule sendReadReq if (!holdReadReq);
        match {.addr, .pcHash, .hitMiss} = memAccesses.first;
        if (`VERBOSE) $display("%t Sending read req for %h!", $time, pcHash);
        strideTable.rdReq(truncate(pcHash));
        rdRespEntry <= memAccesses.first;
        memAccesses.deq;
    endrule


    rule updateStrideEntry;
        //Find slot in vector
        //if miss and slot empty
        //if slot init, put address, stride and move to transit
        //if slot transit or steady, verify stride, and move to steady
        //    also put last_prefetched
        //if stride wrong, move to transit
        match {.addr, .pcHash, .hitMiss} = rdRespEntry;
        strideTableIndexT index = truncate(pcHash);
        StrideEntryAdaptive se = strideTable.rdResp;
        strideTable.deqRdResp;
        StrideEntryAdaptive seNext = se;
        Bit#(13) observedStride = {1'b0, addr[11:0]} - {1'b0, se.lastAddr};
        if (`VERBOSE) $writeh("%t Stride Prefetcher updateStrideEntry ", $time,
            fshow(hitMiss), " ", addr,
            ". Entry ", index, " state is ", fshow(se.state), "\n");
        if (se.state == EMPTY) begin
            if (hitMiss == MISS) begin 
                seNext.lastAddr = truncate(addr);
                seNext.state = INIT;
                if (`VERBOSE) $display(", allocate entry");
            end
            else begin
                if (`VERBOSE) $display(", ignore");
            end
        end 
        else if (se.state == INIT && observedStride != 0) begin
            seNext.stride = observedStride;
            seNext.state = TRANSIENT;
            seNext.lastAddr = truncate(addr);
            if (`VERBOSE) $display(", set stride to %h", seNext.stride);
        end
        else if (se.state == TRANSIENT && observedStride != 0) begin
            if (observedStride == se.stride) begin
                //Here we transition from TRANSIENT to STEADY, so init this field
                seNext.cLinesPrefetched = 0;
                seNext.state = STEADY1;
                if (`VERBOSE) $display(", stride %h is confirmed!", seNext.stride);
            end
            else begin
                seNext.state = TRANSIENT;
                seNext.stride = observedStride;
                if (`VERBOSE) $display(", old stride is broken! New stride: %h", seNext.stride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else if (stateAtLeastSteady(se.state) && observedStride != 0) begin
            if (observedStride == se.stride) begin
                if (se.lastAddr[11:6] != addr[11:6]) begin
                    //This means we have crossed a cache line since last access
                    seNext.cLinesPrefetched = 
                        (se.cLinesPrefetched == 0) ? 0 : se.cLinesPrefetched - 1;
                end
                seNext.state = incrementSteady(se.state);
                if (`VERBOSE) $display(", stride %h is sustained, advance STEADY number!", se.stride);
            end
            else if (se.state == STEADY4 || se.state == STEADYLAST) begin
                //Leniency towards some stride changes
                seNext.state = STEADY1;
                seNext.cLinesPrefetched = 0; //We've jumped to some other address, so start fetching again!
                if (`VERBOSE) $display(", old stride is broken, but tolerate it! Keep old stride: %h", se.stride);
            end
            else begin
                seNext.state = TRANSIENT;
                seNext.stride = observedStride;
                if (`VERBOSE) $display(", old stride is broken! New stride: %h", seNext.stride);
            end
            seNext.lastAddr = truncate(addr);
        end
        else
            if (`VERBOSE) $display("");
        
        strideEntryForPrefetch.enq(tuple3(seNext, addr, pcHash));
    endrule

    rule createPrefetchRequests;
        match {.se, .addr, .pcHash} = strideEntryForPrefetch.first;
        //If this rule is looping, then we'll have a valid cLinesPrefetchedLatest
        Bit#(4) cLinesPrefetched = fromMaybe(se.cLinesPrefetched, cLinesPrefetchedLatest);

        if (stateAtLeastSteady(se.state) && 
            cLinesPrefetched != 
            cLinesAheadToPrefetch(se.state, se.stride)) begin
            //can prefetch
            
            Bit#(13) strideToUse;
            Bit#(13) cLineSize = fromInteger(valueof(DataSz));
            if (se.stride[12] == 1 && se.stride > -cLineSize) begin
                //stride is negative and jumps less than one cline
                strideToUse = -cLineSize;
            end
            else if (se.stride[12] == 0 && se.stride < cLineSize) begin
                //stride is positive and jumps less than one cline
                strideToUse = cLineSize;
            end 
            else begin
                strideToUse = se.stride;
            end

            let reqAddr = addr + 
                (signExtend(strideToUse) * zeroExtend(cLinesPrefetched + 1));

            addrToPrefetch.enq(reqAddr);
            // We will still be processing this StrideEntry next cycle, 
            // so hold off any potential read requests until we do a writeback
            holdReadReq.send();
            cLinesPrefetchedLatest <= Valid(cLinesPrefetched + 1);
            if (`VERBOSE) $display("%t Stride Prefetcher getNextPrefetchAddr requesting %h for entry %h", $time, reqAddr, pcHash[7:0]);
        end
        else begin
            //cant prefetch
            if (`VERBOSE) $display("%t Stride Prefetcher no possible prefetch for entry %h", $time, strideTableIndexT'(truncate(pcHash)));
            strideEntryForPrefetch.deq;
            se.cLinesPrefetched = cLinesPrefetched;
            cLinesPrefetchedLatest <= Invalid;
            strideTable.wrReq(truncate(pcHash), se);
        end
    endrule

    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        memAccesses.enq(tuple3 (addr, pcHash, hitMiss));
    endmethod

    method ActionValue#(Addr) getNextPrefetchAddr;
        addrToPrefetch.deq;
        return addrToPrefetch.first;
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif

endmodule