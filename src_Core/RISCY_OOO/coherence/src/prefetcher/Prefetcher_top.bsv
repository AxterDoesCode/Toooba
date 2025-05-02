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

import ISA_Decls   :: *;
import CrossBar::*;
import GetPut::*;
import RWBramCore::*;
import FIFO::*;
import ConfigReg::*;
import Fifos::*;
import FIFOF::*;
import SpecialFIFOs :: *;
import Ehr::*;
import CacheUtils::*;
import CCTypes::*;
import Types::*;
import Vector::*;
import BuildVector::*;
import ProcTypes::*;
import CHERICap::*;
import CHERICC_Fat::*;
import MemoryTypes::*;
import TlbTypes::*;

import Prefetcher_intf::*;
import InstructionPrefetchers::*;
import StridePrefetchers::*;
import MarkovPrefetchers::*;
import CheriPrefetchers::*;
import NewCheriPrefetchers::*;
import ModifiedCheriPrefetchers::*;
import SignaturePathPrefetcher::*;

`define VERBOSE True

`ifdef DATA_PREFETCHER_IN_L1LL
    `define DATA_PREFETCHER_IN_L1
    `define DATA_PREFETCHER_IN_LL
`endif

`ifdef DATA_PREFETCHER_IN_L1_FORWARDING
    `define DATA_PREFETCHER_IN_L1
`endif

module mkDoNothingPrefetcher(Prefetcher);
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (False);
        return 64'h0;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule

module mkAlwaysRequestPrefetcher(Prefetcher);
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr;
        return 64'h8000ff00;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule

module mkAlwaysRequestTlbPrefetcher#(TlbToPrefetcher toTlb)(Prefetcher);
    rule reqTlb;
        $display ("%t Prefetcher req to TLB", $time);
        CapPipe start = almightyCap;
        let cp = setAddr(start, 64'hc000dead).value;
        toTlb.prefetcherReq(PrefetcherReqToTlb{
            cap: cp,
            id: 0
        });
    endrule
    rule asd;
        $display ("%t Prefetcher tlb deqprefetcherresp", $time);
        toTlb.deqPrefetcherResp;
    endrule
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        $display ("%t Prefetcher reportAccess %h", $time, addr, fshow(hitMiss));
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (False);
        $display ("%t Prefetcher getNextPrefetchAddr", $time);
        toTlb.deqPrefetcherResp;
        return toTlb.prefetcherResp.paddr;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule

module mkPrintPrefetcher(Prefetcher);
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        if (hitMiss == HIT) begin
            if (`VERBOSE) $display("%t PrintPrefetcher report HIT %h", $time, addr);
        end
        else begin
            if (`VERBOSE) $display("%t PrintPrefetcher report MISS %h", $time, addr);
        end
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (False);
        return 64'h0;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule


module mkPCPrefetcherAdapter#(module#(Prefetcher) mkPrefetcher)(PCPrefetcher);
    let p <- mkPrefetcher;
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        p.reportAccess(addr, hitMiss);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr;
        let x <- p.getNextPrefetchAddr;
        return x;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return p.events;
    endmethod
`endif
endmodule

module mkCheriPrefetcherAdapter#(module#(Prefetcher) mkPrefetcher)(CheriPrefetcher);
    let p <- mkPrefetcher;
    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if (!isPrefetch && memOp == Ld) p.reportAccess(addr, hitMiss);
    endmethod
    method Action reportCacheDataArrival(CLine lineWithTags, Addr accessAddr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    endmethod
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let addr <- p.getNextPrefetchAddr;
        return PendingPrefetch {
            addr: addr,
            cap: almightyCap,
            nextLevel: False,
            auxData: NoPrefetchAuxData
        };
    endmethod
    method ActionValue#(PrefetcherBroadcastData) getBroadcastData if (False);
        return ?;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return p.events;
    endmethod
`endif
endmodule


module mkCheriPCPrefetcherAdapterFromPC#(module#(PCPrefetcher) mkPrefetcher)(CheriPCPrefetcher);
    let p <- mkPrefetcher;
    method Action reportAccess(Addr addr, PCHash pcHash, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        if(!isPrefetch && memOp == Ld) p.reportAccess(addr, hash(pcHash), hitMiss);
    endmethod
    method Action reportCacheDataArrival(CLine lineWithTags, Addr accessAddr, PCHash pcHash, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    endmethod
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let addr <- p.getNextPrefetchAddr;
        return PendingPrefetch {
            addr: addr,
            cap: almightyCap,
            nextLevel: False,
            auxData: NoPrefetchAuxData
        };
    endmethod
    method ActionValue#(PrefetcherBroadcastData) getBroadcastData if (False);
        return ?;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return p.events;
    endmethod
`endif
endmodule

module mkCheriPCPrefetcherAdapterFromCheri#(module#(CheriPrefetcher) mkPrefetcher)(CheriPCPrefetcher);
    let p <- mkPrefetcher;
    method Action reportAccess(Addr addr, PCHash pcHash, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        p.reportAccess(addr, hitMiss, memOp, isPrefetch, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod
    method Action reportCacheDataArrival(CLine lineWithTags, Addr accessAddr, PCHash pcHash, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        p.reportCacheDataArrival(lineWithTags, accessAddr, memOp, wasMiss, wasPrefetch, wasNextLevel, hasSuccessor, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x <- p.getNextPrefetchAddr;
        return x;
    endmethod
    method ActionValue#(PrefetcherBroadcastData) getBroadcastData;
        let x <- p.getBroadcastData;
        return x;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
        p.sendBroadcastData(data);
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return p.events;
    endmethod
`endif
endmodule

module mkNextLevelPrefetcherAdapter#(module#(CheriPCPrefetcher) mkPrefetcher)(CheriPCPrefetcher);
    let p <- mkPrefetcher;
    method Action reportAccess(Addr addr, PCHash pcHash, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        p.reportAccess(addr, pcHash, hitMiss, memOp, isPrefetch, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod
    method Action reportCacheDataArrival(CLine lineWithTags, Addr accessAddr, PCHash pcHash, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        p.reportCacheDataArrival(lineWithTags, accessAddr, pcHash, memOp, wasMiss, wasPrefetch, wasNextLevel, hasSuccessor, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let x <- p.getNextPrefetchAddr;
        x.nextLevel = True;
        return x;
    endmethod
    method ActionValue#(PrefetcherBroadcastData) getBroadcastData;
        let x <- p.getBroadcastData;
        return x;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
        p.sendBroadcastData(data);
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return p.events;
    endmethod
`endif
endmodule

module mkDoNothingPCPrefetcher(PCPrefetcher);
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (False);
        return 64'h0000000080000080;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule

module mkPrintPCPrefetcher(PCPrefetcher);
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
        if (hitMiss == HIT)
            if (`VERBOSE) $display("%t PCPrefetcher report HIT %h", $time, addr);
        else
            if (`VERBOSE) $display("%t PCPrefetcher report MISS %h", $time, addr);
    endmethod
    method ActionValue#(Addr) getNextPrefetchAddr if (False);
        return 64'h0000000080000080;
    endmethod
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
        return unpack(0);
    endmethod
`endif
endmodule



module mkCheriPrefetcherVector#(Vector#(size, module#(CheriPrefetcher)) mkPrefetchers)
(
    PrefetcherVector#(size)
) provisos (
    Alias#(idxT, Bit#(TLog#(size)))
); 
    Vector#(size, CheriPrefetcher) prefetchers;
    for (Integer i = 0; i < valueOf(size); i=i+1) begin
        prefetchers[i] <- mkPrefetchers[i];
    end
    Fifo#(1, Tuple2#(PendingPrefetch, idxT)) prefetchRq <- mkBypassFifo;
    Fifo#(1, Tuple2#(PrefetcherBroadcastData, idxT)) broadcastRq <- mkBypassFifo;

    function XBarDstInfo#(Bit#(0),Tuple2#(PendingPrefetch, idxT)) convertPrefetchRq(idxT item, PendingPrefetch a);
        return XBarDstInfo { 
            idx: 0,
            data: tuple2(a, item)
        };
    endfunction
    function Get#(PendingPrefetch) prefetchReqGet(CheriPrefetcher p) = toGet(p.getNextPrefetchAddr);
    mkXBar(convertPrefetchRq, map(prefetchReqGet, prefetchers), vec(toPut(prefetchRq)));

    function XBarDstInfo#(Bit#(0),Tuple2#(PrefetcherBroadcastData, idxT)) convertBroadcastRq(idxT item, PrefetcherBroadcastData a);
        return XBarDstInfo { 
            idx: 0,
            data: tuple2(a, item)
        };
    endfunction
    function Get#(PrefetcherBroadcastData) broadcastReqGet(CheriPrefetcher p) = toGet(p.getBroadcastData);
    mkXBar(convertBroadcastRq, map(broadcastReqGet, prefetchers), vec(toPut(broadcastRq)));

    method ActionValue#(Tuple2#(PendingPrefetch, idxT)) getNextPrefetchAddr;
        prefetchRq.deq;
        return prefetchRq.first;
    endmethod

    method Action reportAccess(Bit#(TLog#(size)) idx, Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        prefetchers[idx].reportAccess(addr, hitMiss, memOp, isPrefetch, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod

    method Action reportCacheDataArrival(Bit#(TLog#(size)) idx, CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        prefetchers[idx].reportCacheDataArrival(lineWithTags, addr, memOp, wasMiss, wasPrefetch, wasNextLevel, hasSuccessor, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
    endmethod

    method ActionValue#(Tuple2#(PrefetcherBroadcastData, idxT)) getBroadcastData;
        broadcastRq.deq;
        return broadcastRq.first;
    endmethod
    method Action sendBroadcastData(idxT idx, PrefetcherBroadcastData data);
        prefetchers[idx].sendBroadcastData(data);
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
    //IMPORTANT design to get events only from Core 0
        return prefetchers[0].events;
    endmethod
`endif
endmodule



module mkCheriPCPrefetcherMultiplier#(
    Vector#(size, module#(CheriPCPrefetcher)) mkPrefetchers
)(CheriPCPrefetcher);

    Bool verbose = False;

    Vector#(size, CheriPCPrefetcher) prefetchers;
    for (Integer i = 0; i < valueOf(size); i=i+1) begin
        prefetchers[i] <- mkPrefetchers[i];
    end
    Fifo#(1, PendingPrefetch) prefetchRq <- mkBypassFifo;
    Fifo#(1, PrefetcherBroadcastData) broadcastRq <- mkBypassFifo;

    function XBarDstInfo#(Bit#(0), PendingPrefetch) convertPrefetchRq(Bit#(TLog#(size)) item, PendingPrefetch a);
        return XBarDstInfo { idx: 0, data: a };
    endfunction
    function Get#(PendingPrefetch) prefetchReqGet(CheriPCPrefetcher p) = toGet(p.getNextPrefetchAddr);
    mkXBar(convertPrefetchRq, map(prefetchReqGet, prefetchers), vec(toPut(prefetchRq)));

    function XBarDstInfo#(Bit#(0), PrefetcherBroadcastData) convertBroadcastRq(Bit#(TLog#(size)) item, PrefetcherBroadcastData a);
        return XBarDstInfo { idx: 0, data: a };
    endfunction
    function Get#(PrefetcherBroadcastData) broadcastReqGet(CheriPCPrefetcher p) = toGet(p.getBroadcastData);
    mkXBar(convertBroadcastRq, map(broadcastReqGet, prefetchers), vec(toPut(broadcastRq)));

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        prefetchRq.deq;
        return prefetchRq.first;
    endmethod

    method Action reportAccess(Addr addr, PCHash pcHash, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].reportAccess(addr, pcHash, hitMiss, memOp, isPrefetch, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
        end
    endmethod

    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, PCHash pcHash, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].reportCacheDataArrival(lineWithTags, addr, pcHash, memOp, wasMiss, wasPrefetch, wasNextLevel, hasSuccessor, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
        end
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData;
        broadcastRq.deq;
        return broadcastRq.first;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].sendBroadcastData(data);
        end
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
    //IMPORTANT design to get events only from Core 0
        return prefetchers[0].events;
    endmethod
`endif
endmodule



module mkCheriPrefetcherMultiplier#(
    Vector#(size, module#(CheriPrefetcher)) mkPrefetchers
)(CheriPrefetcher);

    Bool verbose = False;

    Vector#(size, CheriPrefetcher) prefetchers;
    for (Integer i = 0; i < valueOf(size); i=i+1) begin
        prefetchers[i] <- mkPrefetchers[i];
    end
    Fifo#(1, PendingPrefetch) prefetchRq <- mkBypassFifo;
    Fifo#(1, PrefetcherBroadcastData) broadcastRq <- mkBypassFifo;

    function XBarDstInfo#(Bit#(0), PendingPrefetch) convertPrefetchRq(Bit#(TLog#(size)) item, PendingPrefetch a);
        return XBarDstInfo { idx: 0, data: a };
    endfunction
    function Get#(PendingPrefetch) prefetchReqGet(CheriPrefetcher p) = toGet(p.getNextPrefetchAddr);
    mkXBar(convertPrefetchRq, map(prefetchReqGet, prefetchers), vec(toPut(prefetchRq)));

    function XBarDstInfo#(Bit#(0), PrefetcherBroadcastData) convertBroadcastRq(Bit#(TLog#(size)) item, PrefetcherBroadcastData a);
        return XBarDstInfo { idx: 0, data: a };
    endfunction
    function Get#(PrefetcherBroadcastData) broadcastReqGet(CheriPrefetcher p) = toGet(p.getBroadcastData);
    mkXBar(convertBroadcastRq, map(broadcastReqGet, prefetchers), vec(toPut(broadcastRq)));

    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        prefetchRq.deq;
        return prefetchRq.first;
    endmethod

    method Action reportAccess(Addr addr, HitOrMiss hitMiss, MemOp memOp, Bool isPrefetch, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].reportAccess(addr, hitMiss, memOp, isPrefetch, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
        end
    endmethod

    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, MemOp memOp, Bool wasMiss, Bool wasPrefetch, Bool wasNextLevel, Bool hasSuccessor, PrefetchAuxData prefetchAuxData, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].reportCacheDataArrival(lineWithTags, addr, memOp, wasMiss, wasPrefetch, wasNextLevel, hasSuccessor, prefetchAuxData, boundsOffset, boundsLength, boundsVirtBase, capPerms);
        end
    endmethod

    method ActionValue#(PrefetcherBroadcastData) getBroadcastData;
        broadcastRq.deq;
        return broadcastRq.first;
    endmethod
    method Action sendBroadcastData(PrefetcherBroadcastData data);
        for (Integer i = 0; i < valueOf(size); i=i+1) begin
            prefetchers[i].sendBroadcastData(data);
        end
    endmethod

`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events;
    //IMPORTANT design to get events only from Core 0
        return prefetchers[0].events;
    endmethod
`endif
endmodule



module mkL1IPrefetcher(Prefetcher);
`ifdef INSTR_PREFETCHER_IN_L1
    `ifdef INSTR_PREFETCHER_NEXT_LINE_ON_ALL
        Parameter#(1) lines <- mkParameter;
        let m <- mkNextLineOnAllPrefetcher(lines);
    `elsif INSTR_PREFETCHER_NEXT_LINE_ON_MISS
        Parameter#(1) lines <- mkParameter;
        let m <-  mkNextLineOnMissPrefetcher(lines);
    `elsif INSTR_PREFETCHER_SINGLE_WINDOW
        Parameter#(3) lines <- mkParameter;
        let m <-  mkSingleWindowPrefetcher(lines);
    `elsif INSTR_PREFETCHER_SINGLE_WINDOW_TARGET
        Parameter#(16) numLastRequests <- mkParameter;
        Parameter#(1) cacheLinesInRange <- mkParameter;
        let m <-  mkSingleWindowTargetPrefetcher(numLastRequests, cacheLinesInRange);
    `elsif INSTR_PREFETCHER_MULTI_WINDOW
        Parameter#(4) numWindows <- mkParameter;
        Parameter#(2) lines <- mkParameter;
        let m <-  mkMultiWindowPrefetcher(numWindows, lines);
    `elsif INSTR_PREFETCHER_MULTI_WINDOW_TARGET
        Parameter#(4) numWindows <- mkParameter;
        Parameter#(16) numLastRequests <- mkParameter;
        Parameter#(16) cacheLinesInRange <- mkParameter;
        let m <-  mkMultiWindowTargetPrefetcher(numWindows, numLastRequests, cacheLinesInRange);
    `endif
`else
    let m <- mkDoNothingPrefetcher;
`endif
    return m;
endmodule

module mkLLIPrefetcher(Prefetcher);
`ifdef INSTR_PREFETCHER_IN_LL
    `ifdef INSTR_PREFETCHER_NEXT_LINE_ON_ALL
        Parameter#(1) lines <- mkParameter;
        let m <-  mkNextLineOnAllPrefetcher(lines);
    `elsif INSTR_PREFETCHER_NEXT_LINE_ON_MISS
        Parameter#(1) lines <- mkParameter;
        let m <-  mkNextLineOnMissPrefetcher(lines);
    `elsif INSTR_PREFETCHER_SINGLE_WINDOW
        Parameter#(3) lines <- mkParameter;
        let m <-  mkSingleWindowPrefetcher(lines);
    `elsif INSTR_PREFETCHER_SINGLE_WINDOW_TARGET
        Parameter#(16) numLastRequests <- mkParameter;
        Parameter#(1) cacheLinesInRange <- mkParameter;
        let m <-  mkSingleWindowTargetPrefetcher(numLastRequests, cacheLinesInRange);
    `elsif INSTR_PREFETCHER_MULTI_WINDOW
        Parameter#(4) numWindows <- mkParameter;
        Parameter#(2) lines <- mkParameter;
        let m <-  mkMultiWindowPrefetcher(numWindows, lines);
    `elsif INSTR_PREFETCHER_MULTI_WINDOW_TARGET
        Parameter#(4) numWindows <- mkParameter;
        Parameter#(16) numLastRequests <- mkParameter;
        Parameter#(3) cacheLinesInRange <- mkParameter;
        let m <-  mkMultiWindowTargetPrefetcher(numWindows, numLastRequests, cacheLinesInRange);
    `endif
`else
    let m <- mkDoNothingPrefetcher;
`endif
    return m;
endmodule

module mkL1DPrefetcher#(TlbToPrefetcher toTlb)(CheriPCPrefetcher);
`ifdef DATA_PREFETCHER_IN_L1
    `ifdef DATA_PREFETCHER_BLOCK
        Parameter#(1) numLinesEachWay <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkBlockPrefetcher(numLinesEachWay)));
    `elsif DATA_PREFETCHER_STRIDE
        //let m <- mkStridePCPrefetcher;
        Parameter#(512) strideTableSize <- mkParameter;
        Parameter#(1) cLinesAheadToPrefetch <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkStride2PCPrefetcher(strideTableSize, cLinesAheadToPrefetch));
    `elsif DATA_PREFETCHER_STRIDE_ADAPTIVE
        Parameter#(512) strideTableSize <- mkParameter;
        Parameter#(1) cLinesPrefetchMin <- mkParameter;
        Parameter#(2) cLinesSmallStridePrefetchMax <- mkParameter;
        Parameter#(4) cLinesBigStridePrefetchMax <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkStrideAdaptivePCPrefetcher(
            strideTableSize, 
            cLinesPrefetchMin, 
            cLinesSmallStridePrefetchMax, 
            cLinesBigStridePrefetchMax));
    `elsif DATA_PREFETCHER_MARKOV
        Parameter#(2) maxChainLength <- mkParameter;
        Parameter#(2048) narrowEntries <- mkParameter;
        Parameter#(128) wideEntries <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkMarkovPrefetcher(maxChainLength, narrowEntries, wideEntries)));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT
        Parameter#(1) maxChainLength <- mkParameter;
        Parameter#(32) numLastRequestsTracked <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkMarkovOnHitPrefetcher(maxChainLength, numLastRequestsTracked)));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT_2
        Parameter#(1) maxChainLength <- mkParameter;
        Parameter#(32) numLastRequestsTracked <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkMarkovOnHit2Prefetcher(maxChainLength, numLastRequestsTracked)));
    `elsif DATA_PREFETCHER_ALL_IN_CAP
        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        let m <- mkAllInCapPrefetcher(maxCapSizeToPrefetch);
    `elsif DATA_PREFETCHER_CHERI_STRIDE
        Parameter#(512) strideTableSize <- mkParameter;
        Parameter#(3) cLinesAheadToPrefetch <- mkParameter;
        Parameter#(1) pcInHash <- mkParameter;
        Parameter#(0) boundsInHash <- mkParameter;
        let m <- mkCheriStridePrefetcher(toTlb, strideTableSize, cLinesAheadToPrefetch, pcInHash, boundsInHash);
        //let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
        //let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkAlwaysRequestTlbPrefetcher(toTlb)));
    `elsif DATA_PREFETCHER_CHERI_STRIDE_MIX
        Vector#(2, module#(CheriPCPrefetcher)) ms;
        Parameter#(512) strideTableSize <- mkParameter;
        Parameter#(1) cLinesAheadToPrefetch <- mkParameter;
        Parameter#(1) pcInHash <- mkParameter;
        Parameter#(0) pcNotInHash <- mkParameter;
        Parameter#(1) boundsInHash <- mkParameter;
        Parameter#(0) boundsNotInHash <- mkParameter;
        ms[0] = mkCheriStridePrefetcher(toTlb, strideTableSize, cLinesAheadToPrefetch, pcInHash, boundsNotInHash);
        ms[1] = mkCheriStridePrefetcher(toTlb, strideTableSize, cLinesAheadToPrefetch, pcNotInHash, boundsInHash);
        let m <- mkCheriPCPrefetcherVector(ms);
        //let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
        //let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkAlwaysRequestTlbPrefetcher(toTlb)));
    `elsif DATA_PREFETCHER_CAP_SPATIAL
        Parameter#(1048576) maxCapSizeToTrack <- mkParameter;
        Parameter#(2048) bitmapTableSize <- mkParameter;
        Parameter#(4) filterTableSize <- mkParameter;
        Parameter#(128) inverseDecayChance <- mkParameter;
        let m <- mkCapBitmapPrefetcher(maxCapSizeToTrack, bitmapTableSize, filterTableSize, inverseDecayChance);
    `elsif DATA_PREFETCHER_CAP_PTR
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        let m <- mkCapPtrPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance);
    `elsif DATA_PREFETCHER_CAP_PTR_NEW
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(1) onlyOnMiss <- mkParameter;
        Parameter#(0) onlyExactCap <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap));
    `elsif DATA_PREFETCHER_CAP_PTR_NEW_ONHIT
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(0) onlyOnMiss <- mkParameter;
        Parameter#(0) onlyExactCap <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap));
    `elsif DATA_PREFETCHER_CAP_PTR_NEW_EXACTCAP
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(1) onlyOnMiss <- mkParameter;
        Parameter#(1) onlyExactCap <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap));
    `elsif DATA_PREFETCHER_CAP_PTR_NEW_EXACTCAP_ONHIT
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(0) onlyOnMiss <- mkParameter;
        Parameter#(1) onlyExactCap <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap));
    `elsif DATA_PREFETCHER_CAP_SPATIAL_PTR
        Vector#(2, module#(CheriPCPrefetcher)) ms;

        Parameter#(2097152) ptrMaxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChancePtr <- mkParameter;
        ms[0] = mkCapPtrPrefetcher(toTlb, ptrMaxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChancePtr);

        Parameter#(1048576) maxCapSizeToTrack <- mkParameter;
        Parameter#(2048) bitmapTableSize <- mkParameter;
        Parameter#(4) filterTableSize <- mkParameter;
        Parameter#(128) inverseDecayChanceSpatial <- mkParameter;
        ms[1] = mkCapBitmapPrefetcher(maxCapSizeToTrack, bitmapTableSize, filterTableSize, inverseDecayChanceSpatial);

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_PTR_HYBRID
        Vector#(2, module#(CheriPCPrefetcher)) ms;

        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(0) onPrefetchHit <- mkParameter;
        ms[0] = mkCheriPCPrefetcherAdapterFromPC(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));

        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(0) onlyOnMiss <- mkParameter;
        Parameter#(0) onlyExactCap <- mkParameter;
        ms[1] = mkCheriPCPrefetcherAdapterFromCheri(mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap));

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_CHASER_ALLINBASELINE
        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(1) onDemandMiss <- mkParameter;
        Parameter#(0) onPrefetchHit <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));
    `elsif DATA_PREFETCHER_CAP_CHASER
        Vector#(2, module#(CheriPCPrefetcher)) ms;

        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(0) onPrefetchHit <- mkParameter;
        ms[0] = mkCheriPCPrefetcherAdapterFromCheri(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1) l1OnlyMode <- mkParameter;
        Parameter#(16) trainingTableDecayCycles <- mkParameter;
        Parameter#(0) useFiltering <- mkParameter;
        ms[1] = mkCheriPCPrefetcherAdapterFromCheri(mkL1CapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, l1OnlyMode, trainingTableDecayCycles, useFiltering));

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_CHASER_FILTER
        Vector#(2, module#(CheriPCPrefetcher)) ms;

        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        ms[0] = mkCheriPCPrefetcherAdapterFromCheri(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1) l1OnlyMode <- mkParameter;
        Parameter#(16) trainingTableDecayCycles <- mkParameter;
        Parameter#(1) useFiltering <- mkParameter;
        ms[1] = mkCheriPCPrefetcherAdapterFromCheri(mkL1CapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, l1OnlyMode, trainingTableDecayCycles, useFiltering));

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT
        Vector#(2, module#(CheriPCPrefetcher)) ms;

        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        ms[0] = mkCheriPCPrefetcherAdapterFromCheri(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(0) l1OnlyMode <- mkParameter;
        Parameter#(16) trainingTableDecayCycles <- mkParameter;
        Parameter#(0) useFiltering <- mkParameter;
        ms[1] = mkCheriPCPrefetcherAdapterFromCheri(mkL1CapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, l1OnlyMode, trainingTableDecayCycles, useFiltering));

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT_SOLO
        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(0) l1OnlyMode <- mkParameter;
        Parameter#(16) trainingTableDecayCycles <- mkParameter;
        Parameter#(0) useFiltering <- mkParameter;
        let m <- mkCheriPCPrefetcherAdapterFromCheri(mkL1CapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, l1OnlyMode, trainingTableDecayCycles, useFiltering));
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT_STRIDE
        Vector#(3, module#(CheriPCPrefetcher)) ms;

        Parameter#(256) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        ms[0] = mkCheriPCPrefetcherAdapterFromCheri(mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit));

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(0) l1OnlyMode <- mkParameter;
        Parameter#(16) trainingTableDecayCycles <- mkParameter;
        Parameter#(0) useFiltering <- mkParameter;
        ms[1] = mkCheriPCPrefetcherAdapterFromCheri(mkL1CapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, l1OnlyMode, trainingTableDecayCycles, useFiltering));

        Parameter#(512) strideTableSize <- mkParameter;
        Parameter#(1) cLinesPrefetchMin <- mkParameter;
        Parameter#(2) cLinesSmallStridePrefetchMax <- mkParameter;
        Parameter#(4) cLinesBigStridePrefetchMax <- mkParameter;
        ms[2] = mkCheriPCPrefetcherAdapterFromPC(mkStrideAdaptivePCPrefetcher(
            strideTableSize, 
            cLinesPrefetchMin, 
            cLinesSmallStridePrefetchMax, 
            cLinesBigStridePrefetchMax));

        let m <- mkCheriPCPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_SPP
        Parameter#(64) stSets <- mkParameter;
        Parameter#(4) stWays <- mkParameter;
        Parameter#(512) ptEntries <- mkParameter;
        Prob prefetchThreshold = 7'b1100000;
        Bool useFilter = True;
        let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkSignaturePathPrefetcher(
            "./div_table.memhex",
            stSets, stWays, ptEntries, prefetchThreshold, useFilter)));
        //let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkPrintPrefetcher));
    `elsif DATA_PREFETCHER_MEASURER
        let m <- mkPCCapMeasurer;
    `endif
`else 
    let m <- mkCheriPCPrefetcherAdapterFromPC(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
    // Parameter#(512) strideTableSize <- mkParameter;
    // Parameter#(2) cLinesAheadToPrefetch <- mkParameter;
    // let m <- mkCheriPCPrefetcherAdapterFromPC(mkStride2PCPrefetcher(strideTableSize, cLinesAheadToPrefetch));
`endif
    return m;
endmodule

module mkLLDPrefetcher#(TlbToPrefetcher toTlb)(CheriPrefetcher);
`ifdef DATA_PREFETCHER_IN_LL
    `ifdef DATA_PREFETCHER_BLOCK
        Parameter#(1) numLinesEachWay <- mkParameter;
        let m <- mkCheriPrefetcherAdapter(mkBlockPrefetcher(numLinesEachWay));
    `elsif DATA_PREFETCHER_STRIDE
        doAssert(False, "Illegal data prefetcher type for LL cache!");
    `elsif DATA_PREFETCHER_STRIDE_ADAPTIVE
        doAssert(False, "Illegal data prefetcher type for LL cache!");
    `elsif DATA_PREFETCHER_MARKOV
        Parameter#(2) maxChainLength <- mkParameter;
        Parameter#(2048) narrowEntries <- mkParameter;
        Parameter#(128) wideEntries <- mkParameter;
        let m <- mkCheriPrefetcherAdapter(mkMarkovPrefetcher(maxChainLength, narrowEntries, wideEntries));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT
        Parameter#(1) maxChainLength <- mkParameter;
        Parameter#(32) numLastRequestsTracked <- mkParameter;
        let m <- mkCheriPrefetcherAdapter(mkMarkovOnHitPrefetcher(maxChainLength, numLastRequestsTracked));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT_2
        Parameter#(1) maxChainLength <- mkParameter;
        Parameter#(32) numLastRequestsTracked <- mkParameter;
        let m <- mkCheriPrefetcherAdapter(mkMarkovOnHit2Prefetcher(maxChainLength, numLastRequestsTracked));
    `elsif DATA_PREFETCHER_ALL_IN_CAP
        doAssert(False, "Illegal data prefetcher type for LL cache!");
    `elsif DATA_PREFETCHER_SPP
        Parameter#(64) stSets <- mkParameter;
        Parameter#(4) stWays <- mkParameter;
        Parameter#(512) ptEntries <- mkParameter;
        Prob prefetchThreshold = 7'b0100000;
        Bool useFilter = True;
        let m <- mkCheriPrefetcherAdapter(mkSignaturePathPrefetcher(
            "./div_table.memhex",
            stSets, stWays, ptEntries, prefetchThreshold, useFilter));
    `elsif DATA_PREFETCHER_CAP_PTR_NEW
        Parameter#(2097152) maxCapSizeToTrack <- mkParameter;
        Parameter#(4096) ptrTableSize <- mkParameter; 
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(4) inverseDecayChance <- mkParameter;
        Parameter#(0) onlyOnMiss <- mkParameter;
        Parameter#(0) onlyExactCap <- mkParameter;
        let m <- mkCapPtrPrefetcherNonPC(toTlb, maxCapSizeToTrack, ptrTableSize, trainingTableSize, inverseDecayChance, onlyOnMiss, onlyExactCap);
    `elsif DATA_PREFETCHER_CAP_CHASER_ALLINBASELINE
        Parameter#(512) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(1) onDemandMiss <- mkParameter;
        Parameter#(0) onPrefetchHit <- mkParameter;
        let m <- mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit);
    `elsif DATA_PREFETCHER_CAP_CHASER
        Parameter#(512) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        let m <- mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit);
    `elsif DATA_PREFETCHER_CAP_CHASER_FILTER
        Parameter#(512) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        let m <- mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit);
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT
        Vector#(2, module#(CheriPrefetcher)) ms;

        Parameter#(512) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        ms[0] = mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit);

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter;
        ms[1] = mkLLCapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize);

        let m <- mkCheriPrefetcherMultiplier(ms);
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT_SOLO
        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter;
        let m <- mkLLCapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize);
    `elsif DATA_PREFETCHER_CAP_CHASER_SPLIT_STRIDE
        Vector#(2, module#(CheriPrefetcher)) ms;

        Parameter#(512) maxCapSizeToPrefetch <- mkParameter;
        Parameter#(0) onDemandHit <- mkParameter;
        Parameter#(0) onDemandMiss <- mkParameter;
        Parameter#(1) onPrefetchHit <- mkParameter;
        ms[0] = mkCapChaserAllInPrefetcher(maxCapSizeToPrefetch, onDemandHit, onDemandMiss, onPrefetchHit);

        Parameter#(512) maxCapSizeToTrack <- mkParameter;
        Parameter#(256) ptrTableSize <- mkParameter;
        ms[1] = mkLLCapChaserPrefetcher(toTlb, maxCapSizeToTrack, ptrTableSize);

        let m <- mkCheriPrefetcherMultiplier(ms);
    `endif
`else 
    let m <- mkCheriPrefetcherAdapter(mkDoNothingPrefetcher);
`endif
    return m;
endmodule