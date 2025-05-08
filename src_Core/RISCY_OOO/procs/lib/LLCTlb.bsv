
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

`include "ProcConfig.bsv"
import ClientServer::*;
import DefaultValue::*;
import GetPut::*;
import Types::*;
import ProcTypes::*;
import TlbTypes::*;
import Performance::*;
import FullAssocTlb::*;
import ConfigReg::*;
import Fifos::*;
import FIFO::*;
import CHERICC_Fat::*;
import Cntrs::*;
import SafeCounter::*;
import CacheUtils::*;
import LatencyTimer::*;
import HasSpecBits::*;
import Vector::*;
import Ehr::*;
import Prefetcher_intf::*;
import CHERICap::*;
import CHERICC_Fat::*;
`ifdef PERFORMANCE_MONITORING
import PerformanceMonitor::*;
import CCTypes::*;
import BlueUtils::*;
import StatCounters::*;
`endif

export LLCTlbRqToP(..);
export LLCTlbRsFromP(..);
export LLCTlbToParent(..);
export ParentToLLCTlb(..);
export LLCTlb(..);
export mkLLCTlb;

typedef `LLC_TLB_SIZE LLCTlbSize;

typedef struct {
    Vpn vpn;
    idxT id;
} LLCTlbRqToP#(type idxT) deriving(Bits, Eq, FShow);

typedef struct {
    TaggedTlbEntry entry;
    idxT id;
} LLCTlbRsFromP#(type idxT) deriving(Bits, Eq, FShow);

interface LLCTlbToParent#(type idxT, type flushT);
    interface Client#(LLCTlbRqToP#(idxT), LLCTlbRsFromP#(idxT)) lookup;
    interface Client#(flushT, flushT) flush;
endinterface

interface ParentToLLCTlb#(type idxT, type flushT);
    interface Server#(LLCTlbRqToP#(idxT), LLCTlbRsFromP#(idxT)) lookup;
    interface Server#(flushT, flushT) flush;
endinterface

interface LLCTlb;
    method Bool flush_done;
    method Action flush;
    method Action updateVMInfo(VMInfo vm);
    method Bool noPendingReq;

    // req/resp
    interface TlbToPrefetcher toPrefetcher;

    // req/resp with L2 TLB
    interface LLCTlbToParent#(LLCTlbReqIdx, void) toParent;
    `ifdef PERFORMANCE_MONITORING
        method EventsLL events;
    `endif
endinterface

typedef FullAssocTlb#(LLCTlbSize) LLCTlbArray;
module mkLLCTlbArray(LLCTlbArray);
    let m <- mkFullAssocTlb(True); // randomness in replacement
    return m;
endmodule

// a pending tlb req may be in following states
typedef union tagged {
    void None;
    void WaitParent;
    LLCTlbReqIdx WaitPeer;
} LLCTlbWait deriving(Bits, Eq, FShow);

module mkLLCTlb(LLCTlb);
    Bool verbose = False;

    // TLB array
    LLCTlbArray tlb <- mkLLCTlbArray;

    // processor init flushing by setting this flag
    Reg#(Bool) needFlush <- mkReg(False);
    Reg#(Bool) waitFlushP <- mkReg(False);

    // current processor VM information
    Reg#(VMInfo) vm_info <- mkReg(defaultValue);

    // pending reqs
    // pendWait should be meaningful even when entry is invalid. pendWait =
    // WaitParent True means this entry is waiting for parent TLB resp;
    // pendWait = WaitPeer means this entry is waiting for a resp initiated by
    // another req. Thus, pendWait must be None when entry is invalid.
    Vector#(LLCTlbReqNum, Ehr#(2, Bool)) pendValid <- replicateM(mkEhr(False));
    Vector#(LLCTlbReqNum, Reg#(LLCTlbWait)) pendWait <- replicateM(mkReg(None));
    Vector#(LLCTlbReqNum, Reg#(PrefetcherReqToTlb)) pendInst <- replicateM(mkRegU);
    Vector#(LLCTlbReqNum, Reg#(TlbResp)) pendResp <- replicateM(mkRegU);

    RWire#(void) updatingVMInfo <- mkRWire;

    let pendValid_noMiss = getVEhrPort(pendValid, 0);
    let pendValid_resp = getVEhrPort(pendValid, 0); // write
    let pendValid_doPRs = getVEhrPort(pendValid, 1); // assert
    let pendValid_req = getVEhrPort(pendValid, 1); // write

    // free list of pend entries, to cut off path from procResp to procReq
    Fifo#(LLCTlbReqNum, LLCTlbReqIdx) freeQ <- mkCFFifo;
    Reg#(Bool) freeQInited <- mkReg(False);
    Reg#(LLCTlbReqIdx) freeQInitIdx <- mkReg(0);

    // request queue from prefetcher
    Fifo#(4, PrefetcherReqToTlb) rqFromPrefetcher <- mkBypassFifo;

    // req & resp with parent TLB
    Fifo#(LLCTlbReqNum, LLCTlbRqToP#(LLCTlbReqIdx)) rqToPQ <- mkCFFifo; // large enough so won't block on enq
    Fifo#(2, LLCTlbRsFromP#(LLCTlbReqIdx)) rsFromPQ <- mkCFFifo;

    // flush req/resp with parent TLB
    Fifo#(1, void) flushRqToPQ <- mkCFFifo;
    Fifo#(1, void) flushRsFromPQ <- mkCFFifo;
    
    // When a resp comes, we first process for the initiating req, then process
    // other reqs that in WaitPeer.
    Reg#(Maybe#(LLCTlbReqIdx)) respForOtherReq <- mkReg(Invalid);

    // do flush: start when all misses resolve
    Bool noMiss = all(\== (False) , readVReg(pendValid_noMiss));

    // LLC TLB performance events
    `ifdef PERFORMANCE_MONITORING
        Array#(Reg#(EventsLL)) perf_events <- mkDRegOR (3, unpack (0));
    `endif

    rule doFlush(needFlush && !waitFlushP && noMiss);
        if(verbose) $display ("%t LLCTlb doFlush", $time);
        tlb.flush;
        flushRqToPQ.enq(?);
        waitFlushP <= True;

        EventsLL ev = unpack(0);
        ev.evt_TLB_FLUSH = 1;
        perf_events[2] <= ev;
    endrule

    rule doFinishFlush(needFlush && waitFlushP);
        flushRsFromPQ.deq;
        needFlush <= False;
        waitFlushP <= False;
        if(verbose) $display("[LLCTlb] flush done");
    endrule

    // get resp from parent TLB
    // At high level, this rule is always exclusive with doFlush, though
    // we don't bother to make compiler understand this...
    rule doPRs(rsFromPQ.notEmpty);
        let pRs = rsFromPQ.first;
        // the current req being served is either the initiating req or other
        // req pending on the same resp
        let idx = fromMaybe(pRs.id, respForOtherReq);
        let vaddr = getAddr(pendInst[idx].cap);

        if(pRs.entry matches tagged ValidTlbEntry .en) begin
            // check permission
            if (verbose)
                $display("[LLCTlb] doPRs: vm_info: ", fshow(vm_info),
                         "      en     : ", fshow(en),
                         "      vaddr  : ", fshow(vaddr)
                         );
            let permCheck = hasVMPermission(
                vm_info,
                en.pteType,
                en.pteUpperType,
                en.ppn,
                en.level,
                DataLoad,
                False, // cap store?
                True
            ); // potential cap load?
            if (permCheck.allowed) begin
                // fill TLB, and record resp
                tlb.addEntry(en);
                let trans_addr = translate(vaddr, en.ppn, en.level);
                pendResp[idx] <= tuple3(trans_addr, Invalid, permCheck.allowCap);
                if(verbose) begin
                    $display("[LLCTlb] refill: idx %d; vaddr: %h", idx, vaddr,
                             "; ", fshow(trans_addr));
                end
            end 
            else begin
                // page fault
                pendResp[idx] <= tuple3(?, Valid (permCheck.excCode), False);
                if(verbose) begin
                    $display("[LLCTlb] refill no permission: idx %d; vaddr: %h", idx, vaddr);
                end
            end
        end
        else if(pRs.entry == TlbDisabled) begin
            doAssert(True, "L2TLB should not be disabled if TLB sent a request");
        end 
        else begin
            // page fault
            pendResp[idx] <= tuple3(?, Valid (excLoadPageFault), False);
            if(verbose) $display("[LLCTlbTLB] refill page fault: idx %d; vaddr: %h", idx, vaddr);
        end

        // get parent resp, miss resolved, reset wait bit
        pendWait[idx] <= None;

        doAssert(pendValid_doPRs[idx], "entry must be valid");
        if(isValid(respForOtherReq)) begin
            doAssert(pendWait[idx] == WaitPeer (pRs.id), "entry must be waiting for resp");
        end
        else begin
            doAssert(pendWait[idx] == WaitParent, "entry must be waiting for resp");
        end

        // find another req waiting for this resp
        function Bool waitForResp(LLCTlbReqIdx i);
            // we can ignore pendValid here, because not-None pendWait implies
            // pendValid is true
            return pendWait[i] == WaitPeer (pRs.id) && i != idx;
        endfunction
        Vector#(LLCTlbReqNum, LLCTlbReqIdx) idxVec = genWith(fromInteger);
        if(find(waitForResp, idxVec) matches tagged Valid .i) begin
            // still have req waiting for this resp, keep processing
            respForOtherReq <= Valid (i);
            doAssert(pendValid_doPRs[i], "waiting entry must be valid");
        end
        else begin
            // all req done, deq the pRs
            respForOtherReq <= Invalid;
            rsFromPQ.deq;
        end

        // Performance monitoring
        EventsLL ev = unpack(0);
        ev.evt_TLB_MISS = 1;
        perf_events[0] <= ev;
    endrule

    // init freeQ
    rule doInitFreeQ(!freeQInited);
        freeQ.enq(freeQInitIdx);
        freeQInitIdx <= freeQInitIdx + 1;
        if(freeQInitIdx == fromInteger(valueof(LLCTlbReqNum) - 1)) begin
            freeQInited <= True;
            if(verbose) $display ("%t LLCTlb doInitFreeQ done", $time);
        end
    endrule

    function Maybe#(LLCTlbReqIdx) validRespIdx;
        function Bool validResp(LLCTlbReqIdx i);
            return pendValid_resp[i] && pendWait[i] == None;
        endfunction
        Vector#(LLCTlbReqNum, LLCTlbReqIdx) idxVec = genWith(fromInteger);
        return find(validResp, idxVec);
    endfunction

    rule handleReq if (
        !needFlush && 
        !rsFromPQ.notEmpty && 
        rqToPQ.notFull && 
        freeQInited
    ); 
        if(verbose) $display ("%t LLCTlb handleReq", $time);
        // allocate MSHR entry
        freeQ.deq;
        LLCTlbReqIdx idx = freeQ.first;
        doAssert(!pendValid_req[idx], "free entry cannot be valid");
        doAssert(pendWait[idx] == None, "entry cannot wait for parent resp");
        pendValid_req[idx] <= True;

        let req = rqFromPrefetcher.first;
        rqFromPrefetcher.deq;

        pendInst[idx] <= req;
        let vaddr = getAddr(req.cap);
        
`ifdef SECURITY
        // Security check
        // Forbid any data load shared outside of the protection domain
        // if shared load are not allowed
        // No need to special case M mode with special vm_info value because we
        // assume that we allow shared load all the time when in M mode.
        // (Because we are always non speculative in M mode)
        if (!vm_info.sanctum_authShared && outOfProtectionDomain(vm_info, vaddr))begin
            pendWait[idx] <= None;
            pendResp[idx] <= tuple3(?, Valid (excLoadAccessFault), False);
        end
`else
        // No security check
        if (False) begin
            noAction;
        end
`endif
        else if (vm_info.sv39) begin
            let vpn = getVpn(vaddr);
            let trans_result = tlb.translate(vpn, vm_info.asid);
            if (!validVirtualAddress(vaddr)) begin
                // page fault
                Exception fault = excLoadPageFault;
                pendWait[idx] <= None;
                pendResp[idx] <= tuple3(?, Valid (fault), False);
                if(verbose) $display("[LLCTlb] req invalid virtual address: idx %d; vaddr: %h", idx, vaddr);
            end 
            else if (trans_result.hit) begin
                // TLB hit
                let entry = trans_result.entry;
                // check permission
                if(verbose) $display("prefetcherReq: vm_info: ", fshow(vm_info),
                     "         en     : ", fshow(entry),
                     "         vaddr  : ", fshow(vaddr)
                     );
                let permCheck = hasVMPermission(
                    vm_info,
                    entry.pteType,
                    entry.pteUpperType,
                    entry.ppn,
                    entry.level,
                    DataLoad,
                    False, // cap store?
                    True // potential cap load?
                ); 
                if (verbose) $display("Permission check output 2: ", fshow(permCheck));
                if (permCheck.allowed) begin
                    // update TLB replacement info
                    tlb.updateRepByHit(trans_result.index);
                    // translate addr
                    Addr trans_addr = translate(vaddr, entry.ppn, entry.level);
                    pendWait[idx] <= None;
                    pendResp[idx] <= tuple3(trans_addr, Invalid, permCheck.allowCap);
                    if(verbose) begin
                        $display("[LLCTlb] req (hit): idx %d; vaddr: ", idx, vaddr,
                                 "; ", fshow(trans_result));
                    end
                end
                else begin
                    // page fault
                    pendWait[idx] <= None;
                    pendResp[idx] <= tuple3(?, Valid (permCheck.excCode), False);
                    if(verbose) $display("[LLCTlb] req no permission: idx %d; vaddr: %h", idx,vaddr);
                end
            end
            else begin
                // TLB miss, req to parent TLB only if there is no existing req
                // for the same VPN already waiting for parent TLB resp
                function Bool reqSamePage(LLCTlbReqIdx i);
                    // we can ignore pendValid here, because not-None pendWait implies
                    // pendValid is true
                    let vaddr_i = getAddr(pendInst[i].cap);
                    return pendWait[i] == WaitParent && getVpn(vaddr) == getVpn(vaddr_i);
                endfunction
                Vector#(LLCTlbReqNum, LLCTlbReqIdx) idxVec = genWith(fromInteger);
                if(find(reqSamePage, idxVec) matches tagged Valid .i) begin
                    // peer entry has already requested, so don't send duplicate req
                    pendWait[idx] <= WaitPeer (i);
                    doAssert(pendValid_req[i], "peer entry must be valid");
                    if(verbose) begin
                        $display("[LLCTlb] req miss, pend on peer: idx %d, ",
                                 idx, "; vaddr: %h", vaddr, "; ", fshow(i));
                    end
                end
                else begin
                    // this is the first req for this VPN
                    pendWait[idx] <= WaitParent;
                    rqToPQ.enq(LLCTlbRqToP {
                        vpn: vpn,
                        id: idx
                    });
                    if(verbose) begin
                        $display("[LLCTlb] req miss, send to parent: idx %d, vaddr: %h",
                                 idx, vaddr);
                    end
                end
            end
        end
        else begin
            // bare mode
            pendWait[idx] <= None;
            pendResp[idx] <= tuple3(vaddr, Invalid, True);
            if(verbose) $display("LLCTlb %m req (bare): vaddr: %h", vaddr);
        end

        // Performance monitoring
        EventsLL ev = unpack(0);
        ev.evt_TLB = 1;
        perf_events[1] <= ev;
    endrule
    
    method Action flush if(!needFlush);
        needFlush <= True;
        waitFlushP <= False;
        if(verbose) $display("%t LLCTlb flush", $time);
        // this won't interrupt current processing, since
        // (1) miss process will continue even if needFlush=True
        // (2) flush truly starts when there is no pending req
    endmethod

    method Bool flush_done = !needFlush;

    method Action updateVMInfo(VMInfo vm);
        if(verbose) $display("%t LLCTlb updateVMInfo", $time);
        vm_info <= vm;
    endmethod

    method Bool noPendingReq = noMiss;

    interface TlbToPrefetcher toPrefetcher;
        method Action prefetcherReq(PrefetcherReqToTlb req) if(
            !needFlush && 
            !rsFromPQ.notEmpty && 
            rqToPQ.notFull && 
            freeQInited && 
            freeQ.notEmpty
        );
            if(verbose) $display ("%t LLCTlb prefetcherReq ", $time, fshow(req));
            rqFromPrefetcher.enq(req);
        endmethod

        method Action deqPrefetcherResp if(
            validRespIdx matches tagged Valid .idx &&&
            freeQInited
        );
            if(verbose) $display ("%t LLCTlb deqPrefetcherReq ", $time, fshow(idx));
            pendValid_resp[idx] <= False;
            freeQ.enq(idx);
        endmethod

        method TlbRespToPrefetcher prefetcherResp if(
            validRespIdx matches tagged Valid .idx &&& 
            freeQInited
        );
            let resp = pendResp[idx];
            let req = pendInst[idx];
            return TlbRespToPrefetcher {
                paddr: tpl_1(resp),
                cap: req.cap,
                id: req.id,
                haveException: isValid(tpl_2(resp)),
                permsCheckPass: tpl_3(resp)
            };
        endmethod
    endinterface

    interface LLCTlbToParent toParent;
        interface Client lookup;
            interface request = toGet(rqToPQ);
            interface response = toPut(rsFromPQ);
        endinterface
        interface Client flush;
            interface request = toGet(flushRqToPQ);
            interface response = toPut(flushRsFromPQ);
        endinterface
    endinterface

    `ifdef PERFORMANCE_MONITORING
        method EventsLL events = perf_events[0];
    `endif

endmodule
