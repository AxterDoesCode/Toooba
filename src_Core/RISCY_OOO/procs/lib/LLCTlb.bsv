
// Copyright (c) 2017 Massachusetts Institute of Technology
//
//-
// RVFI_DII + CHERI modifications:
//     Copyright (c) 2020 Jonathan Woodruff
//     All rights reserved.
//
//     This software was developed by SRI International and the University of
//     Cambridge Computer Laboratory (Department of Computer Science and
//     Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
//     DARPA SSITH research programme.
//
//     This work was supported by NCSC programme grant 4212611/RFA 15971 ("SafeBet").
//-
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
import DefaultValue::*;
import Types::*;
import ProcTypes::*;
import TlbTypes::*;
import Fifos::*;
import CacheUtils::*;
import Vector::*;
import Ehr::*;
import CCTypes::*;
import CHERICC_Fat::*;
import CHERICap::*;
import Prefetcher_intf::*;

export LLCTlbRqToP(..);
export LLCTlbRsFromP(..);
export LLCTlbToParent(..);
export ParentToLLCTlb(..);
export LLCTlb(..);
export mkLLCTlb;

typedef struct {
    Vpn vpn;
    idxT id;
} LLCTlbRqToP#(type idxT) deriving(Bits, Eq, FShow);

typedef struct {
    TaggedTlbEntry entry;
    idxT id;
} LLCTlbRsFromP#(type idxT) deriving(Bits, Eq, FShow);

interface LLCTlbToParent#(type idxT);
    interface FifoDeq#(LLCTlbRqToP#(idxT)) rqToP;
    interface FifoEnq#(LLCTlbRsFromP#(idxT)) rsFromP;
endinterface

interface ParentToLLCTlb#(type idxT);
    interface FifoEnq#(LLCTlbRqToP#(idxT)) rqFromLLCTlb;
    interface FifoDeq#(LLCTlbRsFromP#(idxT)) rsToLLCTlb;
endinterface

interface LLCTlb;
    // req/resp
    interface TlbToPrefetcher toPrefetcher;

    // req/resp with L2 TLB
    interface LLCTlbToParent#(PrefetcherTlbReqIdx) toParent;
endinterface

(* synthesize *)
module mkLLCTlb(LLCTlb);

    Vector#(PrefetcherTlbReqNum, Ehr#(2, Bool)) pendValid <- replicateM(mkEhr(False));
    Vector#(PrefetcherTlbReqNum, Reg#(PrefetcherReqToTlb)) pendReq <- replicateM(mkRegU);
    let pendValid_resp = getVEhrPort(pendValid, 0); // write
    let pendValid_req = getVEhrPort(pendValid, 1);  // write
    let pendValid_pRs = getVEhrPort(pendValid, 1);  // assert

    Fifo#(PrefetcherTlbReqNum, LLCTlbRqToP#(PrefetcherTlbReqIdx)) rqToPQ <- mkCFFifo;
    Fifo#(1, LLCTlbRsFromP#(PrefetcherTlbReqIdx)) rsFromPQ <- mkCFFifo;
    Fifo#(PrefetcherTlbReqNum, TlbRespToPrefetcher) rsToPrefetcherQ <- mkCFFifo;

    rule doPRs;
        let pRs = rsFromPQ.first;
        rsFromPQ.deq;
        doAssert(pendValid_pRs[pRs.id], "LLC TLB pRs for invalid id");

        if(pRs.entry matches tagged ValidTlbEntry .en) begin
            rsToPrefetcherQ.enq(TlbRespToPrefetcher {
                paddr: translate(getAddr(pendReq[pRs.id].cap), en.ppn, en.level),
                cap: pendReq[pRs.id].cap,
                id: pRs.id,
                haveException: False,
                permsCheckPass: (en.pteType.readable && en.pteUpperType.cap_readable)
            });
        end 
        else if(pRs.entry == TlbDisabled) begin
            rsToPrefetcherQ.enq(TlbRespToPrefetcher {
                paddr: getAddr(pendReq[pRs.id].cap),
                cap: pendReq[pRs.id].cap,
                id: pRs.id,
                haveException: False,
                permsCheckPass: True
            });
        end
        else begin
            rsToPrefetcherQ.enq(TlbRespToPrefetcher {
                paddr: ?,
                cap: pendReq[pRs.id].cap,
                id: pRs.id,
                haveException: True,
                permsCheckPass: False
            });
        end
    endrule

    interface TlbToPrefetcher toPrefetcher;
        method Action prefetcherReq(PrefetcherReqToTlb req);
            pendReq[req.id] <= req;
            doAssert(pendValid_req[req.id] == False, "overlapping ids in LLC Tlb req");
            pendValid_req[req.id] <= True;
            rqToPQ.enq(LLCTlbRqToP {vpn: getVpn(getAddr(req.cap)), id: req.id});
        endmethod

        method Action deqPrefetcherResp;
            rsToPrefetcherQ.deq;
            pendValid_resp[rsToPrefetcherQ.first.id] <= False;
        endmethod

        method TlbRespToPrefetcher prefetcherResp;
            return rsToPrefetcherQ.first;
        endmethod
    endinterface

    interface LLCTlbToParent toParent;
        interface rqToP = toFifoDeq(rqToPQ);
        interface rsFromP = toFifoEnq(rsFromPQ);
    endinterface

endmodule
