
// Copyright (c) 2017 Massachusetts Institute of Technology
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

import GetPut::*;
import ClientServer::*;
import Connectable::*;
import Types::*;
import ProcTypes::*;
import TlbTypes::*;
import CacheUtils::*;
import ITlb::*;
import DTlb::*;
import LLCTlb::*;
import L2Tlb::*;
import Vector::*;
import CrossBar::*;
import BuildVector::*;

module mkTlbConnect#(ITlbToParent i, DTlbToParent d, FifoDeq#(LLCTlbRqToP#(PrefetcherTlbReqIdx)) rqFromLLCTlb, FifoEnq#(LLCTlbRsFromP#(PrefetcherTlbReqIdx)) rsToLLCTlb, L2TlbToChildren l2)(Empty);
    // give priority to DTlb req
    (* descending_urgency = "sendDTlbReq, sendITlbReq, sendLLCTlbReq" *)
    rule sendDTlbReq;
        DTlbRqToP r <- toGet(d.rqToP).get;
        l2.rqFromC.put(L2TlbRqFromC {
            child: D (r.id),
            vpn: r.vpn
        });
    endrule

    rule sendITlbReq;
        ITlbRqToP r <- toGet(i.rqToP).get;
        l2.rqFromC.put(L2TlbRqFromC {
            child: I,
            vpn: r.vpn
        });
    endrule

    rule sendLLCTlbReq;
        LLCTlbRqToP#(PrefetcherTlbReqIdx) r <- toGet(rqFromLLCTlb).get;
        l2.rqFromC.put(L2TlbRqFromC {
            child: LLC(r.id),
            vpn: r.vpn
        });
    endrule

    rule sendRsToDTlb(l2.rsToC.first.child matches tagged D .id);
        L2TlbRsToC r <- toGet(l2.rsToC).get;
        d.ldTransRsFromP.enq(DTlbTransRsFromP {
            entry: r.entry,
            id: id
        });
    endrule

    rule sendRsToITlb(l2.rsToC.first.child == I);
        L2TlbRsToC r <- toGet(l2.rsToC).get;
        i.rsFromP.enq(ITlbRsFromP {entry: r.entry});
    endrule

    rule sendRsToLLCTlb(l2.rsToC.first.child matches tagged LLC .id);
        L2TlbRsToC r <- toGet(l2.rsToC).get;
        rsToLLCTlb.enq(LLCTlbRsFromP {
            entry: r.entry,
            id: id
        });
    endrule

    mkConnection(d.flush.request, l2.dTlbReqFlush);
    mkConnection(i.flush.request, l2.iTlbReqFlush);

    rule sendFlushDone;
        let x <- l2.flushDone.get;
        d.flush.response.put(?);
        i.flush.response.put(?);
    endrule
endmodule

module mkLLCTlbConnect#(LLCTlbToParent#(CombinedLLCTlbReqIdx) llcTlb, Vector#(CoreNum, ParentToLLCTlb#(PrefetcherTlbReqIdx)) l2Tlbs)(Empty);
    // Crossbar from L2TLBs into the LLC
    function XBarDstInfo#(Bit#(0), LLCTlbRsFromP#(CombinedLLCTlbReqIdx)) getL2TlbRsDstInfo(Bit#(TLog#(CoreNum)) idx, LLCTlbRsFromP#(PrefetcherTlbReqIdx) rs);
        return XBarDstInfo {idx: 0, data: LLCTlbRsFromP {
            entry: rs.entry,
            id: {rs.id, extend(idx)}
        }};
    endfunction
    function Get#(LLCTlbRsFromP#(PrefetcherTlbReqIdx)) l2TlbRsGet(ParentToLLCTlb#(PrefetcherTlbReqIdx) l2Tlb) = toGet(l2Tlb.rsToLLCTlb);
    mkXBar(getL2TlbRsDstInfo, map(l2TlbRsGet, l2Tlbs), vec(toPut(llcTlb.rsFromP)));

    rule doForwardRq;
        let rq = llcTlb.rqToP.first;
        llcTlb.rqToP.deq;
        Bit#(TLog#(CoreNum)) idx = truncate(rq.id);
        l2Tlbs[idx].rqFromLLCTlb.enq(LLCTlbRqToP {
            vpn: rq.vpn,
            id: truncateLSB(rq.id)
        });
    endrule
endmodule
