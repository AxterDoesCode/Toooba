
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

import BRAMCore::*;
import Fifos::*;
import Vector::*;
import ConfigReg::*;

interface RWSetAssocBramCore#(type addrT, type wayT, type dataT, type tagT);
    method Action wrReq(addrT a, wayT w, dataT d);
    method Action rdReq(addrT a, tagT tag);
    method Maybe#(Tuple2#(wayT, dataT)) rdResp;
    method wayT rdRepl;
    method Bool rdRespValid;
    method Action deqRdResp;
endinterface

module mkRWSetAssocBramCore#(
    function Bool isMatch(dataT data, tagT tag),
    function Bool isReplaceCandidate(dataT data)
)(RWSetAssocBramCore#(addrT, wayT, dataT, tagT)) provisos(
    Bits#(addrT, addrSz), Bits#(wayT, waySz), Bits#(dataT, dataSz), Bits#(tagT, tagSz),
    Arith#(wayT), PrimIndex#(wayT, a__),
    NumAlias#(wayNum, TExp#(waySz))
);

    Vector#(wayNum, BRAM_DUAL_PORT#(addrT, dataT)) brams <- replicateM(mkBRAMCore2(valueOf(TExp#(addrSz)), False));
    
    // The next way to use for replacement
    Reg#(wayT) nextWay <- mkConfigRegU;
    
    // 1 elem pipeline fifo to add guard for read req/resp
    // must be 1 elem to make sure rdResp is not corrupted
    // BRAMCore should not change output if no req is made
    Fifo#(1, tagT) rdReqQ <- mkPipelineFifo;

    method Action wrReq(addrT a, wayT w, dataT d);
        brams[w].a.put(True, a, d);
    endmethod

    method Action rdReq(addrT a, tagT tag);
        rdReqQ.enq(tag);
        for (Integer i = 0; i < valueOf(wayNum); i=i+1) begin
            brams[i].b.put(False, a, ?);
        end
    endmethod

    method Maybe#(Tuple2#(wayT, dataT)) rdResp if(rdReqQ.notEmpty);
        Maybe#(Tuple2#(wayT, dataT)) wayAndData = Invalid;
        for (Integer i = 0; i < valueOf(wayNum); i=i+1) begin
            if (isMatch(brams[i].b.read, rdReqQ.first)) begin
                wayAndData = Valid(tuple2(fromInteger(i), brams[i].b.read));
            end
        end
        return wayAndData;
    endmethod

    method wayT rdRepl if(rdReqQ.notEmpty);
        wayT way = nextWay;
        for (Integer i = 0; i < valueOf(wayNum); i=i+1) begin
            if (isReplaceCandidate(brams[i].b.read)) begin
                way = fromInteger(i);
            end
        end
        return way;
    endmethod

    method rdRespValid = rdReqQ.notEmpty;

    method Action deqRdResp;
        rdReqQ.deq;
        nextWay <= nextWay + 1;
    endmethod
endmodule