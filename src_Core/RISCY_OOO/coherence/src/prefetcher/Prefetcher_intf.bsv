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
import CacheUtils::*;
import Types::*;
import CCTypes::*;
import ISA_Decls   :: *;
import ProcTypes::*;
import CHERICap::*;
import CHERICC_Fat::*;
import MemoryTypes::*;

typedef enum {
    HIT = 1'b0, MISS = 1'b1
} HitOrMiss deriving (Bits, Eq, FShow);

typedef struct {
	Bit#(Report_Width) evt_0;
	Bit#(Report_Width) evt_1;
	Bit#(Report_Width) evt_2;
	Bit#(Report_Width) evt_3;
	Bit#(Report_Width) evt_4;
} EventsPrefetcher deriving (Bits, FShow);

interface Prefetcher;
    (* always_ready *)
    method Action reportAccess(Addr addr, HitOrMiss hitMiss);
    method ActionValue#(Addr) getNextPrefetchAddr();
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events();
`endif
endinterface

interface PCPrefetcher;
    (* always_ready *)
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
    method ActionValue#(Addr) getNextPrefetchAddr();
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events();
`endif
endinterface

interface CheriPCPrefetcher;
    (* always_ready *)
    method Action reportAccess(Addr addr, PCHash pcHash, HitOrMiss hitMiss, MemOp memOp, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    method Action reportCacheDataArrival(CLine lineWithTags, Addr addr, PCHash pcHash, MemOp memOp, 
        Bool wasMiss, Bool wasPrefetch, Addr boundsOffset, Addr boundsLength, Addr boundsVirtBase, Bit#(31) capPerms);
    method ActionValue#(Tuple2#(Addr, CapPipe)) getNextPrefetchAddr();
`ifdef PERFORMANCE_MONITORING
    method EventsPrefetcher events();
`endif
endinterface