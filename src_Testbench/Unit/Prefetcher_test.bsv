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
import Prefetcher_top::*;
import MarkovPrefetchers::*;
import StridePrefetchers::*;
import InstructionPrefetchers::*;
import RWBramCore::*;
import StmtFSM::*;
import Types::*;
import Fifos::*;

module mkTargetTableTest(Empty);
    TargetTable#(64, 16) t <- mkTargetTable;
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                t.writeReq('h8000, 'h800a); // goes in short table
            endaction
            action
                t.writeReq('h8001, 'h80008000); // goes in long table
            endaction
            action
                t.readReq('h8000); // comes from short table
            endaction
            action
                let x <- t.readResp(); // comes from short table
                doAssert(x == Valid('h800a), "test fail!");
            endaction
            action
                t.readReq('h8001); // comes from long table
            endaction
            action
                let x <- t.readResp(); // comes from long table
                doAssert(x == Valid('h80008000), "test fail!");
            endaction
            action
                t.writeReq('h80000000, 'h21230000); // goes in long table
            endaction
            action
                t.readReq('h80000000); // comes from long table
            endaction
            action
                let x <- t.readResp(); // comes from long table
                doAssert(x == Valid('h21230000), "test fail!");
            endaction
            action
                t.writeReq('h7000, 'h6fde); // goes in short table backwards
            endaction
            action
                t.readReq('h7000); // get from short table
            endaction
            action
                let x <- t.readResp(); // get from short table
                doAssert(x == Valid('h6fde), "test fail!");
            endaction
            action
                t.readReq('h7000); // get from short table
            endaction
            action
                let x <- t.readResp(); // get from short table
                doAssert(x == Valid('h6fde), "test fail!"); //entry still there
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkTargetTableDoubleTest(Empty);
    TargetTableDouble#(2048, 128) t <- mkTargetTableDouble;
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                t.sendReadWriteReq('h8000, MISS); // goes in short table
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h800a, MISS); // goes in short table
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8080000b, MISS); // goes in long table
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); // comes from short table
            endaction
            action
                let x <- t.readResp(); 
                doAssert(x == tuple2(Valid('h800a), Invalid), "test fail!");
            endaction
            action
                t.sendReadWriteReq('h800a, MISS); // comes from long table
            endaction
            action
                let x <- t.readResp(); 
                doAssert(x == tuple2(Valid('h8080000b), Invalid), "test fail!");
            endaction


            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h2123000c, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, HIT); 
            endaction
            action
                let x <- t.readResp(); 
                doAssert(x == tuple2(Valid('h2123000c), Valid('h800a)), "test fail!");
            endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h2123000c, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h2123000c), Valid('h800a)), "test fail!");
            endaction


            /// ---- Add third entry (narrow) 8003
            action
                t.sendReadWriteReq('h8003, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                //wide entry is moved to LRU
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h8003), Valid('h2123000c)), "test fail!");
            endaction
            action
                t.sendReadWriteReq('h8003, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h8003), Valid('h2123000c)), "test fail!");
            endaction
            //refresh 21230000
            action
                t.sendReadWriteReq('h2123000c, MISS); 
            endaction
            action let x <- t.readResp(); endaction

            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h2123000c), Valid('h8003)), "test fail!");
            endaction

            /// ---- Add another entry (wide) 2123000d
            action
                t.sendReadWriteReq('h2123000d, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                //wide entry is moved to LRU
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h2123000d), Valid('h2123000c)), "test fail!");
            endaction


            /// ---- Add fifth entry (narrow) 8004
            action
                t.sendReadWriteReq('h8004, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                //wide entry is moved to LRU
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h8004), Valid('h2123000d)), "test fail!");
            endaction
            // --- Add a sixth narrow entry 8005
            action
                t.sendReadWriteReq('h8005, MISS); 
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h8000, MISS); 
            endaction
            action
                //wide entry is moved to LRU
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h8005), Valid('h8004)), "test fail!");
            endaction


            action 
                t.sendReadWriteReq('h7004, MISS); // get from short table 
            endaction

            action
                let x <- t.readResp(); 
                doAssert(x == tuple2(Invalid, Invalid), "test fail!");
            endaction
            action
                t.sendReadWriteReq('h6fde, MISS); // get from short table
            endaction
            action let x <- t.readResp(); endaction
            action
                t.sendReadWriteReq('h7004, MISS); // get from short table
            endaction
            action
                let x <- t.readResp();
                doAssert(x == tuple2(Valid('h6fde), Invalid), "test fail!");
            endaction
            action
                t.sendReadWriteReq('h200, HIT); // get from short table
            endaction
            action
                let x <- t.readResp();
                doAssert(x == tuple2(Invalid, Invalid), "test fail!"); //entry was removed!
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkMultiWindowTargetPrefetcherTest(Empty);
    Parameter#(4) numWindows <- mkParameter;
    Parameter#(4) numLastRequests <- mkParameter;
    Parameter#(3) numLinesInRange <- mkParameter;
    let p <- mkMultiWindowTargetPrefetcher(numWindows, numLastRequests, numLinesInRange);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                p.reportAccess('h800040, MISS);
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800080, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h8000c0, "test fail!");
            endaction
            action
                p.reportAccess('h8000c0, HIT); //Report hit inside window
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800100, "test fail!");
            endaction
            action
                p.reportAccess('h804000, HIT); //Report hit outside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //Previous window still recommended
                doAssert(x == 'h800140, "test fail!");
            endaction
            action
                p.reportAccess('h800140, MISS); //Report miss inside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //Previous window still recommended
                doAssert(x == 'h800180, "test fail!");
            endaction

            // -----  Allocate other windows ----- 
            action
                p.reportAccess('h700000, MISS); //Report miss outside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //new window recommended
                doAssert(x == 'h700040, "test fail!");
            endaction
            action
                p.reportAccess('h900000, MISS); //Report miss outside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //new window recommended
                doAssert(x == 'h900040, "test fail!");
            endaction
            action
                p.reportAccess('h600000, MISS); //Report miss outside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //new window recommended
                doAssert(x == 'h600040, "test fail!");
            endaction
            action
                p.reportAccess('h800180, HIT); //Report hit inside oldest window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //oldest window recommended
                doAssert(x == 'h8001c0, "test fail!");
            endaction

            // ----- Trigger window deletion -----
            action
                p.reportAccess('h500000, MISS); //Report miss outside window,
                //discard window with 'h70..
            endaction
            action
                let x <- p.getNextPrefetchAddr; //new window recommended
                doAssert(x == 'h500040, "test fail!");
            endaction
            action
                p.reportAccess('h700040, HIT); //Report hit inside now deleted window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //most recent window still recommended
                doAssert(x == 'h500080, "test fail!");
            endaction

            // ----- Reorder some more windows around
            action
                p.reportAccess('h8001c0, MISS); //Report hit inside now deleted window
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h800200, "test fail!");
            endaction

            // ------ Test saving and prefetching target clines
            action
                p.reportAccess('h810000, MISS); //Report miss somewhere far away
            endaction
            action
                let x <- p.getNextPrefetchAddr; //New window allocated and recommended
                doAssert(x == 'h810040, "test fail!");
            endaction
            action
                p.reportAccess('h800180, MISS); //Report miss back home
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h8001c0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; //target address recommended
                doAssert(x == 'h500000, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h800200, "test fail!"); // window addresss recommended
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkSingleWindowTargetPrefetcherTest(Empty);
    //2 ahead
    //remember last 2 target table requests.
    Parameter#(2) numLastRequests <- mkParameter;
    Parameter#(2) cacheLinesInRange <- mkParameter;
    let p <-  mkSingleWindowTargetPrefetcher(numLastRequests, cacheLinesInRange);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                p.reportAccess('h80000040, MISS);
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000080, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800000c0, "test fail!");
            endaction
            action
                p.reportAccess('h800000c0, HIT); //Report hit inside window
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000100, "test fail!");
            endaction
            action
                p.reportAccess('h80004000, HIT); //Report hit outside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //Previous window still recommended
                doAssert(x == 'h80000140, "test fail!");
            endaction
            action
                p.reportAccess('h80000140, MISS); //Report miss inside window
            endaction
            action
                let x <- p.getNextPrefetchAddr; //Previous window still recommended
                doAssert(x == 'h80000180, "test fail!");
            endaction
            action
                p.reportAccess('h81000200, MISS); //Report miss somewhere far away
            endaction
            action
                let x <- p.getNextPrefetchAddr; //New window allocated and recommended
                doAssert(x == 'h81000240, "test fail!");
            endaction
            action
                p.reportAccess('h80000180, MISS); //Report miss back home
            endaction
            action endaction
            action
                p.reportAccess('h82000000, MISS); //Report miss far away 2
            endaction
            action
                p.reportAccess('h80000140, MISS); //Report miss back home
            endaction
            action
                let x <- p.getNextPrefetchAddr; //target address recommended
                doAssert(x == 'h81000200, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80000180, "test fail!"); // window addresss recommended
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkStridePCPrefetcherTest(Empty);
    Parameter#(512) strideTableSize <- mkParameter;
    Parameter#(3) cLinesAheadToPrefetch <- mkParameter;
    let p <- mkStridePCPrefetcher(strideTableSize, cLinesAheadToPrefetch);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action $display("%t", $time); p.reportAccess('h80000040, 'h0069, MISS); endaction
            action p.reportAccess('h80000080, 'h0069, HIT); endaction
            action p.reportAccess('h800000a0, 'h0069, HIT); endaction
            action p.reportAccess('h800000c0, 'h0069, MISS); endaction
            action p.reportAccess('h800000e0, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000100, "test fail!");
            endaction
            action p.reportAccess('h80000100, 'h0069, HIT); endaction
            action p.reportAccess('h80000120, 'h0069, HIT); endaction
            action p.reportAccess('h80000140, 'h0069, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000140, "test fail!");
            endaction
            action endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000180, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800001c0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000200, "test fail!");
            endaction
            action p.reportAccess('h900001f0, 'h006a, MISS); endaction
            action p.reportAccess('h900001c0, 'h006a, HIT); endaction
            action p.reportAccess('h90000190, 'h006a, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000150, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000110, "test fail!");
            endaction
            action p.reportAccess('h90000100, 'h006b, MISS); endaction
            action p.reportAccess('h90000200, 'h006b, MISS); endaction
            action p.reportAccess('h90000300, 'h006b, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h900000d0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000400, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000500, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000600, "test fail!");
            endaction
            action p.reportAccess('h90000160, 'h006a, HIT); endaction
            // -- use older entry
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h900000a0, "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkStrideAdaptivePCPrefetcherTest(Empty);
    // config is 2 - 3 - 5
    Parameter#(512) strideTableSize <- mkParameter;
    Parameter#(2) cLinesPrefetchMin <- mkParameter;
    Parameter#(3) cLinesSmallStridePrefetchMax <- mkParameter;
    Parameter#(5) cLinesBigStridePrefetchMax <- mkParameter;
    let p <- mkStrideAdaptivePCPrefetcher(
        strideTableSize, 
        cLinesPrefetchMin, 
        cLinesSmallStridePrefetchMax, 
        cLinesBigStridePrefetchMax);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action $display("%t", $time); p.reportAccess('h80000040, 'h0069, MISS); endaction
            action p.reportAccess('h80000080, 'h0069, HIT); endaction
            action p.reportAccess('h800000a0, 'h0069, HIT); endaction
            action p.reportAccess('h800000c0, 'h0069, MISS); endaction
            action p.reportAccess('h800000e0, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000100, "test fail!");
            endaction
            action p.reportAccess('h80000100, 'h0069, HIT); endaction
            action p.reportAccess('h80000120, 'h0069, HIT); endaction
            action p.reportAccess('h80000140, 'h0069, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000140, "test fail!");
            endaction
            action endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000180, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800001c0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000200, "test fail!");
            endaction
            action p.reportAccess('h900001f0, 'h006a, MISS); endaction
            action p.reportAccess('h900001c0, 'h006a, HIT); endaction
            action p.reportAccess('h90000190, 'h006a, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000240, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000280, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000150, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000110, "test fail!");
            endaction
            action p.reportAccess('h90000100, 'h006b, MISS); endaction
            action p.reportAccess('h90000200, 'h006b, MISS); endaction
            action p.reportAccess('h90000300, 'h006b, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000400, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000500, "test fail!");
            endaction
            action p.reportAccess('h90000160, 'h006a, HIT); endaction
            // -- use older entry
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h900000e0, "test fail!");
            endaction
            action p.reportAccess('h80000080, 'h0069, MISS); endaction
            //Tolerate broken stride, request again
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800000c0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000100, "test fail!");
            endaction
            action p.reportAccess('h80000088, 'h0069, MISS); endaction
            action p.reportAccess('h80000090, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800000d0, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000110, "test fail!");
            endaction
            action p.reportAccess('h80000098, 'h0069, MISS); endaction
            action p.reportAccess('h800000a0, 'h0069, MISS); endaction
            action p.reportAccess('h800000a8, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000168, "test fail!");
            endaction
            action p.reportAccess('h800000b0, 'h0069, MISS); endaction
            action p.reportAccess('h800000b8, 'h0069, MISS); endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkMarkovOnHit2PrefetcherTest(Empty);
    Parameter#(2) maxChainLength <- mkParameter;
    Parameter#(2) numLastRequestsTracked <- mkParameter;
    let p <- mkMarkovOnHit2Prefetcher(maxChainLength, numLastRequestsTracked);
    mkAutoFSM(
        seq
            action
                p.reportAccess('h80010000, MISS);
            endaction
            action
                p.reportAccess('h80010700, MISS); 
            endaction
            action
                p.reportAccess('h90010000, MISS); 
            endaction
            action
                p.reportAccess('ha0010300, MISS); 
            endaction
            action
                p.reportAccess('h80010000, MISS); //back to start
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80010700, "test fail!");
            endaction

            //Add second target
            action
                p.reportAccess('h80010900, MISS); 
            endaction
            action
                p.reportAccess('h80010000, MISS); //back to start
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80010900, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80010700, "test fail!");
            endaction

            action
                p.reportAccess('ha0010300, MISS); 
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80010000, "test fail!");
            endaction
            action
                p.reportAccess('ha0010200, MISS); 
            endaction
            action
                p.reportAccess('ha0010300, MISS); 
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'ha0010200, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h80010000, "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkMarkovPrefetcherTest(Empty);
    Parameter#(2) maxChainLength <- mkParameter;
    Parameter#(2048) narrowEntries <- mkParameter;
    Parameter#(1024) wideEntries <- mkParameter;
    let p <- mkMarkovPrefetcher(maxChainLength, narrowEntries, wideEntries);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                p.reportAccess('h8000, MISS);
            endaction
            action
                p.reportAccess('h8700, MISS); 
            endaction
            action
                p.reportAccess('h9000, MISS); 
            endaction
            action
                p.reportAccess('ha000, MISS); 
            endaction
            action
                p.reportAccess('h8000, MISS); //back to start
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h8700, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h9000, "test fail!");
            endaction
            action
                p.reportAccess('h8700, HIT); 
            endaction
            action
                p.reportAccess('ha000, MISS); 
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'h8000, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr; 
                doAssert(x == 'ha000, "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule
module mkOverflowPipelineFifoTest(Empty);
    //let p <- mkMultipleWindowPrefetcher;
    Fifo#(4, Bit#(8)) p <- mkOverflowPipelineFifo;
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action
                p.enq('h01);
            endaction
            action
                p.enq('h02);
            endaction
            action
                p.enq('h03);
            endaction
            action
                p.enq('h04);
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h01, "test fail!");
            endaction
            action
                p.enq('h05);
                let x = p.first; 
                p.deq;
                doAssert(x == 'h02, "test fail!");
            endaction
            action
                p.enq('h06);
            endaction
            action
                p.enq('h07);
                let x = p.first; 
                p.deq;
                doAssert(x == 'h03, "test fail!");
            endaction
            action
                p.enq('h08);
            endaction
            action
                p.enq('h09);
                let x = p.first; 
                p.deq;
                doAssert(x == 'h05, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h06, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h07, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h08, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h09, "test fail!");
            endaction
            action
                doAssert(!p.notEmpty, "test fail!");
            endaction
            action
                $display("test done!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkOverflowBypassFifoTest(Empty);
    // Problem: BSV doesn't seem to allow enq and deq in the same action, so we can't actually
    // test the bypass behaviour here.
    Fifo#(4, Bit#(8)) p <- mkOverflowBypassFifo;
    mkAutoFSM(
        seq
            action
                p.enq('h01);
            endaction
            action
                p.enq('h02);
            endaction
            action
                p.enq('h03);
            endaction
            action
                p.enq('h04);
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h01, "test fail!");
            endaction
            action
                p.enq('h05);
            endaction
            action
                p.deq;
                let x = p.first; 
                doAssert(x == 'h02, "test fail!");
            endaction
            action
                p.enq('h06);
            endaction
            action
                p.enq('h07);
            endaction
            action
                p.deq;
                let x = p.first; 
                doAssert(x == 'h04, "test fail!");
            endaction
            action
                p.enq('h08);
            endaction
            action
                p.enq('h09);
            endaction
            action
                p.deq;
                let x = p.first; 
                doAssert(x == 'h06, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h07, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h08, "test fail!");
            endaction
            action
                let x = p.first; 
                p.deq;
                doAssert(x == 'h09, "test fail!");
            endaction
            action
                doAssert(!p.notEmpty, "test fail!");
            endaction
            action
                $display("test done!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkStride2PCPrefetcherTest(Empty);
    Parameter#(512) strideTableSize <- mkParameter;
    Parameter#(2) cLinesAheadToPrefetch <- mkParameter;
    let p <- mkStride2PCPrefetcher(strideTableSize, cLinesAheadToPrefetch);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action $display("%t", $time); p.reportAccess('h80000040, 'h0069, MISS); endaction
            action p.reportAccess('h80000080, 'h0069, HIT); endaction
            action p.reportAccess('h800000a0, 'h0069, HIT); endaction
            action p.reportAccess('h800000c0, 'h0069, MISS); endaction
            action p.reportAccess('h800000e0, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000120, "test fail!");
            endaction
            action p.reportAccess('h80000100, 'h0069, HIT); endaction
            action p.reportAccess('h80000120, 'h0069, HIT); endaction
            action p.reportAccess('h80000140, 'h0069, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000160, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000180, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h800001c0, "test fail!");
            endaction
            action p.reportAccess('h900001f0, 'h006a, MISS); endaction
            action p.reportAccess('h900001c0, 'h006a, HIT); endaction
            action p.reportAccess('h90000190, 'h006a, HIT); endaction
            action p.reportAccess('h90000160, 'h006a, HIT); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000150, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000110, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h900000e0, "test fail!");
            endaction
            action p.reportAccess('h90000100, 'h006b, MISS); endaction
            action p.reportAccess('h90000200, 'h006b, MISS); endaction
            action p.reportAccess('h90000300, 'h006b, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000400, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h90000500, "test fail!");
            endaction
            action p.reportAccess('ha0000420, 'h006b, MISS); endaction
            action p.reportAccess('ha0000520, 'h006b, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'ha0000620, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'ha0000720, "test fail!");
            endaction

            action p.reportAccess('h90000130, 'h006a, HIT); endaction
            // -- use older entry
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h900000b0, "test fail!");
            endaction
            
            // -- test blocking on page boundaries
            action p.reportAccess('ha0000000, 'h006c, MISS); endaction
            action p.reportAccess('ha0000400, 'h006c, MISS); endaction
            action p.reportAccess('ha0000800, 'h006c, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'ha0000c00, "test fail!");
            endaction
            action p.reportAccess('ha0000c00, 'h006c, MISS); endaction
            action p.reportAccess('hb0000000, 'h006c, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'hb0000400, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'hb0000800, "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkPrefetcherVectorTest(Empty);
    Parameter#(2) lines <- mkParameter;
    PrefetcherVector#(3) p <- mkCheriPrefetcherVector(mkNextLineOnMissPrefetcher(lines));
    mkAutoFSM(
        seq
            action p.reportAccess(1, 'h90000000, MISS); endaction
            action p.reportAccess(0, 'h80000000, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h90000040, 1), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h90000080, 1), "test fail!");
            endaction
            action p.reportAccess(0, 'h40000000, MISS); endaction
            action p.reportAccess(1, 'h50000000, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h80000040, 0), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h40000040, 0), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h50000040, 1), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h40000080, 0), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('h50000080, 1), "test fail!");
            endaction
            action p.reportAccess(2, 'ha0000000, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('ha0000040, 2), "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                $display("%t Got %x", $time, x);
                doAssert(x == tuple2('ha0000080, 2), "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule

module mkSimpleStridePCPrefetcherTest(Empty);
    Parameter#(512) strideTableSize <- mkParameter;
    Parameter#(2) cLinesAheadToPrefetch <- mkParameter;
    Parameter#(2) minConfidenceToPrefetch <- mkParameter;
    let p <- mkSimpleStridePCPrefetcher(strideTableSize, cLinesAheadToPrefetch, minConfidenceToPrefetch);
    mkAutoFSM(
        seq
            // ----- Send misses and stuff to one window -----
            action $display("%t", $time); p.reportAccess('h80000040, 'h0069, MISS); endaction
            action p.reportAccess('h80000080, 'h0069, HIT); endaction
            action p.reportAccess('h800000a0, 'h0069, HIT); endaction
            action p.reportAccess('h800000c0, 'h0069, MISS); endaction
            action p.reportAccess('h800000e0, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000120, "test fail!");
            endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000160, "test fail!");
            endaction
            action p.reportAccess('h80000400, 'h0069, MISS); endaction
            action p.reportAccess('h80000300, 'h0069, MISS); endaction
            action p.reportAccess('h80000200, 'h0069, MISS); endaction
            action p.reportAccess('h80000100, 'h0069, MISS); endaction
            action
                let x <- p.getNextPrefetchAddr;
                doAssert(x == 'h80000000, "test fail!");
            endaction
            action
                $display("Test finished!");
            endaction
            action
                $display("Test finished!");
            endaction
        endseq
    );
endmodule