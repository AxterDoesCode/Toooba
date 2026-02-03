import MemoryTypes::*; // Import from RISCYOOO
import TlbTypes ::*;
import CCTypes ::*;
import Prefetcher::*;
import FIFO::*;

import Types::*;

interface CDP#(
    type reqT
);
    method Action enqLineL1(reqT req, Line line);
    interface Prefetcher prefetcher;
endinterface

typedef struct {
    reqT req;
    Line line;
} L1ToCDPT#(type reqT) deriving (Bits, FShow, Eq);

module mkCDP(
    CDP#(reqT)
) provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req));
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        $display("AlexLog: CDP deqLineL1");
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                /* I'm curious if the candidate vaddr are at the offset of the actual thing requested 
                (e.g. pointer loading a pointer, or if its discovering pointers within the line) */
                $display("AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
            end
            //else
                //$display("AlexLog: No CDP candidate vaddr found, offset: %d, LineDataOffset: ", i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
        end
    endrule

    method Action enqLineL1(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("AlexLog: CDP enqLineL1");
    endmethod

    interface Prefetcher prefetcher;
        method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        endmethod
        method ActionValue#(Addr) getNextPrefetchAddr if (False);
            return 64'h0;
        endmethod
    endinterface
endmodule
