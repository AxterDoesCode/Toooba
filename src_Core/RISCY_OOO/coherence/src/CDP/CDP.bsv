import TlbTypes ::*;
import CCTypes ::*;
import Prefetcher::*;
import FIFO::*;

interface CDP#(type reqT);
    method Action enqLineL1(reqT req, Line line);
    interface Prefetcher prefetcher;
endinterface

typedef struct {
    reqT req
    Line line
} L1ToCDPT#(type reqT) deriving (Bits, FShow);

module mkCDP(CDP);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    method Action enqLineL1(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("AlexLog: CDP enqLineL1");
    endmethod

    interface prefetcher;
        method Action reportAccess(Addr addr, HitOrMiss hitMiss);
        endmethod
        method ActionValue#(Addr) getNextPrefetchAddr if (False);
            return 64'h0;
        endmethod
    endinterface
endmodule
