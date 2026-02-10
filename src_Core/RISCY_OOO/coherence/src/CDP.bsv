import MemoryTypes::*; // Import from RISCYOOO
import TlbTypes ::*;
import CCTypes ::*;
import Prefetcher::*;
import FIFO::*;
import Fifos::*;
import Ehr::*;

import Types::*;

interface CDP#(
    type reqT
);
    method Action enqLineL1(reqT req, Line line);
    interface PCPrefetcher prefetcher;
endinterface

typedef struct {
    reqT req;
    Line line;
} L1ToCDPT#(type reqT) deriving (Bits, FShow, Eq);

typedef struct {
    Addr paddr;
    Addr vaddr;
} NextCandT deriving (Bits, FShow, Eq);

module mkCDP(
    CDP#(reqT)
) provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);

    FIFO#(L1ToCDPT#(reqT)) l1ToCDP <- mkFIFO;

    // 8 used, one line there is potentially 8 candidate vaddr
    SupFifo#(8, 8, NextCandT) nextCandidateBuffer <- mkSupFifo;

    rule deqLineL1;
        L1ToCDPT#(reqT) x = l1ToCDP.first;
        LineDataOffset dataSel = getLineDataOffset(getReqAddr(x.req)); // This is purely for $display
        l1ToCDP.deq;
        let reqVpn = getReqVpn(x.req);
        Integer enqIdx = 0;
        $display("%t AlexLog: CDP deqLineL1", $time);
        for (Integer i = 0; i < 8; i = i + 1) begin
            if (getVpn(x.line[i]) == reqVpn &&& getReqOp(x.req) == Ld) begin
                nextCandidateBuffer.enqS[enqIdx].enq(
                    NextCandT{
                        paddr: getReqAddr(x.req), 
                        vaddr: x.line[i]});
                // Probably change logging here to just see the candidate vaddr -> candidate paddr?
                $display("%t AlexLog: CDP candidate vaddr found, offset: %d, LineDataOffset: ", $time, i, fshow(dataSel), fshow(x.line[i]), fshow(reqVpn), fshow(x.req));
                enqIdx = enqIdx + 1;
            end
        end
    endrule

    method Action enqLineL1(reqT req, Line line);
        let tmp = L1ToCDPT{
            req: req,
            line: line
        };
        l1ToCDP.enq(tmp);
        $display("%t AlexLog: CDP enqLineL1", $time);
    endmethod

    interface PCPrefetcher prefetcher;
        method Action reportAccess(Addr addr,Bit#(16) pcHash, HitOrMiss hitMiss);
            if (hitMiss == HIT) begin
                $display("%t AlexLog: prefetcher report HIT %h", $time, addr);
            end
            else begin
                $display("%t AlexLog: prefetcher report MISS %h", $time, addr);
            end
        endmethod

        method ActionValue#(Addr) getNextPrefetchAddr; // Do I want some condition here?
            // Found a virtual address and need to translate it now,
            // because I'm matching the VPN that caused to load to potential vaddrs with the same VPN, then the PPN should also be the same
            let x = nextCandidateBuffer.deqS[0].first;
            nextCandidateBuffer.deqS[0].deq;
            // Use the same VPN -> PPN, but get the offset of the candidate vaddr
            Addr nextAddr = zeroExtend({getPpn(x.paddr), getPageOffset(x.vaddr)});
            $display("%t AlexLog: CDP Prefetch addr issued. paddr: %h | vaddr: %h", $time, nextAddr, x.vaddr);
            return nextAddr;
        endmethod
    endinterface
endmodule
