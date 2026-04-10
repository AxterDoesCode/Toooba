import Types::*;
import TlbTypes::*;
import MemoryTypes::*;
import CCTypes::*;

typedef struct {
    Addr addr;
    Vpn  vpn;
    Bool nextLevel;
} PendingPrefetch deriving (Bits, Eq, FShow);

typedef enum {
    HIT = 1'b0, MISS = 1'b1
} HitOrMiss deriving (Bits, Eq, FShow);

interface PCPrefetcher;
    (* always_ready *)
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
    method ActionValue#(Addr) getNextPrefetchAddr();
endinterface

interface SudoPrefetcher;
    (* always_ready *)
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss);
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr();
endinterface

interface CacheLinePrefetcher#(
    type reqT
);
    (* always_ready *)
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
    method Action reportIncomingCacheLine(reqT req, Line line);
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr();
endinterface

module mkPCToCacheLinePrefetcherAdapter#(module#(PCPrefetcher) mkPCPrefetcher)(CacheLinePrefetcher#(reqT));
    let p <- mkPCPrefetcher;
    method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss, Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
        p.reportAccess(addr, pcHash, hitMiss);
    endmethod
    method ActionValue#(PendingPrefetch) getNextPrefetchAddr;
        let addr <- p.getNextPrefetchAddr;
        return PendingPrefetch{
            addr: addr,
            vpn: ?, // No VPN carried? Can we carry a VPN through?, If we are combining prefetchers then maybe this needs to become a Maybe type
            nextLevel: False
        };
    endmethod
    method Action reportIncomingCacheLine(reqT req, Line line);
        $display("%t AlexLog: CDP reportIncomingCacheLine", $time);
    endmethod
endmodule
