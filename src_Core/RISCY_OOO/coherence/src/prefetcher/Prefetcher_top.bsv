import Prefetcher::*;
import Prefetcher_intf::*;
import CDP::*;
import CCTypes::*;
import Types::*;

module mkL1DPrefetcher(CacheLinePrefetcher#(reqT))
provisos (
    Bits#(reqT, _reqSz), 
    FShow#(reqT),
    IsProcRq#(reqT)
);
`ifdef DATA_PREFETCHER_IN_L1
    `ifdef DATA_PREFETCHER_BLOCK
        let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkBlockPrefetcher));
    `elsif DATA_PREFETCHER_STRIDE
        //let m <- mkBRAMStridePCPrefetcher;
        let m <- mkPCToCacheLinePrefetcherAdapter(mkStride2PCPrefetcher);
    `elsif DATA_PREFETCHER_STRIDE_ADAPTIVE
        let m <- mkPCToCacheLinePrefetcherAdapter(mkBRAMStrideAdaptivePCPrefetcher);
    `elsif DATA_PREFETCHER_MARKOV
        let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkBRAMMarkovPrefetcher));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT
        let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkBRAMMarkovOnHitPrefetcher));
    `elsif DATA_PREFETCHER_MARKOV_ON_HIT_2
        let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkMarkovOnHit2Prefetcher));
    `elsif DATA_PREFETCHER_CDP
        Parameter#(4096) trainingTableSize <- mkParameter;
        Parameter#(4096) pcTableSize <- mkParameter;
        Parameter#(1024) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelative(trainingTableSize, pcTableSize, decayInterval, matchBits);
    `endif
    //let m <- mkPCPrefetcherAdapter(mkAlwaysRequestPrefetcher);
`else 
    let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
`endif
    return m;
endmodule
