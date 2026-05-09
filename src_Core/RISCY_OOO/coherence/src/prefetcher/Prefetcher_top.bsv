import Prefetcher::*;
import Prefetcher_intf::*;
import CDP::*;
import SelectiveCDP::*;
import CCTypes::*;
import Types::*;
import TlbTypes::*;

module mkL1DPrefetcher#(TlbToPrefetcher toTlb)(CacheLinePrefetcher#(reqT))
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
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter; // For downsize 2 configuration, used a 128 size pcTable, whilst decayInterval remained at 16, I'm guessing the high confidence patterns stayed (for Voronoi).
        Parameter#(16) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelative(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_NAIVE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPNaive(toTlb, matchBits);
    `elsif DATA_PREFETCHER_SELECTIVECDP
        // SelectiveCDP: per-PC confidence table + dual-mode picker +
        // neighbour-chain follow-up + prefetch filter + kill switch.
        // Neighbour-chain fires on both hit and miss responses.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkSelectiveCDP(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `endif
    //let m <- mkPCPrefetcherAdapter(mkAlwaysRequestPrefetcher);
`else 
    let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
`endif
    return m;
endmodule
