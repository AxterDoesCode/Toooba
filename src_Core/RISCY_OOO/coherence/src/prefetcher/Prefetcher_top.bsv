import Prefetcher::*;
import Prefetcher_intf::*;
import CDP::*;
import CDPLLC::*;
import CDPMultiIssue::*;
import CDPPathHist::*;
import CDPPathHistXor::*;
import CDPAdaptive::*;
import CDPProbTT::*;
import CDPKillSwitch::*;
import CDPAttrib::*;
import CDPHybrid::*;
import CDPHybrid2::*;
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
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelative(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_LLC
        // Variant B: LLC-routed CDP — prefetches go to the parent cache only, no L1 population.
        // Reduces L1 pollution at the cost of L1-hit latency vs LLC-hit latency on the target.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeLLC(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_MULTIISSUE
        // Variant C: multi-offset CDP — emit top-2 high-conf offsets per decision.
        // Targets treeadd/voronoi where both child pointers live in the same line.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeMultiIssue(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_PATHHIST
        // Variant D: path-history-keyed CDP — PC-table indexed by hash(pcHash ^ pathSig)
        // where pathSig is a rolling XOR of last few pcHashes (SPP-inspired).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativePathHist(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_PATHHIST_XOR
        // Variant D2: path-history via pure XOR of last-4 pcHashes (order-INDEPENDENT).
        // Same set of recent PCs in any order → same signature. Tests whether the
        // shift-based ordering in Variant D was helpful or over-sensitive.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativePathHistXor(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold);
    `elsif DATA_PREFETCHER_CDP_ADAPTIVE
        // Variant E: per-PC adaptive L1/LLC routing. Tracks useful/useless counters
        // per PC-table entry; routes high-accuracy PCs to L1 (reap hit-latency) and
        // low-accuracy PCs to LLC (avoid L1 pollution). Ebrahimi et al.-inspired.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        // 15/16 = 93.75% — very strict. The observed useless counter is biased
        // LOW (filter entries evict before useless events can attribute), so
        // threshold must compensate by being close to 1.0 to actually demote
        // the pollution-causing PCs.
        Parameter#(15)   accHighConfThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeAdaptive(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, accHighConfThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH
        // Variant H: strict "do no harm" kill-switch CDP. Per-PC uselessCount;
        // once a PC accumulates killThreshold useless attributions it stops
        // issuing ANY prefetches (not LLC-routed, just suppressed).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;   // 5 uselessBumps → blacklist (with 1024-entry filter for better attribution)
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitch(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_PROBTT
        // Variant F: probabilistic TT overwrite. Same as baseline CDP but a TT
        // existing-entry overwrite is accepted only ttOverwriteNum / ttOverwriteDenom
        // of the time (default ~6.25%). Keeps established (vaddr -> pcHash) training
        // context alive longer across scans by competing PCs.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(1)    ttOverwriteNum <- mkParameter;    // num / denom = overwrite probability
        Parameter#(16)   ttOverwriteDenom <- mkParameter;  // power of 2
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeProbTT(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, ttOverwriteNum, ttOverwriteDenom);
    `elsif DATA_PREFETCHER_CDP_ATTRIB
        // Variant J: separate 4096-entry secondary attribution table for
        // unbiased useless-event attribution, independent of the 1024-entry
        // dedup filter. Feeds the same ratio-based kill-switch gate as H,
        // but with a 1x (not 3x amplified) uselessCount bump -- testing
        // whether unbiased attribution alone is enough signal.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(2)    killThreshold <- mkParameter;   // J2: dropped 5 -> 2 to match H4's effective rate (H4 amplifies 3x)
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeAttrib(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_HYBRID
        // Variant L: classifier-dispatched CDP. Per-PC 64-entry stride
        // classifier; if a PC shows >=3 consecutive stride matches with a
        // non-zero line-granularity stride, it's flagged STRIDE-class and
        // CDP's content-scan prefetch is SUPPRESSED for that PC. Research-
        // grounded (IPCP ISCA'20, Ebrahimi HPCA'09).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(3)    strideClassThreshold <- mkParameter;   // 3 consecutive stride matches -> STRIDE-class
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeHybrid(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, strideClassThreshold);
    `elsif DATA_PREFETCHER_CDP_HYBRID2
        // Variant L2: same classifier as L, but stride-class PCs get a
        // stride-ahead prefetch EMITTED (not just suppressed).
        // CDP content-scan still applies to non-strided PCs.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(3)    strideClassThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeHybrid2(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, strideClassThreshold);
    `elsif DATA_PREFETCHER_CDP_NAIVE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPNaive(toTlb, matchBits);
    `endif
    //let m <- mkPCPrefetcherAdapter(mkAlwaysRequestPrefetcher);
`else 
    let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
`endif
    return m;
endmodule
