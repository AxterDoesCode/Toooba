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
import CDPKillSwitchH6::*;
import CDPKillSwitchH7::*;
import CDPKillSwitchH8::*;
import CDPKillSwitchH8B::*;
import CDPKillSwitchH9::*;
import CDPKillSwitchH9B::*;
import CDPKillSwitchH10::*;
import CDPKillSwitchCA::*;
import CDPAttrib::*;
import CDPHybrid::*;
import CDPHybrid2::*;
import CDPPerceptron::*;
import CDPPPFRoute::*;
import CDPUtilConf::*;
import CDPUtilConfRoute::*;
import CDPGlobalGate::*;
import CDPBitMatch::*;
import CDPBitMatchPoly::*;
import CDPBMPolySupp::*;
import CDPBMPolyGrad::*;
import CDPBMDensThresh::*;
import CDPBMAlignSupp::*;
import CDPBMAlign8Supp::*;
import CDPBMAlignSuppConf::*;
import CDPBMChainScan::*;
import CDPBMAlignSuppConfT1::*;
import CDPBitMatchStride::*;
import CDPBitMatchPolyStride::*;
import CDPBitMatchEarly::*;
import CDPBitMatchPolyEarly::*;
import CDPBitMatchEarly2::*;
import CDPBitMatchEarly3::*;
import CDPBitMatchPolyEarly2::*;
import CDPBitMatchEarly4::*;
import CDPPureStride::*;
import CDPBMGSDeg::*;
import CDPBMAligned::*;
import CDPIRatio::*;
import DBP::*;
import SPP::*;
import SPPCooksey::*;
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
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_MB20
        // H4 at matchBits=20 (tighter than default 16 — fewer noise candidates).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(20)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitch(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_MB24
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(24)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitch(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_MB27
        // H4 at matchBits=27 (same-page only — tightest possible).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(27)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitch(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H6
        // Variant H6: H4 + enlarge incomingQ from 32 to 256. Instrumentation
        // showed the 32-entry staging FIFO fills for 9.9% of em3d cycles
        // (20-51% in compute-light phase), stalling pipelineResp_cRq. A bigger
        // FIFO buffers over the transient bursts.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH6(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H8
        // Variant H8: identical to H7 (same kill-switch + overflow-bypass FIFO).
        // Exists as a refactor playground -- current revision folds the 6
        // parallel pending-TLB register vectors into a single struct.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH8(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H8B
        // Variant H8B: 4-bit counters + halving-on-saturation. Isolates
        // halving's effect at H7's saturation point.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH8B(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H9
        // Variant H9: H7 + D-style shift-XOR path signature. pcTable keyed by
        // hash(pcHash ^ pathSig); TT stores scanSig (not raw pcHash) in its
        // pcHash field. Path signature updated in drainIncomingEvents only.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH9(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H9B
        // Variant H9B: H7 + D2-style XOR-of-last-4 path signature. Order-
        // independent ring buffer; hypothesis is that permutation collapse
        // reduces training dilution seen in H9.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH9B(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H10
        // Variant H10: H7 + per-prefetch lead-time instrumentation. Algorithm
        // identical to H7; filter entry gains issueCycle. On useful hit, log
        // line includes leadTime for post-hoc DRAM-vs-LLC classification.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH10(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H11
        // Variant H11: H7 with confidenceThreshold=3 (was 1). More selective
        // issuing — only emits prefetches when an offset has been "validated"
        // multiple times. Hypothesis: silences treeadd's polluting PCs
        // (9094/909a/9082, 5.6% accuracy) while preserving patricia's 84e0
        // (96% accuracy, saturates fast).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(3)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH7(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H12
        // Variant H12: H7 with confidenceThreshold=5. Even more selective.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(5)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH7(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_H7
        // Variant H7: H4 + non-blocking incomingQ via mkOverflowBypassFifo.
        // enq is always ready — on full, the oldest staged event is dropped
        // to make room. Trades training completeness for never blocking
        // pipelineResp_cRq. Kept at 32-entry; the semantic change is the
        // drop-on-full behaviour.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchH7(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_KILLSWITCH_CA
        // Variant H5: H4 + cache-aware dedup. On every demand-miss refill,
        // register the new lineAddr in the prefetchFilter so future prefetch
        // decisions for already-cached lines drop at filter HIT (killing the
        // 60-80% redundant-prefetch volume on treeadd/health).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(5)    killThreshold <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeKillSwitchCA(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
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
    `elsif DATA_PREFETCHER_CDP_PPF
        // Variant M: per-(PC, relOff) perceptron filter. Replaces H-family
        // kill-switch with a 256-entry signed-weight table. Weight +1 on
        // useful-hit, -1 on useless-evict; issue iff weight >= 0.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // issue iff perceptron >= 0
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativePPF(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_UTILCONF
        // Variant O: utility-gated conf. Training hits only make patterns
        // eligible (conf = threshold); useful/useless attribution events
        // climb/demote the conf within the existing pcTable infrastructure.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // unused in O
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeUtilConf(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_GLOBALGATE
        // Variant YY: global sliding trust score gates all decisions. Score>=0
        // issues normally; score<0 suppresses except 1/8 bleed-through.
        // Decay: halve score every 4096 cycles.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // unused in YY
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeGlobalGate(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_UTILCONFROUTE
        // Variant Z: O + N fusion. conf>=2 -> L1 (proven useful); conf==1 -> LLC
        // (eligible but unproven). No binary suppression; graceful degradation.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // unused in Z
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeUtilConfRoute(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_PPFROUTE
        // Variant N: PPF-gated ROUTING. Perceptron weight >= threshold -> L1;
        // weight < threshold -> LLC. Always issue (no binary drop). Targets
        // treeadd's B-style LLC-routing win without killing patricia's L1 win.
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // L1 iff perceptron >= 0
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativePPFRoute(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_NAIVE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPNaive(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_IRATIO
        // Variant IRATIO: per-PC issue-ratio kill-switch using DENSE issued
        // and useful counters (not sparse useless-evict attribution). Kills a
        // PC when issuedCount>=64 && useful*10<issued (<10% acc).
        Parameter#(64) trainingTableSize <- mkParameter;
        Parameter#(1024) pcTableSize <- mkParameter;
        Parameter#(256) decayInterval <- mkParameter;
        Parameter#(16)   matchBits <- mkParameter;
        Parameter#(1)    confidenceThreshold <- mkParameter;
        Parameter#(0)    killThreshold <- mkParameter;    // unused in IRATIO
        CacheLinePrefetcher#(reqT) m <- mkCDPStatefulRelativeIRatio(toTlb, trainingTableSize, pcTableSize, decayInterval, matchBits, confidenceThreshold, killThreshold);
    `elsif DATA_PREFETCHER_CDP_BITMATCH
        // Variant BM: clean bit-matching-only prefetcher. Miss-only + 1024
        // dedup filter. No PC table, no TT, no conf.
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatch(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHPOLY
        // BM-POLY-MB27 (best POLY) — kept at mb=27 since that was best.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchPoly(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMPOLYSUPP
        // BMPolySupp-MB27: multi-match → SUPPRESS (not LLC-route). If
        // treeadd's multi-match pattern stops issuing entirely, we converge
        // to NoPref on treeadd.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMPolySupp(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMPOLYGRAD
        // BMPolyGrad-MB27: graded routing by match count.
        //   1       -> L1 (clean pointer)
        //   2-3     -> LLC (noisy but useful to pre-warm)
        //   >=4     -> SUPPRESS (high noise; likely false pos)
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMPolyGrad(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMDENSTHRESH
        // BMDensThresh-MB27: BMPolySupp + per-PC reliability gate.
        // Tracks a 4-bit signed score per PC (256 entries). Single-match
        // from PCs with negative score (mostly-multi-match history) are
        // suppressed, killing the unreliable-PC tail of single-match false
        // positives.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMDensThresh(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMALIGNSUPP
        // BMAlignSupp-MB27: BMPolySupp + pointer-shape filters.
        // Candidate must also be 16-byte aligned AND have upper 25 bits
        // zero (valid SV39 vaddr shape). Tightens false-positive rate.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAlignSupp(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMALIGN8SUPP
        // BMAlign8Supp-MB27: same as BMAlignSupp but 8-byte alignment only.
        // Catches pointers embedded in pointer-arrays (which may have 8-byte
        // spacing but not 16-byte) that AlignSupp's 16-byte gate rejects.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAlign8Supp(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMALIGNSUPP_MB24
        // BMAlignSupp-MB24: relax same-page to 24-bit VPN match with the
        // shape filter still in place. Cross-page pointer chase may become
        // viable when the shape filter is tight enough.
        Parameter#(24)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAlignSupp(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMALIGNSUPPCONF
        // BMAlignSuppConf-MB27: BMAlignSupp + per-PC attribution gating.
        // On reportUsefulPrefetch: +1 score for the issuing PC.
        // On reportEviction:       -1 score for the issuing PC.
        // Suppress future single-match issue if PC score <= -2.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAlignSuppConf(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMALIGNSUPPCONFT1
        // BMAlignSuppConfT1-MB27: AlignSuppConf with tighter threshold
        // (suppress at score <= -1 instead of -2). Kills PCs faster.
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAlignSuppConfT1(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMCHAINSCAN
        // BMChainScan-MB27: AlignSupp + classical Cooksey depth-1 chain scan.
        // On arrival of a first-level bit-match prefetch, re-scan its line
        // for more pointer candidates and issue them as isNeighbourLine=True
        // (depth-1 termination).
        Parameter#(27)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMChainScan(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHSTRIDE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchStride(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHPOLYSTRIDE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchPolyStride(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHEARLY
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchEarly(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHPOLYEARLY
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchPolyEarly(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHEARLY2
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchEarly2(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHEARLY3
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchEarly3(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHPOLYEARLY2
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchPolyEarly2(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BITMATCHEARLY4
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBitMatchEarly4(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_PURESTRIDE
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPPureStride(toTlb, matchBits);
    `elsif DATA_PREFETCHER_CDP_BMGSDEG
        Parameter#(16)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMGSDeg(toTlb, matchBits);
    `elsif DATA_PREFETCHER_SPPCOOKSEY
        // Variant SPPCooksey: SPP + Cooksey bit-match pointer discovery
        // on demand Ld L1 misses. SPP learns intra-page delta patterns,
        // Cooksey catches cross-page pointer-chase by scanning returned
        // cache-line data for pointer-shaped values. Orthogonal fusion
        // targeting SPP's weakness on scattered pointer-chase (patricia).
        CacheLinePrefetcher#(reqT) m <- mkSPPCooksey(toTlb);
    `elsif DATA_PREFETCHER_SPP
        // Variant SPP: Signature Path Prefetcher (Kim/Pugsley/Gratz/Reddy/Wilkerson/Chishti MICRO '16).
        // 256-entry ST + 512-entry PT + 1024-entry PF, path-confidence
        // lookahead prefetching. Ported from ldh35-fpga-cap_chaser with
        // interface adapted to current tree. ~5.37 KB of state.
        CacheLinePrefetcher#(reqT) m <- mkSPP(toTlb);
    `elsif DATA_PREFETCHER_DBP
        // Variant DBP: Dependence-Based Prefetcher (Roth/Moshovos/Sohi ASPLOS '98).
        // 128-entry PPW + 256-entry CT; learns per-PC producer->consumer
        // correlations via value equality; issues prefetches as
        // (producer's loaded value + learned offset). Faithful paper
        // reimplementation; no bit-match, no confidence gate.
        CacheLinePrefetcher#(reqT) m <- mkDBP(toTlb);
    `elsif DATA_PREFETCHER_CDP_BMALIGNED
        // BM-Aligned + MB20: stack both false-positive filters.
        // - 16-byte alignment check on candidate ([3:0]==0) — rejects most
        //   integer-valued data.
        // - matchBits=20 — requires 20 upper VPN bits to agree, vs 16.
        // Both attack false positives from different angles; stack test.
        Parameter#(20)   matchBits <- mkParameter;
        CacheLinePrefetcher#(reqT) m <- mkCDPBMAligned(toTlb, matchBits);
    `endif
    //let m <- mkPCPrefetcherAdapter(mkAlwaysRequestPrefetcher);
`else 
    let m <- mkPCToCacheLinePrefetcherAdapter(mkPCPrefetcherAdapter(mkDoNothingPrefetcher));
`endif
    return m;
endmodule
