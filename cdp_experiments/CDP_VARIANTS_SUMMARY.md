# CDP Prefetcher Variants — Summary, Mechanisms, Results

**Project:** Toooba RISC-V CDP prefetcher dissertation research  
**Date range:** 2026-04-19 → 2026-04-20  
**Working branch:** `ac2822CDPDeepDive`  
**Primary simulator:** Bluesim via `builds/RV64ACDFIMSU_Toooba_bluesim`

## Methodology

### Configuration
- Core: `CORE_SMALL`, cache size `ALEX_SMALLISH`
- Data prefetcher location: `L1` (except LLC-routed variants, which direct to the parent cache)
- Default PC/TT parameters (baseline CDP): `trainingTableSize=64`, `pcTableSize=1024`, `decayInterval=256`, `matchBits=16`, `confidenceThreshold=1`
- L1 demand path fires `reportIncomingCacheLine` on miss; `reportAccess` on every access; `reportUsefulPrefetch` on demand-hit of a previously-prefetched line

### Benchmark suite
Initially 5 Olden/MiBench pointer-chase benchmarks:
- `em3d`, `health`, `patricia`, `treeadd`, `voronoi`

Expanded later (2026-04-20 late) to 8:
- `bh`, `bisort`, `em3d`, `health`, `patricia`, `perimeter`, `treeadd`, `tsp`

### Reference baselines
- **decay16** (original CDP with pcTable decay interval 16): -10.49% vs NoPref (our oldest reference)
- **decay256** (baseline CDP with slower decay): +3.52% vs decay16, -7.34% vs NoPref
- **NoPrefetcher** (DATA_PREFETCHER_LOCATION=NONE): +11.72% vs decay16
- Speedup numbers reported as `(baseline_cycles - variant_cycles) / variant_cycles` (higher = better) against either decay16 or NoPref

### Metric sources
All results compared using two metric streams:
1. **Cycle counts** from `instret:N ... CYCLES` in benchmark logs
2. **TooobaLogParser** parser output: `usefulPrefetch`, `uselessPrefetch`, `uselessPrefetchBecausePerms`, `latePrefetch`, `demandOwned`, `prefetchHit`, `prefetchMiss`

---

## Family A: PC/TT CDP (content-directed *offset* prefetching — "learn which offsets to follow")

All variants in this family use the baseline architecture of `mkCDPStatefulRelative`:
- Training table (TT): set-associative BRAM, size 64 × 2-way = 128 entries. On miss, scan loaded line for bit-match candidates; for each, write `(candVaddr → pcHash, relOffset)` into TT.
- PC table: direct-mapped BRAM, 1024 entries. Each entry: `(pcHash, conf[15])` where `conf[i]` is a 3-bit saturating counter for relative offset (`i - 7`).
- Decay: LFSR-based; every `decayInterval` cycles, pick a random pcTable entry and decrement all its conf values.
- Decision: on each miss, look up pcTable for issuing PC; find max-relOffset with `conf >= threshold`; derive target line address and issue.

### Baseline variant

| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **decay16** | CDP with decay=16 (original) | 0% | -10.49% |
| **decay256** | Just slower decay | +3.52% | -7.34% |

### B: LLC-routed — "route all prefetches to LLC, not L1"
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **B** (CDP_LLC) | `nextLevel: True` on all prefetches. Cuts L1 pollution at cost of L1-hit latency. | +1.88% | -8.81% |

Crushed patricia (-6.35%) — patricia relies on L1 hit latency. Won treeadd (+7.01%) by avoiding pollution.

### C: Multi-issue — "emit top-2 high-conf offsets per decision"
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **C** (CDP_MULTIISSUE) | On prefetch decision, issue top-2 offsets in parallel instead of only highest. | identical to B | - |

### D family: Path-history-keyed CDP
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **D** (CDP_PATHHIST) | PC-table indexed by `hash(pcHash ^ pathSig)` where pathSig = rolling XOR of last 4 pcHashes (order-sensitive via shift). | ~+3.9% | -7.0% |
| **D2** (CDP_PATHHIST_XOR) | Order-independent pure XOR of last-4 pcHashes. | slightly lower | - |

D > D2 → order-sensitive recency helps.

### E family: Per-PC L1/LLC adaptive routing
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **E** (CDP_ADAPTIVE) | Per-PC `useful/useless` counters. High-acc PCs → L1, low-acc → LLC. Default: L1. | ≈+3.6% | - |
| **E2** | E + feedback loop (changes reporting path) | ≈+3.6% | - |
| **E3** (L1-default + demote) | L1 default, demote to LLC on `acc < 15/16`. | +3.78% | - |
| **E4** (LLC-default + promote) | Opposite default. | +2.36% | - |

L1-default beats LLC-default — patricia protection matters more than treeadd pollution avoidance.

### F: Probabilistic TT overwrite
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **F** (CDP_PROBTT) | On TT overwrite collision, only accept with probability 1/16 (LFSR-gated). Keeps (vaddr→pcHash) training context alive across competing scans. | +4.08% | -6.84% |

### H family: Per-PC kill-switches
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **H** | Per-PC `uselessCount`; kill at threshold 3 useless bumps. | +3.7% | -6.95% |
| **H2** (CDP_KILLSWITCH_kt5_filt1024) | Threshold 5 + larger attribution filter. | +3.9% | - |
| **H3** (amp3) | Amplify each useless bump by 3× (compensate for sparse attribution). | +3.85% | - |
| **H4** (ratio) | Kill if `useful*K < (useful+useless)` over a window. | **+4.07%** | -6.85% |

### J family: Unbiased attribution
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **J** (CDP_ATTRIB) | 4096-entry separate attribTable (independent of the 1024-entry dedup filter) to catch ~10× more useless attribution events. Same ratio gate as H4. | +3.66% | -7.21% |
| **J2** (kt2) | J + killThreshold=2 to match H4's effective rate. | +3.66% | - |

### L family: Classifier-dispatched CDP
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **L** (CDP_HYBRID) | Stride classifier (per-PC): detect stride-class PCs; for those, *suppress* CDP content-scan. | +3.95% | - |
| **L2** (CDP_HYBRID2) | Same classifier; for stride-class PCs, *emit* line+1 stride-ahead instead of CDP scan. | **+4.14%** | **-6.78%** |

L2 is the strongest PC/TT family result.

### M/N: Per-decision perceptron filter
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **M** (CDP_PPF) | 256-entry signed-weight perceptron indexed by `hash(pcHash) XOR (relOff+7)`. Weight +1 on useful attribution, -1 on useless. Issue iff weight >= 0. | +3.86% | -7.03% |
| **N** (CDP_PPFROUTE) | Same perceptron; weight ≥ 0 → L1, weight < 0 → LLC. Always issue. | +3.96% | -6.91% |

### O/Z: Utility-gated conf
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **O** (CDP_UTILCONF) | Replace baseline conf update. Training hit brings conf to threshold (1); useful attribution bumps +1; useless attribution bumps -1. Pattern-recurrence not directly rewarded. | +3.68% | -7.12% |
| **Z** (CDP_UTILCONFROUTE) | O + graded routing: conf ≥ 2 → L1, conf == 1 → LLC. | +2.07% | -8.65% (LLC-default trap) |

### YY: Global trust gate
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **YY** (CDP_GLOBALGATE) | Signed whole-suite score tracking `usefulAttrib - uselessAttrib`. Score ≥ 0 → issue; score < 0 → suppress (with 1/8 LFSR bleed-through). Score halved every 4096 cycles. | +3.55% | -7.22% |

Bug: treeadd's useless attribution is structurally undersampled (only 0.5% of real pollution gets attributed), so its net stays positive and gate never closes there — the exact benchmark it should have saved.

### IRATIO family: Issue-ratio kill-switch (catastrophic)
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **IRATIO v1** | Per-PC `(issuedCount, usefulCount)` in pcTable. Kill if `issued ≥ 64 AND useful*10 < issued` (<10% acc). | -7.48% | -16% |
| **IRATIO v2** | Raised to `issued ≥ 128`, `useful*20 < issued`. | -7.98% | -16% |

Root cause: adding IssueBump to pcTable pipeline doubled FIFO traffic, causing backpressure that stalled the demand path. The cycle cost exceeded any filtering benefit. Direction abandoned.

---

## Family B: Pure Cooksey bit-matching (no offset learning)

These variants implement only the bit-matching primitive from Cooksey et al. 2002's original CDP: scan loaded lines for words whose upper-16 bits match the load's VPN, treat them as pointer candidates.

### State: ~8 KB dedup filter + tiny TLB-in-flight bookkeeping. No PC table, no training table, no confidence counter, no attribution table.

### Core variant family
| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **BM** (CDP_BITMATCH) | Miss-only scan. Require both matchBits match AND same-VPN (no cross-page). 1024-entry hash-keyed dedup filter. | +10.67% | **-0.93%** |
| **BM-v3** (paddr-gate) | Allow cross-page, but drop prefetches whose translated paddr falls outside main memory (0x80000000..0x90000000). Prevents AXI fabric errors. | +10.83% | -0.79% |
| **BM-POLY** | BM-v3 + count matches per line. If `matchCount >= 2` → route candidates to LLC (multi-match = noise or "both children"). | +11.20% | -0.46% |

### +Stride family (Cooksey's original architecture)
**Important context:** the original Cooksey 2002 paper paired bit-matching pointer discovery with a next-line stride prefetcher. Our "+STRIDE" variants replicate that architecture; they are not novel relative to Cooksey.

| Variant | Mechanism | vs decay16 | vs NoPref |
|---|---|---:|---:|
| **BM+STRIDE** | BM-v3 + emit `line+1` stride prefetch on every miss. | +12.24% | +0.47% |
| **BM-POLY+STRIDE** | BM-POLY + `line+1` stride. | +12.84% | +1.01% |
| **BM-EARLY** | BM + stride on *miss* (`line+1`) AND on *demand hit* (`line+1`). Earlier stride timing. | +13.22% | +1.35% |
| **BM-POLY-EARLY** | POLY + EARLY. | +13.21% | +1.34% |
| **BM-EARLY2** | BM + degree-2 miss stride (`line+1, line+2`) + degree-1 hit stride. | +13.68% | +1.76% |
| **BM-EARLY3** | BM + degree-2 miss stride + degree-2 hit stride. | **+13.99%** | **+2.03%** |
| **BM-POLY-EARLY2** | POLY + EARLY2. | +13.73% | +1.80% |
| **BM-EARLY4** | Degree-3 miss stride + degree-2 hit stride. Too aggressive. | +13.23% | +1.36% (regression) |

---

## Family C: Critical ablation — **PureStride** (2026-04-20)

User-requested ablation: "Is BM+STRIDE's win from bit-matching, or from stride alone?" Disable bit-matching, keep everything else.

| Variant | Mechanism | vs decay16 | vs NoPref | Delta vs PureStride |
|---|---|---:|---:|---:|
| **PureStride** (CDP_PURESTRIDE) | Exact BM-EARLY3 infrastructure but bit-match scan DISABLED. Degree-2 stride (miss) + degree-2 stride (hit) + dedup + paddr-gate only. | +13.64% | **+1.72%** | baseline |
| **BM-EARLY3** | PureStride + bit-match scan. | +13.99% | +2.03% | **+0.31%** |

### Per-benchmark bit-matching contribution over PureStride (ΔNoPref = BM-EARLY3 – PureStride)

| bench | PureStride vs NoPref | BM-EARLY3 vs NoPref | bit-match delta |
|---|---:|---:|---:|
| em3d | -0.69% | +1.69% | **+2.38%** (genuinely helps) |
| health | -0.78% | -0.71% | +0.07% (nothing) |
| **patricia** | **+13.84%** | **+13.69%** | **-0.15%** (bit-match doesn't help!) |
| treeadd | -2.22% | -3.08% | **-0.86%** (bit-match HURTS) |
| voronoi | -0.69% | -0.60% | +0.09% (nothing) |

**Key dissertation finding:** BM+STRIDE-family "wins" are ~85% stride, ~15% bit-matching. Patricia — long considered the paragon of CDP success — gets its +13.84% speedup entirely from stride, not from Cooksey's pointer discovery. The trie's nodes are laid out sequentially enough that `line+1/line+2` catches them.

---

## Family D: Novel bit-match uses (after PureStride redirect)

These variants are designed to make bit-matching contribute genuinely, not ride stride's coat-tails. They are measured against the **PureStride baseline** (the correct zero for isolating bit-match's value).

### Control-signal use (not a prefetch source)

| Variant | Mechanism | vs decay16 | vs NoPref | Delta vs PureStride |
|---|---|---:|---:|---:|
| **BMGS-Deg** (CDP_BMGSDEG) | Bit-match is a *control signal*. Count matches `k` in line; emit `clamp(k, 0, 4)` stride prefetches on miss (deg-2 hit-stride unchanged). No bit-match candidates issued as prefetches. | +13.78% | +1.85% | +0.13% |

Per-bench parser accuracy:
- em3d: 32% (vs PureStride's ?) — lower than BM-EARLY3's 49%
- health: 1.3%
- patricia: 73.4% (lower than PureStride's 80.1%!)
- treeadd: 0.1%

Observation: letting bit-match suppress prefetching in cold regions (matchCount=0) genuinely helps em3d but hurts patricia slightly. Net is small positive delta over PureStride.

### Alignment filter (in progress)

| Variant | Mechanism | vs decay16 | vs NoPref | Notes |
|---|---|---:|---:|---|
| **BM-Aligned v1** (64-byte) | BM + require candidate `[5:0]==0`. Too strict — treeadd's pointers aren't cache-line-aligned. | ≈0% | ≈NoPref (barely prefetches) | treeadd zero candidates |
| **BM-Aligned v2** (16-byte) | BM + require candidate `[3:0]==0`. Matches glibc malloc default. | in-flight | - | - |

---

## Family E: PC/TT CDP without stride (bit-matching learning — planned)

Based on user redirect ("stop adding stride to PC/TT — make bit-matching itself viable"):

| Variant | Mechanism | Status |
|---|---|---|
| **BM-Scan-L1Res** | Bit-match not only the arriving line but also recently-accessed L1-resident lines (small ring buffer). | Planned |
| **CDP-OffsetConf** | Replace baseline CDP's `conf[relOff]` with `conf[wordOffset]` (slot 0..7 in line). | Planned |
| **CDP-TargetTable** | Table keyed by candidate VPN; track useful/useless per VPN. Skip bit-match prefetches to proven-bad target regions. | Planned |
| **CDP-PerPCFilter** | IRATIO's kill-switch applied to pure bit-matching only (no stride masking). | Planned |
| **CDP-ChainScan** | On prefetched line arrival, bit-match its content, chain prefetch those. Novel: Cooksey on prefetched data. | Planned |
| **CDP-RegionLearn** | Track VPN ranges that generate useful bit-match targets. Boost aggressiveness in hot regions, suppress in cold. | Planned |

---

## Sorted leaderboard (5-benchmark suite, vs NoPref)

| Rank | Variant | vs decay16 | vs NoPref | Family |
|---:|---|---:|---:|---|
| 1 | BM-EARLY3 | +13.99% | **+2.03%** | BM+stride (Cooksey-faithful) |
| 2 | BMGS-Deg | +13.78% | +1.85% | Novel: bit-match as control signal |
| 3 | BM-POLY-EARLY2 | +13.73% | +1.80% | BM+stride |
| 4 | BM-EARLY2 | +13.68% | +1.76% | BM+stride |
| 5 | **PureStride** | +13.64% | **+1.72%** | **Pure stride (bit-match disabled)** |
| 6 | BM-EARLY4 | +13.23% | +1.36% | BM+stride (regressed) |
| 7 | BM-POLY-EARLY | +13.21% | +1.34% | BM+stride |
| 8 | BM-POLY+STRIDE | +12.84% | +1.01% | BM+stride |
| 9 | BM+STRIDE | +12.24% | +0.47% | BM+stride |
| 10 | BM-POLY | +11.20% | -0.46% | Pure BM |
| 11 | BM-v3 | +10.83% | -0.79% | Pure BM |
| 12 | BM (same-page) | +10.67% | -0.93% | Pure BM |
| 13 | L2 (best PC/TT) | +4.14% | -6.78% | PC/TT |
| 14 | F (ProbTT) | +4.08% | -6.84% | PC/TT |
| 15 | H4 (KillSwitch) | +4.07% | -6.85% | PC/TT |
| 16 | N (PPFRoute) | +3.96% | -6.91% | PC/TT |
| 17 | M (PPF) | +3.86% | -7.03% | PC/TT |
| 18 | YY (GlobalGate) | +3.55% | -7.22% | PC/TT |
| 19 | decay256 | +3.52% | -7.34% | PC/TT |
| 20 | Z (UtilConfRoute) | +2.07% | -8.65% | PC/TT (LLC trap) |
| 21 | B (LLC-all) | +1.88% | -8.81% | PC/TT (LLC trap) |
| 22 | decay16 | 0% | -10.49% | Reference |
| - | IRATIO v1/v2 | -7.48% / -7.98% | -16%+ | PC/TT (pipeline overhead trap) |

---

## Dissertation-grade findings

1. **Cooksey bit-matching alone is not a net win** on this benchmark suite. BM (pure bit-match + dedup) at -0.93% vs NoPref, worse than having no prefetcher. PC/TT-learning family worse still (-6 to -10%). The learning layer adds more pipeline overhead than its filtering benefit justifies.

2. **Most "CDP" speedup reported in our BM+STRIDE family is stride prefetching.** PureStride ablation shows 85% of BM-EARLY3's +2.03% is from stride alone; bit-match contributes ~+0.31% net (about 15% of the already-modest gain).

3. **Patricia — widely cited as CDP's canonical success case — is actually a stride benchmark.** 80.1% strict prefetch accuracy with no bit-matching whatsoever. Trie nodes in memory are sequential enough that `line+1`/`line+2` catches them.

4. **Treeadd is prefetcher-unpredictable by any variant we've tried.** Strict accuracy sits at 0.0-0.3% across all variants. Cycles improve via `demandOwned` (in-flight merges), not via landed prefetches.

5. **`uselessPrefetchBecausePerms` dominates health (78%) and treeadd (93%) of useless prefetches.** The prefetched line is evicted because of coherence upgrades — demand stores need M state, kicking out the prefetched line. This class of waste is unfixed by any bit-match or stride variant; needs store-aware routing.

6. **PC/TT family caps at ~+4% vs decay16.** Pipeline overhead (BRAM reads/writes per decision in a 64-deep FIFO) consumes the filtering benefit. Removing the state machine (BM/PureStride) immediately adds +8 percentage points.

7. **IRATIO was instructive in failure.** Adding yet more pcTable traffic (IssueBump per prefetch + UsefulBump) doubled pipeline pressure and dropped cycles by -7.48%. Even perfect signal cannot overcome the cost of its measurement if the measurement itself stalls the demand pipeline.

8. **Patricia "FAIL 1"** on all variants (including NoPref) is a pre-existing test-harness issue in the patricia binary, not a CDP-correctness bug. Cycle counts remain comparable for speedup. The patricia exit-code-3 is tohost-reported regardless of prefetcher state.

---

## Log archive

All per-variant logs archived at `/local/scratch/ac2822/NewTooobaLogs/variant<NAME>_<VARIANT>_2026-04-20/`.

Parser caches (`.webapp_cache.json`) accompany each log for fast comparison via the TooobaLogParser webapp. To inspect:

```
cd /auto/homes/ac2822/Documents/Code/Toooba/TooobaLogParser
/tmp/toooba-venv/bin/python app.py --log-root /local/scratch/ac2822/NewTooobaLogs --host 0.0.0.0 --port 8888
```

Navigate to `http://localhost:8888` and pick two variants to compare side by side. Metric to use for accuracy: `usefulPrefetch / prefetchMiss`.
