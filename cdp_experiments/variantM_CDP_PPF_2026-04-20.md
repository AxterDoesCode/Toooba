# Variant M: PPF-style perceptron filter on CDP decisions (2026-04-20)

256-entry signed-4-bit perceptron indexed by `hash(pcHash)[7:0] XOR (relOff+7)`.
Replaces H's per-PC kill-switch with a per-(PC, relOff) signed weight.
Uses J's 4096-entry attribution table so useful/useless attribution is unbiased.

- `perceptronVote`: issue iff `weight >= killThreshold`
- Params: killThreshold=0, pcTable=1024, trainingTable=64, decay=256, matchBits=16, confThresh=1
- Config: `DATA_PREFETCHER_TYPE := CDP_PPF`, L1 routed

## Results

Cycles (fewer is better):

| Bench | NoPrefetch | decay256 (CDP baseline) | L2 (prior best) | M (this) |
|---|---:|---:|---:|---:|
| em3d | 83,355 | 88,246 | 87,949 | 88,637 |
| health | 1,258,698 | 1,342,254 | 1,341,304 | 1,339,066 |
| patricia | 1,416,398 | 1,342,074 | 1,325,868 | 1,323,869 |
| treeadd | 564,733 | 732,828 | 723,118 | 732,051 |
| voronoi | 202,004 | 213,033 | 212,958 | 212,189 |

Speedup geomean vs decay16 pre-experiment baseline:

| Variant | em3d | health | patricia | treeadd | voronoi | geomean |
|---|---:|---:|---:|---:|---:|---:|
| decay256 | +3.50% | +2.13% | +4.59% | +4.48% | +2.91% | **+3.52%** |
| F-probTT | +3.81% | +1.96% | +5.53% | +5.77% | +3.36% | **+4.08%** |
| H4-killswitch | +3.73% | +2.14% | +5.79% | +5.53% | +3.21% | **+4.07%** |
| L2-hybrid | +3.85% | +2.20% | +5.87% | +5.88% | +2.95% | **+4.14%** |
| **M-ppf** | +3.04% | +2.37% | +6.03% | +4.59% | +3.32% | **+3.86%** |

Vs NoPrefetch, all CDP variants are net slowdowns (L2 -6.78%, M -7.03%, decay16
-10.49%). Whole-suite CDP is still slower than turning the prefetcher off — the
work is choosing the least-bad dial. (This corrects the earlier L2 memory entry
that claimed +7.27% vs NoPrefetch — it was actually +7.27% vs the noisier
decay16 baseline, not NoPrefetch.)

## Per-variant telemetry

| Bench | issued | useful | useless attrib | acc% |
|---|---:|---:|---:|---:|
| em3d | 258 | 23 | 18 | 8.9% |
| health | 10,207 | 3,848 | 709 | 37.7% |
| patricia | 1,981 | 1,370 | 54 | 69.2% |
| treeadd | 14,211 | 3,194 | 83 | 22.5% |
| voronoi | 130 | 12 | 5 | 9.2% |

## Root-cause analysis

M lands **+0.34% over decay256 but -0.28% behind L2**. The perceptron is barely
filtering anything:

1. **Zero-init + threshold=0 means every decision passes by default.** Weights
   start at 0, `perceptronVote = weight >= 0 = True`. Decisions are only
   suppressed after enough useless bumps push the weight negative.

2. **Attribution is sparse.** On treeadd, 14,211 prefetches issued but only 83
   useless bumps attributed (0.58% useless attribution vs ~78% expected useless
   rate based on 22.5% accuracy). Useful bumps map 1:1 with demand-hits (3,194).
   The attribTable's 4096 entries get hash-overwritten by newer prefetches
   before the corresponding evictions fire — same pollution problem J aimed at,
   still not fully solved.

3. **Per-(PC, relOff) granularity is fine but 256 entries forces aliasing.** With
   ~1024 PCs × ~15 relOffs = 15,360 potential pairs mapped to 256 buckets,
   unrelated PCs share weights. When A's useful hit bumps a bucket up, B's
   useless evict on the same bucket cancels it.

4. **Patricia is the only benchmark where M beats L2 (+6.03 vs +5.87 on
   patricia).** Everywhere else L2's stride-ahead for STRIDE-class PCs is
   strictly better than M's per-decision perceptron.

## Verdict

M is NOT a new best. L2 remains the leader at +4.14% vs decay16.
M is net-neutral (slightly better than decay256, slightly worse than L2).

## Next-step options

- **M2**: raise perceptron size 256 -> 1024 or 4096 (match attribTable) to
  reduce aliasing. Principled but may not help if attribution is the real
  bottleneck.
- **M3**: warm-start perceptron at +1 and raise threshold to 1. Forces new
  (PC, relOff) pairs to prove themselves via at least one useful hit. Cleaner
  "do no harm" gate.
- **Stack L2+M**: L2's classifier dispatches STRIDE PCs to stride-ahead; for
  non-STRIDE PCs, apply M's perceptron gate to CDP. If M's gate is too weak
  alone, stacking on top of L2's classifier may extract additional gains from
  the pointer-chase PCs where CDP is already useful.
