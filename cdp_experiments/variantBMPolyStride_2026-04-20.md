# Variant BM-POLY+STRIDE — 2026-04-20

Stack BM-POLY (multi-match → LLC routing) on top of BM+STRIDE (line+1 stride
on every miss). Both mechanisms augment pure Cooksey bit-matching with
small, orthogonal filters; no PC/TT learning layer.

## Why stacking works

Parser analysis of BM+STRIDE showed two remaining pathologies:
1. **Treeadd's -4.13% vs NoPref**: 93% of useless prefetches were
   `uselessPrefetchBecausePerms` — prefetched lines evicted by coherence
   churn (the "both children in same line" pattern).
2. **Patricia +6.72% vs NoPref**: stride catches the trie-array sequential
   access that bit-matching misses.

BM-POLY fixed (1) by routing multi-match lines to LLC (-1.17% on treeadd).
BM+STRIDE fixed (2) by emitting line+1 per miss (+6.72% on patricia).
Stacking preserves both.

## Results

Cycles (fewer is better):

| Bench | NoPref | L2 (best PC/TT) | BM+STRIDE | BM-POLY+STRIDE |
|---|---:|---:|---:|---:|
| em3d | 83,355 | 87,949 | 83,649 | 84,146 |
| health | 1,258,698 | 1,341,304 | 1,254,717 | 1,258,221 |
| patricia | 1,416,398 | 1,325,868 | 1,327,260 | **1,321,931 (best)** |
| treeadd | 564,733 | 723,118 | 589,088 | **571,691** |
| voronoi | 202,004 | 212,958 | 201,824 | **201,498 (best)** |

Speedup vs NoPref:

| Variant | em3d | health | patricia | treeadd | voronoi | GEOMEAN |
|---|---:|---:|---:|---:|---:|---:|
| BM+STRIDE | -0.35% | +0.32% | +6.72% | -4.13% | +0.09% | +0.47% |
| BM-POLY | -0.65% | -0.31% | -0.01% | -1.17% | -0.17% | -0.46% |
| **BM-POLY+STRIDE** | **-0.94%** | **+0.04%** | **+7.15%** | **-1.22%** | **+0.25%** | **+1.01%** |

Speedup vs decay16 baseline: **+12.84%** (L2 +4.14%, NoPref +11.72%).

## Interpretation

- **First variant to be a >+1% net win over NoPref.** Previous family caps
  were +0.47% (BM+STRIDE) and -0.46% (BM-POLY); stacking adds their gains
  without interference.
- **Treeadd recovery**: POLY routing kept bad prefetches out of L1.
- **Patricia reach**: stride's line+1 remains the key lever for trie traversal.
- **Cost**: em3d's tiny regression (-0.94% vs NoPref from -0.35% BM+STRIDE)
  — probably from the LLC routing of 3-5 word multi-matches where L1
  routing was fine.

## Next steps

- **BM-EARLY** (stride-on-HIT): attacks the 3840-count `latePrefetch` on
  treeadd observed in parser data. Compiling now.
- **Stride degree tuning**: emit line+1 AND line+2? Tradeoff of more reach
  vs more pollution. Worth trying after BM-EARLY.
- **Store-aware routing**: the perms-eviction problem on health/treeadd
  suggests a future refinement — distinguish load-triggered vs
  store-triggered prefetches.
