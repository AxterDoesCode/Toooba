# Variant BMDensThresh-MB27 — per-PC reliability gate

Date: 2026-04-21  •  Config: `DATA_PREFETCHER_TYPE=CDP_BMDENSTHRESH` + `matchBits=27`

## Hypothesis
BMPolySupp issues single-match prefetches at 10.9% accuracy on treeadd —
90% of "clean" single-match issues are false positives. If we gate on a
per-PC reliability signal, we can kill the untrustworthy tail.

**Mechanism:** 256-entry `Int#(4)` per-PC score.
- New PCs start at +2 (optimistic cold-start)
- matchCount == 1 → score += 1 (sat +7)
- matchCount >= 2 → score -= 2 (sat -8)
- Gate on single-match issue: only pass if score >= 0
- Multi-match always suppressed (BMPolySupp policy inherited)

## Result — cycles vs NoPref (lower is better)
| bench | NoPref | BMPolySupp | BMDensThresh | Dens Δ vs NoPref | Dens Δ vs Supp |
|---|---:|---:|---:|---:|---:|
| bh       | 1,219,571 | 1,219,571 | 1,219,571 | 0.00%  |  0.00% |
| bisort   |   989,251 |   988,690 |   989,073 | +0.02% | -0.04% |
| em3d     |    83,355 |    83,099 |    83,783 | -0.51% | -0.82% |
| health   | 1,258,698 | 1,261,339 | 1,258,107 | +0.05% | +0.26% |
| patricia | 1,416,398 | 1,416,398 | 1,416,398 |  0.00% |  0.00% |
| perimeter| 2,692,517 | 2,692,517 | 2,692,517 |  0.00% |  0.00% |
| treeadd  |   564,733 |   567,223 |   567,928 | -0.57% | -0.12% |
| tsp      | 6,638,315 | 6,638,315 | 6,638,315 |  0.00% |  0.00% |

**Geomean:** BMDensThresh = **-0.13% vs NoPref** (worse than BMPolySupp's -0.04%).

## The filter IS working — but cycle-wise no win

| bench | Supp issued | Supp useful | Supp acc | Dens issued | Dens useful | Dens acc |
|---|---:|---:|---:|---:|---:|---:|
| em3d    |   157 |   7 |  4.5% |    35 |   8 | 22.9% |
| treeadd |10,682|1,169| 10.9% | 7,753 |1,121| 14.5% |
| health  |15,604|  225|  1.4% |14,983 |  225|  1.5% |
| bisort  | 1,728|  172|  9.9% | 1,183 |  151| 12.8% |

DensThresh cuts prefetch count on all benches and raises per-prefetch accuracy.
Em3d accuracy 4.5% → 22.9%. Treeadd 10.9% → 14.5%. But cycle time is unchanged
to slightly worse:

**Why the accuracy improvement doesn't convert to speedup**

The filter kills 2,929 prefetches on treeadd but only 48 of them were useful —
yet those 48 useful prefetches each saved ~200 cycles (≈9,600 cycles lost).
The remaining 2,881 killed-bad-prefetches save LLC pollution, but the net
cycle effect is slightly negative (−3,195 cycles on treeadd vs Supp).

Per-PC multi-match density is a **weak proxy** for single-match usefulness,
because on tree-traversal PCs both patterns fire — the "badness" score
flips PCs into negative after a few multi-matches even though the PC also
produces valuable single-match prefetches. We lose real value for modest
false-positive reduction.

## Conclusion
- The per-PC gate mechanism works as designed (cuts bad prefetches, raises accuracy).
- But the *signal* — per-PC multi-match density — is the wrong proxy. On
  pointer-chasing workloads, the same PCs produce both clean and noisy lines.
- Need a **direct signal**: actual useful/useless attribution per PC
  (reportUsefulPrefetch), i.e. BM-PostConf.

## Next
BM-PostConf: replace the density-based score with a usefulness-based score.
Track per-PC useful/useless events; gate single-match issue by observed
useful%. Uses `reportUsefulPrefetch` (currently ignored in BM family).
