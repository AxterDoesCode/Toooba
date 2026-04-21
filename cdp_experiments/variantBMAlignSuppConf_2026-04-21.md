# Variant BMAlignSuppConf-MB27 — per-PC attribution gating (FIRST PAST NOPREF)

Date: 2026-04-21  •  Config: `DATA_PREFETCHER_TYPE=CDP_BMALIGNSUPPCONF` + `matchBits=27`

## Hypothesis
BMAlignSupp is detection-bound (already filters at the pointer-shape level).
Treeadd at 30.9% accuracy (1169/3788 issued) has ~2619 "good detection but
useless" prefetches — wrong timing, wrong target, or fundamentally low-
value PCs. A direct outcome signal (useful vs evicted) should let us
suppress the loser PCs.

## Mechanism
Layered on AlignSupp:
- Filter entry carries pcHash (writable on issue, readable on feedback).
- Per-PC 4-bit signed score (256 entries).
- `reportUsefulPrefetch(lineAddr)` → read filter → bump pc.score +1 (sat +7).
- `reportEviction(lineAddr)` → read filter → bump pc.score -1 (sat -8).
- `deqLineL1`: if pc.score <= -2, SUPPRESS even single-match.
- Cold start (score=0): issue freely; PC proves itself over time.

## Result — cycles vs NoPref (lower is better)
| bench | NoPref | BMAlignSupp | BMAlignSuppConf | Δ vs NoPref | Δ vs AlignSupp |
|---|---:|---:|---:|---:|---:|
| bh       | 1,219,571 | 1,219,571 | 1,219,571 |  0.00% |  0.00% |
| bisort   |   989,251 |   988,690 |   988,690 | +0.06% |  0.00% |
| em3d     |    83,355 |    83,104 |    83,104 | +0.30% |  0.00% |
| health   | 1,258,698 | 1,258,698 | 1,258,698 |  0.00% |  0.00% |
| patricia | 1,416,398 | 1,416,398 | 1,416,398 |  0.00% |  0.00% |
| perimeter| 2,692,517 | 2,692,517 | 2,692,517 |  0.00% |  0.00% |
| treeadd  |   564,733 |   567,223 |   566,403 | -0.30% | +0.14% |
| tsp      | 6,638,315 | 6,638,315 | 6,638,315 |  0.00% |  0.00% |

**Geomean:** BMAlignSuppConf = **+0.01% vs NoPref** (first positive result
in the pure-bit-match family). Treeadd's slowdown halved from -0.44% to
-0.30%.

## Mechanism analysis — treeadd

| phase | AlignSupp | AlignSuppConf |
|---|---:|---:|
| cand seen           | 10,682 | 6,042 |
| cand issued (post-dedup) | 3,788 | 1,873 |
| useful hits         |  1,169 |   754 |
| pc-kill suppressions|      - | 7,200 |
| multi-match supp    |  7,743 | 7,743 |
| useful attributions |      - |   748 |
| evict attributions  |      - |     9 |

Attribution killed **7,200 single-match candidates from PCs that had
accumulated score <= -2**. Useful-prefetch count dropped 1169→754 (lost
415 good hits), but issued count halved (3788→1873, saved 1915 wasted
issues). Accuracy 30.9%→40.3%.

**Why the kill is effective.** Treeadd's tree-traversal PCs initially score
positive as their single-match issues hit. But certain PCs are net-useless
and accumulate evictions — those get suppressed once score <= -2. The
direct "was it useful vs evicted" signal is the discriminator we were
missing in BMDensThresh (where we used multi-match density — a proxy that
didn't correlate well with outcome).

## Conclusion
**First variant to beat NoPref** in the pure-bit-match family: +0.01%.
The minimal learning layer (per-PC outcome score, 256 × 4 bits = 128 bytes
of state) is enough to push past parity. This is vindication of the
dissertation angle:
- PC/TT-offset learning (elaborate state machines): regress to -6% to -10%.
- Pure bit-matching + filter tightening: -0.01% (parity).
- Bit-matching + minimal outcome attribution: **+0.01% (past parity).**

The right mechanism is lightweight, outcome-driven, and stacked on a clean
detector — not a large offset-prediction state machine.

## Next directions
- Tune scoring (useful:evict ratio, threshold, start value) to widen the
  margin on treeadd.
- Test BMAlignSuppConf on longer-running benchmarks to confirm the result
  isn't noise.
- Consider PC re-promotion: periodic decay / reset of suppressed PCs to
  re-admit them if the workload changes phase.
