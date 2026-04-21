# Variant Z: utility-conf-graded routing (O + N fusion) — 2026-04-20

Base: Variant O. Replace always-L1 issue with routing based on conf level:
- `conf >= 2` (proven useful): L1 route (reap hit-latency on strong patterns)
- `conf == 1` (freshly eligible, unproven): LLC route (no pollution risk)
- `conf == 0`: doesn't reach here (foundHighConf requires >= threshold=1)

**Motivation:** N (perceptron routing) preserved patricia but didn't reduce
treeadd pollution — perceptron weights never went sufficiently negative.
Z uses the cleaner 15K-slot conf signal with a STRICT L1 criterion (conf>=2)
so only patterns with at least one useful attribution event reach L1.

## Results (vs decay16 baseline)

| Bench | L2 | B(LLC all) | N | Z (this) |
|---|---:|---:|---:|---:|
| em3d | 87,949 | 88,418 | 88,427 | 88,122 |
| health | 1,341,304 | 1,332,522 | 1,337,554 | **1,326,674 (best)** |
| patricia | 1,325,868 | 1,498,784 | 1,321,767 | **1,501,325 (worst)** |
| treeadd | 723,118 | 715,472 | 732,426 | **715,763 (near-best)** |
| voronoi | 212,958 | 212,675 | 212,189 | **211,968 (best)** |

Geomean speedup vs decay16: **+2.07%** (L2 +4.14%, B +1.88%)

## Analysis

Z's per-bench signature mirrors Variant B (LLC-all) almost exactly:
- treeadd +6.97% (B had +7.01%)
- patricia -6.50% (B had -6.35%)
- health +3.32% (best among all CDP variants)
- voronoi +3.43% (best)

This means: **conf == 2 is almost never reached**. Most prefetches fire with
conf == 1 (just-trained), which routes to LLC. Effective behavior is "route
everything to LLC", reproducing B's pattern.

Why conf rarely climbs to 2:
- Decay timer ticks every 256 cycles, LFSR-picks a random pcTable entry,
  decrements all its conf values by 1. With 1024 entries, each entry decays
  every ~256K cycles. Slow compared to attribution frequency.
- But training hits bump conf back to 1 whenever they fire; demoted
  patterns don't stay demoted (same oscillation as O).
- Useful attribution at rate ~1 per prefetch (if useful) should climb to 2.
  But conf for THAT slot has to accumulate before decay / new training pulls
  it back down. Racey and infrequent.

## Verdict

Z inherits O's conf dynamics issue AND adds the B-style patricia penalty.
The direction (conf-graded routing) is sound but the conf update rules need
a redesign — perhaps: **demoted patterns stay at conf=0 even on training
hits, until proven by useful attribution**.

## Next

- Try **Variant O2**: no training-hit re-enable. Once conf hits 0, only
  useful attribution can re-enable.
- Try **YY (global gate)**: system-level auto-disable, not per-pattern. In
  progress.
