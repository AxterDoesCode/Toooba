# Exp 4: highest-conf offset selection (2026-04-20)

## Change
Single edit in `pcTableResp`'s PrefetchIssue branch selection loop: pick the
highest-confidence offset above threshold, rather than "last-iterated above
threshold" (which always selected the most-negative relOffset when multiple
offsets passed). Baseline TT=64, pcTable=1024, decay=16, threshold=1,
matchBits=16 preserved.

Earlier attempt at multi-offset top-2 via Ehr + nested function caused `bsc`
elaboration to pin 99% CPU for 20+ min with no completion — abandoned.

## Results

| Bench | B cycles | E4 cycles | Δ% | B acc% | E4 acc% | B useful | E4 useful | B issued | E4 issued |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| em3d     | 91,334   | 91,341   | +0.01% | 5.7  | 9.8  | 24   | 35   | 418  | 357  |
| health   | 1,370,782| 1,367,651| **-0.23%**  | 28.7 | 31.8 | 6680 | 7292 | 23274| 22933|
| patricia | 1,403,670| 1,420,357| **+1.19%**  | 11.3 | 10.4 | 1762 | 1726 | 15589| 16538|
| treeadd  | 765,632  | 765,457  | -0.02% | 16.7 | 15.9 | 3318 | 3149 | 19897| 19833|
| voronoi  | 219,239  | 219,747  | +0.23% | 16.6 | 23.1 | 56   | 75   | 337  | 325  |

## Verdict
Mixed. Modest cycle improvement on health (-0.23%), essentially flat on
em3d/treeadd/voronoi, patricia still regresses (+1.2%).

Accuracy went UP on em3d (+4.1pp), health (+3.1pp), voronoi (+6.5pp);
DOWN on patricia (-0.9pp), treeadd (-0.8pp). Useful count up for em3d (+46%),
health (+9%), voronoi (+34%); down for patricia (-2%), treeadd (-5%).

## Reading
Picking highest-conf instead of most-negative-relOffset mostly helps because
the "highest conf" slot is the most-trained pattern at that PC — more likely
to be the actual traversal path. BUT for patricia the baseline's "pick the
most-negative relOffset" seems to serendipitously favour fresh low-conf
patterns (conf 1-3 ≈ 88% accurate vs conf=7 ≈ 43% per parser Direct tracking).
No universal selection wins for every benchmark.

## Cumulative experiments log

| Exp | Change | Patricia Δ% | Health Δ% | Em3d Δ% | Treeadd Δ% | Voronoi Δ% |
|---|---|---:|---:|---:|---:|---:|
| 1 | Useless-prefetch provenance + punish | +4.5% | +0.01% | -0.3% | +0.1% | +0.1% |
| 2 | confidenceThreshold 1 → 2 | +6.2% | +0.14% | -1.0% | +0.05% | -0.17% |
| 3 | trainingTableSize 64 → 1024 | +3.2% | +0.34% | +0.01% | +0.09% | +0.30% |
| 4 | Highest-conf selection (vs most-negative-offset) | +1.2% | **-0.23%** | +0.01% | -0.02% | +0.23% |

All four experiments regress patricia to some degree. Patricia is highly
sensitive to prefetcher changes because baseline CDP is already productive for
it; any modification that shifts which offsets get issued reduces its useful
count.

## Next directions to consider

- **Per-page-scope gating**: parser shows patricia's cross-page prefetches are
  66% accurate (838/1271) while same-page are 0.5% (3/564). Filtering to
  cross-page-only could reduce patricia's wasted prefetches dramatically.
  Would need measuring on other benchmarks (might hurt health's same-page wins).
- **Lead-time analysis**: 420 late prefetches on patricia (2.8%), 1084 on health
  (3.8%). Earlier issue (e.g., predictive lookahead) could convert some to useful.
- **Hybrid selection**: pick highest-conf AND also enqueue the most-negative-
  relOffset one if different. Revives the multi-offset idea but with a simpler
  BSC implementation (no Ehr — use a FIFO-backed `secondIssueQ`).
- **Keep current Exp 4 change**: it's a net positive on health/em3d/voronoi;
  patricia's +1.2% is small relative to prior experiments' +3-6%.
