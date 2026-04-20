# Exp 2: confidenceThreshold 1 → 2 (no punish) (2026-04-19)

## Change
Single edit: `Prefetcher_top.bsv` `Parameter#(1) confidenceThreshold` → `Parameter#(2)`. No other changes. Exp1's CDP.bsv changes reverted.

## Results

| Bench | B cycles | E2 cycles | Δ% | B acc% | E2 acc% | B useful | E2 useful | B issued | E2 issued |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| em3d     | 91,334   | 90,396   | -1.0% | 5.7  | 5.3  | 24  | 18  | 418  | 341 |
| health   | 1,370,782| 1,372,759| +0.14%| 28.7 | 29.4 | 6680| 6449| 23274| 21940 |
| patricia | 1,403,670| 1,491,067| **+6.2%**| 11.3 | 7.9  | 1762| 1137| 15589| 14318 |
| treeadd  | 765,632  | 766,014  | +0.05%| 16.7 | 15.9 | 3318| 3194| 19897| 20082 |
| voronoi  | 219,239  | 218,866  | -0.17%| 16.6 | 12.1 | 56  | 56  | 337  | 463 |

## Verdict
**Net negative again.** Patricia +6.2% slower (worse than Exp1's +4.5%). Accuracy
also DROPPED on em3d, patricia, treeadd, voronoi — counter-intuitive.

## Analysis
The accuracy drop is because useful drops faster than issued does. Raising the
threshold doesn't strictly reduce issues; it changes *which* offsets win the
selection loop (loop picks last high-conf slot encountered). So raising threshold
shifts the prefetch target rather than uniformly filtering — and the shift
sometimes points at worse offsets.

Patricia's `noHighConf` jumped 31737 → 42554 (+34%). So 34% more decisions now
find no high-conf offset at all. Coverage dropped further than in Exp1.

## Converging insight: patricia is coverage-sensitive
Baseline patricia IPC = 1.00, instret=1401353. Both Exp1 (punish) and Exp2 (threshold=2)
reduced patricia's `useful` prefetches and slowed its cycles — via different mechanisms.
The common thread: **patricia's prefetcher is already productive; any change that
reduces coverage (useful prefetches issued) directly slows the benchmark**.

Implication: for patricia, future experiments should *increase* coverage or
*preserve* it while making other improvements. Blind accuracy-tightening hurts.

## Next
- Exp 3: **grow trainingTableSize 64 → 1024** (2-way still). Baseline TT is only
  128 slots for thousands of distinct pointer vaddrs — the eviction/aliasing
  rate must be non-trivial. A bigger TT should keep more (vaddr, pcHash, relOffset)
  triples live longer, leading to more training events and more useful prefetches.
  No algorithmic change, just a parameter bump.
