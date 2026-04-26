# DBP v1 — faithful Dependence-Based Prefetcher results

Date: 2026-04-22
Branch: `ac2822CDPDeepDive`
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/DBP.bsv`
Logs:   `/local/scratch/ac2822/NewTooobaLogs/variantDBP_v1_2026-04-22/`

## Geomean landscape (8-bench Olden vs NoPref2)

| bench     |   NoPref2 |   BaseCDP |      DBP v1 |         H7 |  Base Δ | DBP Δ |   H7 Δ |
|:----------|----------:|----------:|------------:|-----------:|--------:|------:|-------:|
| bh        | 1,219,571 | 1,220,351 |   1,219,571 |  1,219,582 |  +0.06% | 0.00% |  +0.00% |
| bisort    |   989,251 | 1,071,372 |     989,134 |    985,152 |  +8.30% | −0.01% | −0.41% |
| em3d      | 1,739,832 | 1,938,906 |   1,734,091 |  1,739,043 | +11.44% | −0.33% | −0.05% |
| health    | 1,258,698 | 1,317,260 |   1,258,032 |  1,246,504 |  +4.65% | −0.05% | −0.97% |
| patricia  | 1,416,398 | 1,325,290 |   1,414,849 |  1,245,569 |  −6.43% | −0.11% | **−12.06%** |
| perimeter | 2,692,517 | 2,739,559 |   2,692,517 |  2,692,523 |  +1.75% | 0.00% |  +0.00% |
| treeadd   |   564,733 |   701,587 |     564,733 |    558,042 | **+24.23%** | 0.00% | −1.18% |
| tsp       | 6,638,315 | 6,737,129 |   6,638,315 |  6,638,315 |  +1.49% | 0.00% |  +0.00% |
| **geomean** |         |           |             |            | **+5.35%** | **−0.06%** | **−1.92%** |

**Verdict:** DBP v1 is effectively NoPref (−0.06% geomean, i.e. noise-level
parity). Zero regressions on any bench. But also zero meaningful wins —
patricia stays at NoPref (vs −12.06% under H7), treeadd stays at NoPref
(vs −1.18% under H7).

## Prefetcher activity — parser `CRqCreationLine` totals

| bench     | issued | HIT    | OWNED | miss | missLL | useful | late | timely | useless | strict% | timely% |
|:----------|-------:|-------:|------:|-----:|-------:|-------:|-----:|-------:|--------:|--------:|--------:|
| bh        |      0 |      — |     — |    — |      — |      — |    — |      — |       — |       — |       — |
| bisort    |    344 |    300 |     7 |   37 |      0 |     36 |    3 |     33 |       1 |  97.3%  |  89.2%  |
| em3d      |    840 |    675 |    24 |  141 |      0 |     19 |   18 |      1 |     122 |  13.5%  |   0.7%  |
| health    |  1,478 |    519 |   193 |  766 |      0 |    762 |  330 |    432 |       4 |  99.5%  |  56.4%  |
| patricia  |     89 |     64 |     6 |   19 |      4 |     10 |    4 |      6 |       9 |  52.6%  |  31.6%  |
| perimeter |      0 |      — |     — |    — |      — |      — |    — |      — |       — |       — |       — |
| treeadd   |    324 |    324 |     0 |    0 |      0 |      0 |    0 |      0 |       0 |  —      |  —      |
| tsp       |      0 |      — |     — |    — |      — |      — |    — |      — |       — |       — |       — |

Activity counters from DBP's `$display` instrumentation:

| bench    | drainEvents | correlationsLearned | triggers | issueMiss | filtHit |
|:---------|-----------:|--------------------:|---------:|----------:|--------:|
| bh       |         30 |                   0 |        0 |         0 |       0 |
| bisort   |      6,390 |                 569 |      639 |       344 |     295 |
| em3d     |     34,803 |                 212 |    1,575 |       920 |     655 |
| health   |     31,325 |                 170 |    5,154 |     1,478 |   3,676 |
| patricia |      5,721 |                 105 |      348 |        89 |     259 |
| perimeter|        987 |                   0 |        0 |         0 |       0 |
| treeadd  |     21,324 |                  19 |    1,307 |       324 |     983 |
| tsp      |      1,913 |                   0 |        0 |         0 |       0 |

## Why DBP v1 is "almost NoPref"

Three root causes, in order of magnitude:

### (1) Training only on L1 misses — MASSIVE under-training vs paper

The paper trains PPW on **every committed load**. Our `reportIncomingCacheLine`-gated
trigger fires only on **L1 demand misses**. On patricia, demand misses are ~9.8k
per run; total loads are ~200k. We see 20× fewer training events than the paper.
Per-bench `drainEvents` shows 6k–35k events for benches where H7 prefetches
2–15k per run — the training volume is simply too low to populate the CT
densely enough to fire.

Evidence:
- **patricia only learned 105 correlations** in a 1.4M-cycle run. H7 issued
  2,168 prefetches hitting 1,456 DRAM lines on the same bench. DBP caught 4
  DRAM misses. **The DRAM win is missing because correlations aren't learned
  for the hot pointer-chase PCs before they fire.**
- **treeadd 19 correlations**. Treeadd has 184k Ld commits total but only
  21k drain events — because treeadd is heavily L1-hit-dominated (most
  pointer-chase is in-cache once the tree is warm).

### (2) Patricia DRAM miss isn't being prefetched

Patricia's value under H7 is entirely about the 1,456 prefetchMissLL — DBP v1
has `prefetchMissLL = 4`. Those DRAM-bound pointer-chase accesses are exactly
what DBP's mechanism *should* catch — but we're missing the training signal
before the relevant miss fires.

### (3) treeadd is 100% "prefetch-HIT" — late prefetches

324 prefetches issued on treeadd, **all 324 HIT in L1** (no useful count, no
useless, no demandOwned). This means: the prefetch for the next node arrived
*after* the demand had already filled that line. DBP caught the correlation
but launched the prefetch too late. This is the paper's "tight loop, no work
to overlap" signature — they observed the same effect on treeadd in Fig 8.

On the positive side, treeadd is **not regressing** — H7 went from +24.23%
(Base CDP) to −1.18% by (a) removing back-pressure and (b) killing useless
prefetches. DBP avoids both problems structurally: back-pressure-free
(mkOverflowBypassFifo staging), and issues so few prefetches that pollution
cost is zero.

## Comparison to paper's Figure 8

Paper reports on same Olden codes (with voronoi; we have tsp instead):

| bench | Paper's DBP speedup | Our DBP v1 |
|---|---|---|
| bh | ~1% | 0.00% |
| bisort | ~3% | +0.01% |
| em3d | ~15% | +0.33% |
| health | ~20% | +0.05% |
| perimeter | ~10% | 0.00% |
| treeadd | ~2% | 0.00% |
| tsp | ~1% | 0.00% |

We're substantially under the paper's reported speedups. Two things our
adaptation does NOT do that they did:

- **Train on all load commits, not just misses**. This is the biggest
  difference. Paper's PPW is fed every load; ours only misses.
- **Dataflow cascade** (prefetch completions re-probe CT to spawn further
  prefetches). Paper has this; we deliberately skipped it in v1. This
  matters for list traversal: once a prefetched cache line arrives, the
  paper's scheme chains into the NEXT pointer-chase prefetch immediately.

## Natural next steps (for discussion)

1. **v2: Train on `reportAccess` (all loads, not just misses)**. This
   requires adding a PPW-update-only path from `reportAccess`, separate
   from the miss-path that does trigger/consumer-attribution.
   Low-risk change; would close the training-volume gap with the paper.

2. **v3: Dataflow cascade**. Wire prefetch-completion events
   (`reportUsefulPrefetch` or a new `reportPrefetchFill`) back into the
   CT-probe pipeline. Cascades one-deep. Matches paper's single-
   instance-ahead model.

3. **DBP + Cooksey bit-match (originally planned)**. Layer Cooksey's
   pointer-shape filter on PPW insertion. Probably does less here than
   in CDP since DBP's value-equality matching is already exact; the bit-
   match is mostly de-noising the PPW. Might help on em3d (which had
   low strict-acc=13.5%, suggesting PPW aliasing).

Recommendation: ship v2 (train on all loads) before DBP-BitMatch — the
training-volume gap is the dominant issue. Once v2 matches the paper's
Figure 8 qualitatively, bit-match augmentation becomes the interesting
delta to measure.
