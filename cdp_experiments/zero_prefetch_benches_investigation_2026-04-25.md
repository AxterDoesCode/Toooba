# Investigation: bh / perimeter / tsp — why CDP doesn't fire & is there opportunity?

Date: 2026-04-25
Source: H7 archive at `/local/scratch/ac2822/NewTooobaLogs/variantH7_overflowBypass_2026-04-22/`

## Why CDP doesn't fire

Demand misses by op:

| bench | total miss | St miss | Ld miss | Ld % |
|:------|----------:|--------:|--------:|-----:|
| bh        |  18,553 | 18,523 |    30 | **0.16%** |
| perimeter |  36,380 | 35,393 |   987 | **2.7%** |
| tsp       |  38,397 | 36,484 | 1,913 | **5.0%** |

CDP's `reportIncomingCacheLine` only triggers `EvDemandLdMiss` for `op == Ld && wasMiss && !isPrefetch && !wasNeighbour`. These three benches are 95-99.8% St-miss-dominated, which gates out almost all of CDP's normal training pathway.

But that's only half the story.

## The Ld misses that DO exist target tiny working sets

| bench | Ld misses | unique miss cache-lines | avg miss/line | Ld accesses | unique access cache-lines |
|:------|----------:|------------------------:|--------------:|------------:|--------------------------:|
| bh        |    30 | 26 | **1.2** (compulsory) |     7,450 |  94 |
| perimeter |   987 | 14 | **70.5** (thrashing!) | 275,544 |  16 |
| tsp       | 1,913 | 26 | **73.6** (thrashing!) | 747,349 |  33 |

**perimeter and tsp aren't pointer-chase memory-bound — they're cache-conflict-bound on a tiny working set.** Perimeter's tight inner loop sweeps 16 unique cache-lines; the L1 (or its associativity) can only hold ~14 of them at a time, so each line gets re-missed ~70 times.

bh has 26 unique compulsory-miss lines spread across a small contiguous region (0x80002940-0x800029c0 stride pattern). Looks more like a sequential sweep than pointer-chasing.

## What pointer values exist in their Ld miss cache lines?

Even though CDP doesn't fire, I checked whether the cache lines from these Ld misses *contain* matchBits=16-passing heap pointers (filtering out code/text addresses):

| bench | sampled Ld miss lines | lines with heap pointer | distinct heap pointers discovered |
|:------|----------------------:|------------------------:|----------------------------------:|
| bh        |    30 |   0 (0%)  |     0 |
| perimeter |   987 | 438 (44%) |   335 |
| tsp       | 1,913 | 683 (36%) |   543 |

Plenty of heap pointers in perimeter/tsp's lines — but they point at the wider heap, not at the 14/26 lines that are actually being thrashed. So even a perfectly-trained CDP would discover candidates that never get demand-loaded later.

## Realistic prefetch opportunity ceiling per bench

Estimating the maximum cycle savings from a *theoretically-perfect* prefetcher:

### bh
- 30 Ld misses, ~26 of which are compulsory; the rest could potentially be prefetched.
- Best case: 30 × ~100 cyc DRAM-hit savings = **~3,000 cycles** out of 1.22M total = **~0.25% potential**.
- Pattern looks stride-like (sequential 64-byte step), so a stride prefetcher would catch them. CDP wouldn't, because the cache lines don't contain heap pointers.

### perimeter
- 987 Ld misses but only 14 unique cache-line targets.
- 14 lines are compulsory; the other 973 are **conflict/capacity misses** on the same lines re-missed.
- CDP can't help conflict misses (doesn't track which lines were recently evicted).
- Best-case prefetching savings on compulsory misses: 14 × 100 cyc = **~1,400 cyc** out of 2.69M = **~0.05% potential**.
- True remedy is bigger L1 / higher associativity, not prefetching.

### tsp
- 1,913 Ld misses but only 26 unique lines (similar thrashing pattern).
- 26 compulsory + 1,887 conflict.
- Best-case prefetching: 26 × 100 = **~2,600 cyc** out of 6.64M = **~0.04% potential**.
- Same diagnosis as perimeter.

## Aggregate impact on geomean

If I were *somehow* able to capture every bit of available opportunity on these three benches, total geomean improvement would be:

```
∛(0.9975 × 0.9995 × 0.9996) - 1 ≈ -0.11 pp on the 8-bench geomean.
```

In the noise floor of any normal CDP variant change.

## Why CDP can't even fire on the few Ld misses present

For **bh**: 0% of cache lines have heap pointers. CDP scans and finds no candidates. No TT writes ever happen. No Training. No prefetches.

For **perimeter / tsp**: 36-44% of lines DO have heap pointers, so CDP's scan would write TT entries — but those discovered pointers point at OTHER heap lines that are never demand-loaded later (the thrashing inner loop only revisits its 14 / 26 unique lines). So Training-trigger TT-hits never fire, no PC-table conf accumulates, no prefetches issue.

In short: **the discovered pointers and the demand misses live in disjoint regions of the heap**.

## Recommendation: don't pursue these benches

These three benches contribute ~0% of CDP's leverage:

- **bh** is a cold-cache, low-Ld-miss bench. Stride prefetching would help marginally (~0.25%); CDP can't.
- **perimeter / tsp** are conflict-miss-bound on tiny working sets. No prefetcher class fixes that — only cache sizing or replacement policy.

**Where the actual H7 headroom lives:**

| bench | H7 vs NoPref2 | gap to "perfect" |
|:---|---:|:---|
| bh        |  +0.0009% | none reachable |
| bisort    |  −0.41% | small |
| em3d      |  −0.05% | residual back-pressure (already analyzed) |
| **health**| **−0.97%** | timely 841 / demandMissLL 3,056 → ~70% of LLC misses still unprefetched |
| **patricia** | **−12.06%** | timely 1,437 / demandMissLL 3,869 → ~63% of DRAM misses still unprefetched |
| perimeter |  +0.0002% | none reachable |
| **treeadd** | **−1.18%** | high redundancy (87% prefetchHit), low timely-miss |
| tsp       |  +0.0001% | none reachable |

**Real-headroom benches are health, patricia, treeadd.** They already have CDP firing; the question is whether we can convert more demand misses into timely prefetches. Specifically:

- **health**: 3,056 LLC misses but only 841 timely-useful — the kill-switch is suppressing too many or training too slowly.
- **patricia**: H7 already captures ~38% of DRAM misses; another 60% lives in PCs the kill-switch isn't reaching.
- **treeadd**: lots of `prefetchHit` (already-resident lines re-prefetched), low fresh-fetch fraction. A redundancy filter would help.

## Suggested next directions (in priority order)

1. **Pollution audit on health** — find which PCs are issuing the 1,659 useless prefetches and what fraction should be killed earlier. Possibly tighten killThreshold.
2. **Patricia coverage extension** — patricia has high accuracy (96%) but only catches 38% of DRAM misses. Investigate which PCs miss but never train (e.g., warm-up loads, large stride).
3. **Treeadd redundancy filter** — drop prefetches whose target line is already L1-resident (current filter only deduplicates against issued prefetches, not L1 contents).
4. **Larger prefetchFilter** (4096-8192 entries) — increases attribution coverage from 20-35% to 80-90%, lets us drop the 3× amplification, addresses path-history rescue at the same time.

Skip bh / perimeter / tsp — there's nothing CDP-shaped left there.
