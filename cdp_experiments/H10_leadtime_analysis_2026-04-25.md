# H10 — lead-time instrumentation: why patricia is the only DRAM-bypass bench

Date: 2026-04-25
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitchH10.bsv`
Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH10_leadtime_2026-04-25/`

## Variant

H10 = H7 + per-prefetch `issueCycle` field in the prefetchFilter entry.
Algorithm and cycle counts identical to H7 (verified: 8/8 benches match
H7 exactly down to single cycles). The new log line on every useful hit:

```
%t AlexLog: CDP Kill useful hit: lineAddr X pcHash Y leadTime Z
```

where `Z = cur_cycle − issueCycle`.

**Important semantic note.** `leadTime` is the *issue-to-consumption*
interval, NOT the fill latency. A short leadTime means demand fired
shortly after prefetch issue (regardless of where the fill came from).
A long leadTime means the prefetched line sat in cache for a while
before demand consumed it. Fill latency itself (DRAM ~150 cyc vs LLC
~30 cyc) is NOT directly measurable from leadTime alone.

## Question being investigated

User's observation: "demand misses for the Olden benchmarks that see
0.5%-1% increase are just seeing useful prefetches which hit in L2.
Patricia sees gains because it reduces the number of demand misses
that go to DRAM."

The right metric for this is the *parser's* `prefetchMissLL` ∩
`usefulPrefetch`, which says: of the prefetches whose fill missed in
LLC (= went to DRAM), how many were consumed by a demand?

## Per-bench DRAM-bypass count (from parser, validates user's observation)

| bench     | issued | usefulPrefetch | prefetchMissLL | DRAM-bypass count | DRAM-bypass % |
|:----------|-------:|---------------:|---------------:|------------------:|--------------:|
| bisort    |    524 |    390 |     0 |     0 | 0% |
| em3d      |  1,992 |     43 |     0 |     0 | 0% |
| **health**| 12,240 |  3,332 |   **1** |   **1** | **0.03%** |
| **patricia** | 2,168 | 1,442 | **1,456** | **~1,442** | **~100%** |
| treeadd   | 15,324 |  1,612 |     0 |     0 | 0% |

User's observation confirmed quantitatively. **Only patricia gets
DRAM-bypass.** Everyone else: prefetch fill comes from LLC, demand
saves only ~10 cyc.

## Estimated cycle savings broken down

Per-useful savings: ~100 cyc DRAM-bypass, ~10 cyc LLC-shuffle.

| bench | timely useful | saved at DRAM | saved at LLC | total est. | observed Δ vs NoPref2 |
|:------|--------------:|--------------:|-------------:|-----------:|----------------------:|
| bisort   |   296 |     0 |  2,960 |   2,960 |   4,099 |
| em3d     |    36 |     0 |    360 |     360 |     789 |
| health   | 2,215 |   100 | 22,140 |  22,240 |  12,194 |
| **patricia** | **1,437** | **143,700** |     0 | **143,700** | **170,829** |
| treeadd  | 1,580 |     0 | 15,800 |  15,800 |   6,691 |

Patricia's 143,700-cyc DRAM-savings dwarfs every other bench's
LLC-savings combined.

## H10 lead-time distributions per bench (issue → demand consumption)

| bench    | n useful | min | p25 | median | p75  | p95   | shape |
|:---------|---------:|----:|----:|-------:|-----:|------:|:------|
| **patricia** | 1,465 | 1 | 202 | **219** | 247 | 562 | **tight unimodal at ~220 cyc** |
| health   | 3,537 | 1 | 16  | 73    | 616 | 4,641 | bimodal (15-30 + 100-1000) |
| treeadd  | 1,618 | 15 | 53  | 168   | 465 | 1,058 | broad unimodal |
| bisort   |   395 | 15 | 17  | 34    | 144 | 2,672 | bimodal (15-30 + tail) |
| em3d     |    28 | 15 | 25  | 36    | 67  | 17,663 | small sample, mostly short |

**Patricia's signature is the tight ~220 cyc median.** Each useful
prefetch fires almost exactly DRAM-fill latency (~150 cyc) ahead of
the demand load. The prefetch-fill arrives just before the demand,
maximizing DRAM-bypass benefit.

The other benches have **bimodal** distributions:
- Short tail (15-30 cyc): prefetch barely beats demand (LLC-fill
  arrives just before demand, ~10 cyc savings).
- Long tail (>500 cyc): prefetch fires very early, line sits in L1
  for hundreds of cycles before demand consumes. Wasted lead time —
  the savings are still LLC-only because LLC residency doesn't decay
  fast enough to push the prefetch out to DRAM.

## Per-PC breakdown (top PCs by useful event count)

### patricia — 96% of gain from one PC (`pcHash 84e0`)

| pcHash | issued | useful | useful% | medL | p25 | p75 | p95 |
|:-------|-------:|-------:|--------:|-----:|----:|----:|----:|
| **84e0** | **1,459** | **1,408** | **96.5%** | **219** | 202 | 244 | 490 |
| 9330 |  63 | 11 | 17.5% |  63 |   2 |    72 |    197 |
| 9054 |  37 | 10 | 27.0% | 531 |  15 | 13,916 | 207,434 |
| 9078 |  88 | 10 | 11.4% | 116,177 | 8,897 | 200,617 | 660,659 |
| 9056 |  55 |  8 | 14.5% | 160,899 | 41,174 | 255,755 | 340,981 |

PC 84e0 alone = 1,408 / 1,442 = **97.6% of patricia's useful events**.
Tight leadTime distribution (p25-p75 = 202-244) confirms this PC's
prefetches are DRAM-fill-aligned. Other patricia PCs are essentially
noise — low useful%, wild leadTime variance.

### health — three behavioral classes of hot PCs

| pcHash | issued | useful | useful% | medL | shape |
|:-------|-------:|-------:|--------:|-----:|:------|
| 93d4 | 3,667 | 1,100 | 30.0% |   725 | long lead — early prefetch, demand much later |
| 943e | 1,731 | 1,067 | 61.6% |    17 | **short lead** — prefetch barely on time |
| 9374 | 2,523 |   594 | 23.5% |    16 | short lead — same pattern |
| 9406 | 1,008 |   204 | 20.2% |    16 | short lead |
| 9414 | 1,244 |   138 | 11.1% |   270 | mid lead |

The three "short-lead" PCs (943e, 9374, 9406) account for 1,865 useful
events with median leadTime ~16 cyc. These are likely cases where the
prefetch fires *concurrently* with the demand miss being processed —
the prefetch fill arrives just before the demand load gets to MSHR
allocation. Useful, but only saving ~10 cyc each (LLC-fill latency).

### treeadd — clear good-vs-bad PC split (kill-switch under-suppressing)

| pcHash | issued | useful | useful% | medL |
|:-------|-------:|-------:|--------:|-----:|
| 92a0 |   303 | 214 | **70.6%** |   41 |
| 91ee |   297 | 202 | **68.0%** |  172 |
| 91f8 |   270 | 193 | **71.5%** |   52 |
| 90e0 |   177 | 134 | **75.7%** |   73 |
| 9094 | **3,886** | 170 | **4.4%** | 478 |
| 909a | **2,802** | 167 | **6.0%** | 203 |
| 9082 | **2,253** | 162 | **7.2%** | 1,052 |

Treeadd's 4 "good" PCs (92a0/91ee/91f8/90e0) have 68-76% accuracy with
743 useful events from 1,047 issued. The 3 "bad" PCs (9094/909a/9082)
issue **8,941 prefetches** (58% of treeadd's total!) with only 499
useful events (5.6% accuracy). These are the kill-switch's missed
targets — they evade `us > uf` because their useful count, while low
in fraction, is non-zero and the absolute count slowly accumulates.

This is exactly the "pollution audit" opportunity — tighter killThreshold
or a different gate (e.g., useful% < 10% → suppress) would cut treeadd's
useless prefetch traffic by ~half and save the LLC cycles those eat.

### bisort — single-PC dominant + good behavior

| pcHash | issued | useful | useful% | medL |
|:-------|-------:|-------:|--------:|-----:|
| 93c2 |  338 | 291 | 86.1% |   19 |
| 9390 |   88 |  55 | 62.5% |  235 |

bisort is well-behaved — high accuracy, no pollution PCs.

### em3d — essentially all noise

All PCs have 1.4-7.4% useful%. Em3d's CDP firings are mostly producing
LLC-hits on already-cached lines (high prefetchHit, low usefulPrefetch).

## Why patricia is unique — structural answer

**Working-set sizing relative to LLC:**

| bench | rough working set | fits LLC (1MB)? | prefetch-fill source |
|:------|-------------------|:----------------|:---------------------|
| bisort, em3d, health, treeadd | <1MB | yes | LLC (saves ~10 cyc) |
| patricia | several MB (large trie) | **NO** | **DRAM (saves ~100 cyc)** |

Memory note `cdp_insight_llc_resize.md` already noted that small
benches have IDENTICAL cycles at 1MB and 512KB LLC — the working sets
fit in either. Patricia's data set is structurally too big.

So the user's observation is structural, not algorithmic:
**you cannot get DRAM-bypass benefit on a bench whose working set
fits in LLC, no matter how good the prefetcher.** Once a line is in
LLC, all prefetches hit LLC, all fills are ~30 cyc, all savings are
~10 cyc.

## Implications for getting more H7 headroom

Patricia is the only bench where reducing demand-DRAM-misses gives big
gains. H7 currently captures only 38% of patricia's DRAM misses
(1,456 / 3,869). The remaining 62% (≈2,400 DRAM misses) live in the
patricia PCs that are NOT 84e0.

But looking at the per-PC table: all non-84e0 PCs on patricia have
low useful% and mostly issue useless prefetches. They're not silent
because they're well-trained — they're silent in *aggregate impact*
because their accuracy is bad.

**To extend patricia coverage, we need to enable PCs to discover
correct candidates and accumulate confidence.** Several possible
mechanisms:
- Higher `confidenceThreshold` would suppress weak PCs entirely (bad).
- Lower `confidenceThreshold` (already at 1) can't go lower.
- More cross-PC sharing (e.g., shared signature like SPP) — but this
  was tested in H9/H9B and dilutes patricia further.
- **Larger prefetchFilter** to improve attribution — useless events
  that currently don't attribute could trip the kill-switch on bad PCs,
  allowing the good PCs more BRAM real estate.
- **L1-residency filter for treeadd-style benches** — cut the 8,941
  pollution prefetches on 9094/909a/9082, freeing pipeline + LLC
  bandwidth.

For health/treeadd/bisort/em3d, **DRAM-bypass is structurally
impossible** without shrinking LLC or growing the workload. We can
only optimize the LLC-shuffle benefit (~10 cyc per useful) and reduce
overhead.

## Recommended directions (post-H10)

1. **Treeadd pollution audit & tighter kill-switch.** PCs 9094/909a/9082
   issue 8,941 prefetches with 5.6% accuracy. Even modest suppression
   would save the LLC-fetch overhead. Try a useful%-based gate:
   `if (uf+us >= 8 && uf < (uf+us)/4) suppress` (i.e., <25% useful rate
   over 8 events → kill).
2. **Patricia non-84e0 PC coverage.** Investigate why 9054/9078/9056 etc
   issue prefetches but rarely produce useful hits. Are they on stride
   patterns CDP can't catch? Or wrong-target pointer chases?
3. **Larger prefetchFilter (4096-8192 entries)** — addresses both the
   kill-switch attribution gap (currently ~20-35%) AND would give
   path-history variants enough room to not dilute. Two birds.
4. **Drop pursuit of bh / perimeter / tsp** — confirmed earlier
   (`cdp_insight_zero_prefetch_benches_no_opportunity.md`). No CDP-
   shaped opportunity.

H7 remains the dissertation reference. Headroom story is now clear:
patricia coverage extension and treeadd pollution reduction.

## Artifacts

- Source: `CDPKillSwitchH10.bsv` (instrumentation only, cycle-identical to H7)
- Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH10_leadtime_2026-04-25/`
- This memo and `cdp_insight_dram_bypass_unique_to_patricia.md`
