# H13 (H7 + train CDP on store misses too) — negative + correctness failure

Date: 2026-04-26
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitchH13.bsv`
Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH13_store_training_2026-04-26/`

## Variant

H13 = H7 with the `op == Ld` gate widened to `op == Ld || op == St` in
both `reportIncomingCacheLine` and `deqCacheLines`. Store misses now
trigger the same training+scan+PrefetchIssue pipeline as load misses.
Goal: get CDP firing on bh / perimeter / tsp, which are 95-99.8% St-miss-
dominated under H7.

## Results (default 1MB LLC)

| bench     |   NoPref2 |        H7 |       H13 | H13 − H7 | % |
|:----------|----------:|----------:|----------:|---------:|------:|
| bh        | 1,219,571 | 1,219,582 | 1,219,582 |       +0 | 0.000% |
| bisort    |   989,251 |   985,152 |   985,190 |      +38 | +0.004% |
| em3d      | 1,739,832 | 1,739,043 | 1,736,550 |   **−2,493** | **−0.143%** |
| **health**| 1,258,698 | 1,246,504 | 1,254,307 |   **+7,803** | **+0.626%** |
| patricia  | 1,416,398 | 1,245,569 | 1,243,415 |   −2,154 | −0.173% |
| perimeter | 2,692,517 | 2,692,523 | 2,692,523 |       +0 | 0.000% |
| **treeadd** |   564,733 |   558,042 | **CRASH** |       — | **fabric DECERR @ cyc 463,243** |
| tsp       | 6,638,315 | 6,638,321 | 6,638,321 |       +0 | 0.000% |

**7-bench geomean (excluding crashed treeadd):**

| variant | vs NoPref2 |
|:---|---:|
| H7  | **−2.020%** |
| H13 | **−1.977%** (+0.044 pp regression) |

## Three findings

### 1. Treeadd CRASHED — store-miss training is structurally unsafe

Treeadd hit `LLC_AXI4_Adapter.rl_handle_read_rsp: fabric response error`
at cycle 463,243 — same correctness failure mode as H9 (path-history
variant). Mechanism:

- During treeadd's tree-construction phase, store misses fetch fresh
  cache lines that contain stale or random heap data.
- CDP scans those lines for matchBits=16-passing words — without any
  semantic check that those words are actually pointers.
- One such "false pointer" passed VPN filtering, was issued as a
  prefetch, and the resulting paddr fell in unmapped DRAM.
- The AXI fabric returned `rresp=0x3` (DECERR), which Toooba's LLC
  adapter handles by exiting the simulator.

**Generalisation:** load-miss line content has *just been read*, so
its words are mostly real pointers (anything else would have caused
the program to behave differently before). Store-miss line content
is *about to be overwritten* — it can be stale, uninitialised, or
random. Training CDP on store misses is fundamentally less safe
because the input distribution is wider.

This is the same correctness lesson H9 surfaced (see
`cdp_insight_pathhist_order.md` 2026-04-24 update): mechanisms that
*expand* CDP's pcTable keyspace or input sources without proportional
safety gates surface invalid-region prefetches.

### 2. Health regression (+7,803 cyc / +0.626%) — predicted pollution

Store-miss training on health adds new pcTable entries for store-PCs
that don't issue useful prefetches but DO accumulate confidence over
time. These entries pollute the kill-switch ratio gate (`us > uf`)
because their useful counts come from coincidental same-line demand
hits while their useless counts grow with eviction.

Predicted in advance; observed +0.63%.

### 3. Em3d / patricia mild improvements (small surprise)

- **em3d −2,493 cyc (−0.143%)**: em3d already had high prefetchHit
  rate at H7 (1,908 / 1,992 = 96%). Store-miss training apparently
  added a few useful candidates without polluting much. Modest gain.
- **patricia −2,154 cyc (−0.173%)**: small discovery boost from
  store-PCs in patricia's trie-build phase finding pointer values
  that the load-miss-only path missed.

Neither is dissertation-defining; both within bench-to-bench noise.

### 4. bh / perimeter / tsp unchanged — confirms the structural ceiling

bh has 18,523 store misses but they hit fresh / `aaaa…`-filled memory
during init. CDP scans find 0 matchBits-passing pointer values. No TT
writes, no prefetches, identical to H7.

Perimeter / tsp similar. Their store misses are on cache lines whose
content doesn't contain heap pointers passing the matchBits filter
(or, where it does, the resulting candidates point to lines that are
never demand-loaded later because the demand-Ld-miss target set is
14 / 26 unique cache lines).

**This empirically confirms** the analysis from
`cdp_insight_zero_prefetch_benches_no_opportunity.md`: bh / perimeter
/ tsp are not addressable by any extension of CDP's training input.
Their access patterns require a different prefetcher class entirely
(stride for bh's compulsory misses; temporal/Markov for
perimeter/tsp's conflict misses).

## Decision: H13 is unsafe, do NOT promote

The treeadd crash is a **correctness violation**, not just a perf
regression. Even though the cycle data on the surviving 7 benches
shows only a modest +0.044 pp geomean regression, real-system
deployment of H13 would crash on workloads that match treeadd's
construction-phase pattern (any benchmark that does heavy memory
initialization with stores into fresh memory).

The H7 + Ld-only training design is an unintentional safety filter:
load-miss lines have already been "validated" by the program's prior
reads. Store-miss lines have not.

## Possible safer alternative (not built)

A more defensive design: enable store-miss training but add a
**per-prefetch paddr-range filter** that rejects prefetches whose
translated paddr falls outside the LLC-adapter's DRAM range. Would
prevent the crash. Implementation is in L1Bank.bsv or the LLC
adapter, not the prefetcher. Worth considering as a general defensive
addition, separate from the store-training experiment.

## Memory updates

- `cdp_insight_h13_store_training_unsafe.md` (new)
- `MEMORY.md` index entry

## Variant catalog implication

H13 sits alongside H9 in the "expanded-input → fabric DECERR" failure
class. Both demonstrate the safety-by-restriction property of H7's
single-Ld-PC keying.

## Artifacts

- Source: `CDPKillSwitchH13.bsv`
- Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH13_store_training_2026-04-26/`
- This memo
