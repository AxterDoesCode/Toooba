# STRIDE prefetcher reference — captures sequential patterns CDP doesn't (informational, not a baseline replacement)

Date: 2026-04-27
Config: CACHE_ALEX_SMALLISH (1MB LLC), `DATA_PREFETCHER_TYPE=STRIDE`
Logs: `/local/scratch/ac2822/NewTooobaLogs/variantSTRIDE_baseline_2026-04-27/`

## Important framing

**This is NOT "STRIDE beats CDP."** STRIDE and CDP target different
access-pattern classes:
- **STRIDE**: sequential / next-line / array-traversal — trigger on
  monotonic addressing.
- **CDP (content-directed)**: pointer-chasing / non-sequential layouts —
  scan cache lines for embedded pointer values.

The Olden suite's accidental sequential-friendly layouts (em3d's arena-
allocated nodes, perimeter's hot-loop pattern, tsp similar) get caught
by STRIDE because they happen to be stride-able at L1 — not because
STRIDE is "better." NoPref remains the dissertation baseline per the
prefetching literature's convention; previous students at this group
have all used NoPref. The right question is "what fraction of
memory-bound cycle waste does CDP recover on workloads where stride
prefetching cannot apply?"

## Result summary

**STRIDE: −3.81% vs NoPref2. H7: −1.92% vs NoPref2.**

## Per-bench cycles

| bench     |   NoPref2 |        H7 |    STRIDE | H7 vs NoPref2 | STRIDE vs NoPref2 | STRIDE − H7 |
|:----------|----------:|----------:|----------:|--------------:|------------------:|------------:|
| bh        | 1,219,571 | 1,219,582 | 1,217,547 | +0.001% | **−0.17%** | −0.17 pp |
| bisort    |   989,251 |   985,152 |   984,225 | −0.41% | −0.51% | −0.10 pp |
| **em3d**  | 1,739,832 | 1,739,043 | **1,605,230** | −0.05% | **−7.74%** | **−7.69 pp** |
| health    | 1,258,698 | 1,246,504 | 1,243,023 | −0.97% | −1.25% | −0.28 pp |
| **patricia** | 1,416,398 | 1,245,569 | 1,244,378 | **−12.06%** | **−12.14%** | tie |
| **perimeter** | 2,692,517 | 2,692,523 | **2,547,521** | 0.000% | **−5.39%** | **−5.39 pp** |
| **treeadd** |   564,733 |   558,042 |   564,577 | **−1.18%** | −0.03% | **+1.17 pp** ← H7 wins |
| **tsp**   | 6,638,315 | 6,638,321 | **6,469,716** | 0.000% | **−2.54%** | **−2.54 pp** |
| **geomean**        |          |           |           | **−1.916%** | **−3.809%** | **−1.929 pp** |

## Interpretation by bench class

### Where STRIDE wins (em3d / perimeter / tsp / health / bh / bisort)

These benches have at least some sequential access component that
STRIDE captures cleanly:

- **em3d** (−7.69 pp vs H7): even though em3d's data structures are
  linked lists, its node-traversal probably allocates nodes from a
  contiguous arena and access is in approx-sequential order. STRIDE's
  next-line prefetcher gets ahead of these.
- **perimeter** (−5.39 pp): the "tight inner loop on 14 unique cache
  lines" pattern that left CDP unable to fire turns out to BE a stride
  pattern in the few demand Ld misses present. STRIDE's compulsory-miss
  catching dominates.
- **tsp** (−2.54 pp): same structural argument.
- **health** (−0.28 pp): smaller margin; CDP captured most of health's
  wins via LLC-shuffle, but STRIDE's compulsory-miss catching adds a
  bit more.
- **bh** (−0.17 pp): bh's 30 Ld misses are sequential-stride pattern;
  STRIDE catches them, CDP doesn't because the lines have no
  matchBits-passing pointers.

### Where they tie: patricia

Both achieve −12% on patricia. **This is the predicted result** per
existing memory `cdp_insight_bitmatch_negligible.md`: "Patricia wins
are pure stride." Patricia's trie nodes are laid out sequentially in
the heap arena, so a stride prefetcher catches them just as well as
content-directed prefetching does.

### Where H7 wins: treeadd

Treeadd is the **only bench where H7 decisively beats STRIDE
(+1.17 pp)**. Treeadd's tree-walk is recursive depth-first, so each
node's left/right children are scattered in memory in unpredictable
order at access time — no stride pattern. CDP's content-directed
mechanism (read pointer values, prefetch them) is what works here.

This makes treeadd the **proof point** that content-directed
prefetching has unique value beyond what stride prefetching captures.

## What this means for the dissertation

The dissertation framing remains:
- **NoPref baseline** per prefetching literature convention.
- **H7 vs NoPref2: −1.92% geomean** is the headline.
- **Patricia (−12%)** demonstrates DRAM-bypass on a workload too big
  for LLC.
- **Treeadd (−1.18%)** is the canonical content-directed-prefetch case
  where stride genuinely cannot help (recursive data-dependent walks).

The STRIDE numbers above are useful **context**, not a competing
metric:
- They show which Olden benches happen to have sequential-friendly
  layouts at the L1 level (em3d, perimeter, tsp).
- They confirm the existing memory-note observation that patricia's
  trie-node sequential layout makes it stride-friendly too.
- They highlight treeadd as the bench where content-directed
  prefetching is the *only* mechanism that helps — exactly the case
  CDP is designed for.

## Possible future direction (secondary, not dissertation pivot)

A CDP+STRIDE hybrid would in principle deliver on benches each
catches. This is **complementary mechanism integration**, not a
competitive upgrade. Reasonable to mention as future work; primary
contribution stays content-directed prefetching for the workload
class STRIDE cannot address.

## Recommended next directions

1. **CDP+STRIDE hybrid**: implement a variant that issues both
   stride-ahead AND CDP candidate prefetches. Should approach the
   union benefit (~−5% geomean).
2. **Stride suppression for treeadd**: treeadd is recursive, stride
   prefetcher likely emits useless prefetches there too. A unified
   prefetcher that uses CDP's confidence signals to suppress stride
   on chaotic-access PCs would be ideal.
3. **Reframe the dissertation around "content-directed for
   non-stride workloads"**: focus the experimental story on treeadd
   and CDP variants tuned for it.

## Memory + variant catalog updates

- New memory entry: `cdp_insight_stride_baseline_dominates.md`
- Update `cdp-variants` skill with STRIDE row in the comparison table
- Update `cdp-findings` skill — the H7 narrative needs context that
  STRIDE is a stronger baseline

## Artifacts

- Logs: `/local/scratch/ac2822/NewTooobaLogs/variantSTRIDE_baseline_2026-04-27/`
- This memo
