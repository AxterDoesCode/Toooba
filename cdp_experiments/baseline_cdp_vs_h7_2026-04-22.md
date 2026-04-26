# Baseline CDP (`mkCDPStatefulRelative`) vs H7 — cycle + parser comparison

Date: 2026-04-22
Branch: `ac2822CDPDeepDive` (tip: `510c306c`)
Both variants measured on the current tree, which includes:
- CapPtr §3.4.2 fix (`LLCache.bsv:308 respLoadWithE=True`, commit `c64b77c9`)
- em3d resized to 500-node (`~1.7M` cycle baseline)

This isolates H7's contribution cleanly — the back-pressure decoupling +
the per-PC useful/useless counters + the kill-switch. The S→E latency tax
and the small-em3d weighting issue are already off the table.

## Build selection

Both binaries built from the same source commit, differing only in
`DATA_PREFETCHER_TYPE`:

| Variant | macro | module |
|---|---|---|
| Base | `DATA_PREFETCHER_CDP` | `mkCDPStatefulRelative` (CDP.bsv) |
| H7   | `DATA_PREFETCHER_CDP_KILLSWITCH_H7` | `mkCDPStatefulRelativeKillSwitchH7` (CDPKillSwitchH7.bsv) |

NoPref reference: **`variantNoPref2_postCapPtrFix_2026-04-22`** — fresh
8-bench NoPref build on the current commit (`510c306c`) with the
CapPtr §3.4.2 MESI fix in place. A prior re-run with the old
mixed-source NoPref showed identical numerics (0.001% noise), so
the MESI fix does not affect NoPref — it only changes LLC behaviour
on prefetch-hit, a code path NoPref never touches.

## NoPref2 sanity check (MESI-fix effect on baseline)

Re-ran 8-bench NoPref from scratch with `DATA_PREFETCHER_LOCATION=NONE`
on the same tip to confirm the CapPtr §3.4.2 fix does not shift the
baseline:

| bench | old NoPref | NoPref2 | Δ cyc | Δ% |
|:--|--:|--:|--:|--:|
| bh | 1,219,582 | 1,219,571 | −11 | −0.0009% |
| bisort | 989,257 | 989,251 | −6 | −0.0006% |
| em3d | 1,739,838 | 1,739,832 | −6 | −0.0003% |
| health | 1,258,704 | 1,258,698 | −6 | −0.0005% |
| patricia | 1,416,404 | 1,416,398 | −6 | −0.0004% |
| perimeter | 2,692,523 | 2,692,517 | −6 | −0.0002% |
| treeadd | 564,739 | 564,733 | −6 | −0.0011% |
| tsp | 6,638,321 | 6,638,315 | −6 | −0.0001% |

Deltas are <1% of a percent (single-digit cycles out of ~1M). The MESI
fix only affects LLC behaviour on a prefetch hit — a code path NoPref
never executes. **Baseline is stable; all CDP deltas below are real.**

## Cycle results vs NoPref2 (lower is better)

| bench     |    NoPref2 |   BaseCDP |         H7 | Base/NP2 | H7/NP2 | BaseΔ | H7Δ |
|:----------|-----------:|----------:|-----------:|---------:|-------:|------:|----:|
| bh        |  1,219,571 | 1,220,351 |  1,219,582 |   1.0006 | 1.0000 | +0.06% | +0.00% |
| bisort    |    989,251 | 1,071,372 |    985,152 |   1.0830 | 0.9959 | +8.30% | −0.41% |
| em3d      |  1,739,832 | 1,938,906 |  1,739,043 |   1.1144 | 0.9995 | +11.44% | −0.05% |
| health    |  1,258,698 | 1,317,260 |  1,246,504 |   1.0465 | 0.9903 | +4.65% | −0.97% |
| patricia  |  1,416,398 | 1,325,290 |  1,245,569 |   0.9357 | 0.8794 | **−6.43%** | **−12.06%** |
| perimeter |  2,692,517 | 2,739,559 |  2,692,523 |   1.0175 | 1.0000 | +1.75% | +0.00% |
| treeadd   |    564,733 |   701,587 |    558,042 |   1.2423 | 0.9882 | **+24.23%** | **−1.18%** |
| tsp       |  6,638,315 | 6,737,129 |  6,638,321 |   1.0149 | 1.0000 | +1.49% | +0.00% |
| **geomean** |          |           |            | **1.0535** | **0.9808** | **+5.35%** | **−1.92%** |

## Headline

- Baseline CDP is **+5.35% slower than NoPref** on the 8-bench geomean.
- H7 is **−1.92% faster than NoPref**.
- Net H7 vs Base CDP: **−6.9% geomean** (1.0535 / 0.9808).

## Per-bench attribution

1. **bh, perimeter, tsp** — identical for H7 and NoPref; Base CDP is
   +0.06 / +1.75 / +1.49%. These benches issue **zero prefetches** (the
   parser-metrics section will confirm; they're store-dominated so the
   load-miss trainer never fires). The Base-vs-NoPref slowdown is pure
   **method-guard back-pressure** from `reportIncomingCacheLine` — demand
   loads still classify through the method and stall on `l1ToCDP.enq`
   guards when downstream CDP rules fall behind. H7's `mkOverflowBypassFifo`
   staging FIFO is trivially non-blocking, so the L1 pipeline sees
   zero stall cycles from the method call. Three benches where "the
   prefetcher issues nothing" and Base is still net-slow → pure
   implementation/back-pressure, not algorithm.

2. **bisort, em3d** — Base CDP +8.30% / +11.44%, H7 ≈ parity. CDP does
   issue on these (524 / 1992 prefetches under H7). The 8-12 pp
   swing is still mostly back-pressure: em3d's `incomingQ` stays full
   for ~10% of cycles under blocking-FIFO semantics (see memory
   `cdp_insight_em3d_residual_backpressure`). Replacing blocking enq
   with drop-on-full recovers the stall cycles; the prefetch value is
   separately small (em3d = 1,908/1,992 prefetches are already L1-
   resident HITs — wasted work, but under H7 wasted work is free).

3. **health, treeadd** — Base +4.65% / +24.23% → H7 −0.97% / −1.19%.
   treeadd is the biggest swing: +24.23% → −1.19% (a 25 pp delta).
   Baseline CDP's treeadd regression comes from a combination of (a)
   blocking back-pressure and (b) pollution — treeadd issues 15k
   prefetches/run, 87% already-in-L1 HIT, so under blocking FIFO
   semantics the prefetcher spends pipeline slots blocking the demand
   path while contributing no new data. H7 eliminates (a); the useful
   signal from the timely 1,580 prefetches (small per-useful savings
   since prefetchMissLL=0, all LLC-hit) is just barely positive once
   (a) is off the table.

4. **patricia** — the only bench where baseline CDP was already a net
   winner (−6.43%). patricia's working set exceeds LLC, prefetches
   save ~100 cyc/useful at DRAM. H7 extends the win to −12.06% because
   even patricia sees some back-pressure cost under blocking FIFO,
   and eliminating it unlocks ~half the remaining headroom.

## What the ZERO-prefetch benches tell us

Base CDP vs NoPref on bh/perimeter/tsp isn't noise — the numbers are:
- bh:        +0.06% (effectively zero; trivially-load-light bench)
- perimeter: +1.75%
- tsp:       +1.49%

H7 flattens all three to 0.00%. This is the clean signature of
**method-guard back-pressure independent of algorithm**: the
prefetcher issues nothing, but the *path through*
`reportIncomingCacheLine` still stalls the L1 demand pipeline whenever
any downstream CDP FIFO (training, ttReq, etc.) fills from a
transient burst. H7's drop-on-full staging fifo makes the method a
pure enqueue with no guards — the back-pressure channel vanishes.

This is the single cleanest piece of evidence that H7's value over
baseline CDP is primarily structural (the `mkOverflowBypassFifo`
staging), not algorithmic (the per-PC kill-switch).

## Prefetch-quality table (TooobaLogParser `CRqCreationLine` totals)

| bench     | variant | issued | HIT    | OWNED | miss   | missLL | useful | late  | timely | useless | strict | timely |
|:----------|:--------|-------:|-------:|------:|-------:|-------:|-------:|------:|-------:|--------:|-------:|-------:|
| bh        | Base    |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |
| bh        | H7      |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |
| bisort    | Base    |  9,303 |  3,665 |    31 |  5,607 |      0 |  1,613 |   186 |  1,427 |   3,994 |  28.8% |  25.5% |
| bisort    | H7      |    524 |     98 |    28 |    398 |      0 |    390 |    94 |    296 |       8 |  98.0% |  74.4% |
| em3d      | Base    |  5,051 |  4,659 |   111 |    281 |      0 |    128 |    31 |     97 |     153 |  45.6% |  34.5% |
| em3d      | H7      |  1,992 |  1,908 |    18 |     66 |      0 |     43 |     7 |     36 |      23 |  65.2% |  54.5% |
| health    | Base    | 24,246 | 15,668 | 1,202 |  7,376 |      0 |  5,082 | 1,418 |  3,664 |   2,294 |  68.9% |  49.7% |
| health    | H7      | 12,240 |  6,350 | 1,548 |  4,342 |      1 |  3,332 | 1,117 |  2,215 |   1,010 |  76.7% |  51.0% |
| patricia  | Base    |  3,964 |  1,859 |   181 |  1,924 |  1,481 |  1,669 |   103 |  1,566 |     255 |  86.7% |  81.4% |
| patricia  | H7      |  2,168 |    614 |    54 |  1,500 |  1,456 |  1,442 |     5 |  1,437 |      58 |  96.1% |  95.8% |
| perimeter | Base    |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |
| perimeter | H7      |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |
| treeadd   | Base    | 19,269 | 14,394 | 1,648 |  3,227 |      0 |  3,070 | 1,427 |  1,643 |     157 |  95.1% |  50.9% |
| treeadd   | H7      | 15,324 | 13,310 |   334 |  1,680 |      0 |  1,612 |    32 |  1,580 |      68 |  96.0% |  94.0% |
| tsp       | Base    |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |
| tsp       | H7      |      0 |      — |     — |      — |      — |      — |     — |      — |       — |      — |      — |

## Prefetch-quality observations (Base → H7)

- **H7 issues strictly fewer prefetches** on every bench — the kill-switch
  is actively suppressing. Ratios:
  - bisort: 9,303 → 524 (**×17.7 fewer**)
  - em3d:    5,051 → 1,992 (×2.5)
  - health: 24,246 → 12,240 (×2.0)
  - patricia: 3,964 → 2,168 (×1.8)
  - treeadd: 19,269 → 15,324 (×1.26)

- **Timely accuracy rises dramatically** on 4 of 5 issuing benches:
  - bisort: 25.5% → 74.4% (+48.9 pp)
  - em3d: 34.5% → 54.5% (+20.0 pp)
  - treeadd: 50.9% → 94.0% (+43.1 pp)
  - patricia: 81.4% → 95.8% (+14.4 pp)
  - health: 49.7% → 51.0% (+1.3 pp — flat)

- **Useless prefetches are crushed**:
  - bisort: 3,994 → 8 (−99.8%)
  - health: 2,294 → 1,010 (−56%)
  - patricia: 255 → 58 (−77%)
  - treeadd: 157 → 68 (−57%)
  - em3d: 153 → 23 (−85%)

- **Useful counts drop in H7**, but `timely_useful` stays close for the
  LLC-bound benches and drops for the DRAM-bound:
  - bisort: 1,427 → 296 timely (−1,131 timely — mostly LLC-hit, ~5-10 cyc each)
  - em3d: 97 → 36 (−61 timely)
  - health: 3,664 → 2,215 (−1,449 timely — all LLC, small per-useful)
  - patricia: 1,566 → 1,437 (−129 timely, all DRAM — the only bench where
    H7 plausibly *loses* useful cycles, but the back-pressure-removal and
    pollution-reduction overcompensate: patricia still gains 5.6 pp more
    than under baseline CDP, dropping from −6.43% to −12.06%)
  - treeadd: 1,643 → 1,580 (−63 timely — basically preserved)

## What this shows about H7's value

Two mechanisms are stacked in H7 vs baseline CDP:

1. **Back-pressure removal** (`mkOverflowBypassFifo` staging): explains
   the bh/perimeter/tsp deltas entirely (0 prefetches on both variants,
   +0.06 / +1.75 / +1.49% → 0.00%). Also contributes a big fraction of
   the bisort/em3d/treeadd swings since those issue under blocking-FIFO
   semantics in Base.

2. **Kill-switch gate** (per-PC useless attribution): cuts noise. On
   bisort the kill-switch removes 3,986 of 3,994 useless prefetches
   and 8,779 of 9,303 total prefetches. Timely-useful count drops too,
   but H7 bisort is still faster than Base — the pollution avoidance
   outweighs the lost useful work.

The kill-switch also explains the higher H7 timely_acc: by raising
the bar for issue, it shifts the mix toward higher-confidence PCs.
On treeadd this is the largest gain in the variant landscape — from
50.9% to 94.0% timely accuracy.

## Net

Replacing `mkCDPStatefulRelative` with `mkCDPStatefulRelativeKillSwitchH7`
takes the 8-bench geomean from **+5.35%** slower than NoPref to
**−1.92%** faster — a **−6.9 pp** net improvement while keeping the
same 4KB-same-page CDP core mechanism. The H7 variant is the first
CDP configuration to beat NoPref on this Olden suite.

