# SPP + Cooksey (additive fusion v1) — negative finding

Date: 2026-04-23
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/SPPCooksey.bsv`
Design memo: `cdp_experiments/SPP_Cooksey_design_2026-04-23.md`
Logs: `/local/scratch/ac2822/NewTooobaLogs/variantSPPCooksey_v1_2026-04-23/`

## Design implemented

SPPCooksey v1 = pure SPP (unchanged SPP submodules) + additive Cooksey
scan on every **demand Ld L1 miss**. Cooksey scans the 8 aligned 64-bit
words of the returned cache line; any word whose upper 16 VPN bits
agree with the access's VPN AND whose low 3 bits are zero is enqueued
as a prefetch candidate. Candidates bypass SPP's internal prefetch
filter and go directly into the shared post-filter prefetch queue.

## Cycle results (vs NoPref2, 8-bench geomean)

| bench     | NoPref2   | SPP       | SPPCooksey | H7        | SPP%   | SPPC%  | H7%    | Cook−SPP cyc |
|:----------|----------:|----------:|-----------:|----------:|-------:|-------:|-------:|-------------:|
| bh        | 1,219,571 | 1,218,389 |  1,218,389 | 1,219,582 | −0.10% | −0.10% | +0.00% |           0 |
| bisort    |   989,251 |   989,514 |    983,052 |   985,152 | +0.03% | **−0.63%** | −0.41% |      **−6,462** |
| em3d      | 1,739,832 | 1,731,179 |  1,735,220 | 1,739,043 | −0.50% | −0.27% | −0.05% |      +4,041 |
| health    | 1,258,698 | 1,196,481 |  1,195,979 | 1,246,504 | −4.94% | **−4.98%** | −0.97% |         −502 |
| patricia  | 1,416,398 | 1,402,457 |  1,408,703 | 1,245,569 | −0.98% | −0.54% | −12.06% |     +6,246 |
| perimeter | 2,692,517 | 2,688,330 |  2,696,857 | 2,692,523 | −0.16% | +0.16% | +0.00% |     +8,527 |
| treeadd   |   564,733 |   565,097 |    564,585 |   558,042 | +0.06% | −0.03% | −1.18% |        −512 |
| tsp       | 6,638,315 | 6,700,810 |  6,705,810 | 6,638,321 | +0.94% | +1.02% | +0.00% |     +5,000 |
| **geomean** |         |           |            |           | **−0.72%** | **−0.69%** | **−1.92%** |            |

**Net:** SPPCooksey geomean is **−0.69%**, vs pure SPP at **−0.72%**.
Cooksey additive fusion is effectively a wash — 3 benches improve,
4 benches regress, and the sum in geomean is within 0.03 pp.

## What Cooksey actually did (delta vs SPP)

| bench     | Δ issued | Δ timely-useful | Δ useless | cycle Δ |
|:----------|---------:|----------------:|----------:|--------:|
| bh        |       +1 |              0  |       0   |       0 |
| bisort    |   +9,537 |         +2,147  |   +2,124  |  **−6,462** |
| em3d      |  +10,924 |           +244  |   +5,100  |   +4,041 |
| health    |   +3,497 |            +52  |     +274  |     −502 |
| patricia  |     +161 |            +37  |      +62  |   +6,246 |
| perimeter |     +562 |           +293  |      +29  |   +8,527 |
| treeadd   |  +25,925 |         +1,077  |     +693  |     −512 |
| tsp       |     +322 |            +37  |      +70  |   +5,000 |

## Key finding: the design hypothesis was wrong

**Hypothesised** (design memo, §"What we expect to see"): "Patricia:
significant improvement" — Cooksey would catch patricia's scattered
pointer-chase where SPP can't.

**Observed:** Patricia REGRESSED (−0.98% → −0.54%, +6,246 cycles).

Why the prediction failed:
- Cooksey issued only **+161 extra prefetches** on patricia.
- Patricia's pointer values span wider regions than a same-8MB
  VPN window (matchBits=16). Most of patricia's trie-node
  pointers span pages that are not upper-16-bit-matched with the
  accessing VPN, so the Cooksey shape filter REJECTS them.
- The 161 that did pass were mostly noise; the 6,246 cycle
  slowdown comes from general pollution / added bandwidth,
  not a meaningful Cooksey contribution.

**Why H7 beats SPPCooksey on patricia (−12.06% vs −0.54%):** H7 is
not just Cooksey. H7 is Cooksey + PC-keyed learning + kill-switch.
The kill-switch (per-PC useless attribution) suppresses pointer-shape-
but-wrong candidates. SPPCooksey has no feedback loop — it simply
emits every shape-passing candidate. Without suppression, noise
accumulates and doesn't help patricia.

## Where Cooksey did help and where it hurt

**Helped (bisort, −6.5k cycles):** bisort issued 9,537 extra
prefetches, 2,147 timely. Bisort's binary-tree nodes have a clean
same-region pointer layout, so Cooksey's 16-bit-VPN filter had a
good hit rate. 2,147 timely × ~5 cyc LLC-hit ≈ 10k cycles saved;
minus ~2k pollution cost from 2,124 useless = clean ~6-8k saved.

**Hurt (em3d, +4k; perimeter +8.5k; tsp +5k):**
- em3d's nodes contain floating-point arrays mixed with pointers.
  Cooksey's bit-match filter incorrectly flags FP bit patterns that
  happen to match the VPN upper bits. Result: 5,100 extra useless.
- perimeter is quad-tree, already well-covered by SPP. Cooksey adds
  562 extra issues and most are late-duplicate (perimeter's existing
  8,691 late). Pipeline overhead outweighs the 293 extra timely.
- tsp's stores train SPP AND trigger Cooksey scans on demand misses.
  tsp already over-prefetches under SPP; adding more is counter-
  productive.

**Neutral wash:** treeadd +25k issued but only +1k timely (28% of SPP's
issues were HIT; Cooksey's were 75% HIT). Massive waste but
interestingly no cycle cost — treeadd's demandOwned dynamics hide it.

## Takeaway for dissertation narrative

Naive additive Cooksey-on-top-of-SPP is a **negative result**. The
two mechanisms are orthogonal in coverage but compete for the same
bandwidth/pipeline resources; adding Cooksey to SPP doubles the
issue rate on benches where SPP was already over-aggressive, and
doesn't help on benches where SPP under-covers (because Cooksey's
bit-match filter rejects exactly the pointers SPP missed).

This is consistent with a broader pattern seen earlier in the CDP
variant landscape: **additive fusion of orthogonal prefetchers tends
to aggregate noise before aggregating signal.** Hybrid
prefetchers (e.g., Pythia, Bera et al.) use reinforcement-learning-
based selection between prefetcher outputs rather than additive
union, precisely to avoid this.

## Next-step options (ranked)

1. **Cooksey-as-SPP-fallback (Option A from design memo).** Fire
   Cooksey ONLY when SPP's base-depth PT lookup produces zero
   candidates above threshold (i.e. cold PT entry / novel page).
   This avoids the "double-emission" problem and targets the SPP-
   weakness regime specifically. Requires tapping the PT→Calculator
   path to detect zero-candidate cases. Moderate complexity.

2. **Add a useful/useless counter to Cooksey candidates** (like
   H7's kill-switch). Track useful/useless per-candidate-source
   (Cooksey vs SPP) and throttle Cooksey's output based on its
   own accuracy. High complexity, partially recreates H7 inside
   SPPCooksey.

3. **Tighter Cooksey filter (matchBits=27, same-page only).** Simple
   one-line change; would reduce the em3d/perimeter overhead but
   would also reduce Cooksey's already-tiny contribution on
   patricia to probably zero. Probably not worth it.

4. **Add GHR to SPP.** Address SPP's cross-page weakness via the
   paper's own mechanism instead of bolting on Cooksey. This is the
   paper-faithful route; cleaner dissertation narrative. ~100 LOC
   to add to SPP.bsv.

Recommended next direction: **(4) GHR**. If the goal is to show
"SPP correctly implemented approaches H7 on these Olden benches",
GHR is the missing piece from the paper. Bolting Cooksey on top of
SPP is a more novel research direction but the v1 negative finding
shows it needs more sophistication (item 1 or 2) to be worthwhile.
