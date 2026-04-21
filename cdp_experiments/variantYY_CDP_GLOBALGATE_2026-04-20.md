# Variant YY: global trust-score gate — 2026-04-20

Base: Variant O. Add a signed global score register tracking
`usefulAttrib - uselessAttrib` across ALL PCs. Decision gate: score>=0 issues,
score<0 suppresses (except 1/8 LFSR bleed-through). Score halved every 4096
cycles for freshness.

Motivation: oracle analysis showed +13.27% geomean upper-bound if we could
disable CDP on hostile benchmarks. Per-PC filters cap around +4%; a
system-level auto-disable could theoretically break through.

## Results (vs decay16)

| Bench | L2 | O | YY (this) |
|---|---:|---:|---:|
| em3d | 87,949 | 88,682 | 88,981 |
| health | 1,341,304 | 1,342,511 | 1,343,537 |
| patricia | 1,325,868 | 1,327,159 | 1,329,726 |
| treeadd | 723,118 | 732,836 | 732,836 |
| voronoi | 212,958 | 212,642 | 212,642 |

**Geomean vs decay16: +3.55%** (L2 +4.14%, decay256 +3.52%)

## Gate behaviour (critical finding)

| Bench | ISSUE | BLEED | SUPPRESS | Gate closed? |
|---|---:|---:|---:|---|
| em3d | 918 | 192 | 1,352 | Often (60%) |
| treeadd | 84,394 | 0 | 0 | **Never** |

Em3d's gate closed most of the time (too sensitive in this cold benchmark).
Treeadd's gate NEVER closed — despite its -22% slowdown being the worst case.

## Root cause of the treeadd gate failure

YY's score = `usefulAttrib - uselessAttrib`. But attribution is asymmetric:
- Useful attribution via reportUsefulPrefetch: 100% reliable.
- Useless attribution via reportEviction + attribTable lookup: only 0.5% of
  actual pollution events captured on treeadd, because attribTable is
  hash-overwritten by newer prefetches before the corresponding eviction
  fires (from per-PC deep dive: treeadd PC 9094 has ~4000 pollution events
  but only 21 attributed useless bumps).

So the score on treeadd is `3194 - 98 = +3096` (strongly positive), even
though the actual useful/total ratio is only 22.5% (net pollution).

## Verdict

YY is NOT a win. It inherits the attribution-density bug from the entire
M/N/O/Z family — aggregating a biased signal just preserves the bias.

## Follow-up direction

**Variant IRATIO**: per-PC kill-switch using `issuedCount` (dense, 100%
coverage) as the divisor, not `uselessCount` (sparse). Ratio = useful /
issued. Kill when issued >= 64 AND useful * 10 < issued. Should correctly
identify treeadd PC 9094 (186/4326 = 4.3%) while sparing patricia 84e0
(1304/1341 = 97.2%). Building now.
