# Exp 9: decayInterval=256 + highest-conf selection (2026-04-20)

## Change (layered on Exp 7)
Kept `Prefetcher_top.bsv` `Parameter#(256) decayInterval` and additionally
flipped the `pcTableResp` PrefetchIssue selection loop from "last-iterated
above threshold" to "highest-confidence slot above threshold" (tie-breaks
lowest relOffset). Same algorithmic change as Exp 4, but now layered on the
stable-pattern state Exp 7 produces.

## Results

| Bench    | Baseline  | Exp 7 (pure decay=256) | Exp 9 (decay=256 + highConf) | vs baseline | vs Exp 7 |
|----------|----------:|-----------------------:|----------------------------:|------------:|---------:|
| em3d     | 91,334    | 88,331                 | 88,246                      | -3.38%      | -0.10%   |
| health   | 1,370,782 | 1,340,702              | 1,342,254                   | -2.08%      | +0.12%   |
| patricia | 1,403,670 | 1,335,441              | 1,342,074                   | -4.39%      | **+0.50%**   |
| treeadd  | 765,632   | 724,101                | 732,828                     | -4.28%      | **+1.21%**   |
| voronoi  | 219,239   | 213,070                | 213,033                     | -2.83%      | -0.02%   |
| **geomean** | —      | **-3.79%**             | -3.45%                      | —           | **+0.34%** |

## Verdict
**Net regression vs Exp 7.** Treeadd loses 1.2%, patricia loses 0.5%. The
"highest-conf selection" change that looked marginally positive on baseline
(Exp 4) is strictly worse when layered on Exp 7's slow-decay regime.

## Reading
Once decay is slow enough that almost every decision finds a high-conf
pattern, picking the highest-conf slot starts consistently landing on the
saturated conf=7 slots — which aren't actually the most accurate. Low-conf
(recently trained, specific) and high-conf (long-lived, generic) are both
productive. The baseline's "last-iterated above threshold" actually biased
toward recently-seen / negative relOffset patterns, which evidently helped
treeadd and patricia.

## Reverted
`src_Core/RISCY_OOO/coherence/src/prefetcher/CDP.bsv` returned to baseline.
Final working tree: **Prefetcher_top.bsv decayInterval=256, everything else
baseline**.
