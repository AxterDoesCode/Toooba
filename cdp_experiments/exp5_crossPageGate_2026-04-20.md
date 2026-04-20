# Exp 5: cross-page-only gate on in-bounds prefetches (2026-04-20)

## Change (layered on Exp 4's highest-conf selection)
In `pcTableResp` PrefetchIssue in-bounds branch, added a guard requiring
`getVpn(candidate) != reqVpn` (cross-page) before enqueuing the TLB request.
Same-page in-bounds candidates are now dropped, logged as "skipped samePage".
Neighbour-line prefetches untouched. Motivated by parser's
`cdpPref_{crossPage,samePage}_{Useful,Useless}` breakdown — except we later
learned those Useful counts were undercounted (see Exp 5 analysis below).

## Results

| Bench | B cycles | E5 cycles | Δ% | B acc% | E5 acc% | B useful | E5 useful | B issued | E5 issued |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| em3d     | 91,334    | 91,136   | -0.22% | 5.7  | 13.8 | 24   | 39   | 418   | 283  |
| health   | 1,370,782 | 1,371,800| +0.07% | 28.7 | 29.3 | 6680 | 5967 | 23274 | 20359|
| patricia | 1,403,670 | 1,432,879| **+2.08%**  | 11.3 | 31.8 | 1762 | 1237 | 15589 | 3889 |
| treeadd  | 765,632   | 754,384  | **-1.47%**  | 16.7 | 8.6  | 3318 | 508  | 19897 | 5892 |
| voronoi  | 219,239   | 220,001  | +0.35% | 16.6 | 25.0 | 56   | 52   | 337   | 208  |

## Verdict
**Mixed**. Treeadd gains the biggest cycle improvement seen across all five
experiments (-1.47%) — dropping same-page prefetches really helps it (its
same-page prefetches were genuinely pollution: -85% issued, but only -85%
useful too, and the cycles improved, meaning cache-pressure relief outweighed
coverage loss).

Patricia LOST ground: -30% useful (1762 → 1237), cycles +2.1%. The parser had
undercounted same-page useful by ~250× for patricia — ~525 "real" useful
same-page prefetches got killed.

## Observations

- The `cdpPref_samePage_Useful` count from the parser is unreliable (parser
  cRq-linking undercounts, and different benchmarks get different undercount
  rates). Do NOT use it as a primary signal to design gating policies.
- Treeadd's pointer walking is dominantly cross-page → same-page gate is ~free.
- Patricia's pointer walking has significant same-page structure → gating hurts.
- Health is essentially indifferent (accuracy +0.6pp, cycles flat).
- Same-page vs cross-page is a **workload-dependent axis** — a fixed gate is
  not portable.

## Cumulative experiments log

| Exp | Change | Patricia | Health   | Em3d   | Treeadd | Voronoi | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| 1 | Useless-prefetch punish                      | +4.5% | +0.01% | -0.3% | +0.1% | +0.1% | negative |
| 2 | confidenceThreshold 1 → 2                    | +6.2% | +0.14% | -1.0% | +0.05%| -0.17%| negative |
| 3 | trainingTableSize 64 → 1024                  | +3.2% | +0.34% | +0.01%| +0.09%| +0.30%| negative |
| 4 | Highest-conf selection                       | +1.2% | -0.23% | +0.01%| -0.02%| +0.23%| marginal |
| 5 | Exp 4 + same-page in-bounds drop             | +2.1% | +0.07% | -0.22%| **-1.47%** | +0.35% | mixed |

Nothing dominates. Patricia is penalized by every tried change — baseline CDP
is already well-tuned for patricia, and any modification that redistributes
coverage costs cycles.

## Recommended next directions (research-level)

- **Per-PC adaptive gating**: track (useful, useless) per PC, only fire
  prefetches for PCs above some accuracy threshold. Requires a per-PC
  histogram, but small (pcTableSize entries × 2 counters).
- **Path-history / global-history signature**: per ThingsToTry plan — use
  hash of last N pcHashes as the PC-table key. Captures *context* rather than
  raw PC identity. Expected to help cases where the same PC visits multiple
  independent data structures.
- **Demand-parallel prefetching**: issue prefetch decisions earlier in the
  pipeline (on PC predict, not miss/hit). Might trim lead-time issues (~3-4%
  prefetches currently arrive late per parser).
- **SPP-style multiplicative confidence + lookahead chaining**: two-level
  prefetching where a high-confidence pattern triggers a second prefetch at
  relative offset from the first. Needs more structure but addresses coverage
  directly.
