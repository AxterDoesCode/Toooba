# CDP prefetcher experiment log (2026-04-19 → 2026-04-20)

Iteration log for `mkCDPStatefulRelative` on the `ac2822CDPDeepDive` branch.
Baseline = the checked-in CDP mechanism at the start of 2026-04-19. See
`baseline_2026-04-19.md` for the initial metrics.

## Experiments — Exp 7 is the final winner

| Exp | One-line change | Pat | Health | Em3d | Treeadd | Voronoi | geomean |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | Useless-prefetch eviction → punish PC table slot      | +4.5% | 0 | -0.3% | 0 | 0 | +1.0% |
| 2 | confidenceThreshold 1 → 2                             | +6.2% | 0 | -1.0% | 0 | 0 | +1.0% |
| 3 | trainingTableSize 64 → 1024                           | +3.2% | 0 | 0     | 0 | 0 | +0.7% |
| 4 | Highest-conf offset select                            | +1.2% | -0.2% | 0 | 0 | 0 | +0.2% |
| 5 | Exp 4 + same-page in-bounds gate                      | +2.1% | 0 | -0.2% | **-1.5%** | 0 | +0.2% |
| 6 | decayInterval 16 → 64                                 | -4.2% | -1.2% | -1.8% | -3.9% | -2.1% | -2.65% |
| **7** | **decayInterval 16 → 256**                        | **-4.9%** | **-2.2%** | **-3.3%** | **-5.4%** | **-2.8%** | **-3.79%** |
| 8 | decayInterval 16 → 1024                               | -5.2% | -1.9% | -2.8% | -4.6% | -3.1% | -3.58% |
| 9 | Exp 7 + highest-conf selection                        | -4.4% | -2.1% | -3.4% | -4.3% | -2.8% | -3.45% |

**Final working tree:** single edit in `Prefetcher_top.bsv` — `decayInterval = 256`
(was 16). Nothing else changed in CDP.bsv. Universal win across every benchmark.
Geomean speedup **3.79% vs baseline**.

## Infrastructure changes kept (non-experimental)

- `src_Core/RISCY_OOO/coherence/src/L1Bank.bsv` — added `usefulPrefetchCnt`
  register and the `"AlexLog: CDP Rel useful prefetch hit ..."` emit that
  `CDPUsefulPrefetchLine` in the parser was expecting but that wasn't being
  produced by any BSV code.
- `Tests/Run_benchmarks.py` — narrowed `exclude_list` so only the five
  pointer-chasing benchmarks run (treeadd, health, em3d, voronoi, patricia).
- `TooobaLogParser` submodule — added Direct-path per-conf attribution
  (`usefulPrefetchesAtConfN_Direct`, `usefulPrefetchesUnattributed_Direct`)
  via a lineAddr lookout on `CDPFilterMissLine`, bypassing the fragile
  cRq-creation linking that undercounted useful hits by 2-100× depending on
  benchmark. This uncovered a prior analytical error (see below).
- `cdp_experiments/summarize_logs.sh` — grep-based quick summary.
- `cdp_experiments/parse_summary.sh` — parselogNew-driven summary with
  per-conf useful/useless breakdown.

## Key learnings

1. **Patricia is coverage-sensitive, not accuracy-sensitive.** Baseline CDP
   is already productive for patricia. Every change that tightened precision,
   re-selected offsets, grew tables, or filtered same-page reduced useful
   prefetches → patricia slower. Don't design patricia-aware experiments
   that reduce coverage.

2. **Cross-page vs same-page accuracy is workload-dependent, not universal.**
   Treeadd's same-page prefetches are pollution (dropping them = -1.47%
   cycles); patricia's are useful (dropping them = +2.1% cycles). Any
   one-size-fits-all gate on this axis will hurt some workload. Adaptive
   per-PC gating is a better direction.

3. **Saturated confidence is NOT the noise signal it first appeared to be.**
   The parser's cRq-creation linking path had a systematic undercount at
   high conf (because redundant prefetches hit in L1 and weren't scored as
   useful). The Direct-attribution path shows conf=7 is ~43% accurate for
   patricia and ~44-50% for health/treeadd — roughly comparable to lower
   conf levels. See `/home/ac2822/.claude/projects/.../memory/cdp_insight_conf_saturation.md`.

4. **Parser pitfalls**: always verify that a derived counter agrees with the
   raw log-line count before acting on it. Example: `cdpUsefulAtConfN`
   (linking-based) summed to ~12% of `usefulPrefetches` (raw count) for
   patricia → treat linking-based breakdowns as a LOWER bound, not as truth.

## Suggested next directions (not yet tried)

- **Path-history / global-history signature as PC-table key** (per ThingsToTry
  TODO line 136) — captures *context*, not raw PC.
- **Per-PC adaptive gating**: (useful, useless) counters per PC, only issue
  when accuracy > X%.
- **SPP-style multiplicative confidence + lookahead chaining**.
- **Lead-time reduction**: 3-4% of prefetches arrive late per parser — earlier
  issue could convert to useful.
- **Multi-offset issue**, but implemented WITHOUT the Ehr pattern that caused
  bsc elaboration to hang (try a FIFO-backed `secondIssueQ`).

## Archive locations

Benchmark logs saved at `/local/scratch/ac2822/NewTooobaLogs/`:
- `exp3_TT1024_2026-04-20/` — trainingTableSize=1024 run
- `exp4_highestConf_2026-04-20/` — highest-conf selection run
- `exp5_crossPageGate_2026-04-20/` — Exp4 + same-page drop run
