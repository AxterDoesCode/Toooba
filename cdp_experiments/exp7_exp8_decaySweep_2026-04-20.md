# Exp 7 / Exp 8: decayInterval sweep 64 → 256 → 1024 (2026-04-20)

## Change
Continuing Exp 6's winning knob. Single-param edit each time.

## Results

| Bench    | Baseline   | Exp 6 (64)  | Exp 7 (256) | Exp 8 (1024) |
|----------|-----------:|------------:|------------:|-------------:|
| em3d     | 91,334     | 89,652      | **88,331**  | 88,782       |
| health   | 1,370,782  | 1,354,471   | **1,340,702** | 1,344,602  |
| patricia | 1,403,670  | 1,344,726   | 1,335,441   | **1,331,059**|
| treeadd  | 765,632    | 735,875     | **724,101** | 730,256      |
| voronoi  | 219,239    | 214,719     | 213,070     | **212,382**  |

Vs baseline (speedup):

| Bench    | Exp 6 Δ%  | Exp 7 Δ%  | Exp 8 Δ%  |
|----------|----------:|----------:|----------:|
| em3d     | -1.84%    | **-3.29%**| -2.79%    |
| health   | -1.19%    | **-2.19%**| -1.91%    |
| patricia | -4.20%    | -4.86%    | **-5.17%**|
| treeadd  | -3.89%    | **-5.42%**| -4.62%    |
| voronoi  | -2.06%    | -2.81%    | **-3.12%**|
| **geomean** | **-2.65%** | **-3.79%** | -3.58%  |

## Verdict
**Exp 7 (decayInterval=256) is the overall winner** (best geomean). Patricia
and voronoi still improve marginally at 1024, but em3d/health/treeadd regress
slightly — we've overshot the knee. **Keeping decayInterval=256** in the
working tree.

## Observations

- Every benchmark benefits from slower decay at least up to 256×.
- The bottom of `noHighConf` drops dramatically at 256: patricia went from
  baseline 31,737 no-high-conf decisions down to 3, treeadd went 9,144 → 194.
  Almost every decision now finds a prefetch candidate above threshold.
- Accuracy stays in the same range — we're NOT trading accuracy for coverage.
  We're just keeping more already-trained patterns alive.
- At 1024, health increased `noHighConf` from 3 (Exp 7) to 119 (Exp 8),
  suggesting some patterns are over-retained and contaminate decisions.

## Still on the table

- Sweep in the 256-1024 range for per-benchmark optima (512, 384, etc.).
- Given Exp 7's win, re-try Exp 4 (highest-conf selection) layered on top —
  now that patterns are stable, the "highest conf" slot is meaningful.
- Consider `decrementBy` (make each decay event subtract 2 instead of 1) to
  reset stale patterns faster while keeping fire frequency low.
