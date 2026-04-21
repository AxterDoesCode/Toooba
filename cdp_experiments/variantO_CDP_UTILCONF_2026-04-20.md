# Variant O: utility-gated confidence — 2026-04-20

Base: Variant M's attribution infrastructure, minus the perceptron. Change:
replace baseline CDP's pattern-recurrence conf counter with a utility-gated
conf:

- Training hit: `conf = max(conf, threshold=1)` (makes pattern eligible, no
  climb)
- Useful-hit attribution: `conf += 1` (saturate at 7)
- Useless-evict attribution: `conf -= 1` (floor at 0)
- Decision: `conf >= threshold` (same as baseline)

Implemented via new `UtilBump` tag in the pcTable read-modify-write pipeline,
so all conf updates serialise through the existing pcTable infrastructure.
Attribution via the 4096-entry attribTable from J (unbiased, no aliasing).

**Motivation:** CDP baseline's conf is a pattern-recurrence counter with no
correlation to actual prefetch utility — saturates at 7 instantly but many
saturated patterns have 8-22% accuracy. O's conf is a true utility score,
with 15,360 distinct (PC, relOff) slots in pcTable (vs M's 256-entry
perceptron that heavily aliases).

## Results (vs decay16 baseline)

| Bench | L2 | M-ppf | N-ppfroute | O (this) |
|---|---:|---:|---:|---:|
| em3d | 87,949 | 88,637 | 88,427 | 88,682 |
| health | 1,341,304 | 1,339,066 | 1,337,554 | 1,342,511 |
| patricia | 1,325,868 | 1,323,869 | 1,321,767 | 1,327,159 |
| treeadd | 723,118 | 732,051 | 732,426 | 732,836 |
| voronoi | 212,958 | 212,189 | 212,189 | 212,642 |

Geomean speedup vs decay16: **+3.68%** (L2 +4.14%, decay256 +3.52%)

## Analysis

Per-bench attribution (issued / useful-bump / useless-bump):

| Bench | issued | useful bump | useless bump | ratio |
|---|---:|---:|---:|---:|
| em3d | 261 | 22 | 18 | 1.22x |
| health | 16,396 | 5125 | 1075 | 4.77x |
| patricia | 2,373 | 1581 | 95 | 16.6x |
| treeadd | 18,085 | 2971 | 98 | 30.3x |
| voronoi | 186 | 27 | 7 | 3.86x |

Attribution ratios look strong (useful >> useless) but cycle counts are
essentially baseline-CDP. Hypothesis: **training hits re-elevate demoted
patterns continuously**. A pattern whose useless attribution pushes conf
to 0 gets a training hit shortly after (training signal is denser than
attribution) and the training rule bumps conf back to threshold=1. Pattern
re-enabled → re-issues prefetch → accumulates more useless events. Oscillation.

## Verdict

O does NOT beat L2. Utility-gated conf alone is insufficient because training
hits keep re-enabling demoted patterns.

## Follow-up

- **Z (conf-graded routing)**: build on O, add graded routing (conf>=2 -> L1,
  conf=1 -> LLC). Tested, +2.07% — LLC-default behavior on patricia ruins
  the benchmark.
- The oscillation issue could be addressed by *removing* training-hit
  promotion once a pattern has any useless attribution — "once demoted,
  stays demoted until proven useful". Worth trying in a follow-up variant
  if the YY direction doesn't work out.
