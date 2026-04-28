# power-SMALL_INT — CDP fires correctly, working set still fits in LLC

Date: 2026-04-27
Config: CACHE_ALEX_SMALLISH (1MB LLC), power at SMALL_INT_PROBLEM_SIZE
  (4×6×2×3 = 144 leaves, ~9KB working set)
Logs: `/local/scratch/ac2822/NewTooobaLogs/variant{NoPref,H7}_power_smallint_2026-04-27/`

## Goal

The TINY power result (`power_tiny_2026-04-27.md`) showed CDP firing
correctly but with no cycle benefit because the 64-leaf working set
fits entirely in L1 (8KB). Wanted an intermediate size that overflows
L1 to expose more demand misses without exceeding our iteration budget.

## Sizing journey

| config | leaves | work-set | wall clock per config |
|:---|---:|---:|---:|
| TINY (4×4×2×2) | 64 | ~10KB | ~8 min ✓ |
| **SMALL_INT (4×6×2×3)** | **144** | **~9KB** | **~17 min ✓** |
| MEDIUM (6×8×3×4) | 576 | ~35KB | >45 min wall, killed |
| SMALL_PROBLEM_SIZE (8×16×5×10) | 6,400 | ~800KB | >1.5h wall, killed (see `power_runtime_blocker_2026-04-27.md`) |

SMALL_INT is the sweet spot for iteration speed.

## Results

| variant | cycles | Δ |
|:---|---:|---:|
| NoPref-power-SMALL_INT | 4,823,765 | reference |
| H7-power-SMALL_INT | 4,823,192 | **−573, −0.012%** |

## Parser metrics under H7

| metric | value |
|:---|---:|
| demand | 505,239 |
| demandMiss | 2,506 |
| demandMissLL (DRAM) | 190 |
| prefetch issued | 137 |
| prefetchHit (already L1) | 90 (66% redundant) |
| prefetchMiss | 34 |
| **prefetchMissLL (DRAM)** | **0** |
| usefulPrefetch | 29 |
| uselessPrefetch | 5 |

Useful rate: **29 / (29+5) = 85.3%** — high accuracy.

Demand miss op breakdown: 2,096 Ld + 446 St (balanced, unlike
bh/perimeter/tsp's St-dominated profile).

## Interpretation

CDP works correctly on power-SMALL_INT:
- 85% useful rate, only 5 useless prefetches over the run.
- Pointer-chasing pattern (Root → Lateral → Branch → Leaf) is exactly
  what CDP is designed for. All 29 useful events are real wins.

But the working set is still too small for DRAM-bypass:
- ~9KB of node data fits comfortably in 1MB LLC.
- 0 of the 137 issued prefetches go to DRAM (`prefetchMissLL = 0`).
- Each useful prefetch saves only ~10 cyc (LLC→L1 transfer).
- 29 × 10 = ~290 cyc savings, masked by overhead from 5 useless +
  90 redundant prefetches.

## Where this leaves power for the dissertation

Power is a **clean qualitative validation** of CDP's mechanism on a
new pointer-chasing workload, but not a **quantitative**
contribution to the geomean.

Two reasonable framings:

1. **Include as supporting evidence**: power's 85% accuracy at
   SMALL_INT validates that CDP's content-directed scan + matchBits
   filter generalizes across pointer-chasing workloads, even outside
   the original 8-bench Olden subset. The cycle delta is small because
   the working set is small.

2. **Use power-SMALL_INT under TINYLL config** (LLC=128KB) — would
   push the ~9KB working set above LLC, exposing DRAM-bypass material
   for CDP. Same framework as the TINYLL experiment that doubled
   health's gain. Easy follow-up if dissertation needs power-as-DRAM-
   bypass validation.

## Build infra working

The riscv64-unknown-elf-gcc / TORONTO / mcmodel workarounds documented
in `power_tiny_2026-04-27.md` continue to work for power. Other Olden
benches (treeadd, health, em3d) could be similarly resized using the
same recipe if dissertation argumentation needs it.

## Decision

Power excluded from the standing 8-bench iteration set (insufficient
signal at this size). Available as a "validation third-party bench"
data point in the dissertation. Follow-up under TINYLL is one rebuild +
two bench runs (~50 min total) if dissertation needs it.

## Artifacts

- `Tests/benchmarks/Toooba-olden/power/src/power.h`: SMALL_INT and
  MEDIUM ifdefs added; TINY remains.
- `Tests/benchmarks/Toooba-olden/power/Makefile`: `-DSMALL_INT_PROBLEM_SIZE -DTORONTO`
- `Tests/benchmarks/power.bin`: rebuilt at SMALL_INT
- Logs: `/local/scratch/ac2822/NewTooobaLogs/variant{NoPref,H7}_power_smallint_2026-04-27/`
