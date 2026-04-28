# power benchmark — runtime blocker, abandoned this iteration

Date: 2026-04-27

## Goal

Add Olden's `power` benchmark to the bench suite. Power is structurally
pointer-chasing — nested linked lists Root → Lateral → Branch → Leaf
with `next_lateral`, `next_branch` pointers — a relevant data point for
content-directed prefetching.

## What we tried

1. Removed `power.bin` from `Tests/Run_benchmarks.py` exclude_list.
2. Confirmed `power.bin` exists in `Tests/benchmarks/` (Apr 9 build).
3. Confirmed Makefile already has `-DSMALL_PROBLEM_SIZE` (NUM_FEEDERS=8,
   LATERALS_PER_FEEDER=16, BRANCHES_PER_LATERAL=5, LEAVES_PER_BRANCH=10
   ≈ 6,400 leaves; total working set ~800KB-1MB).
4. Built NoPref simulator (DATA_PREFETCHER_LOCATION=NONE).
5. Started bench at 16:42.

## Result

- 1h 37m wall clock at 99.9% CPU steady — process making progress, no
  crash, no fabric error.
- Log file 0 bytes (Bluesim only flushes on exit; tohost not yet hit).
- Killed at 18:20 with `pkill -9 -f bluetcl`.

## Why this is a blocker for the iteration cycle

Each NoPref/H7/STRIDE/etc. config requires its own simulator binary.
Power as currently built takes >1.5h per config. To bench all current
variants (NoPref2 + H7 + STRIDE) on power would require 3 × ~1.5h ≈
4.5 hours of dedicated wall-clock time, with no other variant work
possible during that window (the simulator binary is single-instance).

Realistically: ~10-12h would be needed to add power to all already-run
variants in the catalog. Not feasible at this stage.

## Why scaling power down further is non-trivial

Could in principle add a `TINY_PROBLEM_SIZE` ifdef in `power.h` with
NUM_FEEDERS=4, LATERALS_PER_FEEDER=8, etc. But rebuilding `power.bin`
requires the cross-compile toolchain. Earlier attempts to rebuild
benchmarks (em3d grow, treeadd grow) hit:
- `riscv64-elf-gcc` vs `riscv64-unknown-elf-gcc` naming mismatch (fixable)
- `cm/cmmd.h` missing → `-DTORONTO` workaround (fixable)
- `R_RISCV_HI20 relocation truncated to fit` — linker code-model issue,
  unresolved blocker

So shrinking power requires fixing the linker code-model issue first,
which is a separate effort.

## Decision

Power excluded from the dissertation bench set. Documented in the
exclude_list comment with pointer to this memo. Previous student's
note in `ThingsToTry.txt:38` ("perimeter, treeadd and power are timing
out. This is done") was correct for perimeter and treeadd post-fix,
but power's runtime remains prohibitive at this Toooba/CACHE_ALEX_SMALLISH
configuration even with `-DSMALL_PROBLEM_SIZE`.

For the dissertation, the 8-bench suite (bh, bisort, em3d, health,
patricia, perimeter, treeadd, tsp) is the standing comparison set.

## Future work (if power coverage is dissertation-required)

1. Resolve the `R_RISCV_HI20 relocation truncated` linker model issue —
   probably switch from `-mcmodel=medany` to `-mcmodel=medium` or use
   a different linker script.
2. Add `-DTINY_PROBLEM_SIZE` to power.h with NUM_FEEDERS=4,
   LATERALS_PER_FEEDER=8, BRANCHES_PER_LATERAL=3, LEAVES_PER_BRANCH=6
   (≈576 leaves, ~70KB working set).
3. Rebuild `power.bin`, expect <30 min wall clock per config.
4. Bench against all variants in the catalog.

## Artifacts

- exclude_list reverted to standard 8-bench (with power.bin excluded again).
- This memo.
