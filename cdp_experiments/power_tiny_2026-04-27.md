# power benchmark — TINY_PROBLEM_SIZE rebuild + first NoPref/H7 comparison

Date: 2026-04-27

## What we did

1. Added `TINY_PROBLEM_SIZE` ifdef to `Toooba-olden/power/src/power.h`:
   `NUM_FEEDERS=4, LATERALS_PER_FEEDER=4, BRANCHES_PER_LATERAL=2, LEAVES_PER_BRANCH=2`
   → 64 leaves total (vs 6,400 at SMALL_PROBLEM_SIZE).
2. Edited `Toooba-olden/power/Makefile`: `CFLAGS += -DTINY_PROBLEM_SIZE -DTORONTO`
   (the `-DTORONTO` skips the host-only `cm/cmmd.h` includes).
3. Cross-compiled with `make CC=riscv64-unknown-elf-gcc LD=...` overrides
   to fix the toolchain naming mismatch from `riscv64-elf-gcc` to the
   Ubuntu package's `riscv64-unknown-elf-gcc`.
4. Build succeeded — no `R_RISCV_HI20 relocation truncated` issue at this
   workload size.
5. Replaced `Tests/benchmarks/power.bin` with the new ELF (18KB).

## Cycle results

| variant | power cycles | Δ | % |
|:---|---:|---:|---:|
| NoPref-TINY | 2,304,694 | reference | — |
| H7-TINY     | 2,304,674 | **−20** | **−0.0009%** |

Essentially identical — CDP cannot help here.

## Why CDP doesn't help on power-TINY

Parser metrics under H7-TINY:

| metric | count |
|:---|---:|
| demand | 256,169 |
| demandMiss | 340 |
| demandMissLL (DRAM) | 120 |
| prefetch issued | 83 |
| prefetchHit (already in L1) | 78 (94%) |
| prefetchMiss | 5 |
| prefetchMissLL | **0** |
| usefulPrefetch | 5 |
| uselessPrefetch | 0 |

CDP fires correctly — 8,811 CDP log lines, 5 useful prefetches with 0
useless. But the workload is too small:
- 256k demand accesses with only 340 misses (0.13% miss rate)
- 94% of prefetches are redundant (target line already in L1)
- 0 prefetches went to DRAM
- Net 5 useful × ~10 cyc LLC-saving = ~50 cyc benefit, masked by
  pipeline overhead from the 78 prefetchHits

**Power's 64-leaf working set fits entirely in L1 (8KB).** Not memory-
bound at this scale.

## Demand-miss op breakdown

Unlike bh/perimeter/tsp which were 95-99% St-miss-dominated, power-TINY
is **balanced**: 173 Ld misses, 172 St misses. So CDP gets fair training
input — it just doesn't have enough material to prefetch usefully.

## Where this leaves power for the dissertation

Two reasonable framings:

1. **Document power-TINY as supporting evidence** that CDP fires
   correctly on additional pointer-chasing benchmarks but gains scale
   with workload memory pressure (consistent with the LLC-shrink finding:
   CDP value tracks DRAM-miss volume, not the algorithmic class alone).

2. **Try an intermediate power size** (e.g., NUM_FEEDERS=6,
   LATERALS_PER_FEEDER=8, BRANCHES_PER_LATERAL=3, LEAVES_PER_BRANCH=4 →
   576 leaves, ~120KB working set) so the bench overflows L1 but still
   fits in the 30-min wall-clock budget. Build infrastructure now works
   for power, so this is a small follow-up.

The full SMALL_PROBLEM_SIZE setting (6,400 leaves) ran >1.5h wall clock
per config — see `power_runtime_blocker_2026-04-27.md`.

## Build infra fix that was needed

The previous student had `riscv64-elf-gcc` in `Toooba-olden/Makefile.mk`
but the Ubuntu install ships `riscv64-unknown-elf-gcc`. Workaround: pass
`CC=riscv64-unknown-elf-gcc LD=... OBJDUMP=... OBJCOPY=...` on the make
command line. This overrides the `:=` immediate assignment in
Makefile.mk. The other olden benches we never tried to rebuild on the
current box, so they may all need the same workaround if reshaped.

## Artifacts

- `Tests/benchmarks/Toooba-olden/power/src/power.h` — added TINY ifdef
- `Tests/benchmarks/Toooba-olden/power/Makefile` — switched to TINY+TORONTO
- `Tests/benchmarks/power.bin` — rebuilt at TINY size
- Logs: `/local/scratch/ac2822/NewTooobaLogs/variant{NoPref,H7}_power_tiny_2026-04-27/`
- exclude_list will be restored to standard 8-bench (with power.bin
  excluded — power-TINY doesn't show CDP value, no point including it
  in the standing iteration set)
