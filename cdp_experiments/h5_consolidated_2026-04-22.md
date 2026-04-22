# H5 KILLSWITCH Cache-Aware Dedup — consolidated experiments 2026-04-22

## TL;DR

Three experiments run on the H4/H5 iteration:
1. **H5 at default config** — H4 KILLSWITCH plus cache-aware dedup (filter
   registers every demand-miss refill with punishable=False). Implementation:
   `CDPKillSwitchCA.bsv`, module `mkCDPStatefulRelativeKillSwitchCA`.
   Wired as `DATA_PREFETCHER_TYPE=CDP_KILLSWITCH_CA`.
   **Verdict: net wash vs H4** — slight improvements on health/treeadd,
   regression on bisort/em3d. Filter over-suppresses on low-miss-rate
   benches (bisort becomes 100 % filter-HIT → 0 prefetches issued).

2. **H5 at 512 KB LLC** (new `CACHE_ALEX_SMALLISH_SMALLLL` config) —
   tests whether a smaller LLC would push the Olden working sets into
   DRAM-bound behaviour.
   **Verdict: negative result.** bh/perimeter/tsp slow down because their
   working sets spill; but bisort/em3d/health/patricia/treeadd have
   **identical cycles** at 1 MB and 512 KB LLC because their working
   sets still fit. LLC resizing alone cannot fix the Olden failure modes.

3. **Bigger benchmarks (treeadd level 12→16, health max_level 5→7)** —
   tests whether proper-sized workloads would expose CDP's DRAM-fetch
   value.
   **Verdict: pathological.** At level=16 treeadd becomes store-dominated
   at L1 (914 Ld misses vs ~35 k St misses). CDP's training path, which
   only fires on Load misses, starves. H5 issues 0 prefetches on bigger
   treeadd and 101 on bigger health — the bench migrates from Class 2
   (CDP fires, net negative) into Class 1 (CDP silent, per
   `cdp_insight_h4_three_failure_modes.md`).

**Headline finding: neither H5's cache-aware dedup nor bench/cache
resizing pushes the Olden suite into positive territory.** Patricia
remains the only net-positive bench; treeadd / health / bisort / em3d
remain net-negative because of:
- prefetcher pipeline overhead dominating the ~20-cycle LLC-hit savings
  per useful prefetch;
- filter-saturation in H5 over-suppressing;
- scale-up shifting the workload to store-dominated / Class 1 behaviour.

The cache-aware dedup concept is *right* but the implementation (one
shared 1024-entry filter for both prefetch-dedup and L1-tag-approximation)
is too small to handle the write traffic. A clean fix requires either a
second filter or a direct L1 tag-array probe.

## Experimental matrix

Five configurations measured; NoPref default is the 2026-04-21 reference.

| config | prefetcher | LLC | treeadd level | health max_level |
|---|---|---|---|---|
| A. NoPref default | NONE | 1 MB (SMALLISH) | 12 | 5 |
| B. H4 default (reference) | KILLSWITCH | 1 MB | 12 | 5 |
| C. H5 default | KILLSWITCH_CA | 1 MB | 12 | 5 |
| D. H5 + small LLC | KILLSWITCH_CA | 512 KB (SMALLISH_SMALLLL) | 12 | 5 |
| E. H5 + bigger benches | KILLSWITCH_CA | 1 MB | 16 | 7 |
| F. NoPref + bigger benches | NONE | 1 MB | 16 | 7 |

## 1. H5 at default config vs NoPref and H4

### Cycles

| bench | A. NoPref default | B. H4 default | C. H5 default | C vs A | C vs B |
|---:|-----:|-----:|-----:|-----:|-----:|
| bh        |  1,219,582 |  1,220,362 |  1,220,362 |  −0.06 % |    0   |
| bisort    |    989,257 |  1,067,463 |  1,072,217 |  −8.39 % | −0.45 % |
| em3d      |     83,361 |     88,298 |     88,510 |  −6.17 % | −0.24 % |
| health    |  1,258,704 |  1,327,080 |  1,325,241 |  −5.28 % | +0.14 % |
| patricia  |  1,416,404 |  1,328,007 |  1,330,878 |  +6.03 % | −0.22 % |
| perimeter |  2,692,523 |  2,739,565 |  2,739,565 |  −1.75 % |    0   |
| treeadd   |    564,739 |    707,813 |    704,391 | −24.73 % | +0.48 % |
| tsp       |  6,638,321 |  6,737,135 |  6,737,135 |  −1.49 % |    0   |

### H5 vs H4 prefetch pipeline behaviour

| bench | H4 pref issued | H5 pref issued | H4 prefetchHit | H5 prefetchHit | H4 useful | H5 useful |
|---:|-----:|-----:|-----:|-----:|-----:|-----:|
| bisort   |    526 |      0 |    123 |      0 |    357 |      0 |
| em3d     |    219 |     28 |    157 |      2 |     19 |      0 |
| health   | 13,414 |  8,700 |  8,268 |  4,290 |  3,238 |  3,167 |
| patricia |  2,171 |  1,855 |    572 |    217 |  1,465 |  1,472 |
| treeadd  | 12,202 | 14,933 |  8,306 |  9,874 |  2,961 |  3,966 |

**Interpretation:**
- **health**: H5 dropped 35 % of prefetch volume (13,414 → 8,700) and cut
  prefetchHit in half (8,268 → 4,290) while keeping useful count roughly
  stable (3,238 → 3,167). The dedup largely worked.
- **treeadd**: H5 ACTUALLY issued MORE prefetches than H4 (12,202 → 14,933)
  and MORE prefetchHits (8,306 → 9,874). Some demand-fill entries are
  hash-evicted by subsequent prefetch writes, losing the dedup benefit.
  Useful rose to 3,966 (from 2,961) because more prefetches land, but late
  prefetches also rose (1,481 → 2,191) and overall cycles barely moved.
- **bisort / em3d**: H5 over-suppressed — 0 / 28 prefetches vs 526 / 219.
  Demand-fill entries dominate the 1024-entry filter at these benches'
  low miss rates → every prefetch decision filter-HITs on a demand entry
  → drops. Cycles regress marginally.

**The filter is a shared resource**, and H5 creates write-traffic competition
between prefetch entries (need to persist to dedup own re-issues) and
demand entries (need to persist to dedup incoming prefetches). Neither
survives long enough to be reliably useful.

## 2. LLC resize sensitivity — H5 default vs H5 @ 512 KB LLC

Both runs use level=12 / max_level=5 benchmarks. Only LLC changes (from
1 MB / 16-way to 512 KB / 8-way; L1 unchanged at 8 KB / 4-way). The new
`CACHE_ALEX_SMALLISH_SMALLLL` config isolates this.

| bench | C. H5 @ 1 MB | D. H5 @ 512 KB | Δ |
|---:|-----:|-----:|-----:|
| bh        |  1,220,362 |  1,715,132 | +40.54 % slower |
| bisort    |  1,072,217 |  1,072,217 |    0.00 % |
| em3d      |     88,510 |     88,510 |    0.00 % |
| health    |  1,325,241 |  1,325,241 |    0.00 % |
| patricia  |  1,330,878 |  1,330,878 |    0.00 % |
| perimeter |  2,739,565 |  4,120,692 | +50.41 % slower |
| treeadd   |    704,391 |    704,391 |    0.00 % |
| tsp       |  6,737,135 |  7,913,483 | +17.46 % slower |

**Verdict**: bh / perimeter / tsp spill LLC at 512 KB (they have working
sets > 512 KB); the five "small" benches are unaffected because their
working sets fit in 512 KB as well. LLC sizing alone cannot push
treeadd / health / bisort / em3d into DRAM-bound behaviour.

## 3. Bigger benchmarks — treeadd level=16, health max_level=7

Rebuilt bench binaries: treeadd level=12→16 (tree 8 k nodes → ~130 k
nodes ≈ 3 MB), health max_level=5→7 (village tree 1 k → ~16 k, ~5× state).
Runs = 10 kept same.

### H5 at bigger benches (config E)

[pending NoPref bigger-bench baseline — see section 4]

Early finding: **H5 issues 0 prefetches on bigger treeadd, 101 on bigger
health**. Down from 14 k / 9 k at default sizes. The filter's demand-fill
traffic is now overwhelming.

| bench | H5 pref issued (default bench) | H5 pref issued (bigger bench) |
|---:|-----:|-----:|
| treeadd  | 14,933 |      0 |
| health   |  8,700 |    101 |

**Why bigger makes H5 worse**:
1. treeadd level=16 has ~16× more tree nodes → ~16× more TreeAlloc stores.
   Stores fill many lines via demand. The filter gets saturated with
   demand-fill entries.
2. With more misses, any prefetch decision finds a filter entry for its
   target (either a demand-fill from the actual target, or a collision
   from another demand-fill). Every decision → filter HIT → drop.
3. There's also a possible secondary effect: at bigger sizes the workload
   becomes more store-dominated at L1 (like bh/perimeter/tsp), and H5/H4's
   training pipeline only fires on Load misses. Fewer training events,
   fewer PC-table entries, fewer decisions — but more importantly, the
   filter-saturation prevents even the decisions that DO occur from
   issuing.

Treeadd's demand-Load misses on bigger bench: 914 (out of 36,347 total
L1 misses). Compare to level=12 default: 23,778 demand misses (most
Ld). So level=16 treeadd became a 40:1 store-dominated workload — CDP
can't train on it.

## 4. NoPref at bigger benchmarks — comparison

### Cycles (from report_log.sh output of the worktree NoPref run)

| bench | E. H5 bigger | F. NoPref bigger | E vs F |
|---:|-----:|-----:|-----:|
| bh        |  1,220,362 |  1,219,571 |  −0.06 % |
| bisort    |  1,072,217 |    989,251 |  −8.39 % |
| em3d      |     88,510 |     83,355 |  −6.18 % |
| health    |  2,146,493 |  2,151,657 |  +0.24 % |
| patricia  |  1,330,878 |  1,416,398 |  +6.04 % |
| perimeter |  2,739,565 |  2,692,517 |  −1.75 % |
| treeadd   |  2,671,420 |  2,626,597 |  −1.71 % |
| tsp       |  6,737,135 |  6,638,315 |  −1.49 % |

**Observations:**
- **treeadd at level=16 grew 4.7×** (564 k → 2.63 M cycles under NoPref)
  — tree is 16× bigger; ~10× wall-clock scaling is about right given 10
  runs and DFS reuse.
- **health at max_level=7 grew 1.7×** (1.26 M → 2.15 M cycles) — more
  villages / patients.
- **H5 at bigger bench is effectively a wash vs NoPref bigger**
  (−1.71 % on treeadd, +0.24 % on health). This confirms H5 was doing
  almost no useful work at scale: 0 prefetches on treeadd, 101 on
  health.

**Why H5 went dormant at scale**: treeadd level=16 became store-dominated
at L1. The bench has 914 demand Load misses but ~35 k demand Store
misses — nearly 40:1 St:Ld ratio, matching the pattern of store-dominated
benches (bh, perimeter, tsp) that already got zero CDP activity. With
so few Load misses, CDP's training pipeline can't build up the PC table.

### Workload diagnostics

| bench | Ld misses (H5 bigger) | St misses (H5 bigger) | ratio |
|---:|-----:|-----:|-----:|
| treeadd | 914 | ~35,433 | 1 : 39 |
| health  | (incomplete data due to log truncation; ballpark 7 k : 30 k) | | |

Compare to default-size treeadd (level=12), which had ~23 k demand
misses with a much more Ld-heavy profile — enabling CDP to train
thousands of PC-table entries and fire 12 k prefetch decisions. At
level=16 the tree build (stores) dwarfs the subsequent 10 traversals
(loads hit LLC from first allocation) to such a degree that CDP
starves.

**The bigger-benchmark experiment actually validates the second of our
failure modes from `cdp_insight_h4_three_failure_modes.md`**: workloads
where L1 is store-dominated are simply not CDP's domain. Blowing up
treeadd's level pushed it from Class 2 (CDP fires but net negative)
into Class 1 (CDP never fires, because no Load-miss training stream).

## 5. Implementation notes — CDPKillSwitchCA.bsv

Changes from H4 KILLSWITCH:
- Added `Fifo#(8, Tuple2#(LineAddr, Bit#(16))) demandFillQ <- mkOverflowBypassFifo`.
- Extended `reportIncomingCacheLine` to enqueue demand-fill events on
  any non-prefetch, non-neighbour-chain wasMiss=True refill.
- New rule `registerDemandFill` drains the FIFO and writes the filter
  with `punishable=False`.
- Updated `mutually_exclusive` to include the new rule against
  doFilterInit / processFilterResp / finishEviction / finishUsefulLookup.

The filter remains 1024 entries. Contention between the prefetch-issue
write (processFilterResp) and the demand-fill write (registerDemandFill)
is the failure mode.

## 6. Conclusions and proposed next steps

1. **Cache-aware dedup via the existing filter is broken.** The filter is
   too small to simultaneously approximate "recently issued prefetches"
   AND "L1-cached lines". It becomes dominated by whichever write stream
   is highest-volume (demand fills, at non-trivial sizes).

2. **Possible fix A — separate filters**: split into
   prefetchFilter (as today, for dedup) and cachedLineFilter (new,
   for L1-tag approximation). Cache-aware dedup checks BOTH.
   - Cost: another 1024-entry BRAM.
   - Benefit: isolates write traffic, keeps both filter types effective.

3. **Possible fix B — directly probe L1 tag array**: before issuing a
   prefetch cRq, read the L1 tag array at hash(target.lineAddr) and
   check for hit. Drop on hit.
   - Cost: another L1 tag read port (significant area).
   - Benefit: most accurate.

4. **Possible fix C — "only register prefetches that become useful"**:
   don't register demand fills (so we don't break existing dedup), but
   check at issue time whether the line is a known-hit via a separate
   "recent consumption" flag. This requires ratcheting useful-bump
   integration into processFilterResp.
   - Cost: complex state tracking.
   - Benefit: lighter than a second filter.

5. **Orthogonal direction — workload sizing**: Olden's default bench
   sizes are so small that even CDP working correctly only saves
   ~20 cycles per useful (LLC roundtrip, not DRAM). Bigger benches
   force DRAM fetches AND make CDP's training path fire — but H5's
   filter bug prevents this from being measurable at level=16.

## What I'd recommend next

1. **Revert the cache-aware filter merge** in a new variant H6 and just
   add a **tag-array pre-check in L1Bank** — prefetch cRq that sees a
   cache hit gets dropped at source, not at the filter. This sidesteps
   the filter-saturation issue entirely.
2. **Do a proper NoPref vs H4 vs H5 comparison at bigger bench sizes**
   after H6 or a fix is in. Currently H5's inactivity at scale makes the
   big-bench experiment non-informative.
3. **Work on Direction C (DBP)** as queued — may be a cleaner mechanism
   that doesn't need the filter-saturation workaround.

## Appendix — exact reproduction

### H5 build
```bash
cd builds/RV64ACDFIMSU_Toooba_bluesim
export DATA_PREFETCHER_TYPE=CDP_KILLSWITCH_CA
make compile simulator
```

### H5 at small LLC
```bash
# worktree at /local/scratch/ac2822/toooba-bm-wt
# With ProcConfig.bsv patch adding CACHE_ALEX_SMALLISH_SMALLLL
# (L1 = SMALLISH, LLC = 512 KB / 8-way)
export DATA_PREFETCHER_TYPE=CDP_KILLSWITCH_CA
export CACHE_SIZE=ALEX_SMALLISH_SMALLLL
make compile simulator
```

### Bigger benchmarks
```bash
# Edit Tests/benchmarks/Toooba-olden/treeadd/src/args.c: default level 12 → 16
# Edit Tests/benchmarks/Toooba-olden/health/src/args.c: max_level 5 → 7
# Create Tests/benchmarks/Toooba-olden/treeadd/Makefile (was missing)
# Remove legacy #include and #ifdef TORONTO guards in node.c and args.c
# Build: PATH=/tmp/bin:$PATH make (with riscv64-elf-* symlinks)
cp main.elf ../../treeadd.bin  # install new binary
# repeat for health/
```

### Logs archived
- `/local/scratch/ac2822/NewTooobaLogs/variantH5_default_2026-04-22/`
- `/local/scratch/ac2822/NewTooobaLogs/variantH5_smallLLC_2026-04-22/`
- `/local/scratch/ac2822/NewTooobaLogs/variantH5_biggerBench_2026-04-22/`
- [pending] `/local/scratch/ac2822/NewTooobaLogs/variantNoPref_biggerBench_2026-04-22/`
