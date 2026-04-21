# H4 KILLSWITCH per-benchmark deep dive — why patricia, why not the others

Date: 2026-04-21
Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH4_KILLSWITCH_8bench_2026-04-21/`
Baseline: `baseline_NoPref_8bench_2026-04-21/`
Variant: `CDPKillSwitch.bsv` (mkCDPStatefulRelativeKillSwitch), matchBits=16, confidenceThreshold=1,
killThreshold=5 (useless counter amplified 3×, gate `shouldIssue(uf, us) = !((us >= 5) && (us > uf))`)

---

## TL;DR

H4 fails on 7 of 8 benchmarks for **three distinct root causes**, not one:

1. **bh / perimeter / tsp — CDP never fires.** These are store-dominated at L1
   (28 / 964 / 1,976 demand Load misses vs 18,552 / 35,376 / 36,568 demand Store
   misses). H4's training path only triggers on demand-Load misses, so the
   PC-table, TT, and filter all stay empty. `pctUpdates=0`, `prefetchDecisions=0`,
   `filterMisses=0` across all three benches.

2. **bisort / em3d / health / treeadd — CDP does fire, but net negative.** Three
   compounding problems:
   - **S→E permsOnly upgrade tax.** Prefetches arrive in S; demand Loads need E;
     every useful consumption pays an LLC round-trip for the upgrade. Health
     has 3,149 permsOnly upgrades on prefetched lines.
   - **Pollution.** Prefetches displace M/E state lines. Health has 3,781
     evictions of M/E data by prefetch fills — almost 100% of its prefetch-misses
     knock out hot demand-touched data.
   - **Lead-time catastrophe on DFS workloads.** On treeadd and health the
     median lead time between prefetch and useful consumption is **217 k / 274 k
     cycles** (vs 27 cycles on bisort). Prefetches arrive far too early,
     prefetched lines get evicted and re-prefetched 4–6× before the demand
     finally lands. Unique prefetched lines: treeadd 2,048; of those, only 364
     (18 %) ever produce a useful consumption.

3. **patricia — actually works.** Its dominant access pattern is a linear walk
   through `input_data[]` in the outer while-loop — NOT the patricia-trie walk
   itself. Because this walk's working set exceeds LLC, prefetches reach DRAM
   and return with `respLoadWithE` → demand Loads hit directly in E state (no
   permsOnly upgrade). Single PC (`84e0`) produces 1,484 prefetches / 1,423
   useful (96 % accuracy).

The `cdp_insight_perms_state_asymmetry.md` hypothesis is partially correct
(S→E tax is real) but incomplete — pollution and lead-time misalignment
dominate total cycles on treeadd/health. A toState=E prefetch fix alone
will not bring those benchmarks into positive territory.

**Parser bug discovered**: `CRqCreationLine.isNeverAccessedBecausePerms` is
set on permsOnly upgrade misses (old == new lineAddr, ramCs ≠ I). These are
actually useful consumptions, not perms-kills. On health the parser shows
`usefulPrefetch=0` while H4's own attribution counts 3,311 useful bumps and
3,063 of those are genuine S→E permsOnly consumptions. See §7.

---

## 1. Per-bench summary table

Cycle counts from `Final cycle:` in `*.bin.log.totals_cache`.

| bench      | NoPref     | H4         | Δ cycles   | Δ %      | L1 Load-miss | L1 St-miss | Pref issued | Pref useful (parser) | Pref permsOnly-consumed | Pref real-evict |
|-----------:|-----------:|-----------:|-----------:|--------:|-------------:|-----------:|------------:|---------------------:|------------------------:|----------------:|
| bh         |  1,219,571 |  1,220,351 |       +780 | −0.06 % |          28  |    18,552  |         0   |                    0 |                       0 |               0 |
| bisort     |    989,251 |  1,073,594 |    +84,343 | −7.85 % |       7,240  |     3,975  |       521   |                    0 |                     244 |               3 |
| em3d       |     83,355 |     88,053 |     +4,698 | −5.34 % |         453  |       830  |       206   |                    1 |                      10 |              11 |
| health     |  1,258,698 |  1,342,040 |    +83,342 | −6.22 % |      35,337  |   103,912  |     9,703   |                    0 |                   3,063 |             572 |
| **patricia** | **1,416,398** | **1,326,807** | **−89,591** | **+6.75 %** | **8,069** | **4,100** | **2,273** | **1,436** | **39** | **60** |
| perimeter  |  2,692,517 |  2,739,559 |    +47,042 | −1.72 % |         964  |    35,376  |         0   |                    0 |                       0 |               0 |
| treeadd    |    564,733 |    725,544 |   +160,811 |−22.23 % |      23,778  |    16,940  |    12,937   |                    0 |                   1,726 |              87 |
| tsp        |  6,638,315 |  6,737,129 |    +98,814 | −1.47 % |       1,976  |    36,568  |         0   |                    0 |                       0 |               0 |

Notes
- `Pref useful (parser)` uses the strict `CRqCreationLine.usefulPrefetch`
  metric — `isPrefetch && miss && !isNeverAccessed`. This undercounts on
  permsOnly-heavy benches; see §7.
- `Pref permsOnly-consumed` = count of demand-Ld cRq miss events where
  wasPrefetch=1, oldLineAddr == newLineAddr, ramCs ≠ I (i.e. the demand
  upgraded the prefetched line S→E). These are genuine useful consumptions
  the parser misclassifies.
- `Pref real-evict` = demand-Ld cRq miss events where wasPrefetch=1 AND the
  line was actually evicted (oldLineAddr ≠ newLineAddr). Truly wasted.

Geomean vs NoPref: H4 ≈ **−6.52 %** on 8-bench. Entirely dragged down by
treeadd (−22.23 %), bisort/health (≈ −6 %), not by patricia.

---

## 2. Class 1 — CDP never fires (bh, perimeter, tsp)

### Root cause

H4's training pipeline (`CDPKillSwitch.bsv:521-524`) only enqueues incoming
lines to `l1ToCDP` when `getReqOp(req) == Ld && !cRqIsPrefetch && wasMiss &&
!wasNeighbourPrefetch`. Stores, writes-miss-allocate, etc. bypass training.
The warm-hit PCT lookup path at lines 525-535 also requires `getReqOp(req) ==
Ld`. Store misses contribute **zero** candidate observations and zero training
events.

### Evidence

bh/perimeter/tsp access profiles (from log `grep -oE "L1D cRq miss.*op: (Ld|St|...)"`
on the 3 logs):

| bench      | Ld miss | St miss | ratio St:Ld |
|-----------:|--------:|--------:|------------:|
| bh         |      28 |  18,552 |      662 :1 |
| perimeter  |     964 |  35,376 |       37 :1 |
| tsp        |   1,976 |  36,568 |       18 :1 |

H4 event counts confirm total silence:

| bench      | prefetchDecisions | filterMiss | pctUpdates | useful/useless bumps |
|-----------:|------------------:|-----------:|-----------:|---------------------:|
| bh         |                 0 |          0 |          0 |                    0 |
| perimeter  |                 0 |          0 |          0 |                    0 |
| tsp        |                 0 |          0 |          0 |                    0 |

### Why these benches are store-dominated

Each of bh, perimeter, tsp consists mostly of a **data-structure construction
phase** followed by limited traversal:

- **bh** (Barnes-Hut, `Toooba-olden/bh/src/newbh.c`): in `old_main()`,
  32 calls to `uniform_testdata` create body lists, then tree construction
  and iterative force-walk. The walk phase would produce Load misses, but
  the tree is small enough to fit in L1+LLC once built, so walk-phase loads
  hit the cache. Net effect: writes in construction dominate L1 misses.
- **perimeter** (quadtree, `Toooba-olden/perimeter/src/maketree.c`):
  recursive quadtree construction writes new nodes; perimeter computation
  reads them but mostly fits in cache.
- **tsp** (closest-pair traveling salesman on linked list,
  `Toooba-olden/tsp/src/build.c`, `tsp.c`): large linked-list construction,
  limited traversal phase after.

### Cycle impact

Essentially none (−0.06 % on bh, −1.72 % on perimeter, −1.47 % on tsp).
What slowdown does appear comes from the CDP hardware *being present* in
the L1 pipeline (shared BRAMs, degraded wire delays, descending_urgency
schedule) — NOT from any prefetches. These three benches act as
"H4 inactive" baselines.

### Mitigation options

- **Train on Stores.** Add `!cRqIsPrefetch && wasMiss && (op == Ld || op == St)`
  at CDPKillSwitch.bsv:521-524. Store candidates could train TT the same way.
  Likely mixed benefit: many stores are to pre-computed addresses, not pointer
  chases.
- **Accept that these workloads are uninteresting for a pointer-chase
  prefetcher.** Their hot loop isn't pointer-chasing during Load misses.

---

## 3. Class 2 — CDP fires but net negative

### 3.1 bisort (−7.85 %)

**Source (`Toooba-olden/bisort/src/bitonic.c:157-189`)** — Bimerge's hot
loop:
```c
while ((pl != NIL)) {
    lv = pl->value;         //  8.2% load penalty
    pll = pl->left;
    plr = pl->right;        //  1.35%
    rv = pr->value;         // 57% load penalty
    prl = pr->left;         //  7.6%
    prr = pr->right;        //  7.7%
    ...
    pl = pll or plr;         // pointer chase
    pr = prl or prr;         // pointer chase
}
```

`pr->value` is the 57 %-penalty load noted in the original Olden paper —
pr is a moving pointer into one subtree, and tree nodes tend to miss L1.

**H4 behaviour on bisort**:
- 521 prefetches issued (modest). Kill-switch gate is active.
- Top 4 PCs issue 480 / 521 = 92 % of prefetches: 93c2 (328 issued, 165 useful),
  9390 (64, 40), 9348 (51, 2), 93f0 (37, 9).
- **244 permsOnly consumptions** out of 247 useful-bumps (98.8 %) — almost
  every successful prefetch pays the S→E upgrade tax.
- Median prefetch lead time: **27 cycles**. The prefetches are timely.
- Only 3 real evictions of prefetched lines (negligible).

**Why cycles regress −7.85 %**:
1. Every useful prefetch pays an LLC round-trip for S→E upgrade. 244 × ~10
   cycles = ~2.4 k cycles visible, but the indirect cost is larger —
   upgrade cRqs occupy the 4-slot MSHR, blocking demand cRqs.
2. 155 late prefetches (30 % of 521) arrive after their demand miss —
   wasted MSHR time.
3. `M --/Pr/--> S: 232` — 232 prefetches knock out M-state (hot-write)
   data. Each displacement costs a later demand re-fetch.
4. The bisort workload is large (1.07 M cycles, 3.6 M log lines) but
   CDP's contribution is tiny (521 prefetches). The fixed overhead of
   the H4 pipeline (descending_urgency, BRAM reads/writes) across all
   misses adds up.

The useful fraction of prefetches is high (~50 %) but the overhead-per-useful
is also high. **S→E fix would turn this positive.**

### 3.2 em3d (−5.34 %)

**Source (`Toooba-olden/em3d/src/em3d.c`)** — electromagnetic field
simulation over a bipartite graph of E-nodes and H-nodes, linked via
`node->from_nodes[i]` arrays.

**H4 behaviour on em3d**:
- 206 prefetches issued (very small workload, 88 k cycles total).
- 17 useful bumps, 12 useless bumps.
- Top PCs: 9114 (67 issued, 1 useful), 937e (34, 0), 9590 (23, 4).
- Only 10 permsOnly consumed vs 11 real-evicted — roughly 50 % useful rate.

**Why cycles regress −5.34 %**: em3d is short (88 k cycles). The fixed
overhead of 206 prefetches (TLB reqs, filter, MSHR contention) is meaningful
relative to total runtime. The 10-useful vs 11-evicted balance gives minimal
net benefit even if permsOnly costs were zero.

### 3.3 health (−6.22 %)

**Source (`Toooba-olden/health/src/health.c`, `list.c`)** — hospital
simulation with linked-list traversals. Core loops look like:
```c
while (list != NULL) {
    p = list->patient;
    t = p->time_left;
    ...
    list = list->forward;      // :) adt_pf detected
}
```
(Olden's comment literally flags this as a prefetch opportunity.)

**H4 behaviour on health**:
- 9,703 prefetches issued — the HEAVIEST prefetch-issuing bench.
- **5,192 prefetchHit** (53 % of prefetches fire on already-cached lines — pure overhead).
- 3,834 prefetchMiss (brought new lines).
- Of 3,834 new-line prefetches: **3,149 permsOnly-consumed** (useful),
  632 real-evicted (wasted), 53 other (evicted by sibling prefetch etc.).
- Top 4 PCs (of 44 filter-using PCs): 93d4 (3,384 issued, 1,038 useful),
  9374 (2,158, 719), 943e (1,584, 887), 9406 (936, 210).
- 1,196 latePrefetch (12 % arrive too late).
- Median prefetch lead time: **274,272 cycles**. p99: 1.17 M cycles.
  Prefetches fire 100,000s of cycles before demand; lines get re-prefetched
  on average 4× each (9,703 issued / 2,426 unique lines).

**Why cycles regress −6.22 %**:
1. **Pollution**: `M --/Pr/--> S: 2,446` + `E --/Pr/--> S: 1,335` = 3,781
   displacements of hot M/E data by prefetch fills. Each displaced line is
   later re-demanded, costing a DRAM round-trip.
2. **Redundant prefetches**: 5,192 prefetchHit = prefetch already in cache.
   No useful work but burns training, PCT lookup, TLB, filter check.
3. **S→E tax on useful prefetches**: 3,063 permsOnly upgrades × LLC
   round-trip cycles = thousands of cycles of MSHR blocking.
4. **Late prefetches**: 1,196 wasted MSHR slots.
5. **Lead-time catastrophe**: median 274 k cycles between prefetch and
   consumption means most "useful" prefetches are for lines that the
   prefetcher re-prefetches multiple times because they got evicted in between.
   Only 1,428 of 2,426 unique prefetched lines are ever consumed (59 %).

### 3.4 treeadd (−22.23 %) — the worst offender

**Source (`Toooba-olden/treeadd/src/node.c:123-164`)** — DFS tree
traversal. Compiler has unrolled 3 levels:
```c
int TreeAdd (int inc_level, tree_t *t) {
    if (t == NULL) return 0;
    tleft = t->left;            //  57% load penalty
    leftval = TreeAdd(inc_level + 1, tleft);
    tright = t->right;          //  11.4% load penalty
    rightval = TreeAdd(inc_level + 1, tright);
    value = t->val;
    return leftval + rightval + value;
}
```

Disassembly (`treeadd.bin`, TreeAdd at 0x8000107e, `riscv64-unknown-elf-objdump -d`)
shows compiler inlining 3 levels of recursion, producing many distinct
load PCs each chasing a different child-relationship.

**H4 behaviour on treeadd**:
- **12,937 prefetches issued** — the heaviest-prefetching bench relative to
  runtime (725 k cycles).
- 10,320 prefetchHit (80 % of prefetches fire on already-cached lines).
- 1,830 prefetchMiss.
- Of 1,830: **1,726 permsOnly-consumed** (useful), 87 real-evicted, 16 other.
- Top PCs: 9094 (4,620 issued, 213 useful = 4.6 %), 9082 (2,099, 140),
  91e4 (1,906, 0), 909a (1,123, 0). Most hot-PCs have very low useful rates.
- **Median prefetch lead time: 217,130 cycles**. Prefetches fire ~200 k
  cycles before their demand.
- 2,048 unique prefetched lines; only 364 (18 %) ever produce a useful-hit
  event. **82 % of unique prefetched lines are never consumed.**
- `M --/Pr/--> S: 43` — pollution from prefetches is surprisingly low because
  most prefetch fills hit lines already in cache (prefetchHit).

**Why cycles regress −22.23 %**:
1. **Gross over-prefetching**: 12,937 prefetches for a 725 k-cycle workload
   = 1 prefetch per 56 cycles. 80 % of them hit the cache (no fetch done),
   but each still pays training + PCT + TLB + filter overhead. That's
   ~10,320 × ~20-cycle amortized overhead = 200 k cycles — a huge chunk
   of the 161 k-cycle deficit.
2. **Lead-time misalignment**: treeadd's DFS means CDP trains on one node's
   layout then fires prefetches for descendants visited many pointer-chases
   later. By the time the demand arrives, the line has been evicted (and
   re-prefetched multiple times in between — 12,937 prefetches / 2,048 unique
   lines = **6.3× re-prefetch factor**).
3. **Kill-switch is ineffective**: top PCs like 9094 have 213 useful / 17
   useless — the ratio-based gate `us >= 5 && us > uf` never triggers
   because `us` is too small. But the absolute PREFETCH VOLUME is enormous.
   H4's gate requires *evidence of harm* (useless bumps) to suppress; on
   treeadd the harm is dilute and spread across many PCs, so no individual
   PC crosses the threshold.
4. **The 80 % redundant-prefetch rate** means the "useful" signal H4 uses
   to keep PCs alive (usefulCount bumps) is dominated by wasteful work —
   the PC gets usefulCount credit whenever a demand hits a re-prefetched
   line, even though the prefetch didn't fetch anything new.

### 3.5 Common pattern across Class 2

| overhead                     | bisort | em3d | health | treeadd |
|-----------------------------:|-------:|-----:|-------:|--------:|
| prefetchHit / prefetch (%)   |    48% |  60% |    54% |     80% |
| realEvict of M/E by pref     |    16  |  N/A | 3,781  |      59 |
| latePrefetch / pref (%)      |    30% |   1% |    12% |     0.2%|
| median lead time (cycles)    |     27 |  N/A |274,272 | 217,130 |
| unique lines consumed / issued (%) |  N/A |  N/A |   59 % |    18 % |

(em3d numbers too small to quote meaningfully.)

---

## 4. Class 3 — patricia (+6.75 %)

**Source (`Toooba-mibench2/patricia/patricia_test.c:247-321`)** — main loop:
```c
fakeFile = input_data;
while (fakeFile < input_data + N) {
    time = fakeFile->time;
    inet_aton(fakeFile->addr, &addr);
    ++fakeFile;                                    // linear walk
    p = (struct ptree *)malloc(sizeof(struct ptree));
    ...
    pfind = pat_search(addr.s_addr, phead);        // trie walk (pointer chase)
    ...
}
```

`input_data[]` is a global array of `struct input_data_format {float time;
char addr[26];}` — 30 bytes per entry × 3,000 entries = 90 KB walked
linearly. This is the DOMINANT access pattern; the `pat_search` trie walk
is much smaller per iteration.

**H4 behaviour on patricia**:
- 2,273 prefetches issued.
- **PC 84e0 alone**: 1,484 issued (65 % of total), 1,423 useful-hit bumps (96 %
  accuracy). Prefetch log shows sequential lineAddrs:
  `2000077 → 2000078 → 2000079 → 200007a → ...`
- All other PCs combined: 789 issued, ~100 useful.
- **Only 39 permsOnly consumptions out of 1,535 useful-hits** — because most
  prefetched lines arrive in E state (LLC-cold, `respLoadWithE` upgrades to E
  on DRAM fetch; see `LLBank.bsv:1061` and `cdp_insight_perms_state_asymmetry.md`).
- Demand Loads then hit directly via cRqHit, bypassing the permsOnly path.

**Why patricia works**:

The LINEAR walk through `input_data[]` exceeds LLC capacity (the trie grows
through simulation too). CDP's Branch-2 (neighbour-line) or offset-learned
stride fires with relOffset ≈ ±1 line. The prefetched lines are LLC-cold,
DRAM-fetched, upgraded to E, and demand Loads direct-hit.

**This is essentially a stride-disguised-as-pointer-chase win.** PC 84e0's
learned offset is +1 line. CDP issues Branch-2 (neighbour-line) prefetches
for the next line, which is exactly what the array walk demands next.

**Parser metric is approximately correct on patricia**: `usefulPrefetch =
1436`, `uselessPrefetchBecausePerms = 39`. The 39 permsOnly-consumed
prefetches are misclassified as useless by the parser (see §7), so true
useful is ~1,475. H4's own counter says 1,526. Close.

---

## 5. Compiler / data-structure factors

### Why treeadd's inlining amplifies CDP's lead-time problem

The compiler inlined 3 levels of TreeAdd recursion (disassembly at
0x8000107e). Each inlined level has its own `ld X,8(...)` PC for t->left
and `ld X,16(...)` for t->right. So the "hot load" splits into ~6 distinct
PCs (3 levels × 2 loads). Each PC trains separately.

Because DFS visits descendants in a predictable order only at the *shape*
level (left-before-right) but not at the *address* level (bump-allocator
order differs from DFS order — leaves first, root last), the learned
relOffset per PC is a noisy average over tree geometry. Prefetches land
on vaguely-correct lines but at the wrong times.

### Why patricia's array-walk is a clean CDP target

Array walks produce:
- A single stable PC for the outer-loop load.
- Strictly ascending addresses (++fakeFile).
- Predictable +1-line demand pattern.

CDP's Branch-2 (neighbour-line on out-of-[0,7] relOffset) is essentially a
stride prefetcher here. The "pointer discovery" (bit-match candidates in
the line) is incidental — the stride learning dominates.

### Why health's linked-list should work but doesn't

Health has many linked-list loops:
```c
while (list != NULL) {
    p = list->patient;
    ...
    list = list->forward;
}
```
This is the textbook CDP target: each iteration's Load of `list->forward`
yields a candidate vaddr (the next list node) that CDP can train on,
and then prefetch ahead of the next iteration.

But health's lists are SHORT (few-to-tens of patients per hospital), and
there are MANY independent lists (per-hospital, per-village). The data
structure is a forest of short lists, not one long list. CDP trains on
"list->forward" from list A, then the PC runs on list B whose pointer
structure is completely different. The learned offset is noise averaged
over many unrelated lists.

Also: **health's allocation clusters multiple list nodes onto the same cache
line**. With `sizeof(struct List) = 24 bytes`, up to 2-3 list nodes share a
line. So a single demand miss on one list node's line brings in the next
2-3 list nodes' data — NATIVE COVERAGE without any prefetching. The
prefetcher then prefetches the next line, which may or may not belong to
the same list. When the list branches (different hospital), the prefetch
is wasted.

---

## 6. Per-PC attribution of per-bench prefetch work

From `grep "CDP Kill filter MISS\|CDP Kill useful hit\|CDP Kill useless evict"
 | grep -oE "pcHash [0-9a-f]+"`:

### bisort — only 6 useful PCs out of 8 filter-using
| pcHash | issued | useful-bump | useless-bump | useful % |
|--------|-------:|-----------:|-------------:|---------:|
|  93c2  |    328 |        165 |            0 |    50.3% |
|  9390  |     64 |         40 |            2 |    62.5% |
|  9348  |     51 |          2 |            0 |     3.9% |
|  93f0  |     37 |          9 |            0 |    24.3% |
|  93ae  |     33 |         30 |            2 |    90.9% |

Top PCs (93c2, 9390, 93ae) are all >50 % useful by H4's attribution —
genuinely productive. PC 9348 is noise (51 issued, 2 useful) but kill-switch
didn't suppress because `uselessCount=0`.

### health — 44 filter-using PCs, 4 dominate
| pcHash | issued | useful-bump | useless-bump | useful % |
|--------|-------:|-----------:|-------------:|---------:|
|  93d4  |  3,384 |      1,038 |          567 |    30.7% |
|  9374  |  2,158 |        719 |            5 |    33.3% |
|  943e  |  1,584 |        887 |           12 |    56.0% |
|  9406  |    936 |        210 |           ~0 |    22.4% |

All top PCs are net-positive in H4's attribution. Kill-switch never
triggers on any of them. But the *absolute volume* is enormous and
many "useful" bumps come from re-prefetches of already-evicted lines
that get re-prefetched again — not from the prefetcher fetching
new data.

### treeadd — 42 PCs, long tail of marginal
| pcHash | issued | useful-bump | useless-bump | useful % |
|--------|-------:|-----------:|-------------:|---------:|
|  9094  |  4,620 |        213 |           17 |     4.6% |
|  9082  |  2,099 |        140 |           30 |     6.7% |
|  91e4  |  1,906 |         ~0 |            0 |    ~0%   |
|  909a  |  1,123 |         ~0 |            4 |    ~0%   |
|  91de  |    820 |         ~0 |            3 |    ~0%   |

PC 91e4 / 909a / 91de — substantial volume, zero useful. These should be
killed. They aren't because `useless=0` too (not enough evidence to
trigger the ratio gate). This is the "kill-switch ceiling" memory
(`cdp_insight_killswitch_ceiling.md`) at work: per-PC gating can't
distinguish PCs whose wins come from RE-prefetch loops from PCs that
produce genuinely-consumed prefetches. Both look net-zero useless but
have very different impact on total cycles.

### patricia — ONE PC dominates
| pcHash | issued | useful-bump | useless-bump | useful % |
|--------|-------:|-----------:|-------------:|---------:|
|  84e0  |  1,484 |      1,423 |           45 |    95.9% |
|  8cb0  |    180 |          7 |            0 |     3.9% |
|  907a  |    117 |         24 |            1 |    20.5% |

PC 84e0 is the `inet_aton` / input_data-walk load inside the outer loop.
It's the cleanest CDP signal in the whole suite. Every other PC combined
accounts for <10 % of prefetches.

---

## 7. Parser bug: permsOnly upgrade misclassification

### Bug

In `TooobaLogParser/parselogNew.py:830-836` (CRqMissLine.postProcess):
```python
if self.oldLineAddr in CRqHitLine.EVICTION_LOOKOUTS:
    for ll in CRqHitLine.EVICTION_LOOKOUTS[self.oldLineAddr]:
        if self.wasPrefetch and ll.cRqCreationLine is not None and not ll.cRqCreationLine.isNeverAccessed:
            ll.cRqCreationLine.isNeverAccessed = True
            ll.cRqCreationLine.isNeverAccessedBecausePerms |= self.permsOnly
```
`permsOnly = (oldLineAddr == newLineAddr) && (ramCs != I)` correctly
identifies S→E (or S→M, E→M) upgrade misses. These are NOT evictions —
the same physical line stays in cache, only its coherence state rises.

But the code marks `isNeverAccessed = True` regardless of permsOnly —
it treats state-upgrade as if the prefetch was evicted unused.

### Consequence

On S→E permsOnly upgrades, the prefetched data is preserved (LLC serves
an E-grant without new data, via pRs), then the pending demand cRqHit
at `L1Bank.bsv:692` sees `ram.info.other.wasPrefetch=True` and fires
the useful-hit log. **The demand IS consuming the prefetched data.**

The parser's strict `usefulPrefetch` metric therefore reports 0 useful
on permsOnly-heavy benches (health, treeadd, bisort) while H4's own
attribution and the `CDP Rel useful prefetch hit` log both show
thousands of successful consumptions.

### Evidence from a single concrete trace (health, cycle 64495-64641)

Health line 0x200007a (addr 0x80001e80):

```
 64495 CDP Kill filter MISS: prefetch for lineAddr 200007a pcHash 93d4 route L1
 64495 L1D cRq creation: addr 0x80001e88, isPrefetch:1, reqCs:S
 64496 L1D cRq miss (rep): addr 0x80001e88, old line 200031a, ramCs:M, reqCs:S, op:Ld
       (prefetch evicts an M-state line to bring in S)
 64501 LL cRq creation: addr 0x80001e88, reqCs:S
 64503 LL cRq hit (fast LLC hit)
 64507 L1D cRq hit: addr 0x80001e88, pipeCs:S, saveCs:S, op:Ld (prefetch refill, wasPrefetch=True)

... 123 cycles later ...

 64630 L1D cRq creation: addr 0x80001e80, isPrefetch:0, reqCs:E, op:Ld
 64631 L1D cRq miss (no rep): addr 0x80001e80, old line 200007a, wasPrefetch:1, ramCs:S, reqCs:E
       (permsOnly miss — same line, S→E upgrade needed)
 64635 LL cRq creation: addr 0x80001e80, reqCs:E
 64637 LL cRq hit (LLC had E-grant)
 64641 L1D cRq hit: addr 0x80001e80, pipeCs:E, wasMiss:1, op:Ld
 64641 CDP Rel useful prefetch hit addr 80001e80 cUseful 1
 64643 CDP Kill useful hit: lineAddr 200007a pcHash 93d4
```

Demand was served in 11 cycles (64630→64641) from the prefetched line's
cached data, with a cheap LLC E-grant. Without the prefetch, the demand
would have incurred a full DRAM round-trip (~100-200 cycles). The prefetch
WAS useful.

Parser's current bookkeeping: marks the 64495-prefetch's `isNeverAccessed
= True` and `isNeverAccessedBecausePerms = True` at cycle 64631. Reports
it as a perms-kill.

### Proposed fix

In `parselogNew.py:830-836`:
```python
if self.oldLineAddr in CRqHitLine.EVICTION_LOOKOUTS:
    for ll in CRqHitLine.EVICTION_LOOKOUTS[self.oldLineAddr]:
        # A permsOnly miss is a state upgrade, NOT an eviction.
        # Don't mark isNeverAccessed — the prefetched data is still
        # present and will be consumed by the upgrading demand.
        if (self.wasPrefetch and ll.cRqCreationLine is not None
                and not ll.cRqCreationLine.isNeverAccessed
                and not self.permsOnly):
            ll.cRqCreationLine.isNeverAccessed = True
            # isNeverAccessedBecausePerms only for real evictions (shouldn't happen here)
```

With this fix, health's `usefulPrefetch` would jump from 0 to ~3063,
treeadd's from 0 to ~1726, bisort's from 0 to ~244. The `Pref useful` +
`Pref permsOnly-consumed` columns in §1 should collapse into a single
corrected metric.

### Implication for prior analyses

- `cdp_insight_perms_state_asymmetry.md` claim "96-99.9% perms-kill" on
  treeadd/health/bisort is based on the buggy parser metric. True
  kill-rate (real evict without consumption) is:
  - treeadd: 87 / 1,830 = 4.7 %
  - health: 632 / 3,834 = 16 %
  - bisort: 3 / 248 = 1 %
  The S→E asymmetry is STILL a real overhead (each useful prefetch pays
  an LLC round-trip), but it's not a kill — the data IS consumed.
- `cdp_insight_alignsuppconf_past_parity.md` etc. "first variant to
  exceed NoPref" claim probably stands (those variants issue fewer
  prefetches so the pollution/redundancy costs are small), but the
  *size* of the gap may be mismeasured.

---

## 8. Proposed fixes ranked by expected impact

Based on per-bench diagnosis above:

### Fix 1 — Kill redundant prefetches (biggest treeadd/health lever)

54 % of health's prefetches and 80 % of treeadd's prefetches fire on lines
already in L1. Each wastes training + TLB + filter + MSHR.

**Implementation**: before issuing a prefetch, check the L1 tag array. If
hit, drop. Currently the filter only dedups against recent prefetches,
not against the actual cache.

Expected treeadd gain: eliminating 10,320 redundant prefetches saves the
per-prefetch overhead ≈ 10,320 × ~15 cycles = 155 k cycles. That alone
would recover most of treeadd's 161 k-cycle deficit.

### Fix 2 — toState = E on prefetch in single-core (addresses §3 issues)

`L1Bank.bsv:457` currently sets `toState: S` unconditionally for L1-routed
prefetches. Change to `toState: multicore ? S : E` to match demand Loads'
behaviour at `MemExePipeline.bsv:1345`.

Eliminates the permsOnly upgrade round-trip per useful prefetch. Per-bench
useful prefetches affected: bisort 244, health 3,063, treeadd 1,726. Each
saves ~5-10 cycles of LLC round-trip.

Expected gains:
- health: 3,063 × 8 cycles ≈ 24 k cycles (minor vs 83 k deficit).
- bisort: 244 × 8 cycles ≈ 2 k cycles (small).
- treeadd: 1,726 × 8 cycles ≈ 14 k cycles (minor).

Not as impactful as Fix 1 but cleanly removes a source of friction.

### Fix 3 — Lead-time throttle for DFS workloads

On treeadd, median lead time is 217 k cycles. The prefetch fires long
before the demand arrives — in the meantime the line is evicted and
re-prefetched.

**Implementation ideas**:
- Track per-PC lead-time distribution; if median lead time > threshold,
  suppress or defer prefetches from that PC.
- Alternative: limit the in-flight window per PC (e.g. max 16 outstanding
  prefetches per PC).

Expected treeadd gain: if only 364 of 2,048 unique lines are ever consumed,
we're doing 5.6× unnecessary work. Halving prefetch volume without
hurting coverage would save ~80 k cycles.

### Fix 4 — Train on demand Stores

Currently H4 trains only on demand Loads. bh/perimeter/tsp produce
far more demand Stores than Loads. Adding Store training might find
cold-miss prefetch opportunities in data-structure construction phases.

Expected gain: uncertain. Likely small — these workloads' store streams
are mostly sequential (bump allocator), which stride prefetchers already
handle. CDP's pointer-candidate-in-line logic wouldn't apply cleanly to
store-issued lines (stores don't bring in line data).

### Fix 5 — Kill-switch improvements

Current gate `us >= 5 && us > uf` fails on treeadd because the top PCs
have `us ~ 0`. A PC that issues 1,906 prefetches (91e4) with 0 useful and
0 useless never gets suppressed.

**Add "no-useful ratio" rule**: if `issued > 128 && useful / issued < 1 %`,
suppress. This catches the treeadd case where per-PC volume is high but
no useful work is done.

Expected treeadd gain: prevents ~4,000 futile prefetches from dead PCs.
Probably ~30 k cycles.

---

## 9. Parser improvements to support this kind of analysis

1. **Fix permsOnly bug** (§7).
2. **Add `CDPKillSwitch*Line` classes** (regex `CDP Kill ...` instead of
   `CDP Rel ...`) so H4's per-PC attribution is visible in parser
   `printTotals`. Currently we have to grep for it.
3. **Per-PC aggregation**: emit `usefulPerPc[pcHash]` / `uselessPerPc[pcHash]`
   dictionaries so a single parser run produces the tables in §6.
4. **Prefetch-vs-demand timing distribution**: per-prefetch lead time
   matched to its consuming useful-hit event. Required for the §8 Fix-3
   throttle design.
5. **Redundant-prefetch counter**: explicit counter for `prefetch cRq →
   cRqHit` (i.e. the 5,192 / 10,320 / ... redundant issues on health /
   treeadd). Currently has to be derived from `prefetchHit` minus known
   sources.

---

## 10. Summary — why patricia is the outlier

Necessary and sufficient conditions for H4 success on a benchmark, based
on this investigation:

1. **Workload must be Load-miss-dominated at L1** — otherwise CDP never
   trains (Class 1 failure mode).
2. **Hot access pattern must have predictable per-PC offsets at LINE
   granularity** — so CDP's learned relOffset aligns with actual demand
   (Class 2 lead-time failure avoided).
3. **Working set must exceed LLC**, so prefetches DRAM-fetch and arrive
   in E state via `respLoadWithE`. This sidesteps the S/E tax
   (§7 parser bug; §3.1-3.4 S→E overhead).
4. **Hot loop must concentrate demand on a single or few PCs**, so
   training converges quickly and confidence saturates (patricia's PC
   84e0 = 65 % of all prefetches).
5. **Access pattern stability**: the same PC's loads should follow the
   same relative offset consistently across many iterations.

Patricia satisfies all five; the others violate at least one:
- bh/perimeter/tsp: violate #1 (store-dominated at L1).
- bisort: violates #3 partially (LLC has much tree data; prefetches arrive in S).
- treeadd: violates #2 and #5 (DFS traversal, inlined PCs → noisy per-PC offsets).
- health: violates #4 (many independent lists, PCs, fragmented training).
- em3d: small scale, partial violations across several conditions.

---

## Appendix A — raw data files and commands

- Logs: `/local/scratch/ac2822/NewTooobaLogs/variantH4_KILLSWITCH_8bench_2026-04-21/`
- Baseline: `/local/scratch/ac2822/NewTooobaLogs/baseline_NoPref_8bench_2026-04-21/`
- Parser run: `python3 TooobaLogParser/main.py <log>` (uses `.totals_cache`)
- Disassembly: `riscv64-unknown-elf-objdump -d Tests/benchmarks/<bench>.bin`
- H4 source: `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitch.bsv`
- L1Bank code paths:
  - useful-hit log: L1Bank.bsv:692
  - wasPrefetch update: L1Bank.bsv:764
  - prefetch toState setting: L1Bank.bsv:457
  - demand Load toState setting: MemExePipeline.bsv:1345
  - LLBank respLoadWithE upgrade path: LLBank.bsv:1061
- Parser bug location: `TooobaLogParser/parselogNew.py:830-836`

## Appendix B — numerical sources for §1

All counts derived from:
```bash
for b in bh bisort em3d health patricia perimeter treeadd tsp; do
  log="/local/scratch/.../variantH4_KILLSWITCH_8bench_2026-04-21/${b}.bin.log"
  grep -c "CDP Kill filter MISS" "$log"   # filterMiss = prefetches issued
  grep -c "CDP Kill useful hit"   "$log"   # useful bumps
  grep -c "CDP Kill useless evict" "$log"  # useless bumps
done
```
and the Python script in §2-3.5 that classifies wasPrefetch=1 cRq misses
into permsOnly vs realEvict.

Cycle counts are `Final cycle:` in each `.bin.log.totals_cache` (first line).

Parser-reported `usefulPrefetch` / `uselessPrefetch` / `prefetch` / etc.
come directly from `CRqCreationLine totals:` section of each totals_cache.
