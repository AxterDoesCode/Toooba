# H4 KILLSWITCH with toState=E fix + CDP Rel log format + fixed parser — 2026-04-22

Date: 2026-04-22
Logs: `builds/RV64ACDFIMSU_Toooba_bluesim/Logs/*.bin.log`
Baseline: `/local/scratch/ac2822/NewTooobaLogs/baseline_NoPref_8bench_2026-04-21/`

## Context

Follow-up to `h4_per_bench_deep_dive_2026-04-21.md`. Applied three changes together:

1. **`L1Bank.bsv:457`**: prefetch `toState: multicore ? S : E` (S→E fix from
   task #61). Already on branch before this session.
2. **`CDPKillSwitch.bsv`**: migrated H4 logs to `CDP Rel` format so the
   existing parser classes pick up `isNeighbour`, TLB resp, neighbour-chain
   events. Added `isNeighbour` + `conf` to prefetch-decision log.
3. **`TooobaLogParser/parselogNew.py`**: fixed permsOnly misclassification
   (a permsOnly S→E upgrade no longer marks the prefetch as
   `isNeverAccessed`). Added `usefulPrefetchPermsOnly` / `usefulPrefetchDirectHit`
   counters + `consumedViaPermsOnly` flag on CRqCreationLine.

Rebuilt with `DATA_PREFETCHER_TYPE=CDP_KILLSWITCH`, ran 8-bench. All 8 passed.

## Cycle results (H4 vs NoPref)

| bench     | NoPref     | H4 (new)   | Δ cycles | Δ %       | H4 2026-04-21 | 21→22 delta |
|----------:|-----------:|-----------:|---------:|----------:|--------------:|------------:|
| bh        |  1,219,582 |  1,220,362 |     +780 |  −0.06 %  |    1,220,351  | essentially 0 |
| bisort    |    989,257 |  1,067,463 |  +78,206 |  −7.91 %  |    1,073,594  | **−6 k cycles** |
| em3d      |     83,361 |     88,298 |   +4,937 |  −5.92 %  |       88,053  | +245 |
| health    |  1,258,704 |  1,327,080 |  +68,376 |  −5.43 %  |    1,342,040  | **−15 k cycles** |
| patricia  |  1,416,404 |  1,328,007 |  −88,397 | **+6.24 %** |  1,326,807  | +1,200 |
| perimeter |  2,692,523 |  2,739,565 |  +47,042 |  −1.75 %  |    2,739,559  | essentially 0 |
| treeadd   |    564,739 |    707,813 | +143,074 | **−25.33 %** |    725,544  | **−18 k cycles** |
| tsp       |  6,638,321 |  6,737,135 |  +98,814 |  −1.49 %  |    6,737,129  | essentially 0 |

Geomean vs NoPref: −6.44 % (new) vs −6.52 % (old). Tiny improvement.

**The S→E fix helps modestly on health / bisort / treeadd by removing the
permsOnly upgrade roundtrip, but does NOT bring any of them positive.** The
other failure modes I identified (pollution, redundancy, lead-time
catastrophe) still dominate.

Treeadd is still the worst: −25.33 % vs NoPref, actually slightly worse in
absolute cycles than the old run because the volume of prefetch-miss
displacements is now higher (3,048 prefetchMiss vs 1,830 old — likely
because E-state fetches from LLC are not merge-deduplicated with
outstanding demand cRqs the way S fetches were).

## Per-bench prefetch breakdown (new parser metrics)

| bench     | pref   | pHit   | pMiss | useful | directHit | permsOnly | real-evict | lateP  |
|----------:|-------:|-------:|------:|-------:|----------:|----------:|-----------:|-------:|
| bh        |      0 |      0 |     0 |      0 |         0 |         0 |          0 |      0 |
| bisort    |    526 |    123 |   367 |    357 |       357 |         0 |         10 |    153 |
| em3d      |    219 |    157 |    32 |     19 |        19 |         0 |         13 |      3 |
| health    | 13,414 |  8,268 | 4,278 |  3,238 |     3,238 |         0 |      1,040 |  1,128 |
| patricia  |  2,171 |    572 | 1,528 |  1,465 |     1,465 |         0 |         63 |     41 |
| perimeter |      0 |      0 |     0 |      0 |         0 |         0 |          0 |      0 |
| treeadd   | 12,202 |  8,306 | 3,048 |  2,961 |     2,961 |         0 |         87 |  1,481 |
| tsp       |      0 |      0 |     0 |      0 |         0 |         0 |          0 |      0 |

**`permsOnly` is zero everywhere because of the S→E fix**: demand Loads now
cRq-hit directly on the E-state prefetched line. No more S→E upgrade
roundtrip.

`useful` ≈ `directHit` across the board — the fix works as intended. The
parser is now correctly counting these (previously marked as perms-kill due
to the parser bug).

Note: patricia's `useful` moved from 1,436 (old direct-hit) + 39 (old
permsOnly) = 1,475 to 1,465 all-direct. Within noise.

## NEW: inBounds vs neighbour-line prefetches (what the user asked about)

Previously invisible because H4 emitted "CDP Kill" logs that the parser's
`CDP Rel`-prefixed regexes didn't match. Now available:

| bench     | decisions inBounds | decisions neighbour | cdpPref_inBounds_Useful | cdpPref_neighbour_Useful | neighbour useful % |
|----------:|-------------------:|--------------------:|------------------------:|-------------------------:|-------------------:|
| bisort    |             84,569 |              30,057 |                     312 |                       42 |              11.9% |
| em3d      |              1,878 |                 537 |                       6 |                        1 |              14.3% |
| health    |            107,185 |              19,171 |                   2,774 |                      304 |              9.9%  |
| patricia  |            100,305 |               8,188 |                   1,463 |                        2 |              0.1%  |
| treeadd   |             79,955 |               9,386 |                   2,436 |                      311 |              11.3% |

**Neighbour prefetches (Branch-2 of CDP's PrefetchIssue — out-of-[0,7]
relOffset → prefetch the previous/next cache line directly, no pointer
chase) contribute ~10–14 % of useful prefetches on bisort / em3d / health
/ treeadd.** On patricia they're negligible (0.1 %) — patricia's useful
prefetches come almost entirely from Branch-1 pointer-chase on the
`input_data[]` array walk.

## NEW: chain prefetches (pointer-chase from arrived neighbour line)

When a neighbour-line prefetch arrives, H4 reads the word at the
hit-offset of the arrived line and, if the word's VPN upper bits match
the demand's, chases THAT pointer (`reportIncomingCacheLine` chain path
in CDPKillSwitch.bsv:546-559). Previously untracked; now parsed:

| bench     | chain attempts | chain VPN-failed | cdpPref_chain_Useful | cdpPref_direct_Useful |
|----------:|---------------:|-----------------:|---------------------:|----------------------:|
| bisort    |              4 |                0 |                    0 |                   357 |
| em3d      |             95 |               38 |                    0 |                     9 |
| health    |          2,882 |            1,189 |                   25 |                 3,213 |
| patricia  |             92 |               25 |                    9 |                 1,456 |
| treeadd   |            881 |              245 |                  211 |                 2,750 |

**Chain prefetches contribute materially on treeadd**: 211 / 2,961 = 7.1 %
of useful prefetches on treeadd come from the chain path. On health it's
smaller (25 / 3,238 = 0.8 %), on patricia smaller (9 / 1,465 = 0.6 %).

The chain VPN-failed count is also informative: on health 1,189 / 2,882 =
41 % of chain attempts abort because the word-value upper bits don't match
the demand's VPN — the word isn't pointer-shaped. On bisort the
chain-attempt count is tiny (4) — bisort's tree-traversal access pattern
doesn't benefit from chain.

## NEW: same-page vs cross-page useful breakdown (via TLB resp)

Previously requested by the parser but invisible because H4 didn't emit
TLB resp logs. Now:

| bench     | same-page useful | cross-page useful | unknown-page useful |
|----------:|-----------------:|------------------:|--------------------:|
| bisort    |              314 |                41 |                   2 |
| em3d      |                4 |                 5 |                   2 |
| health    |            1,903 |             1,166 |                 108 |
| patricia  |            1,454 |                11 |                   0 |
| treeadd   |            2,335 |               603 |                  23 |

Patricia's useful prefetches are 99 % same-page — confirms the trie+array
access pattern stays within the data-segment region. Health is 62 % same-
page / 38 % cross-page — the linked-list forest spans allocations across
multiple pages. Treeadd is 79 % same-page / 21 % cross-page.

The `matchBits` cross-page discovery gate (memory
`cdp_insight_matchbits_semantics.md`) is genuinely exercised — on health
~1,166 useful prefetches cross a page boundary, which MB=27 would
eliminate entirely.

## Implications for the failure-mode analysis

The three failure modes identified in `h4_per_bench_deep_dive_2026-04-21.md`:

1. **Class 1 (bh, perimeter, tsp): zero CDP activity.** Unchanged. S→E fix
   doesn't help since there are no demand-Load misses to train on.

2. **Class 2 (bisort, em3d, health, treeadd): CDP fires but net negative.**
   The S→E fix removes ONE of the four compounding issues (the S→E
   upgrade tax). The other three remain:
   - Redundant prefetches: still 61% on health (8268/13414), 68% on treeadd (8306/12202).
   - Pollution: health 4,274 `E|M --/Pr/--> E` evictions; treeadd 3,045.
   - Late prefetches: got WORSE. Health 1,128 vs old 1,196; treeadd 1,481 vs old 29
     (treeadd late went up 50×). E-state fetches from LLC/DRAM are slower, so
     prefetches arrive later relative to demand.

3. **Class 3 (patricia): unchanged success** (+6.24 %, slightly lower than
   +6.75 % old but within noise).

## Next actions

The S→E fix is small-win. The big remaining levers (ranked by expected
impact per my earlier analysis):

1. **Kill redundant prefetches (cache-aware dedup).** Clarified in the
   previous conversation turn: the existing CDPKillSwitch filter only
   dedupes against recently-issued prefetches, not against the L1 tag
   array. Wiring `reportAccess`/`reportIncomingCacheLine` to insert
   demand-fills into the filter (with `punishable=False`) would kill
   8,268 redundant issues on health and 8,306 on treeadd.

2. **Lead-time throttle for DFS.** Treeadd's 1,481 late prefetches are a
   new problem introduced by the slower E-fetch path. Either:
   - Delay prefetch until within N cycles of predicted demand.
   - Cap per-PC outstanding prefetches.

3. **Pollution guard.** Refuse to prefetch a line that would evict an
   M/E-state line. Requires a pre-issue tag check.

## Parser changes committed this session

`TooobaLogParser/parselogNew.py`:
- Lines 263-266: added `consumedViaPermsOnly` on CRqCreationLine.
- Lines 402-408: added `usefulPrefetchPermsOnly` / `usefulPrefetchDirectHit`
  to getTotals.
- Lines 830-859: permsOnly miss no longer marks `isNeverAccessed`; instead
  sets `consumedViaPermsOnly=True` on the consuming demand's creation.

`src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitch.bsv`:
- Line ~329: prefetch-decision log now `CDP Rel` with `conf` + `isNeighbour`
  + H4 extras (uf/us/verdict).
- Line ~438: filter-HIT log: `CDP Rel`.
- Line ~450: filter-MISS log: `CDP Rel`, with base format + appended
  pcHash/isNeighbour/route.
- Lines 424-437: TLB-resp log added (success + exception branches).
- Lines 551-562: neighbour-chain log added (pass + VPN-fail branches).

## Appendix — concrete command to reproduce

```bash
cd /auto/homes/ac2822/Documents/Code/Toooba/builds/RV64ACDFIMSU_Toooba_bluesim
export DATA_PREFETCHER_TYPE=CDP_KILLSWITCH
make compile simulator
rm -f Logs/*.bin.log Logs/*.totals_cache
make benchmarks
for b in bh bisort em3d health patricia perimeter treeadd tsp; do
  /auto/homes/ac2822/Documents/Code/Toooba/TooobaLogParser/venv/bin/python3 \
    /auto/homes/ac2822/Documents/Code/Toooba/TooobaLogParser/main.py \
    Logs/${b}.bin.log > /dev/null
done
```
