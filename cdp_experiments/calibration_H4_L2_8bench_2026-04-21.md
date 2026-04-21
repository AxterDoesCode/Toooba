# Calibration: H4 KILLSWITCH + L2 HYBRID2 on 8-bench, parser-verified

Date: 2026-04-21  •  Baseline: baseline_NoPref_8bench_2026-04-21

## Cycle results (8-bench vs NoPref)

| bench | NoPref | H4 | L2 | H4 vs NoPref | L2 vs NoPref |
|---|---:|---:|---:|---:|---:|
| bh        | 1,219,571 | 1,220,351 | 1,220,351 | -0.06% | -0.06% |
| bisort    |   989,251 | 1,073,594 | 1,084,171 | -7.85% | -8.75% |
| em3d      |    83,355 |    88,053 |    87,949 | -5.34% | -5.22% |
| health    | 1,258,698 | 1,342,040 | 1,341,304 | -6.22% | -6.16% |
| patricia  | 1,416,398 | 1,326,807 | 1,325,868 | **+6.75%** | **+6.83%** |
| perimeter | 2,692,517 | 2,739,559 | 2,739,559 | -1.72% | -1.72% |
| treeadd   |   564,733 |   725,544 |   723,118 | **-22.23%** | **-21.86%** |
| tsp       | 6,638,315 | 6,737,129 | 6,737,129 | -1.47% | -1.47% |

**Geomean vs NoPref: H4 ≈ -6.52%, L2 ≈ -6.50%.** Effectively tied.

Both are DRAMATICALLY worse than my pure-bit-match variants (BMAlignSupp at -0.01%,
BMAlignSuppConf at +0.01%) on 8-bench. Treeadd is the killer: -22% slowdown
from 12-18k useless prefetches.

## Parser-verified usefulPrefetch per bench

H4 KILLSWITCH:
| bench | pref | useful | useless | perms | late | acc% |
|---|---:|---:|---:|---:|---:|---:|
| bh        |     0 |   0 |    0 |    0 |   0 | - |
| bisort    |   521 |   0 |  249 |  245 | 155 | 0% |
| em3d      |   206 |   1 |   22 |   10 |   3 | 0.5% |
| health    | 9,703 |   0 | 3,834 | 3,149 | 1196 | 0% |
| **patricia**  | **2,273** | **1,436** | **108** |  **39** |  **49** | **63.2%** |
| perimeter |     0 |   0 |    0 |    0 |   0 | - |
| treeadd   | 12,937 |   0 | 1,830 | 1,726 |  29 | 0% |
| tsp       |     0 |   0 |    0 |    0 |   0 | - |

L2 HYBRID2:
| bench | pref | useful | useless | perms | late | acc% |
|---|---:|---:|---:|---:|---:|---:|
| bh        |     0 |    0 |    0 |    0 |    0 | - |
| bisort    |  6,369 |   17 | 2,791 | 1,091 |  219 | 0.3% |
| em3d      |    253 |    1 |   26 |   19 |    9 | 0.4% |
| health    | 26,546 |   52 | 7,864 | 5,185 | 1,052 | 0.2% |
| **patricia**  |  **4,121** | **1,455** |  **485** |  **208** |  **164** | **35.3%** |
| perimeter |     0 |    0 |    0 |    0 |    0 | - |
| treeadd   | 18,502 |    0 | 3,914 | 3,734 |  341 | 0% |
| tsp       |     0 |    0 |    0 |    0 |    0 | - |

**Finding: Patricia is the ENTIRE source of useful prefetches.** H4 = 1436/1437
(99.9%) come from patricia. L2 = 1455/1525 (95%).

## Root-cause: H4's patricia wins are stride-pattern, NOT pointer chasing

Log inspection on `variantH4_KILLSWITCH_8bench_2026-04-21/patricia.bin.log`:

Useful-hit addresses are all SEQUENTIAL 64-byte-incrementing cache lines:
```
cycle  44294: useful hit addr 0000000080001e00
cycle  44982: useful hit addr 0000000080001e40  (+0x40 = +1 line)
cycle  46029: useful hit addr 0000000080001e80  (+1)
cycle  46785: useful hit addr 0000000080001ec0  (+1)
cycle  47581: useful hit addr 0000000080001f00  (+1)
... 30 consecutive lines prefetched in sequence
```

Prefetches issued by PC 84e0 (1484 of 2273 total = 65%):
```
lineAddr 2000077 -> 2000078 -> 2000079 -> 200007a -> 200007b -> ...
```

These are the paddrs of **input_data[]**, a global array of
`struct input_data_format { float time; char addr[26]; }` — 30 bytes
per entry, 3000 entries. The main loop in `patricia_test.c:247-256`
walks this array sequentially with `++fakeFile`.

**This is a pure linear array walk.** H4's PC/TT offset table learns
"PC 84e0 misses at +1 line offset" and prefetches it. The PC-TT
mechanism is acting as a per-PC stride prefetcher here; no pointer
bits matter.

Implication: **the "patricia is pointer-chasing success" story is
incorrect** — patricia's hot loop is an array walk over non-pointer
structs. H4's win comes from offset-learned stride prefetching for
that sequential scan.

## What H4 fails at (why -22% on treeadd, etc.)

On treeadd: 12,937 prefetches, **0 useful**, 1,726 perms-evicted (13%),
29 late. The PC/TT trains on every demand miss during tree traversal
and learns offsets that don't correspond to pointer chases — it's
learning noise. Same PC/TT learning that works on patricia's stride
pattern generates pure pollution on the random-ish tree walk.

## Implication for Direction A (bit-match-gated TT training)

If patricia's H4 useful hits come from learning offsets in input_data[]
(a pointer-FREE array of time/string structs), then **gating TT training
on bit-match will kill those useful hits** — input_data words don't pass
the shape filter (they're floats and ASCII chars, neither are valid
pointer shapes).

So Direction A would predictably:
- Lose patricia's +6.75% win (gate kills the array-walk learning)
- Avoid treeadd's -22% pollution (gate prevents training on non-pointer offsets)
- Net: probably converges to BMAlignSupp-level results (−0.01% to +0.01%).

This is a meaningful experiment but NOT the "augment PC/TT with pointer
awareness" story we hoped for — the PC/TT isn't doing pointer chasing
to begin with. It's doing disguised stride.

## Recommendation for next steps

The user's core question was "can bit-matching augment PC/TT". Parser
evidence says: on our benchmark suite, PC/TT isn't actually finding
pointers — it's finding strides. So "bit-matching augments PC/TT" is
really "bit-matching gates stride prefetching", and that's essentially
what the prior stride-hybrid variants already tested.

Direction A is still worth running to confirm the hypothesis (gate
kills patricia gain, recovers treeadd). Directions B (recursive
chain scan) and C (dependence-based) remain more novel bets since
they look at DIFFERENT access signals than PC/TT.
