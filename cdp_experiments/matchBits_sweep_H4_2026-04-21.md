# H4 KILLSWITCH matchBits sweep — CDP mechanism is noise-triggered stride emergence

Date: 2026-04-21

## Hypothesis

H4's apparent patricia success at matchBits=16 (+6.75% vs NoPref, 1,436
useful prefetches) is NOT pointer-chasing. It's bit-match noise at loose
matchBits triggering TT training whose statistical offset confidence
converges to stride on linear access patterns. If true, tightening
matchBits to 27 (same-page VPN match required) should collapse patricia's
useful-prefetch count to zero because the input_data[] walk contains only
floats and ASCII — no words with valid SV39 VPN-matching upper bits.

## Methodology

Identical H4 KILLSWITCH mechanism (per-PC useful/useless attribution, kill
threshold 5) at four matchBits settings: 16 (default), 20, 24, 27.
Build + 8-bench + parser. Baseline: `baseline_NoPref_8bench_2026-04-21`.

## Per-bench parser usefulPrefetch (strict L1 metric)

| bench | MB=16 | MB=20 | MB=24 | **MB=27** |
|---|---:|---:|---:|---:|
| bh        |     0 |    0 |    0 |   **0** |
| bisort    |     0 |    0 |    0 |   **0** |
| em3d      |     1 |    1 |    1 |   **0** |
| health    |     0 |    6 |    0 |   **0** |
| **patricia** | **1,436** | **1,448** |   **46** | **0** |
| perimeter |     0 |    0 |    0 |   **0** |
| treeadd   |     0 |    0 |    0 |   **0** |
| tsp       |     0 |    0 |    0 |   **0** |
| **total** | **1,437** | **1,455** |  **47** | **0** |

**Patricia useful cliff between MB20 and MB24**: 1,448 → 46 (97% drop).
**Zero useful anywhere at MB27.**

## Per-bench cycles (vs NoPref)

| bench    | NoPref     | MB=16       | MB=20       | MB=24       | MB=27       |
|----------|-----------:|------------:|------------:|------------:|------------:|
| bh        | 1,219,571  | 1,220,351   | 1,220,351   | 1,220,351   | 1,220,351   |
| bisort    |   989,251  | 1,073,594   | 1,076,670   | 1,071,812   | 1,061,314   |
| em3d      |    83,355  |    88,053   |    87,926   |    87,926   |    86,629   |
| health    | 1,258,698  | 1,342,040   | 1,345,906   | 1,314,134   | 1,303,441   |
| **patricia** | **1,416,398** | **1,326,807** | **1,328,457** | **1,491,716** | **1,495,785** |
| perimeter | 2,692,517  | 2,739,559   | 2,745,724   | 2,745,724   | 2,745,724   |
| treeadd   |   564,733  |   725,544   |   725,694   |   723,898   |   722,815   |
| tsp       | 6,638,315  | 6,737,129   | 6,718,959   | 6,718,959   | 6,718,959   |

Patricia cycles:
- MB16: +6.75% speedup  (matches 1,436 useful)
- MB20: +6.63% speedup  (matches 1,448 useful)
- MB24: **-5.32% slowdown**  (matches 46 useful)
- MB27: **-5.61% slowdown**  (matches 0 useful)

Geomean vs NoPref across 8 benches: MB16 ≈ MB20 ≈ MB24 ≈ MB27 ≈ -6.5% to -6.9%.
Patricia's gain at loose matchBits is offset by slight improvements on
other benches (less pollution), so suite geomean is flat across the sweep.

## Conclusion

**H4 has zero genuine pointer-chasing utility on this suite.** What was
interpreted as "CDP successfully capturing pointer patterns on patricia"
is entirely a consequence of matchBits=16 being so loose that:

1. Every small-integer word in input_data[] passes the bit-match gate
2. Training Table fills with noise candidates at all offsets
3. Statistical correlation with the dominant "+1 line" stride of the
   `++fakeFile` main loop wins the confidence race
4. TT outputs produce line+1 prefetches that happen to land on the next
   line of a genuine linear walk

At matchBits=24 (requiring 24 upper VPN bits to match — consistent with
valid within-2GB-region pointers), almost no input_data words match.
Training stops. Useful count collapses 97%. At matchBits=27 (full VPN =
same-page pointer), zero useful anywhere across the 8-bench suite.

## Implications

1. **The CDP/PC-TT mechanism family does not find pointers on
   Olden+MiBench2 as running on Toooba.** It only produces useful
   prefetches via bit-match-noise-driven stride emergence.

2. **Pure bit-matching variants (BMAlignSupp, etc.) and CDP at MB=27 are
   equivalent in terms of useful-prefetch yield** (both essentially zero).
   My pollution-cutting variants (AlignSupp, AlignSuppConf) reach -0.01%
   to +0.01% vs NoPref, vastly better than H4@any-matchBits (-6.5% to
   -6.9%) because they suppress the spurious prefetches H4 keeps firing.

3. **Direction A (bit-match-gated PC/TT training) is confirmed
   null/negative** — matchBits=27 on H4 already demonstrates what Direction
   A would do: zero useful, residual pollution. No need to build.

4. **The benchmark suite fundamentally cannot distinguish "real
   pointer-chase prefetching" from "stride on linear data"** because the
   bump-allocator + small working sets + depth-first recursion + ASCII
   input arrays conspire to make all genuine pointer-chase structure
   degenerate to stride in practice.

## What to do next

Since the benchmark suite cannot test pointer-chasing validity, the
meaningful remaining experiments are:

- **Direction C-baseline** (plain DBP) — does a genuinely different
  mechanism (PC→address correlation, not bit-matching) find anything
  CDP misses? If not, confirms benchmark limitation.
- **Direction B** (chain scan on AlignSupp) — tests coverage expansion
  via classical Cooksey depth-N, sidesteps bit-match noise question.
- **Benchmark reconsideration** — if all mechanisms fail to find
  pointer-chase signal, the honest contribution shifts to "Olden/MiBench2
  are not pointer-chasing workloads on modern single-core OoO+MSI
  hardware" — a real finding worth writing up if we can back it.
