# Variant BMPolyGrad-MB27 — graded routing by match count

Date: 2026-04-21  •  Config: `DATA_PREFETCHER_TYPE=CDP_BMPOLYGRAD` + `matchBits=27`

## Hypothesis
Extend BMPolySupp-MB27 (current best at -0.04% vs NoPref) by replacing the
binary suppress-or-not policy with a graded routing:
- matchCount == 1     → L1 prefetch (clean single pointer)
- matchCount in [2,3] → LLC prefetch (moderate noise — still pre-warm LLC)
- matchCount >= 4     → SUPPRESS (high noise)

The intuition: "moderate" multi-match lines (2-3) are likely split-pointer
structs where one pointer is real — it's wasteful to suppress entirely, but
cheap to route to LLC as insurance.

## Result — cycles vs NoPref (lower is better)
| bench | NoPref | BMPolySupp | BMPolyGrad | Grad Δ vs NoPref | Grad Δ vs Supp |
|---|---:|---:|---:|---:|---:|
| bh       | 1,219,571 | 1,219,571 | 1,219,571 | 0.00% | 0.00% |
| bisort   |   989,251 |   988,690 |   988,273 | +0.10% | +0.04% |
| em3d     |    83,355 |    83,099 |    83,932 | -0.69% | -1.00% |
| health   | 1,258,698 | 1,261,339 | 1,258,238 | +0.04% | +0.25% |
| patricia | 1,416,398 | 1,416,398 | 1,416,398 | 0.00% | 0.00% |
| perimeter| 2,692,517 | 2,692,517 | 2,692,517 | 0.00% | 0.00% |
| treeadd  |   564,733 |   567,223 |   577,351 | -2.23% | -1.79% |
| tsp      | 6,638,315 | 6,638,315 | 6,638,315 | 0.00% | 0.00% |

**Geomean:** BMPolyGrad = **-0.35% vs NoPref** (worse than BMPolySupp's -0.04%).
**Regression anchor:** treeadd at -2.23%.

## Why — per-match-bucket accounting on treeadd
Count of each routing decision on treeadd's log:

| bucket | matchCount | routing | count |
|---|---|---|---:|
| single | == 1      | L1       | 16,994 |
| multi  | 2-3       | LLC      | 35,541 |
| noise  | >= 4      | SUPPRESS |  1,930 |

Grad issues 32,526 candidates on treeadd (vs BMPolySupp's 10,682 — the
single-match only subset). Useful-prefetch hits:
- BMPolySupp: 10,682 issued → 1,169 useful (10.9% acc)
- BMPolyGrad: 32,526 issued → 2,546 useful (7.8%  acc)

The extra LLC-routed candidates (21,844) yielded only 1,377 useful hits —
6.3% accuracy. That's below the break-even accuracy needed to justify the
LLC-pollution cost, and it manifests as a 1.79% treeadd regression vs Supp.

## Conclusion
The binary SUPPRESS-on-any-multi-match policy in BMPolySupp-MB27 dominates
the graded variant. LLC-routing 2-3 match lines introduces enough pollution
to overwhelm the marginal gain from the few useful hits in that bucket.

**BMPolySupp-MB27 remains the pure-bit-match best** at -0.04% vs NoPref.
Graded routing is strictly worse than binary suppress on this suite.

## Next directions
- BM-PostConf (per-PC useful-hit tracking): gate single-match issue by
  historical useful% of the issuing PC. Unlike TT learning, this only scores
  attribution (no offset table, no training bumps).
- BM-DensityThresh (per-PC match-count filter): suppress entire PCs whose
  loads historically produce noisy (multi-match) lines.
