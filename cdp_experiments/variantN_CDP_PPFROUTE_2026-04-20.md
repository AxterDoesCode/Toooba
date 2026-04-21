# Variant N: PPF-gated routing (L1 vs LLC, not suppression) — 2026-04-20

Base: Variant M's perceptron + attribTable infrastructure. Replace binary
suppress/issue with routing decision: perceptron weight >= threshold -> L1,
weight < threshold -> LLC. Always issue (no drop).

**Motivation:** Variant B (route-all-to-LLC) won treeadd +7.01% but crushed
patricia -6.35%. Per-PC adaptive (E/E3/E4) too noisy. M's per-(PC, relOff)
perceptron is finer-grained; using it for routing (instead of suppression)
should preserve patricia's L1 wins while protecting L1 from treeadd-style
pollution.

## Results (vs decay16 baseline)

| Bench | NoPref | CDP (decay256) | L2 | N (this) |
|---|---:|---:|---:|---:|
| em3d | 83,355 | 88,246 | 87,949 | 88,427 |
| health | 1,258,698 | 1,342,254 | 1,341,304 | 1,337,554 |
| patricia | 1,416,398 | 1,342,074 | 1,325,868 | **1,321,767 (best)** |
| treeadd | 564,733 | 732,828 | 723,118 | 732,426 |
| voronoi | 202,004 | 213,033 | 212,958 | 212,189 |

Geomean speedup vs decay16: **+3.96%** (L2 +4.14%, decay256 +3.52%)

## Analysis

- **Best patricia of any tried variant (+6.20% vs decay16).** The perceptron
  weights climb on useful attribution, keeping patricia's prefetches routed
  to L1.
- **Perceptron barely fires on treeadd** — 4.9% of decisions routed to LLC
  (4129/84584). With 14,211 issued and only 107 useless bumps attributed
  (0.58% attribution rate), the perceptron weights barely go negative.
- Net result: N mostly behaves like baseline CDP, with a small LLC-route
  bleed for em3d (17.8%) that doesn't quite help.

## Verdict

N is NOT a new best (+3.96% < L2 +4.14%), but the per-benchmark signature is
interesting: it's our patricia champion. The perceptron+routing direction is
sound; attribution density is the bottleneck.

## Follow-ups

- **O (utility-gated conf)**: replaces perceptron with existing 15K-slot
  pcTable for attribution fan-out — tested, also +3.68% (no win).
- **Z (conf-graded routing)**: conf>=2 -> L1, conf=1 -> LLC. Tested, +2.07%
  — conf rarely climbs to 2 so LLC-default behavior dominates, reproducing
  Variant B (patricia disaster).
- **YY (global trust gate)**: different architecture — whole-suite score
  drives enable/disable. Expected to resolve the "must be L1-default or die
  on patricia" constraint. Currently building.
