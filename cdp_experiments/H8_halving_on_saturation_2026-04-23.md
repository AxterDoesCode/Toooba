# H8 (6-bit counters + halving-on-saturation) — negative finding

Date: 2026-04-23
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitchH8.bsv`
Logs: `builds/RV64ACDFIMSU_Toooba_bluesim/Logs/*.bin.log` (this run)

## What H8 changes relative to H7

H8 is a strict refactor of H7 plus two *behavioural* tweaks on the per-PC
kill-switch counters:

1. `usefulCount` / `uselessCount` widened **4-bit → 6-bit** (max 15 → 63).
   Saturation pushed out of the typical steady-state range for long-running
   benches.
2. **Halving-on-saturation (SPP-style).** When an increment on `uf` or `us`
   would saturate, halve BOTH counters before applying the increment. Ratio
   preserved, headroom freed, so `us > uf` stays discriminative after long
   runs.

The `shouldIssue(uf, us)` gate itself is unchanged from H7:
`chronic = (us >= killThreshold) && (us > uf); return !chronic`.

## Cycle results (8-bench)

| bench     |   NoPref2 |        H7 |    H8-halv |     H7% |    H8% | H8 − H7 |
|:----------|----------:|----------:|-----------:|--------:|-------:|--------:|
| bh        | 1,219,571 | 1,219,582 |  1,219,582 | +0.00%  | +0.00% |      +0 |
| bisort    |   989,251 |   985,152 |    985,152 | −0.41%  | −0.41% |      +0 |
| em3d      | 1,739,832 | 1,739,043 |  1,739,043 | −0.05%  | −0.05% |      +0 |
| health    | 1,258,698 | 1,246,504 |  1,252,956 | −0.97%  | −0.46% |  **+6,452** |
| patricia  | 1,416,398 | 1,245,569 |  1,245,569 | −12.06% | −12.06% |     +0 |
| perimeter | 2,692,517 | 2,692,523 |  2,692,523 | +0.00%  | +0.00% |      +0 |
| treeadd   |   564,733 |   558,042 |    558,042 | −1.18%  | −1.18% |      +0 |
| tsp       | 6,638,315 | 6,638,321 |  6,638,321 | +0.00%  | +0.00% |      +0 |
| **geomean** |           |           |            | **−1.916%** | **−1.853%** | **+0.065 pp** |

**Net:** H8 with halving-on-saturation is **0.065 pp worse** than H7 — a
small regression, driven entirely by health.

## Halving-activation counts (grep `halved:` on `CDP Kill acc useful/useless bump` log lines)

| bench     | halved=1 | halved=0 | updates | halving fires? |
|:----------|--------:|---------:|--------:|:---------------|
| bh        |       0 |        0 |       0 | kill-switch never trains (no PC lookups) |
| bisort    |       8 |      395 |     403 | rarely (2.0%) |
| em3d      |       0 |       50 |      50 | never saturates |
| health    |      33 |     1587 |   1,620 | rarely (2.0%) |
| patricia  |      42 |     1477 |   1,519 | rarely (2.8%) |
| perimeter |       0 |        0 |       0 | kill-switch never trains |
| treeadd   |      30 |     1653 |   1,683 | rarely (1.8%) |
| tsp       |       0 |        0 |       0 | kill-switch never trains |

Halving does fire on 4 benches (bisort / health / patricia / treeadd) but
at ≲3% of counter-update events. 3 benches (bh / perimeter / tsp) never
train the kill-switch at all — consistent with past "Class-1
store-dominated" finding where CDP never issues.

## Parser attribution: health regression is gate-suppression

Per-bench H7 vs H8-halv TooobaLogParser CRqCreationLine totals.
H7 numbers from `cdp_insight_H7_parser_metrics` memory (2026-04-22):

| bench    |   metric           |      H7 |  H8-halv |       Δ |
|:---------|:-------------------|--------:|---------:|--------:|
| health   | prefetch (issued)  | 12,240  |    5,204 | **−7,036 (−57%)** |
| health   | prefetchHit        |  6,350  |    2,719 | −3,631 |
| health   | prefetchOwned      |  1,548  |      826 |   −722 |
| health   | prefetchMiss       |  4,342  |    1,659 | −2,683 |
| health   | usefulPrefetch     |  2,215  |    1,525 |   **−690** |
| health   | lateUsefulPrefetch |  1,117  |      684 |   −433 |
| health   | timely useful      |  1,098  |      841 |   −257 |
| bisort   | prefetch (issued)  |    524  |      524 |      0 |
| bisort   | usefulPrefetch     |    390  |      390 |      0 |
| patricia | prefetch (issued)  |  2,168  |    2,168 |      0 |
| patricia | usefulPrefetch     |  1,442  |    1,442 |      0 |
| treeadd  | prefetch (issued)  | 15,324  |   15,324 |      0 |
| treeadd  | usefulPrefetch     |  1,612  |    1,612 |      0 |
| em3d     | prefetch (issued)  |  1,992  |    1,992 |      0 |
| em3d     | usefulPrefetch     |     43  |       43 |      0 |

**Cycle-budget reconciliation on health.**
- 690 fewer `usefulPrefetch` events (incl. late).
- health's useful prefetches are almost entirely LLC-hits
  (`prefetchMissLL = 1`), so per-useful savings ≈ 5-10 cyc.
- Best-case recovery from those 690 useful = 690 × ~10 = ~6,900 cyc.
- **Observed regression: 6,452 cyc.** Causal chain closes cleanly —
  the kill-switch is suppressing prefetches that *would have been
  useful*.

H8-halv issued **57% fewer prefetches on health**. The halving mechanism
is turning a PC whose H7-counters sit at `(uf=15, us=15)` into a PC
whose H8-counters sit at `(uf=small, us=bigger)` after halving + `+3`
amplification, which then trips `us > uf` and suppresses all subsequent
prefetches from that PC.

## Interpreting the result

1. **6-bit widening alone is a no-op on 7/8 benches.** bh / bisort / em3d /
   patricia / perimeter / treeadd / tsp are exact-cycle-identical to H7 at
   4-bit. Widening the saturation point from 15 to 63 didn't let any new
   `shouldIssue` decisions flip, because either (a) no PC's counter
   actually reaches 15 (em3d: only 50 updates total) or (b) relative
   ordering of `us` vs `uf` doesn't change when the absolute values get
   scaled.

2. **Halving-on-saturation is a net regression on health — and it's the
   halving, not the widening.** 33 halving events on health coincide
   with a 57% drop in prefetch issuance and a +6,452 cycle slowdown.
   Mechanism (traced via parser): on the hot health PCs, counters reach
   saturation under 6-bit AccUseful bumps; the first halving at an
   AccUseless event immediately amplifies the `us`/`uf` ratio (halving
   preserves the ratio only *before* the +3 amplification adds to `us`).
   Once `us > uf` flips, the PC is permanently suppressed because
   `shouldIssue` never recovers without a decay tick, and decay is
   slow relative to the incoming miss rate on health.

3. **Halving fires but doesn't hurt on bisort / patricia / treeadd.**
   Those benches have enough `us` separation from `uf` (bisort: tiny
   useless count; patricia/treeadd: very high useful count relative to
   useless) that halving doesn't flip `us > uf` — 0 change in issued or
   useful counts across all three.

## Takeaway

Halving-on-saturation as implemented is a **negative result**. The
stated motivation — "when both counters saturate, `us > uf` can't fire
and the gate gets stuck" — turns out not to manifest on the current
8-bench set:

- 3 benches never populate counters (bh / perimeter / tsp).
- 4 benches rarely saturate (≲3% halving rate).
- The 1 bench that does saturate regularly (health) gets *hurt* by the
  halving, not helped.

The 6-bit widening is effectively free (no change on 7/8) so can stay
for safety headroom, but the halving should be removed — the simpler
H7 gate was better.

## Recommended next step

1. **Revert the halving, keep 6-bit widening.** One-line change: drop
   the `sat ? x>>1 : x` halving in both `AccUseful` and `AccUseless`
   arms of `pcTableResp`. Rerun 8-bench; should recover H7's −1.92%
   geomean exactly.

2. **Or pursue the original H8 motivation differently.** The claim
   "gate gets stuck at saturation" is supportable — just not via
   halving. Alternative: make `shouldIssue` use `us > uf` with a
   small absolute tolerance (e.g. `us > uf + 2`) so the threshold
   survives both counters saturating. Or add a periodic *full* decay
   of both counters at a larger interval, rather than a triggered
   halving at the saturation boundary — the latter is a step function,
   the former is a smooth signal.

3. **Instrument shouldIssue outcomes.** Before any more gate tweaks,
   emit `suppressed: N` counts per bench in the parser. We're
   currently inferring what the gate is doing from cycle deltas; a
   direct suppression count would make every subsequent variant
   analysis trivial.
