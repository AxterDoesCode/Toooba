---
variant: H4 decoupled-incoming-queue
file: CDPKillSwitch.bsv
date: 2026-04-22
baseline_1: NoPref (variantNoPref_default_2026-04-22_wtverify)
baseline_2: H4 capchaserFix (variantH4_capchaserFix_2026-04-22)
archive: /local/scratch/ac2822/NewTooobaLogs/variantH4_decoupledQ_2026-04-22
---

# H4 decoupled-incoming-queue

## Problem

`reportIncomingCacheLine` is called synchronously from `pipelineResp_cRq` in
L1Bank on every cache response. Its body enq'd to multiple downstream FIFOs
(`l1ToCDP`, `pcTableRdReqFIFO`, `ttRespQ`, `ttRdReqSupFIFO`, `tlbReqFIFO`).
A Bluespec method has implicit guards from every FIFO it enqueues into; any of
those being full blocks the method which blocks `pipelineResp_cRq` which
stalls the L1 pipeline for every demand response — not only ones targeted at
CDP.

## Fix

1. `incomingQ: Fifo(32, Tuple3#(CDPIncomingBranchT, reqT, Line))` staging FIFO.
2. `reportIncomingCacheLine` now only classifies the branch and enqueues the
   tuple. Single FIFO enq, single implicit guard.
3. New rule `drainIncomingEvents` dequeues and fans out to the same downstream
   FIFOs as before.
4. `l1ToCDP` widened from `mkFIFO` to `mkSizedFIFO(8)`.

Back-pressure now blocks `drainIncomingEvents` (which is internal to CDP), not
the calling `pipelineResp_cRq`.

## Cycles (8-bench)

| Bench | NoPref | H4 capchaser | H4 decoupled | dec vs NoPref | dec vs capchaser |
|---|---:|---:|---:|---:|---:|
| bh | 1,219,571 | 1,220,351 | 1,219,571 | 0.00% | -0.06% |
| bisort | 989,251 | 1,072,211 | 1,004,417 | +1.53% | -6.32% |
| em3d | 83,355 | 88,504 | 85,546 | +2.63% | -3.34% |
| health | 1,258,698 | 1,323,686 | 1,247,565 | **-0.88%** | -5.75% |
| patricia | 1,416,398 | 1,330,872 | 1,246,718 | **-11.98%** | -6.32% |
| perimeter | 2,692,517 | 2,739,559 | 2,692,517 | 0.00% | -1.72% |
| treeadd | 564,733 | 705,747 | 660,979 | +17.04% | -6.34% |
| tsp | 6,638,315 | 6,737,129 | 6,638,315 | 0.00% | -1.47% |

- **Geomean H4 capchaser vs NoPref: +4.92%** (slower)
- **Geomean H4 decoupled vs NoPref: +0.78%** (near parity)
- **Geomean H4 decoupled vs H4 capchaser: -3.95%** (speedup)

Three benches (bh, perimeter, tsp) hit exactly NoPref cycles — Class 1 benches
where CDP never fires. With decoupling, the mere presence of CDP wiring
contributes zero cycle overhead on these. Previously (capchaser) these were
+0.06% / +1.75% / +1.49% slower just from the wiring overhead.

## Parser metrics (decoupled vs capchaser, 5 affected benches)

| Bench | variant | prefetch | HIT | OWNED | timely | late | useless |
|---|---|---:|---:|---:|---:|---:|---:|
| bisort | capchaser | **0** | 0 | 0 | 0 | 0 | 0 |
| bisort | decoupled | 525 | 166 | 18 | 256 | 76 | 9 |
| em3d | capchaser | 28 | 2 | 25 | 0 | 0 | 1 |
| em3d | decoupled | 225 | 186 | 7 | 6 | 1 | 25 |
| health | capchaser | 9563 | 4191 | 908 | 2555 | 1573 | 336 |
| health | decoupled | 13389 | 7407 | 1685 | 2204 | 891 | 1202 |
| patricia | capchaser | 1855 | 217 | 97 | 1453 | 19 | 69 |
| patricia | decoupled | 2053 | 504 | 34 | 1439 | 4 | 72 |
| treeadd | capchaser | 14889 | 9883 | 974 | 1741 | 2195 | 96 |
| treeadd | decoupled | 20290 | 18385 | 87 | 1653 | 36 | 129 |

Sum check (decoupled): HIT+OWNED+timely+late+useless = prefetch (✓ all 5 benches).

## Key finding — the regression was back-pressure, not prefetch pollution

- **bisort capchaser issued 0 prefetches** yet was +8.4% slower than NoPref.
  That cost was *entirely* back-pressure from CDP's internal state machine
  blocking `pipelineResp_cRq`. Decoupling drops the regression to +1.5% and
  simultaneously lets 525 prefetches through.
- **Timely-useful counts barely changed** across all 5 benches: patricia
  1453→1439, treeadd 1741→1653, health 2555→2204. CDP's algorithmic behaviour
  isn't meaningfully different. The cycle wins come from the L1 pipeline no
  longer stalling.
- **Late-useful dropped sharply** on treeadd (2195→36) and health (1573→891).
  Prefetches now arrive ahead of the demand instead of contending with it on
  the stalled pipeline.
- **Demand-owned small shift** — e.g. treeadd 34694→33998, health 16354→16521.
  The "prefetch still in flight when demand arrives" count is about the same.

## Interpretation

The "CDP is bad on non-patricia benches" narrative from 2026-04-19 through
2026-04-21 was conflating two effects:

1. An algorithmic component (prefetch pollution, useless prefetches, late
   arrivals). This exists but is small.
2. A pipeline-back-pressure component from CDP's method-to-multi-FIFO fanout.
   This was dominant and entirely implementation-level.

Disentangling the two changes the interpretation of *every* variant we ran
that touched `reportIncomingCacheLine`.

## Followups

- Retest all live CDP variants with the decoupled pattern — their relative
  rankings may shift (H5 cache-aware, PC/TT family, etc. all depend on this
  method).
- Consider decoupling `reportEviction`, `reportAccess`, `reportUsefulPrefetch`
  similarly if they enqueue to multiple FIFOs. Check whether any of their
  call sites are on hot paths.
- Re-evaluate "kill-switch ceiling" memory — the ceiling may have been a
  back-pressure artifact rather than an algorithmic limit.
