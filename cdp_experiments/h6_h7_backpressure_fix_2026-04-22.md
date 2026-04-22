---
variants: H6 (enlarged blocking FIFO), H7 (non-blocking overflow-bypass FIFO)
files: CDPKillSwitchH6.bsv, CDPKillSwitchH7.bsv
date: 2026-04-22
motivation: fix the residual back-pressure found in H4 decoupled via incomingQ.enq guard
archives:
  - /local/scratch/ac2822/NewTooobaLogs/variantH6_enlargedFifo_2026-04-22
  - /local/scratch/ac2822/NewTooobaLogs/variantH7_overflowBypass_2026-04-22
---

# H6 + H7: two candidate fixes for the residual method-guard back-pressure

## Motivation

After the H4 decoupling fix (cb4d2cef), instrumentation (enq/drain $display)
confirmed that the 32-entry staging FIFO fills (depth=32) for 9.9% of em3d
cycles — 0% in memory-bound init, 20-51% in compute-light phase. When full,
`incomingQ.enq`'s implicit guard fails and `pipelineResp_cRq` in L1Bank
cannot fire. Residual +4.97% em3d slowdown vs NoPref traces entirely to
this.

Two candidate fixes:
- **H6**: enlarge incomingQ from `mkSizedFIFO(32)` to `mkSizedFIFO(256)`
  (8× larger). Still blocking.
- **H7**: replace `mkSizedFIFO(32)` with `mkOverflowBypassFifo`. enq is
  always ready; when full the oldest entry is dropped to make room.

## Results (8-bench, resized em3d)

| Bench | NoPref | H4 dec | H6 | H7 | H6 vs NP | H7 vs NP |
|---|---:|---:|---:|---:|---:|---:|
| bh | 1,219,571 | 1,219,571 | 1,219,571 | 1,219,571 | 0.00% | 0.00% |
| bisort | 989,251 | 1,004,417 | 1,000,615 | 985,146 | +1.15% | **−0.42%** |
| em3d | 1,739,832 | 1,826,347 | 1,821,814 | 1,739,037 | +4.71% | **−0.05%** |
| health | 1,258,698 | 1,247,565 | 1,247,565 | 1,246,498 | −0.88% | **−0.97%** |
| patricia | 1,416,398 | 1,246,718 | 1,246,718 | 1,245,563 | −11.98% | **−12.06%** |
| perimeter | 2,692,517 | 2,692,517 | 2,692,517 | 2,692,517 | 0.00% | 0.00% |
| treeadd | 564,733 | 660,979 | 652,377 | 558,036 | +15.52% | **−1.19%** |
| tsp | 6,638,315 | 6,638,315 | 6,638,315 | 6,638,315 | 0.00% | 0.00% |
| **Geomean** | — | **+1.06%** | **+0.82%** | **−1.92%** | | |

**H7 is faster than NoPref on every non-Class-1 bench. First variant to
achieve negative geomean on 8-bench.**

## Why H6 barely helps

H6 saves only 4.5k cycles on em3d (0.25%) and 8.6k on treeadd (1.5 pp).
Interpretation: the enq rate in compute-light phases CHRONICALLY exceeds
drain rate (not a transient burst). A bigger FIFO just delays the
inevitable; once 256 entries fill, stalling resumes. The drain
bottleneck is mutex annotations on pcTable/TT/filter rules — only one
downstream rule at a time. Adding slack to a chronically-under-drained
FIFO is a weak palliative.

## Why H7 wins

By design, `mkOverflowBypassFifo.enq` has `notFull = True` unconditionally.
`reportIncomingCacheLine`'s enq never blocks, so pipelineResp_cRq never
stalls on this path. When CDP's drain falls behind, the oldest staged
events are silently dropped — the prefetcher loses some training data but
the L1 demand pipeline keeps flowing at full rate.

On treeadd, H4-decoupled was +17% slower than NoPref. H7 is −1.19%
faster. **Treeadd's "algorithmic" slowdown was 100% back-pressure.** Same
story for em3d (+4.97% → −0.05%).

Counter-intuitive outcome: dropping CDP training events gave BETTER
overall results because the cost of blocking L1 (many cycles per stall)
was much larger than the cost of missing a prefetch opportunity
(zero-to-a-few cycles of lost useful prefetch).

## Where prior "CDP hurts Olden" claims now land

Before H7, every Olden bench except patricia showed H4 as net-negative.
The 2026-04-21 "three failure modes" memo argued treeadd/health/bisort
had compounding algorithmic issues (S/E tax, pollution, redundancy,
lead-time catastrophe). After H7:
- Treeadd: +24.97% (c64b77c9) → −1.19% (H7). The remaining pre-decouple
  +24% was ~100% back-pressure, NOT pollution.
- Health: +5.16% → −0.97%.
- Bisort: +8.39% → −0.42%.
- Em3d: +10.98% → −0.05%.

The "H4 Class-2 net-negative" conclusion was largely an artifact of
method-guard back-pressure, not algorithm.

## Tradeoff (H7 only)

- Training-event loss when FIFO is full. Some fraction of L1 hits never
  feed pcTable / TT / TLB chain. Prefetch quality could in principle
  degrade, but empirically 8-bench geomean IMPROVES, not degrades.
- Drops the *oldest* event, not the newest. So training signal is
  biased toward recent events — not necessarily bad for prefetch
  learning.

## Recommended dissertation baseline

H7 should replace H4 as the reference CDP variant. Use
`DATA_PREFETCHER_TYPE=CDP_KILLSWITCH_H7`.
