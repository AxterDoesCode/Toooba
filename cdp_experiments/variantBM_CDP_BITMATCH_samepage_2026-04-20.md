# Variant BM: clean bit-matching-only prefetcher — 2026-04-20

**Pure Cooksey CDP: no PC table, no training table, no confidence, no learning.**

- On L1 load MISS only: scan the loaded 8-word cache line.
- For each word with upper-VPN-bits matching the demand-load's VPN AND
  full-VPN matching (same-page), treat as a pointer candidate.
- Send TLB translation request. On success, pass through 1024-entry
  hash-keyed dedup filter. On filter MISS, issue the prefetch.
- No other state. Cooksey's bit-match primitive + dedup + miss-only gating.

Structural differences from the existing `mkCDPNaive` (never benched):
- Miss-only scan (not every load)
- TLB responses tracked by id register-file (not FIFO order — fixes a
  correctness bug when responses arrive out of order)
- Full same-page requirement (not just upper-matchBits) — defends against
  data words that accidentally pass the matchBits gate but then translate
  to invalid/MMIO paddr, which caused health fabric errors in an earlier
  cross-page version.
- 1024-entry dedup filter (Cooksey had none, recurring pointer words would
  issue duplicate prefetches).

## Results (vs decay16 CDP baseline)

| Bench | NoPref | L2 (best PC/TT) | BM (this) |
|---|---:|---:|---:|
| em3d | 83,355 | 87,949 | **84,048** |
| health | 1,258,698 | 1,341,304 | **1,254,022** |
| patricia | 1,416,398 (FAIL*) | 1,325,868 (FAIL*) | 1,418,019 (FAIL*) |
| treeadd | 564,733 | 723,118 | **588,326** |
| voronoi | 202,004 | 212,958 | **202,056** |

*Patricia's "FAIL 1" is a pre-existing test harness issue — all variants
including NoPref return tohost=3 on this binary. Cycle counts are valid for
speedup comparison.

| Variant | em3d | health | patricia | treeadd | voronoi | GEOMEAN |
|---|---:|---:|---:|---:|---:|---:|
| decay16 (CDP baseline) | 0 | 0 | 0 | 0 | 0 | 0% |
| decay256 | +3.5% | +2.1% | +4.6% | +4.5% | +2.9% | +3.52% |
| L2 (prior best PC/TT) | +3.9% | +2.2% | +5.9% | +5.9% | +2.9% | +4.14% |
| NoPrefetcher | +9.6% | +8.9% | -0.9% | +35.6% | +8.5% | **+11.72%** |
| **BM (this)** | +8.7% | +9.3% | -1.0% | +30.1% | +8.5% | **+10.67%** |

**Vs NoPref:**

| | em3d | health | patricia | treeadd | voronoi | GEOMEAN |
|---|---:|---:|---:|---:|---:|---:|
| L2 | -5.2% | -6.2% | +6.8% | -21.9% | -5.1% | -6.78% |
| BM | -0.8% | +0.4% | -0.1% | -4.0% | -0.0% | **-0.93%** |

## Analysis

**BM is essentially tied with "no prefetcher at all" (-0.93% vs NoPref)**, while
every PC/TT-learning CDP variant is a significant net loss (-6 to -10% vs
NoPref). The same-page filter defeats the pathologies:
- treeadd's "both children loaded in same line" — BM prefetches the child
  that's actually followed since it's discovered only from miss-fetched
  lines rather than every demand access, and only within the same page so
  it hits the real heap region.
- health's list->forward chains — same-page works because the list nodes
  live in one heap region.

**Why BM beats L2 so dramatically:** L2's stride-hybrid +4.14% fights an
uphill battle because the PC/TT pipeline itself (every decision goes through
a 64-deep FIFO with BRAM reads, conf updates, attribTable lookups) adds
cycles per prefetch decision. BM has no pipeline state — TLB request goes
out straight from the line scan, immediately.

## Dissertation implication

For this 5-benchmark pointer-chase suite on Toooba:
- The original Cooksey bit-matching primitive, combined with a minimal
  dedup filter and miss-only gating, captures essentially all of the
  prefetch value achievable by the PC/TT-learning CDP variants.
- The PC/TT-learning layer adds pipeline overhead that dominates over
  whatever filtering benefit it provides on this benchmark mix.
- Direction for future iteration: keep BM as the base and add targeted
  extensions (e.g. NV3 stride-fusion, allow-cross-page-with-paddr-check)
  rather than re-visiting the PC/TT design space.

## Gotchas

1. **Patricia "FAIL 1" is NOT a CDP bug** — it fails on every variant
   including NoPrefetcher. The tohost=3 exit code is a pre-existing test
   issue in the binary itself. Cycle counts are still meaningful for
   speedup comparison.
2. **Cross-page variant caused health fabric error** — translating
   bit-match-derived addresses from cross-page candidates occasionally
   produced paddrs outside main memory, triggering the AXI fabric's
   DECERR response. Same-page filter eliminates this.
3. **Existing mkCDPNaive has a TLB-response-ordering bug** — it uses a
   FIFO to track pending candVaddrs without using the TLB response id,
   which can cause wrong vaddr↔paddr pairing when TLB responses arrive
   out of order. BM fixes this using id-keyed register file.
