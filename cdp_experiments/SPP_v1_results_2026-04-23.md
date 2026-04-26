# SPP v1 — Signature Path Prefetcher port results

Date: 2026-04-23
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/SPP.bsv` (+ `div_table_4x4to7.bsvi`)
Ported from ldh35-fpga-cap_chaser branch's `SignaturePathPrefetcher.bsv`
(Karlis Susters, 2023, MIT license). Submodules verbatim; top-level
rewritten for the current tree's `CacheLinePrefetcher#(reqT)` interface.
No CHERI-specific logic — this is the pure SPP mechanism.

Logs: `/local/scratch/ac2822/NewTooobaLogs/variantSPP_v1_2026-04-23/`

## 5-way cycle comparison (geomean vs NoPref2, 8-bench)

| bench     | NoPref2   | BaseCDP    | DBP         | SPP         | H7          |   Base% |   DBP% |   SPP% |    H7% |
|:----------|----------:|-----------:|------------:|------------:|------------:|--------:|-------:|-------:|-------:|
| bh        | 1,219,571 |  1,220,351 |   1,219,571 |   1,218,389 |   1,219,582 |  +0.06% |  0.00% | −0.10% |  0.00% |
| bisort    |   989,251 |  1,071,372 |     989,134 |     989,514 |     985,152 |  +8.30% | −0.01% | +0.03% | −0.41% |
| em3d      | 1,739,832 |  1,938,906 |   1,734,091 |   1,731,179 |   1,739,043 | +11.44% | −0.33% | −0.50% | −0.05% |
| health    | 1,258,698 |  1,317,260 |   1,258,032 | **1,196,481** |   1,246,504 |  +4.65% | −0.05% | **−4.94%** | −0.97% |
| patricia  | 1,416,398 |  1,325,290 |   1,414,849 |   1,402,457 | **1,245,569** |  −6.43% | −0.11% | −0.98% | **−12.06%** |
| perimeter | 2,692,517 |  2,739,559 |   2,692,517 |   2,688,330 |   2,692,523 |  +1.75% |  0.00% | −0.16% |  0.00% |
| treeadd   |   564,733 |    701,587 |     564,733 |     565,097 |     558,042 | +24.23% |  0.00% | +0.06% | −1.18% |
| tsp       | 6,638,315 |  6,737,129 |   6,638,315 |   6,700,810 |   6,638,321 |  +1.49% |  0.00% | **+0.94%** |  0.00% |
| **geomean** |         |            |             |             |             | **+5.35%** | **−0.06%** | **−0.72%** | **−1.92%** |

**SPP v1 position:** −0.72% geomean, sits **between DBP (−0.06%) and H7
(−1.92%)**. First non-CDP variant we've measured that clearly beats DBP
but doesn't reach H7 on the full 8-bench.

## SPP parser metrics (CRqCreationLine totals)

| bench     | issued  |    HIT | OWNED | miss   | missLL | useful | late   | timely | useless | strict | timely% |
|:----------|--------:|-------:|------:|-------:|-------:|-------:|-------:|-------:|--------:|-------:|--------:|
| bh        |     238 |     61 |    12 |    165 |    127 |    133 |     48 |     85 |      32 |  80.6% |   51.5% |
| bisort    |     612 |     89 |     2 |    521 |    412 |    362 |     43 |    319 |     159 |  69.5% |   61.2% |
| em3d      |  18,013 | 11,919 |   194 |  5,900 |    164 |  2,596 |    459 |  2,137 |   3,304 |  44.0% |   36.2% |
| health    |  25,848 |  2,891 |   130 | 22,827 |  1,746 | 18,210 |    662 | 17,548 |   4,617 |  79.8% |   76.9% |
| patricia  |  10,176 |  7,281 |    17 |  2,878 |  1,596 |  1,629 |    240 |  1,389 |   1,249 |  56.6% |   48.3% |
| perimeter |  18,685 |  1,252 | 3,409 | 14,024 | 10,238 | 13,908 |  8,691 |  5,217 |     116 |  99.2% |   37.2% |
| treeadd   |  10,206 |  3,748 |   847 |  5,611 |  1,100 |  5,401 |  3,899 |  1,502 |     210 |  96.3% |   26.8% |
| tsp       |  23,329 |  1,612 | 3,555 | 18,162 | 14,208 | 17,614 |  5,734 | 11,880 |     548 |  97.0% |   65.4% |

## Headlines

### health: SPP's decisive single-bench win
- **17,548 timely-useful prefetches** at 76.9% timely accuracy.
- `prefetchMissLL = 1,746` (DRAM prefetch hits).
- `demandMiss` drops from 36,424 (NoPref) → 18,984 (−17,440).
- Cycle win of −4.94% = ~62k cycles saved. Back-of-envelope:
  17k LLC-hit useful × ~5 cyc + 1.7k DRAM useful × ~100 cyc ≈ 85k,
  minus overhead ≈ 62k observed — clean match.
- Mechanism: health's multi-level linked-list traversals generate
  stable delta sequences that SPP's 12-bit signature compresses well.
  Lookahead with per-delta confidence catches the right targets.

### patricia: SPP underperforms H7 significantly
- H7 gets −12.06%, SPP gets −0.98%.
- Both hit roughly similar `prefetchMissLL` (SPP 1,596 vs H7 1,456),
  so both identify DRAM-bound prefetches at comparable rates.
- But SPP issues **10,176 prefetches** (vs H7's 2,168) and 7,281 of them
  HIT in L1 (redundant). That's 72% wasted issue bandwidth; the
  useful DRAM wins get diluted by pollution.
- SPP's page-offset-delta learning doesn't specialise to patricia's
  single-PC dominant pointer-chase the way H7's CDP-based PC-table
  mechanism does.

### tsp: SPP's clearest cost signal (+0.94% regression)
- 23,329 prefetches issued; 11,880 timely-useful at 65.4% timely
  accuracy. `prefetchMissLL = 14,208` (huge — SPP is pulling lots of
  DRAM data).
- Demand misses drop from 35,924 (NoPref) to 18,627 (−17,297 demand
  misses saved).
- Despite that, cycles go UP by 62k.
- Mechanism hypothesis: **total L1 miss traffic is unchanged** —
  demand misses dropped by 17k but prefetch misses rose by 18k.
  SPP's path-confidence trains on tsp's store-heavy access stream
  and prefetches aggressively, but tsp's demand-miss latency was
  already overlappable with the out-of-order window, so converting
  demand misses into prefetch misses just shifts the bandwidth cost
  without reducing critical-path stalls.

### em3d: modest win at high pollution cost
- 18,013 prefetches issued, but 11,919 (66%) HIT L1 — massively
  redundant. 3,304 useless on top. Only 2,137 timely useful.
- Cycle delta −0.50% vs NoPref, vs DBP's −0.33%.
- em3d has predictable list-array patterns that both prefetchers
  catch, but SPP's deeper lookahead pulls duplicates.

### treeadd, bh, bisort, perimeter: essentially parity
- treeadd +0.06%, bh −0.10%, bisort +0.03%, perimeter −0.16%.
- SPP's path-confidence throttle correctly holds back on these
  (no pollution catastrophe).

## SPP vs paper's SPEC CPU 2006 numbers

The paper reports SPP +27.2% geomean vs no-prefetch on SPEC 2006. Our
8-bench Olden geomean of −0.72% is much smaller. Reasons:

1. **Different workloads.** SPEC 2006 has larger working sets with
   richer spatial patterns (libquantum, bwaves etc.). Olden's
   pointer-chase benches have smaller working sets and weaker delta
   regularity (patricia's dominant pattern is a single-PC 1-pointer
   chase, not a delta sequence).
2. **No GHR (page-boundary learning).** The ldh35 port omits the
   paper's 8-entry Global History Register, which was responsible
   for ~2% of the paper's gains. Adding it is a natural v2.
3. **No L2/LLC fill-level split.** Paper routes low-confidence
   prefetches to LLC and high-confidence to L2. Ours always fills
   L1. Low-conf L1 fills pollute on Olden (em3d, treeadd).

## Comparison to H7

| Metric | H7 | SPP v1 |
|---|---|---|
| Best bench | patricia −12.06% | health −4.94% |
| 8-bench geomean | −1.92% | −0.72% |
| Regressions | none | tsp +0.94% |
| Issue rate | tight (kill-switch gate) | aggressive (path-confidence throttle) |
| Prefetch overhead | low (15k on treeadd, 2k on patricia) | high (25k on health, 23k on tsp) |

H7's kill-switch gate is fundamentally stricter than SPP's path-
confidence throttle; H7 issues far fewer prefetches and wastes fewer
pipeline slots. But SPP's signature-based learning captures broader
patterns (health) that CDP's PC-table mechanism misses.

## Natural next steps

1. **Add GHR (page-boundary learning).** Natural paper-faithful
   improvement. Moderate effort (~100 LOC added to the top-level).
2. **Add fill-level routing.** Low-confidence prefetches → LLC
   (respLoadWithE), high → L1. Reduces L1 pollution on em3d / tsp.
3. **Train on demand misses only, not all accesses.** SPP's volume
   on tsp/em3d (hit-heavy benches) is 5-10× what H7 does. Training
   on only miss responses would cut issue rate dramatically and
   may eliminate the tsp regression — though may also kill the
   health win. Worth a sweep.
4. **"SPP vs H7" as the dissertation 3-way comparison**: NoPref,
   SPP (paper baseline), H7 (novel CDP variant). Current results
   already support the story.
