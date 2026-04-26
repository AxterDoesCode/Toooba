# SPP + Cooksey — fusion design memo

Date: 2026-04-23
Context: SPP v1 (−0.72% geomean) vs H7 (−1.92%) on Olden. SPP wins on
health (−4.94%) but loses badly on patricia (−0.98% vs H7's −12.06%).
Patricia is a pointer-chase benchmark — exactly the regime Cooksey bit-
matching was designed for. This memo proposes fusing the two mechanisms.

## Deep analysis: what each mechanism sees and misses

### SPP (Kim et al. MICRO '16)
- **Input**: access paddr (addr only; no line data, no PC).
- **State**: per-page 12-bit signature compressing last 4 deltas +
  signature-indexed global pattern table with top-4 (delta, Cdelta)
  predictions.
- **Output**: prefetch addresses `current_line_addr + predicted_delta`.
- **Lookahead**: recursively spawn signatures from predicted deltas
  until path confidence Pd < Tp.
- **Strengths**: any delta sequence learnable in 12 bits; cross-page
  transfer via GHR (paper §III.D); adapts throttle via α.
- **Weaknesses**:
  1. Delta space is bounded to the current 4KB page. Accesses that
     jump to a different page lose signature context (paper addresses
     this with GHR; our port omits GHR).
  2. Pointer-chase across arbitrary pages (patricia-style) has no
     stable delta pattern — SPP sees random "cross-page" events and
     issues low-confidence prefetches or none.
  3. SPP learns from **addresses only** — never looks at cache-line
     DATA. It cannot see "the next access will be at address X"
     unless a delta pattern has been observed repeating.

### Cooksey bit-matching (CDP-family, original Cooksey et al.)
- **Input**: access paddr + full 64-byte cache line DATA.
- **State**: dedup filter (optional), no predictor state.
- **Output**: for each of the 8 aligned 64-bit words in the returned
  line, test if the word is pointer-shaped (upper `matchBits` agree
  with current access's VPN, optionally low-bits-aligned). If so,
  prefetch that target line.
- **Strengths**:
  1. Crosses pages freely — if line content contains a vaddr pointing
     to another page, Cooksey chases it.
  2. Zero training time — fires on first access to a pointer-carrying
     line.
  3. Perfect for scattered pointer-chase (patricia, treeadd internal
     links).
- **Weaknesses**:
  1. No delta learning — can't predict strided array iteration.
  2. Noisy on data-dense benches — integers with upper bits matching
     a VPN coincidentally trigger false prefetches.
  3. Emits one prefetch per pointer candidate, which can be up to 8
     per cache line; aggressive bandwidth cost.

### Orthogonality

The two mechanisms are **complementary**, not overlapping:

| Pattern type                  | SPP handles | Cooksey handles |
|:------------------------------|:-----------:|:---------------:|
| Strided array iteration       |     ✓       |        —        |
| Linked list (same-page)       |     ✓       |        ✓        |
| Linked list (cross-page)      |     GHR     |        ✓        |
| Tree traversal (random pages) |     —       |        ✓        |
| Pointer in struct, data array |     —       |        ✓        |

Cooksey handles exactly the regime SPP struggles with: **pointer values
stored in cache lines that point to arbitrarily distant pages**. This
matches patricia's trie traversal, where each trie node is independently
heap-allocated and next-node addresses are chased through pointer fields.

## Design options

### Option A: Cooksey fires only when SPP's initial PT lookup produces
zero candidates (cold-PT fallback)
Minimally invasive: SPP issues prefetches when the current PT entry has
≥1 delta with Cd ≥ Tp. If the PT lookup returns zero valid predictions
(e.g. cold entry, or aliased signature), fall through to Cooksey scan.
Mechanism: tap the `pteFromPtToCalc` rule; if all 4 deltas fail the
threshold AND depth == 0 (base lookup, not a lookahead recursion), do
a Cooksey scan.

**Intuition**: SPP first, Cooksey as backup. SPP doesn't get polluted.
**Cost**: adds 1–8 prefetches per cold PT event. Cold events are
concentrated in warmup and on page transitions.
**Targets**: patricia (weak PT coverage), em3d (mixed patterns).

### Option B: Cooksey fires on new-page ST allocation (bootstrap)
When the ST creates a fresh entry (`signature=0`), do a Cooksey scan of
the returned line and enqueue prefetches for pointer candidates.
Mechanism: add a hook in `processStRead`'s "else" branch (the
replace-way case). Bypass PT entirely — these are discovery prefetches,
not pattern-matched.

**Intuition**: Replaces the paper's GHR in spirit. GHR bootstraps new
pages by continuing a delta pattern from a previous page; Cooksey
bootstraps by finding pointers in the new page's content.
**Cost**: one scan per ST allocation. ST has 256 entries; on tight
working-set benches, this fires dozens to hundreds of times total.
**Targets**: patricia (fresh trie-node pages), tree benchmarks.

### Option C: Cooksey augments every PT lookahead output
Every time SPP issues a prefetch, also issue Cooksey-candidate prefetches
derived from the current access's line.
**Pros**: Very aggressive coverage.
**Cons**: Doubles prefetch volume on every access; tsp-regression
territory. Rejected.

### Option D: Cooksey-aware signature
Add 1 bit to the signature: "line contains ≥1 Cooksey pointer". PT
now distinguishes pointer-carrying pages from data-dense pages.
**Pros**: Integrates cleanly.
**Cons**: Signature width grows to 13 bits, breaks existing PT index
geometry; complex change with unclear gain. Rejected.

### Option E: Cooksey-gated PT training
Only update ST/PT if line passes Cooksey pointer-shape test. Filter
out pure-data-array accesses from training.
**Pros**: Reduces PT noise.
**Cons**: Heuristic; loses legitimate patterns on mixed-content lines
(e.g. em3d nodes have both pointers and floats). Rejected.

## Recommendation: combine A + B

**SPP-Cooksey v1** = SPP + (B) bootstrap new pages + (A) fallback on
cold PT. These are both "fill-in where SPP is weak" interventions and
compose cleanly:

- On `reportAccess(addr, line, ...)`:
  - ST lookup: if new-page (miss), enqueue a **line-scan** of `line`
    alongside the normal SPP path. **(B)**
  - ST hit & delta > 0: normal SPP PT lookup + lookahead. If the PT
    lookup produces no Cd above Tp at depth=0, enqueue a **line-scan**
    fallback. **(A)**
- Line-scan: for each of 8 aligned 64-bit words in `line`:
  - If upper `matchBits` bits agree with the access's VPN (matchBits=16
    for same ~8MB region, default) and low 3 bits of the candidate
    are zero (pointer alignment), enqueue the candidate's line-addr
    into the existing prefetch filter pipeline.

### Why this fits dissertation work

1. **Clean story**: SPP (paper baseline) + Cooksey (classical pointer
   prefetcher from 1997) + your insight (structural fusion that fills
   SPP's blind spot on pointer-chase workloads).
2. **No overlap with existing CDP variants**: CDP alone uses Cooksey;
   SPP alone uses deltas. This specifically uses Cooksey as a plug-in
   to SPP's mechanism — a novel composition.
3. **Targets SPP's documented weakness**: the paper itself flags mcf
   (random pointer-chase) as where SPP underperforms. Our Olden
   benches have the same shape on patricia.
4. **Orthogonal to GHR**: if we later add the paper's GHR, it handles
   delta-continuation across pages; Cooksey handles pointer-discovery
   across pages. Both can coexist.

## What we expect to see

- **Patricia**: significant improvement (SPP only got −0.98%; Cooksey
  targets patricia's strength). Possibly halfway to H7's −12%.
- **Treeadd**: no change or slight improvement. Treeadd's pointer-chase
  is tight recursion; Cooksey candidates land mostly in already-touched
  lines (late).
- **Health**: neutral to slight improvement. SPP already dominates
  health; Cooksey may add pollution.
- **Em3d**: neutral — em3d has many float-data lines that Cooksey's
  bit-match will misidentify as pointers. Could go either way.
- **Tsp**: neutral to slight regression. Tsp is store-dominated;
  Cooksey fires on store-training events and adds more prefetches on
  top of SPP's already-regressing 23k issues.
- **Bh, bisort, perimeter**: neutral.

Net geomean expectation: −1.0% to −1.5%, closing part of the gap
between SPP (−0.72%) and H7 (−1.92%) via a different route.

## Implementation plan

1. Copy `SPP.bsv` as `SPPCooksey.bsv`, module name `mkSPPCooksey`.
2. Add a `cookseyScan(lineAddr baseLine, Line line, Vpn accessVpn)`
   helper that for each 64-bit word, returns whether it's pointer-
   shaped and its target lineAddr.
3. Modify the `reportAccess` method to ALSO pass the `line` and `Vpn`
   into SPP (currently discarded). Thread `line`+`vpn` through the ST
   interface so the ST's `reportAccess` can flag new-page events
   back to a Cooksey-scan rule.
4. Add a parallel Cooksey scan path: dequeue line-scan events, emit
   pointer candidates into the same TLB+filter pipeline SPP already
   uses.
5. Fallback hook: in the PT-to-Calculator path, if depth=0 and all
   Cdelta < Tp, emit a Cooksey-scan event.

Keep SPP's signature/PT/PrefetchFilter pathways unchanged. This is
strictly additive — Cooksey plugs in as an extra producer into the
existing prefetch-issue pipeline.

Estimated effort: ~100 LOC delta vs SPP.bsv, ~4 hours build + bench.
