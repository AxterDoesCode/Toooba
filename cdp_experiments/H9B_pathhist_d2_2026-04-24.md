# H9B (H7 + D2-style XOR-of-last-4 path signature) — negative, but no crash

Date: 2026-04-24
Source: `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitchH9B.bsv`
Logs: `builds/RV64ACDFIMSU_Toooba_bluesim/Logs/*.bin.log`

## Design

H9B = H7 + D2-style order-independent path-history signature.

```bsv
Reg#(Vector#(4, Bit#(16))) pathHist <- mkConfigReg(replicate(0));

function Bit#(16) pathSigFn(Vector#(4, Bit#(16)) h);
    return h[0] ^ h[1] ^ h[2] ^ h[3];
endfunction

// In drainIncomingEvents on EvDemandLdMiss / EvDemandLdHit:
scanSig  = getPcHash(req) ^ pathSigFn(pathHist);   // read BEFORE update
pathHist <= shiftInAt0(pathHist, getPcHash(req));  // ring buffer
```

Key difference from H9 (D-style shift-XOR): D2 is **order-independent**.
Paths A→B→C and B→A→C produce the same signature, collapsing
permutations into the same pcTable bucket.

## 8-bench results (cycles vs NoPref2, H7, H9)

| bench     |   NoPref2 |        H7 |    H9 (D) |    H9B (D2) |   H9B−H7 |
|:----------|----------:|----------:|----------:|------------:|---------:|
| bh        | 1,219,571 | 1,219,582 | 1,219,582 |   1,219,582 |       +0 |
| bisort    |   989,251 |   985,152 |   988,048 |     988,035 |   +2,883 |
| em3d      | 1,739,832 | 1,739,043 | 1,741,611 |   1,740,793 |   +1,750 |
| health    | 1,258,698 | 1,246,504 | **CRASH** |   **1,251,378** |   +4,874 |
| patricia  | 1,416,398 | 1,245,569 | 1,413,665 |   1,411,424 | **+165,855** |
| perimeter | 2,692,517 | 2,692,523 | 2,692,523 |   2,692,523 |       +0 |
| treeadd   |   564,733 |   558,042 |   561,179 |     559,894 |   +1,852 |
| tsp       | 6,638,315 | 6,638,321 | 6,638,321 |   6,638,321 |       +0 |

## Geomeans

| variant | 8-bench vs NoPref2 | 7-bench (excl. health) |
|:---|---:|---:|
| H7 (reference)     | **−1.9161%** | **−2.0506%** |
| H9 (D, shift-XOR)  | −0.6975% *[health=crash-time 1200222]* | −0.1203% |
| **H9B (D2, XOR-4)** | **−0.2325%** | **−0.1825%** |

8-bench vs H7:
- H9 looks better than H9B at 8-bench, but H9's "health" number is a
  crash-time value at 1,200,222 (simulator exited early on DECERR —
  *shorter* than a real completion would be), so the geomean is
  artificially favorable.
- H9B includes a real PASS for health at 1,251,378, and is a **fair**
  comparison.

Net: H9B regresses **+1.68 pp geomean** vs H7 on 8-bench, **+1.87 pp** on
7-bench. Slightly better than H9's 7-bench (+1.93 pp) but still a major
regression.

## Two clean experimental outcomes

### 1. Order-independence eliminates the DRAM-safety issue

H9 (D-style) crashed on health with an AXI DECERR at cycle 1,200,222.
Mechanism: a specific `(PC, ordered-path)` bucket accumulated `conf=7`
on an offset whose pointer value translated to unmapped DRAM. H7's
single-PC averaging would have cancelled this offset; H9's path
separation allowed the false-high conf to persist.

H9B does not crash. Health runs to completion at 1,251,378 (+4,874 cyc
vs H7, +0.39%). D2's order-independence shrinks the signature space:
for the same set of ~4 recent PCs, D generates ~24 distinct signatures
(permutations of 4 elements), while D2 generates 1. That 24× reduction
of distinct buckets reduces the chance of a specific path accumulating
high conf on a bad offset.

**Takeaway:** when path history MUST be used, D2 is strictly safer than D.
The "D beats D2" conclusion from 2026-04-20 (pre-H4) was based on
aggregate cycle counts that hid the latent correctness issue.

### 2. Patricia training dilution is not fixed by order-collapse

Patricia's regression under H9: **+13.50%** vs H7.
Patricia's regression under H9B: **+13.32%** vs H7.

Virtually identical. D2's permutation-collapse does NOT help here.

Why? Patricia's hot PC is reached via paths that differ in **which PCs
are recent**, not in their order. Different trie-node lookups traverse
different depth-paths (different call sites in the trie walk), so the
*set* of recent PCs is itself different per visit. D and D2 both
produce distinct sigs for distinct sets.

**Takeaway:** training dilution is about path-set diversity, not
path-order diversity. Neither D nor D2 can fix patricia at 1024-entry
pcTable sizing.

## Three-way comparison summary

|                    | D-style (H9)        | D2-style (H9B)       |
|:-------------------|:--------------------|:---------------------|
| Signature mixing   | shift-XOR chain     | ring buffer + XOR reduce |
| Order-sensitive?   | Yes                 | **No**               |
| Distinct sigs/PC   | Max (permutations count) | Min (sets only) |
| Health (safety)    | **Crashed (DECERR)** | Completed, +0.39% |
| Patricia (dilution) | +13.50%            | +13.32% (same)       |
| Geomean vs H7      | +1.93 pp regression | +1.87 pp regression |

D2 is strictly better than D on safety and marginally better on
geomean, but neither is competitive with H7.

## What this tells us

The hypothesis "path history was held back by pre-H4 back-pressure" is
**falsified twice** — both D-style and D2-style H7 rebaselines regress
significantly. The underlying issue is 1024-entry pcTable sizing being
too small to hold per-signature confidence for the path-diversity
typical of these Olden benchmarks.

**H7's single-PC averaging acts as a confidence aggregator across all
paths.** Both path-history variants replace this aggregator with
per-signature isolation, which fails because:
- Training signals scatter (patricia: many paths, no single reaches threshold)
- False-high confidence accumulates in under-trained buckets (health: bad offsets escape averaging)

## Rescue paths (if continuing down this road)

1. **Enlarge pcTable** to 4096 or 8192 entries. More buckets for the same
   signature keyspace would reduce dilution proportionally. Biggest BRAM
   cost but most principled fix.
2. **Aggressive signature compression.** Mask pathSig to 4 or 8 bits
   before XOR. Reduces distinct-signature count. Might help patricia
   but loses path discrimination — worth a 30-min try.
3. **Confidence-weighted PC keying.** `pctIdx = hash(pcHash)` by default,
   `hash(pcHash ^ pathSig)` only when base entry's conf<2 (i.e., path
   refinement only for PCs that *need* it). More code, but addresses
   both dilution (by falling back to PC-only for well-trained PCs) and
   safety (averaging still present for high-conf PCs).
4. **Drop path history entirely.** H7 remains the dissertation reference.
   Move to a different direction (per-decision PPF, larger prefetchFilter
   for better attribution, etc.).

Given the consistent negative results across both D and D2, option 4 is
the recommendation unless a specific research angle (e.g., "path context
matters for a *specific* data structure") is worth defending.

## Artifacts

- Source: `CDPKillSwitchH9B.bsv`
- Logs (this run): `builds/RV64ACDFIMSU_Toooba_bluesim/Logs/*.bin.log`
- H9 (D-style, for comparison): `/local/scratch/ac2822/NewTooobaLogs/variantH9_pathhist_2026-04-24/`
- Memo (H9): `cdp_experiments/H9_pathhist_2026-04-24.md`
