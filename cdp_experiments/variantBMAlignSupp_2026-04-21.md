# Variant BMAlignSupp-MB27 — BMPolySupp + pointer-shape filter

Date: 2026-04-21  •  Config: `DATA_PREFETCHER_TYPE=CDP_BMALIGNSUPP` + `matchBits=27`

## Hypothesis
BMPolySupp's 30.9% issued-accuracy on treeadd (1169 useful / 3788 issued)
is "detection-bound" not "timing-bound". We can't separate timing-good from
timing-bad prefetches without learning, but we CAN tighten the pointer
detector further to kill residual data-looks-like-pointer false positives.

**Additions on top of BMPolySupp:**
- Candidate word must be **16-byte aligned** (low 4 bits == 0). Heap objects
  from glibc malloc / C++ `new` are 16-byte aligned; random integers rarely
  are.
- Candidate word must have **upper 25 bits zero** (bits [63:39]). Addresses
  in Toooba's physical map fit in 39 bits; a word with nonzero upper 25 bits
  is definitely data.
- Candidate must be **non-null**.

## Result — cycles vs NoPref (lower is better)

| bench | NoPref | BMPolySupp | BMAlignSupp | Δ vs NoPref | Δ vs Supp |
|---|---:|---:|---:|---:|---:|
| bh       | 1,219,571 | 1,219,571 | 1,219,571 |  0.00% | 0.00% |
| bisort   |   989,251 |   988,690 |   988,690 | +0.06% | 0.00% |
| em3d     |    83,355 |    83,099 |    83,104 | +0.30% | 0.00% |
| health   | 1,258,698 | 1,261,339 | 1,258,698 |  0.00% | +0.21% |
| patricia | 1,416,398 | 1,416,398 | 1,416,398 |  0.00% | 0.00% |
| perimeter| 2,692,517 | 2,692,517 | 2,692,517 |  0.00% | 0.00% |
| treeadd  |   564,733 |   567,223 |   567,223 | -0.44% | 0.00% |
| tsp      | 6,638,315 | 6,638,315 | 6,638,315 |  0.00% | 0.00% |

**Geomean:** BMAlignSupp = **-0.01% vs NoPref** (new best; up from -0.04%).
Health's regression was fully recovered.

## Mechanism analysis — per-benchmark prefetch counts

| bench | Supp cand→issued→useful | Align cand→issued→useful |
|---|---|---|
| em3d    |   157 →    38 →    7 (18% acc) |   205 →    48 →   16 (33% acc) |
| treeadd |10,682 →  3,788 → 1169 (31% acc) |10,682 →  3,788 → 1169 (31% acc) |
| health  |15,604 →  5,732 →  225 ( 4% acc) |   623 →     7 →    0 ( 0% acc) |
| bisort  | 1,728 →   334 →  172 (51% acc) | 1,728 →   334 →  172 (51% acc) |

**Health is the big win.** Supp's 5,732 issued prefetches at 4% accuracy were
pure pollution — 5,507 useless prefetches costing ~2,641 cycles. AlignSupp's
pointer-shape filter kills almost all of them (issued 7 vs 5,732), restoring
NoPref timing.

**Em3d subtle behavior.** Align has MORE candidates than Supp (205 vs 157)
because the isPtrShape filter is applied during match-count computation: a
line that had 2 raw VPN-matches but only 1 passed the shape test is now
"single-match" instead of "multi-match suppressed". The filter effectively
separates real-pointer words from "coincidentally VPN-matching" data words
within the same line.

**Treeadd unchanged.** Treeadd's pointers are all valid SV39 vaddrs (shape
test passes trivially); the existing multi-match detector is already doing
the right thing.

## Conclusion
Pointer-shape filters (alignment + upper-bits zero) kill detection-level
false positives that remained after VPN-matching + same-page. The gain is
concentrated on health (which had many data words coincidentally matching
VPN). Suite-wide geomean improves from -0.04% to -0.01% vs NoPref.

## Next
- BMAlignSupp-MB24 (relax same-page): does cross-page pointer-chasing
  benefit from the tighter shape filter?
- 8-byte alignment variant: softer shape gate, more candidates allowed.
- Combine BMAlignSupp with BM-EARLY (stride-on-hit) to re-introduce the
  +1.0% line+1 stride gain while keeping the tight detector.
