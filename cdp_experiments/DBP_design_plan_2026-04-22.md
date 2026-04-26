# DBP design plan — Dependence-Based Prefetching in Toooba

Target: implement the Roth / Moshovos / Sohi (ASPLOS '98) Dependence-Based
Prefetcher as a comparison baseline for the dissertation, plus an augmented
variant that layers Cooksey bit-matching on top.

This is a PLAN, not an implementation. Review before I start coding.

---

## 1. Paper's core mechanism (in one paragraph)

DBP dynamically identifies **pointer-load producer→consumer pairs** at
runtime and replays the producer's value through the consumer's
address-generation template to prefetch the consumer's target. Two core
structures: the **PPW** (Potential Producer Window — 128 entries, keyed
by recently-loaded *value*) records `(loaded_value, producer_PC)` for each
committed load. The **CT** (Correlation Table — 256 entries, keyed by
producer-PC) stores `(producer_PC, consumer_PC, template)` correlations
where `template = (opcode, offset)` of the consuming load. At commit, a
consumer's base-register-value is probed against PPW; on a hit, a CT
correlation is created. At load completion, the *producer*-PC is probed
against CT; on a hit, `prefetchAddr = loaded_value + template.offset` is
enqueued. Prefetched blocks sit in a 32-entry Prefetch Buffer (PB) where
their completion spawns further prefetches (dataflow cascade). A
single-instance-ahead counter throttles errant prefetch chains to length 1.
Claimed Olden speedups: 1–25%, avg ~10%.

Key insight: dependence is captured by **value equality** across a window,
not by address-stream arithmetic. This captures non-strided pointer
chasing where Markov / stride / RPT predictors fail.

---

## 2. Toooba adaptation — what's possible with the existing prefetcher interface

The `CacheLinePrefetcher` interface (Prefetcher_intf.bsv) gives us:
```bsv
method Action reportAccess(Addr addr, Bit#(16) pcHash, HitOrMiss hitMiss,
                           Line line, Vpn reqVpn, MemOp op, Bool isPrefetch);
method Action reportIncomingCacheLine(reqT req, Line line, ...);
method Action reportEviction(LineAddr lineAddr);
method Action reportUsefulPrefetch(LineAddr lineAddr);
method ActionValue#(PendingPrefetch) getNextPrefetchAddr();
```

Crucial: **`reportAccess` fires on every L1 access** (hit OR miss), with
`addr` (effective paddr), `pcHash` (PC of the accessing load), `line`
(the 64-byte line of data being accessed), and `op` (Ld/St). This is
close enough to per-load commit visibility for a faithful DBP port.

### Three gaps vs the paper, and how we resolve each

| Paper assumes | Toooba gives us | Resolution |
|---|---|---|
| Per-load committed (PC, base-value, loaded-value, width) | Per-L1-access (pcHash, addr, line) — 64-byte granularity | Treat the 8 aligned 64-bit words of `line` as a producer's candidate "loaded values" (any one of them could have been what the load actually consumed, or will feed a later consumer). |
| PPW keyed by arbitrary load-value | No 64-bit hash BRAM is cheap at scale | 128-entry BRAM, keyed by 7-bit hash of value. Entry carries {value, producer_PC, valid}. |
| Template = (opcode, offset) from the consuming load | We don't see the static load encoding at the prefetcher layer | Simplify: offset=0 templates only. A correlation fires when `consumer_paddr == producer_loaded_value` exactly. This captures the common pointer-chase case (`p = p->next` where the loaded value IS the next element's address). Non-zero-offset correlations (e.g. `p = p->next->left`) are NOT captured in v1. |
| Prefetch Buffer (separate 1 KB cache) | Toooba prefetches fill L1 directly | Reuse the existing CDP prefetch-filter for dedup (1024 entries). Prefetched lines land in L1 with `wasPrefetch=True`, the existing machinery. |

This is a fair approximation: the mechanism still **learns
PC-to-PC correlations via value equality**, which is DBP's core novelty.
What's lost: (a) non-zero-offset templates, (b) dataflow cascade via
completing prefetches re-probing the CT. (b) can be added later; (a) is
a bigger fidelity gap but acceptable for v1.

---

## 3. Data structures

```bsv
typedef struct {
    Bit#(64) value;            // address-sized loaded value
    Bit#(16) producerPC;       // pcHash of the load that produced it
    Bool     valid;
} PPWEntryT deriving (Bits, FShow, Eq);

typedef struct {
    Bit#(16) producerPC;
    Bit#(16) consumerPC;
    Bit#(3)  confidence;       // saturating 3-bit; +1 on correct match, -1 on PPW miss with same prod
    Bool     valid;
} CTEntryT deriving (Bits, FShow, Eq);
```

| Structure | Geometry | Index | Entry size |
|---|---|---|---|
| **PPW** | 128-entry direct-mapped | `hash(value)` → 7 bits | ~81 bits |
| **CT**  | 256-entry direct-mapped | `hash(producerPC)` → 8 bits | ~36 bits |
| **pendingPrefetch filter** | 1024-entry direct-mapped (reuse CDP's) | line-addr hash | Maybe#(LineAddr+pcHash) |
| **incomingQ** | 32-entry `mkOverflowBypassFifo` (H7 lesson) | FIFO | ~220 bits per entry |

Paper's PB (32×32B buffer) maps to Toooba's existing L1-fill machinery;
no separate buffer needed.

---

## 4. Rule-level flow

### 4.1 `reportAccess` (staged into `incomingQ`, H7-style)

Method body is a single enq:
```
incomingQ.enq({pcHash, addr, line, op, isPrefetch});
```
`mkOverflowBypassFifo` — never blocks the L1 demand pipeline (H7 lesson
memory: `bsv_method_guard_backpressure_lesson.md`).

### 4.2 `drainIncomingEvents` — three sequential steps per event

Dequeue one event per cycle (pipelined over multiple BRAM ports):

```
on event {pcHash=C, addr=A, line=L, op, isPrefetch}:
    if op != Ld or isPrefetch: return  // only demand loads produce correlations
    
    // Step 1: Consumer attribution — was this load's base addr produced by someone?
    ppwEntry = ppw.read(hash(A))
    if ppwEntry.valid and ppwEntry.value == A and ppwEntry.producerPC != C:
        // Found a (producer → consumer) dependence
        ctEntry = ct.read(hash(ppwEntry.producerPC))
        if ctEntry.valid and ctEntry.producerPC == ppwEntry.producerPC:
            if ctEntry.consumerPC == C:
                ctEntry.confidence = min(7, ctEntry.confidence + 1)
            else:
                // Collision — replace if confidence is low
                if ctEntry.confidence == 0:
                    ctEntry = {producerPC = ppwEntry.producerPC, consumerPC = C, confidence = 1}
        else:
            ctEntry = {producerPC = ppwEntry.producerPC, consumerPC = C, confidence = 1}
        ct.write(hash(ppwEntry.producerPC), ctEntry)
    
    // Step 2: Producer update — record this load's 8 candidate words as producer values
    for i in 0..7:
        candidate = L[i*64 +: 64]
        if passesPointerFilter(candidate, A):    // see §5 bit-match gate
            ppw.write(hash(candidate), {value = candidate, producerPC = C})
    
    // Step 3: Prefetch trigger — this load might BE a producer for something already known
    ctEntry = ct.read(hash(C))
    if ctEntry.valid and ctEntry.producerPC == C and ctEntry.confidence >= CONF_THRESHOLD:
        // This PC has a learned consumer; prefetch addresses in L that could match consumer's target
        for i in 0..7:
            candidate = L[i*64 +: 64]
            if passesPointerFilter(candidate, A):
                enqueuePrefetch(candidate, ownerPC=C)   // to PRQ / TLB
```

Three BRAM reads + one BRAM write per event (PPW write fans out 8 candidates
over multiple cycles). Realistic pipelining: 2-4 cycles per event. With
the `mkOverflowBypassFifo`, drop-on-full prevents back-pressure.

### 4.3 Throttling

- **Single-instance-ahead** (paper's key throttle): carry a counter bit
  with each prefetch. When a prefetched line fills, do NOT re-probe the
  CT from inside that fill. (In paper, completed prefetches in PB spawn
  more prefetches; we deliberately *don't* do this in v1 for simplicity
  and to follow the paper's "length-1 chain" recommendation.)

- **Confidence gate**: CT entries carry 3-bit saturating confidence.
  Only correlations with `confidence >= 2` issue prefetches. This is a
  simpler version of the paper's "8 consecutive L1 hits disables" (which
  we could add as an additional gate later — but the paper notes this
  also kills useful treeadd prefetches).

- **Dedup filter**: reuse CDP's 1024-entry prefetch filter.

### 4.4 Producer-consumer pair collisions (CT is direct-mapped)

When two different producers hash to the same CT slot, the one with
lower confidence loses. This is the paper's behavior (CT is 4-way
associative there); we approximate with direct-mapped + confidence-
based replacement. If this causes excessive thrashing, a 4-way set
associative CT via `RWSetAssocBramCore` is a small change.

---

## 5. Cooksey bit-match augmentation plan

Three places where Cooksey can be layered on DBP; I'll analyze each and
recommend which to use in the augmented variant.

### Option A: Bit-match gate on PPW insertion (RECOMMENDED)

Before inserting a candidate word `c` into PPW, test whether `c` is
pointer-shaped relative to the producer's paddr `A`:
```
passesPointerFilter(c, A) = (c[38:N] == A[38:N]) && c[3:0] == 0
```
where N is the matchBits (e.g. N=27 for same-page, N=16 for 8 MB region).

**Effect:**
- PPW entries now hold only plausible pointer values, not integers /
  floats / random data.
- Massively cuts false producer-consumer correlations (a stored integer
  happening to equal a later address by coincidence).
- Same filter CDP uses. Proven effective in the CDP variant family.

**Cost:** one 11-bit compare per candidate. Trivial.

### Option B: Bit-match relaxation on PPW lookup (NOT RECOMMENDED)

On PPW miss, relax the consumer's `addr == ppw.value` to a Cooksey
bit-match. Pro: recovers dependencies where the value was slightly
perturbed. Con: creates false correlations (value≈addr but unrelated).
The paper relies on exact equality for dependence precision; relaxing
this is algorithmically at odds with DBP's premise.

### Option C: CDP fallback on CT miss (NOT RECOMMENDED)

When no CT entry exists for the current PC, fall back to CDP's
bit-match scan of the whole line to issue candidate prefetches.

Pro: warmup — DBP isn't useful until correlations are learned; CDP
fills the gap early.
Con: loses DBP's key property (no wasteful bit-match prefetching during
training). Also, if CDP is net-negative on some benches (the current
picture for most Olden benches), using it as warmup bleeds into
steady-state.

Verdict: Option A only. It preserves DBP's semantics and just tightens
the PPW admission test.

---

## 6. Two variants to implement

### Variant 1: `DBP.bsv` → `mkDBP` (pure dependence-based)

- `passesPointerFilter(c, A)` returns `True` unconditionally (no filter).
- Everything else as §4.
- `DATA_PREFETCHER_TYPE=DBP` macro.

### Variant 2: `DBPBitMatch.bsv` → `mkDBPBitMatch` (DBP + Cooksey on PPW insert)

- `passesPointerFilter(c, A) = (c[38:matchBits] == A[38:matchBits]) && c[3:0] == 0`.
- `matchBits` parameter, default 16 (same as H7's default).
- `DATA_PREFETCHER_TYPE=DBP_BITMATCH` macro.

---

## 7. Test matrix (8-bench Olden, comparing vs NoPref2 + H7)

| Variant | Expected characteristic |
|---|---|
| NoPref2 | baseline (cycles reference) |
| H7 | current CDP champion (−1.92% vs NoPref) |
| DBP | faithful paper reproduction on Olden — expected wins on `health/mst/em3d/perimeter` per paper fig 8; may regress on `voronoi` (pointer-light). Baseline for bit-match delta. |
| DBP + BitMatch | same mechanism, pointer-shape-gated PPW. Expected: cleaner correlations, less false-prefetch pollution. Delta vs DBP = bit-match contribution. |

Eight benches: bh, bisort, em3d, health, patricia, perimeter, treeadd,
tsp. Parser metrics (prefetch / usefulPrefetch / lateUseful /
prefetchMissLL) per §cdp-compare rules.

**Key tell for DBP-is-working**: `prefetchHit` should be LOW (not
scanning; exact-match correlations only fire once learned). `strict_acc`
should be HIGH (paper's Fig 7 claims near-100% address-prediction
accuracy with modest CT).

**Key tell for BitMatch contribution**: compare DBP vs DBP+BitMatch.
If +BitMatch improves geomean, bit-match is helping via tighter PPW.
If +BitMatch regresses, it's filtering out genuine correlations.

---

## 8. Implementation steps (once approved)

1. Copy `CDPKillSwitchH7.bsv` as `DBP.bsv`; strip CDP's PC+TT tables;
   keep the incomingQ + staging drain pattern.
2. Add PPW + CT BRAMs; wire the three-step drain rule.
3. Add `DATA_PREFETCHER_DBP` macro; wire in Prefetcher_top.bsv; add to
   Include_RISCY_Config.mk DATA_PREFETCHER_TYPE whitelist.
4. Build + sanity test (treeadd / patricia; expect nonzero prefetch count).
5. Full 8-bench benchmark.
6. Copy DBP as DBPBitMatch; add the pointer filter.
7. Full 8-bench benchmark.
8. Comparison writeup + MEMORY.md updates (follow cdp-variants skill).

Estimated effort: ~4 hours for v1, ~1 hour for BitMatch variant, ~1 hour
for benching and writeup.

---

## 9. Open design questions (flag for user)

1. **CT offset semantics**. v1 uses offset=0 only (exact value-equality
   correlations). This limits the correlations we can capture. Do we
   want to try offset-learning in v2 (record `consumer_paddr -
   producer_value` as the offset)? Small change, but adds another
   dimension of noise.

2. **Dataflow cascade**. Paper has completed prefetches re-probe the CT
   (fig 5d). We explicitly disable this in v1 to enforce length-1
   chains (also matches the paper's recommendation). Worth revisiting
   in a later variant? Requires a new rule on prefetch-fill events.

3. **Confidence gate threshold**. I've picked `>=2` from a 3-bit
   counter. The paper doesn't use a confidence gate in its main
   experiment (only the "L1-hit 8-in-a-row" optional scheme, which
   hurts treeadd). Lower threshold (>=1) = more aggressive; higher
   (>=4) = slower warmup but fewer false positives. Default to 2 but
   sweep if initial results are weak.

4. **matchBits default for DBP+BM**. I've picked 16 (matches H7). On
   Olden pointer-chase codes, same-page (27) is typical. If the
   dissertation story is "bit-match improves DBP", the comparison is
   cleanest with matchBits=16 matching the CDP H7 variant.
