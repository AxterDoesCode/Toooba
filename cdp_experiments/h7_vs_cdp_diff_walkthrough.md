# H7 (`mkCDPStatefulRelativeKillSwitchH7`) vs baseline CDP (`mkCDPStatefulRelative`)

Side-by-side walkthrough for someone already familiar with CDP.bsv. All line
numbers refer to the files as of commit `510c306c`:

- `src_Core/RISCY_OOO/coherence/src/prefetcher/CDP.bsv`
  — baseline `mkCDPStatefulRelative` (L161–L678).
- `src_Core/RISCY_OOO/coherence/src/prefetcher/CDPKillSwitchH7.bsv`
  — `mkCDPStatefulRelativeKillSwitchH7` (L94–L644).

H7 imports types from `CDP::*` (L44), so the baseline's `L1ToCDPT`,
`RelLineOffset`, `TrainingTableEntryT`, `TrainingTableRespQT`, and
`PCRelOffsetConfT` are all reused unchanged.

## 0. Two-sentence summary

H7 = baseline CDP + per-PC useful/useless accuracy counters + a kill-switch
that suppresses prefetches from chronically-bad PCs + a reporting path for
useful/useless attribution + a *non-blocking staging FIFO* on the
L1→prefetcher method boundary so `pipelineResp_cRq` never stalls on CDP.
Net effect: 8-bench geomean goes from +1.06% slower than NoPref (baseline
H4 decoupled) to −1.92% faster than NoPref.

---

## 1. Module signature

**CDP.bsv L161–L168**: six Parameters.
```bsv
module mkCDPStatefulRelative#(
    TlbToPrefetcher toTlb,
    Parameter#(trainingTableSize) _,
    Parameter#(pcTableSize) __,
    Parameter#(decayInterval) ___,
    Parameter#(matchBits) ____,
    Parameter#(confidenceThreshold) _____
)(CacheLinePrefetcher#(reqT))
```

**H7 L94–L102**: one extra Parameter `killThreshold` — the per-PC useless-event
count at which prefetches get suppressed.
```bsv
module mkCDPStatefulRelativeKillSwitchH7#(
    ...,
    Parameter#(confidenceThreshold) _____,
    Parameter#(killThreshold) ______  // % threshold (out of 16) for L1-routing
)(CacheLinePrefetcher#(reqT))
```

Configured in `Prefetcher_top.bsv:149–160` as `Parameter#(5) killThreshold`.

## 2. New and modified types

### 2.1 PC-table entry (base → extended)

**CDP.bsv L150–L153**: `PCTableEntryT { pcHash, conf }`.

**H7 L47–L52**: `PCTableAccEntryT { pcHash, conf, usefulCount, uselessCount }`
— two new 4-bit saturating counters per PC.

### 2.2 Filter entry (base → extended)

**CDP.bsv L218**: `RWBramCore#(Bit#(8), Maybe#(LineAddr)) prefetchFilter` —
256-entry direct-mapped, line-addr only.

**H7 L64–L68, L150**:
```bsv
typedef struct {
    LineAddr lineAddr;
    Bit#(16) pcHash;              // charge this PC on eviction
    Bool     punishable;          // False for neighbour-chain entries
} FilterAccEntryT deriving (Bits, FShow, Eq);

RWBramCore#(Bit#(10), Maybe#(FilterAccEntryT)) prefetchFilter <- mkRWBramCoreForwarded();
```
- Filter is now **1024 entries** (Bit#(10) index) — larger to hold more
  recent prefetches for useful-hit attribution.
- Payload carries `pcHash` so eviction can charge the right PC.
- `punishable` flag disables attribution for neighbour-chain prefetches
  (their ownership is murky — they were triggered by a prefetch hit, not
  a confidence-based PC decision).

### 2.3 NextCandT (base → extended)

**CDP.bsv L23–L27**: `NextCandT { paddr, vaddr, isNeighbourLine }`.

**H7 L56–L61**: `NextCandAdaptT { paddr, vaddr, isNeighbourLine, routeLLC }`.
`routeLLC` is captured at decision time and flows through to
`getNextPrefetchAddr`'s `PendingPrefetch.nextLevel` (L640). In H7 this is
always `False` right now — the routing decision is left as a hook for
future variants but currently all prefetches go to L1.

### 2.4 PCTableRdReqFIFO tag (base → extended)

**CDP.bsv L155–L159**: 3 tag variants — `Training`, `PrefetchIssue`, `Decay`.

**H7 L70–L76**: adds two more variants:
```bsv
typedef union tagged {
    Tuple2#(Bit#(16), RelLineOffset) Training;
    Tuple3#(Addr, Line, Vpn)         PrefetchIssue;
    Bit#(16)                          AccUseful;     // (pcHash) — bump usefulCount
    Bit#(16)                          AccUseless;    // (pcHash) — bump uselessCount
    void                              Decay;
} PCTableRdAdaptTagT deriving (Bits, FShow);
```
The `AccUseful` / `AccUseless` tags are enqueued by `finishUsefulLookup`
and `finishEviction` respectively to feed accuracy back to the PC entry.

### 2.5 incomingQ branch enum (NEW)

**H7 L87–L92** (no counterpart in CDP.bsv):
```bsv
typedef enum {
    EvIgnore,        // does not trigger CDP work
    EvDemandLdMiss,  // feeds l1ToCDP for training candidates
    EvDemandLdHit,   // feeds pcTableRdReqFIFO + ttRespQ + ttRdReqSupFIFO
    EvNeighbourChain // feeds tlbReqFIFO for chain-follow
} CDPIncomingBranchT deriving (Bits, FShow, Eq);
```

## 3. Storage topology changes

| State | CDP.bsv | H7 | Why |
|---|---|---|---|
| `l1ToCDP` | `mkSizedFIFO(32)` (L196) | `mkSizedFIFO(8)` (L125) | size moved to the new staging FIFO |
| `incomingQ` (new) | — | **`Fifo#(32, Tuple3) <- mkOverflowBypassFifo`** (L139) | non-blocking staging — **the H7 winning change** |
| `pcTable` | `PCTableEntryT` (L211) | `PCTableAccEntryT` (L149) | + uf/us counters |
| `prefetchFilter` | Bit#(8) / `Maybe#(LineAddr)` (L218) | Bit#(10) / `Maybe#(FilterAccEntryT)` (L150) | 4× entries, pcHash-aware |
| `nextCandidateBuffer` | `NextCandT` (L220) | `NextCandAdaptT` (L152) | + routeLLC |
| `tlbReqFIFO` | Tuple3 of (vaddr, isNeighbour, crossPage) (L235) | **Tuple6** adding (pcH, punish, rlLLC) (L167) | carry provenance + routing |
| `filterPendingQ` | Tuple2 (filterIdx, cand) (L224) | Tuple3 adding pcHashOfOrigin (L156) | so filter writeback records owning PC |
| TLB pending regs | 3 vectors (L237–L239) | 6 vectors (L169–L176) | +pcHash, +punishable, +routeLLC |
| `evictionQ` | same `mkSizedFIFO(4)` (L226) | same (L157) | — |
| `evictionPendingQ` (new) | — | **`mkSizedFIFO(4)`** (L159) | split eviction path so filter can be read before invalidation |
| `usefulHitQ` (new) | — | **`mkSizedFIFO(4)`** (L163) | reportUsefulPrefetch now does work (was `noAction`) |
| `usefulHitPendingQ` (new) | — | **`mkSizedFIFO(4)`** (L164) | stage-2 of useful-hit lookup |

## 4. Rules — what's new, changed, unchanged

### 4.1 Init rules — minor cosmetic

- `doFilterInit` counter is `Bit#(10)` (H7 L183) vs `Bit#(8)` (CDP L249) — filter grew from 256→1024 entries.
- `mutually_exclusive` for doFilterInit in H7 includes `finishEviction, finishUsefulLookup` (L229), not just `processFilterResp, doEvictionClear` (CDP L285).

### 4.2 `deqCacheLines` — unchanged in structure

Both versions (CDP L305–L352 / H7 L243–L274) do the same thing: read
`l1ToCDP`, do slot-0 training lookup, slots 1-8 candidate lookups, enqueue
one PrefetchIssue into `pcTableRdReqFIFO`. Identical behaviour.

### 4.3 `processTtRdReq` / `ttAccess` — unchanged

CDP L354–L403 / H7 L276–L304. Same logic.

### 4.4 `processPcTableRdReq` — unchanged

CDP L405–L410 / H7 L306–L311. Same.

### 4.5 `pcTableResp` — significantly extended

This is where most of the H7 algorithmic change lives.

#### Training branch
- **CDP.bsv L418–L437** has explicit collision detection with a `collision`
  flag and `$display`; on collision it resets the confidence vector.
- **H7 L319–L337** folds that into a single condition:
  `if (rdResp matches tagged Valid .e &&& e.pcHash == pcHash)` — uses the
  existing entry's conf AND counters if pcHash matches; else starts from
  zero (replicate(0), counters=0). Semantically the same "reset on
  collision" but the write now also carries `usefulCount: curUseful,
  uselessCount: curUseless` (preserved if same-PC, else 0).

#### PrefetchIssue branch — KILL-SWITCH GATE (NEW)
- **CDP.bsv L438–L508** unconditionally enqueues a TLB request after
  finding the best high-confidence offset.
- **H7 L338–L391** wraps the issue in `Bool okToIssue = shouldIssue(entry.usefulCount, entry.uselessCount);`
  (`shouldIssue` defined at L207–L211):
  ```bsv
  function Bool shouldIssue(Bit#(4) uf, Bit#(4) us);
      Bit#(4) threshold = fromInteger(valueOf(killThreshold));
      Bool chronic = (us >= threshold) && (us > uf);
      return !chronic;
  endfunction
  ```
  A PC is "chronic" iff it has both (a) at least `killThreshold` useless
  events AND (b) more useless than useful events. If chronic, ALL
  prefetches from this PC are dropped — no TLB request is even issued.
  The `$display` line (L362–L365) shows `ISSUE` or `SUPPRESSED`.

- H7's in-bounds path (L367–L373) enqueues a Tuple6 carrying `entry.pcHash`,
  `punishable=True`, `routeLLC=False`. Baseline's enqueue (L479) is a
  Tuple3 with just `(candidate, False, crossPage)`.

- No `foundHighConf==False` diagnostic branch in H7 (CDP L461–L467 dropped).
  Just silently skips.

#### AccUseful branch (NEW — H7 L392–L401)
Looks up the pcHash-matching entry, increments `usefulCount` with saturation
at 15, writes back. Fires when `finishUsefulLookup` queues an AccUseful tag.

#### AccUseless branch (NEW — H7 L402–L415)
Bumps `uselessCount` by **3** (amplification), saturates at 15. Fires when
`finishEviction` queues an AccUseless tag. Comment at L404–L406 explains
the 3× amplification as compensating for the filter's ~1-in-3 attribution
capture rate.

#### Decay branch — extended
- **CDP.bsv L509–L515**: only decays `conf` (all 15 counters saturating-dec by 1).
- **H7 L416–L426**: same conf decay PLUS also decays `usefulCount` and
  `uselessCount` by 1 each per decay event. Rolling soft-reset of
  accuracy history.

### 4.6 `processTlbReq` / `processTlbResp` — payload extended

- Payload carries the 3 new fields (pcH, punish, rlLLC) through the TLB
  latency — the new per-slot registers `pendPcHash`, `pendPunishable`,
  `pendRouteLLC` store them.
- `processTlbResp` (H7 L444–L468) enqueues `NextCandAdaptT { …, routeLLC: rlLLC }`
  into `filterPendingQ` along with the pcHash.

### 4.7 `processFilterResp` — writes richer filter entry

- **CDP.bsv L557–L570**: on filter-miss, writes `Valid(lineAddr)`.
- **H7 L471–L493**: on filter-miss, writes
  `Valid(FilterAccEntryT { lineAddr, pcHash: pcH, punishable: True })`.
  This captures provenance for later useful/useless attribution.

### 4.8 Eviction handling — split pipeline (NEW)

- **CDP.bsv L573–L579**: one-rule `doEvictionClear` just invalidates the
  filter slot.
- **H7 L497–L519**: split into two rules:
  - `startEviction` (L497) issues a filter READ + stages in `evictionPendingQ`.
  - `finishEviction` (L505) on BRAM response: if entry matches AND
    `punishable`, enqueues `tagged AccUseless fe.pcHash` into
    `pcTableRdReqFIFO` to charge the owning PC. Then invalidates.

### 4.9 Useful-hit lookup pipeline (NEW — no counterpart in CDP.bsv)

Two new rules at **H7 L526–L548** implementing feedback from
`reportUsefulPrefetch`:
- `startUsefulLookup` — dequeues `usefulHitQ` (line addr), issues filter
  BRAM read, stages in `usefulHitPendingQ`.
- `finishUsefulLookup` — on filter response, if entry matches and is
  `punishable`, enqueues `tagged AccUseful fe.pcHash` into
  `pcTableRdReqFIFO`. Filter entry NOT invalidated (comment L545–L547 —
  keeps dedup signal alive).

### 4.10 Decay tick (unchanged)

`tickDecayCounter` + `issuePcTableDecay` (H7 L550–L559) same as CDP
(L581–L590).

### 4.11 `drainIncomingEvents` — staging FIFO drain (NEW)

**H7 L564–L601**, no counterpart in CDP.bsv. Dequeues `incomingQ`, switches
on `branch`, performs exactly the fan-out that `reportIncomingCacheLine`
used to do inline in CDP.bsv (see §5). All downstream enqueues happen
inside this rule, so back-pressure from them stops at this rule, not at
the caller.

## 5. Method changes

### 5.1 `reportIncomingCacheLine` — totally restructured

**CDP.bsv L592–L646**: three inline branches that fan out directly to
downstream FIFOs:
```bsv
if (inited && Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch)
    l1ToCDP.enq(...);
else if (inited && Ld && !wasMiss && !cRqIsPrefetch && !wasNeighbourPrefetch) {
    pcTableRdReqFIFO.enq(tagged PrefetchIssue ...);
    ttRespQ.enqS[0].enq(...);
    ttRdReqSupFIFO.enqS[0].enq(...);
}
else if (inited && Ld && cRqIsPrefetch && wasNeighbourPrefetch && !wasMiss)
    tlbReqFIFO.enq(...);
```
Each branch adds one or more implicit-`notFull` guards to the calling
`pipelineResp_cRq` rule in L1Bank.bsv. That's how back-pressure leaked
into the L1 demand pipeline.

**H7 L603–L619**: the method now does exactly one thing: classify the
branch and enqueue the tuple into `incomingQ`.
```bsv
CDPIncomingBranchT branch = EvIgnore;
if (inited && Ld && !cRqIsPrefetch && wasMiss && !wasNeighbourPrefetch)
    branch = EvDemandLdMiss;
else if (inited && Ld && !wasMiss && !cRqIsPrefetch && !wasNeighbourPrefetch)
    branch = EvDemandLdHit;
else if (inited && Ld && cRqIsPrefetch && wasNeighbourPrefetch && !wasMiss)
    branch = EvNeighbourChain;
incomingQ.enq(tuple3(branch, req, line));
```

Because `incomingQ` is an `mkOverflowBypassFifo` (`notFull=True`
unconditionally — see L139), this enq's guard is trivially satisfied.
**`reportIncomingCacheLine` therefore never blocks `pipelineResp_cRq`.**
When the FIFO is full, the oldest entry is silently dropped in favour of
the new one — the H7 tradeoff.

The classification branches and the fan-out logic they map to are identical
to CDP.bsv's inline branches; only the location has moved (from the method
body in CDP.bsv to `drainIncomingEvents` in H7). `EvIgnore` maps to "no-op"
in `drainIncomingEvents` (H7 L599) so non-interesting events still get
staged for uniform latency, then dropped by the drain rule.

### 5.2 `reportAccess` — identical

Both versions have an essentially empty body. CDP.bsv L648–L655 has a
commented-out body; H7 L621–L622 is empty. Both compile to no-op.

### 5.3 `reportEviction` — identical enq, different downstream

Both: `evictionQ.enq(lineAddr)` (CDP L657–L659 / H7 L624–L626). What differs
is the CONSUMER: CDP's `doEvictionClear` just invalidates; H7's
`startEviction → finishEviction` pipeline additionally routes a useless
attribution back to the owning PC.

### 5.4 `reportUsefulPrefetch` — was no-op, now active

- **CDP.bsv L661–L664**: `noAction;` (comment: baseline CDP doesn't track
  per-PC usefulness).
- **H7 L628–L630**: `usefulHitQ.enq(lineAddr);` — feeds the useful-hit
  lookup pipeline → filter read → AccUseful bump.

### 5.5 `getNextPrefetchAddr` — routing parameterised

- **CDP.bsv L666–L677**: `nextLevel: False` hard-coded.
- **H7 L632–L643**: `nextLevel: x.routeLLC` — threaded through from the
  decision time. In practice all H7 prefetches set `routeLLC=False`
  (L373, L386, L593), but the hook is there for adaptive-routing
  successors.

## 6. Behaviour comparison at a glance

| Behaviour | baseline CDP | H7 |
|---|---|---|
| Per-PC accuracy tracking | None | Saturating 4-bit useful/useless per pcTable entry |
| Suppress bad PCs? | No | Yes — kill-switch `(us >= killThreshold) && (us > uf)` |
| Useless amplification | n/a | 3× per attributed eviction (H7 L404–L408) |
| Filter size | 256 | 1024 |
| Filter attribution | None | pcHash + punishable per entry |
| Neighbour-chain entries charged? | n/a | No (`punishable=False`) |
| Useful-hit feedback | Ignored | Filter lookup → AccUseful bump |
| Eviction feedback | Just invalidate | Invalidate + AccUseless bump if matched+punishable |
| Decay of accuracy counters | n/a | Decay branch also decrements uf/us |
| Routing decision | Always L1 | Carries `routeLLC`, currently always L1 (hook) |
| **`reportIncomingCacheLine` implicit guards** | **3-5 FIFO `notFull` guards** | **1 guard, trivially True (`mkOverflowBypassFifo`)** |
| Back-pressure into L1 pipeline | Yes (9.9% of em3d cycles) | No — oldest dropped on full |

## 7. Suggested reading order for diff review

1. **H7 L125–L139** (staging FIFO + comments) — the headline change.
2. **H7 L603–L619 vs CDP L592–L646** (`reportIncomingCacheLine` refactor).
3. **H7 L564–L601** (`drainIncomingEvents`) — where the CDP.bsv inline
   fan-out ended up.
4. **H7 L47–L76** (new types) — the PC/filter schema extensions.
5. **H7 L338–L391 vs CDP L438–L508** (`pcTableResp::PrefetchIssue`) — the
   kill-switch gate.
6. **H7 L392–L415** — `AccUseful` and `AccUseless` branches, 3× amplification.
7. **H7 L497–L519** — split eviction pipeline (startEviction/finishEviction).
8. **H7 L526–L548** — useful-hit feedback pipeline (new).
9. **H7 L628–L630** — `reportUsefulPrefetch` is now active (vs CDP's `noAction`).

## 8. What you don't need to re-review

These blocks are verbatim-equivalent to CDP.bsv — if you know the baseline,
skip them:

- Module-level provisos (H7 L103–L123 vs CDP L169–L189).
- Init rules (H7 L213–L241 vs CDP L262–L303), modulo filter size.
- `deqCacheLines` (H7 L243–L274 vs CDP L305–L352).
- `processTtRdReq` / `ttAccess` (H7 L276–L304 vs CDP L354–L403).
- `pcTableResp::Training` — algorithmically equivalent (same-pcHash
  preserves, different-pcHash resets); H7 just inlines what was explicit
  `collision = True` in CDP.
- `pcTableResp::PrefetchIssue` inner geometry (hitOffset, in-bounds vs
  neighbour-line calculation, absTarget bit-shifts) — identical.
- Decay tick (H7 L550–L559 vs CDP L581–L590).
