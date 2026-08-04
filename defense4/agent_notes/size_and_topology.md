# Agent note — size plane + two-edge topology (wave 1)

**sdn-networks-expert, 2026-08-04. Analysis only; SBO sizes VERIFIED from multi_crob_sbo.pcap this
session. Extends the Ditto study to the cross-operation READ-vs-SBO problem.**

## Headline

One Tofino-1 can build the **entire shaping mechanism** (classify → hold → pad to a public size
pattern → filler cells → encapsulate → physical loop → decapsulate → byte-identical restore). It
reaches **Profile A in full** and **Profile B's traffic-shape match**. It does **NOT** reach the
strong claim Obs(READ)≈Obs(SBO): blocked by one byte, the plaintext DNP3 function code, which needs
an **opacity assumption (link crypto) external to the Tofino primitive.**

**Provenance caveat:** READ numbers are the physical SEL-751 (Case A, separate ACK); SBO numbers are
the emulator (Case B, combined ACK) — two stacks. Some "differences" are device artifacts, marked.

## What the plaintext observer sees (H_outer = 66 B verified constant)

Public template unit sizes, per direction, from the pcap: READ req 18 B payload / SELECT req 50 /
SELECT-resp 52 / OPERATE req 50 / OPERATE-resp 52; physical READ response 134 B payload / 200 B wire.
**READ and SBO differ on EVERY observable an on-path monitor measures except per-unit fragmentation
and the 5-tuple:** function code, exchange count (1 vs 2), data-bearing packets (2 vs 4), direction
sequence, M→O/O→M counts, ACK mode (device artifact), request size, response size, DNP3 length,
PSH-ACK count, duration, total bytes. Even with perfect size/count/direction/timing normalization,
**the function code at a fixed offset is an O(1) perfect READ-vs-SBO classifier** (arch §7 made
concrete).

## Profiles A / B / C

- **Profile A (within-operation):** hides device identity via CLRT (grid) + CROB count via request
  size (decoy CROBs, master-side) + within-class response size. **Its security goal never crosses the
  semantic boundary, so plaintext function-code visibility is irrelevant to it.** Fully deliverable on
  Tofino-1 today. ★ Because the outstation *echoes* CROBs, master-side padding to N_max normalizes
  BOTH request and response CROB-count size in one move. **This is the honest, defensible Defense-4
  claim now.**
- **Profile B (cross-op READ≈SBO):** buildable, but on plaintext spends filler bandwidth for **zero**
  semantic concealment — the strong claim collapses to the weak "reduces differences" claim. Value
  proposition depends entirely on opacity.
- **Profile C (continuous cover):** hides idle/frequency, affordable at grid rates (~10 kbit/s), but
  inherits B's opacity requirement + the safety requirement that chaff never egress to the relay as
  live DNP3. Not for MVP.

## Two-edge one-switch topology — MECHANISM feasible, SECURITY not (on TF1 alone)

The observer model is valid **only if the encoder→decoder hop is an EXTERNAL physical cable, not
internal recirculation** (recirc is invisible → invalidates the observer). Binding requirement: the
protected-link port must be an **external front-panel loopback, tapped on that fiber.**

Port table (pipe-0): dp9 master-facing (Vision), dp64 outstation-facing (physical SEL), dp11 emulator
outstation, **dp8/loop = protected-link external loopback (TAP HERE)**, dp68 pktgen (filler + grid
tick). Discriminate pass by ingress port: `ingress_port == loop` → decode; else → encode. Encoder
writes {direction_bit, txn_tag, slot_id} into the outer header; decoder reads direction_bit to select
egress and drops filler-tagged cells. Encap = **prepend** (inner rides as unparsed residual → inner
IP/TCP checksums stay valid, only outer needs a checksum; byte-identical restore by construction).
Cost: +1 front-panel port, +1 cable, no extra pipeline.

★ **The loop makes the encapsulation VISIBLE but not OPAQUE.** TF1 cannot encrypt the residual, so the
cell on the fiber is a plaintext outer wrapping plaintext DNP3 — the observer skips the outer and reads
the inner function code exactly as on the native link. The physical loop is **necessary** (put the
shaped representation on an observable segment; strip padding before endpoints) but **not sufficient**
for the strong claim. Closest one-switch fix: an inline MACsec/bump-in-the-wire crypto device on the
loop cable — shaping stays on-chip, only opacity moves off-chip.

## Minimum public template (from measured sizes)

4 data slots, directions [M→O, O→M, M→O, O→M], 1 cell/slot. **P = [50, 134, 50, 52]** (low-CROB) or
**[256, 134, 256, 52]** (≤16-CROB envelope, from the 14.6 B/CROB fit). Each S_i = the cross-operation
max for that slot's direction (padding can't shrink; multi-size pattern keeps overhead down). **SBO's
2nd exchange forces READ to fabricate 2 filler cells — an M→O AND an O→M dummy (slots 2–3)** — which is
why Profile B (not A) needs the full template + both-direction filler (pktgen + decoder drop). Every
unit ≤256 B ≤ MSS so N*_i = 1; a large multi-fragment READ would need cellization (deferred, out of
MVP — declare a bounded READ envelope). Filler overhead: READ = 100% cell inflation (+234 B), SBO = 0
filler cells + intra-cell padding; both emit identical [116, 200, 116, 118]-wire cells → ~550 B wire
symmetric, indistinguishable on size+count+direction.

## Decisive verdict + the exact external assumption

**Obs(READ)≈Obs(SBO) is NOT reachable on Tofino-1-only.** Four-link proof: (1) function code = 1 byte,
O(1) classifier on plaintext (VERIFIED in pcap); (2) TF1 structurally cannot make the inner opaque
(residual never in PHV); (3) therefore the function code survives all normalization; (4) opacity needs
crypto, which is not a TF1 data-plane primitive.

- **Tofino-buildable → WEAK claim** (verbatim, arch §7): *"Defense 4 reduces the size, timing,
  packet-count, and direction-pattern differences between READ and SBO."* Delivers Profile A in full +
  Profile B's shape match.
- **STRONG claim requires this exact external assumption:** *"a link-layer confidentiality boundary
  (MACsec or equivalent) covers the encoder→decoder protected segment, so the observer sees only
  fixed-size opaque cells; the observer sits solely on that segment, not the native endpoint ports;
  the operator owns both edges while master and outstation stay unmodified."* Under exactly that,
  the SAME mechanism yields Obs(READ)≈Obs(SBO). This is the Ditto boundary applied to the
  cross-operation problem — this design has the peer (2nd pass on the loop) but not the crypto.

**Do NOT claim** "the observer cannot distinguish READ from SBO" for the plaintext testbed. On
plaintext the honest claim is difference-reduction; the strong claim is admissible only with the
stated crypto-boundary deployment assumption.
