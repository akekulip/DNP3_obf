# Indistinguishability across the full transcript — size, timing, READ, SBO

The handshake header is **one** axis of the observable transcript `O = [(Δ_i, S_i, d_i)]`. True
device obfuscation needs SEL-751 and ION7550 to look identical on **every** axis. The load-bearing
fact is that they are different device **classes** (locked taxonomy): **SEL-751 = Case A
(separate-ACK, has a CLRT, is a relay that does SBO controls)**; **ION7550 = Case B (combined-ACK,
no CLRT, is a READ-only meter)**. Some axes collapse cleanly; others carry a *structural* residual
that comes from the class difference, not from a bit we forgot to rewrite.

## Axis-by-axis status

### 1. Handshake header — SOLVED (indistinguishable; silicon-confirmed)
`INDISTINGUISHABILITY.md`. All three devices' normalized SYN/SYN-ACK are byte-identical
(`do=6, opt=[MSS], ttl=64, ip.id=0, window=8192, mss=1460`); confirmed on the ASIC. This axis is a
clean win because a handshake is packet-bounded and stateless — nothing about it depends on the
device class.

### 2. Response timing — CLRT magnitude normalizable; ACK-MODE now NORMALIZED (Experiment 3)
Two sub-signals:
- **CLRT magnitude** (ACK→response delay, ~1.4–1.9 ms on the SEL-751): **normalizable** — this is
  exactly the accepted Defense 4 timing work (hold the response to a public deadline, compress the
  distribution). Proven on silicon for the Case-A SEL-751.
- **ACK mode / packet count** (the *shape*, not the delay): Case A emits **two** packets — a
  separate pure-TCP ACK, then the response — while Case B emits **one** combined ACK+response. A
  passive observer counts packets and reads whether the ACK is separate. **Defense 4 normalizes the
  CLRT delay, not the ACK mode.** So even with identical handshakes and identical CLRT magnitude,
  SEL-751 (2-packet, separate ACK) and ION7550 (1-packet, combined) remain distinguishable on ACK
  mode. This is the known "ACK-mode fingerprint survives → CLRT-magnitude, not anonymity" result.
- **CLOSED (Experiment 3, `../exp3_ack_mode/`):** the normalizer **suppresses the outstation's
  standalone pure ACK** (`ig_dprsr.drop_ctl`); the DNP3 response that follows within the CLRT re-ACKs,
  so the Case-A device emits ONE observable packet, matching Case B. Oracle 10/10 (axis collapses),
  compiles 9.13.1/9.13.2, **silicon 3/3**. This is the predicted "make Case A emit like Case B"
  direction, with the predicted safety envelope: safe for the request→ACK→response pattern within the
  CLRT budget; a fully robust deployment needs light per-flow "response pending" state for
  CONFIRM/keepalive ACKs not followed by data (the store-and-forward boundary).

### 3. Response size (READ) — a bounded primitive exists; cross-device identity needs matched targets
`../../DNP3-size-probe/defense4/size/RESULT.md` (worktree). The READ-range primitive rewrites a
request's object range to a public superset (same request length), so the outstation emits a larger,
**public-target-sized** response — offline oracle 7/7, standalone Tofino compile PASS (native DNP3
CRC). This can drive *each* device's READ response toward the *same* public byte target, which is
what size-indistinguishability requires. **Residuals:** (a) devices differ in object **encoding**
(group/variation → bytes-per-point), so reaching an identical byte count needs a per-device target
mapping to a common public size; (b) **segmentation / packet count** for large responses is a
separate axis the range primitive does not control (a 12 KB response is multi-segment; the segment
boundaries are stack-dependent). The primitive is the request-side lever; matching the *emitted*
size and segmentation across two stacks is the open measurement (needs both devices' real responses
to a range READ — the corpus currently has Class polls, not range READs).

### 4. SBO / controls — Case-A only; the *presence* of controls is a class fingerprint
`../../DNP3-size-probe/defense4/size/SBO_CHARTER.md` + `sbo_oracle.py` (core 10/10). The SBO size
mechanism (real + inert decoy CROBs to a public size, with per-flow TCP sequence-delta translation)
is built and oracle-verified — **for the Case-A SEL-751**. But the ION7550 is a READ-only meter: it
**does not do SELECT/OPERATE at all**. So the mere *occurrence* of an SBO exchange on the wire
identifies the device as the relay, regardless of how its size is padded. Making the two classes
indistinguishable here would require injecting **decoy control traffic toward the meter** — which
either manufactures controls the meter can't answer (breaks the flow) or requires a decoy responder;
this is the safety/feasibility wall, not a byte we can rewrite. The SBO size mechanism obfuscates
*how many* CROBs the SEL-751 selects, which is valuable, but it does not make a relay look like a
meter.

## The honest synthesis

| axis | can SEL-751 and ION7550 be made identical? | status |
|---|---|---|
| handshake header | **yes** | done, **byte-identical on silicon** (captured off the ASIC) |
| CLRT magnitude | yes | Defense 4 (Case-A proven) |
| ACK mode / packet count | **yes** | ✅ done (Experiment 3): oracle 10/10 + compile + silicon 3/3 |
| READ response size | yes if targets are matched to a common public size | primitive built; cross-device match open |
| READ segmentation / packet count | separate lever, not yet built | open |
| SBO / presence of controls | **no** without manufacturing decoy controls | class fingerprint |

This is exactly why the repository verdict is `NO_GO_FULL_TRANSCRIPT` as a *conditional* analytical
no-go: the **handshake axis is a clean bounded win** (now proven), CLRT magnitude is a proven win,
but *universal* transcript invariance across two different device classes runs into structural
residuals (ACK mode, presence-of-controls) that need active, proxy-like manipulation — which the
single-Tofino, no-proxy constraint bounds. The productive program is to keep converting axes to
bounded wins (handshake header — byte-level on silicon; CLRT magnitude; ACK-mode — all now done;
cross-device size-matching is the next) rather than claim the whole transcript at once.

## Next concrete, buildable experiments (in priority order)
1. **Cross-device READ size match**: capture both devices' responses to a range READ, define the
   common public target + per-device range mapping, measure emitted size + segment count.
2. **SBO size on the SEL-751** (already scoped): obfuscate CROB count; document explicitly that it
   does not hide the *presence* of controls.
