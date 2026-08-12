# Defense-4 size cover kernel — REPAIR / DOWNGRADE decision + Gate-B verdict

**Date:** 2026-08-12  ·  **Scope:** `defense4/size/p4/defense4_cover_kernel.p4` (Tofino-1 / TNA),
compile-only (no hardware, no switch load).  ·  **Source sha256 (repaired):**
`8074374074c3d46019d214711111d039ee6b5b891e171ffa863c187f1b499699`.

## Verdict — GATE B: FUNCTIONAL-PASS + COMPILE-PASS (not silicon-integrated)

- **Functional (offline):** PASS. 49 packet vectors through a P4 behavioral emulator and an
  independent front-cover reference agree; every emitted packet carries valid IPv4+TCP
  checksums; the receiver-visible byte stream reassembles byte-exact; the depth-1 restriction
  of `transport_oracle.py` agrees; the fail-closed and legacy-regression controls have teeth.
- **Compile:** PASS. `bf-p4c 9.13.1`, 0 errors, 3 (inherited) warnings, fits 12/12 stages,
  `tofino.bin` produced. Command/version/SHA/warnings/resources in
  `evidence/cover_kernel_repair/`.
- **NOT** silicon-validated. A compile is not a run; nothing was loaded. This is a
  FUNCTIONAL-PASS + COMPILE-PASS result, **not** an integrated (on-hardware) result.

The mechanism was **honestly downgraded** (FIX 3 option b): it inserts **at most one cover per
protected connection**, and every claim, test, and label below is written to that bound.

---

## FIX 1 — Cover bytes are now real and verified (were placeholders)

The pre-repair source emitted `05 64 09 44 00 32 00 01 AB CD C0 C1 02 00 EF 01` — byte-reversed
link addresses and placeholder CRCs `0xABCD`/`0xEF01`. A master's DNP3 link layer would fail the
header CRC and resync, risking mis-framing of the real response.

The correct little-endian frame is verified in `offline/cover_frame_golden.py` by **two
independent CRC-16/DNP implementations** (a bitwise reflected-poly `0xA6BC` routine and an
independent table built by reflecting the canonical `0x3D65`), both cross-checked against the
repo's known-good captured vector (`05642b4401000a00 → 0x610b`), plus a parser and a
corrupted-frame negative control:

```
golden frame:  05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E
               |start| ln ct| dst | src |hcrc| tp ac fc pd|bcrc|
link CRC-16/DNP over 05 64 09 44 32 00 01 00 = 0xC750 -> wire 50 C7
block CRC-16/DNP over C0 C1 02 00            = 0x2ED8 -> wire D8 2E
```

Because a TNA deparser emits a `bit<16>` field big-endian, the P4 constants are byte-swapped to
land these wire bytes: `COVER_DST=0x3200`, `COVER_SRC=0x0100`, `COVER_DL_CRC=0x50C7`,
`COVER_BCRC=0xD82E` (wire order made explicit in the source). The conformance test asserts the
covered opener's on-wire TCP payload **begins with the exact 16 golden bytes**.

## FIX 2 — Fail-closed eligibility, before any state access

The egress is guarded so a packet reaches the size registers ONLY if it is a fully parsed TCP
segment AND the exact-match owner. Concretely:

- **`hdr.tcp.isValid()` gate** wraps the whole egress. An IPv4 **fragment** (MF set or non-zero
  offset), an **IP-options** packet (`ihl>5`), or a non-IPv4/non-TCP frame never extracts TCP,
  so it skips the entire size layer → native, **no register access**.
- **TCP options (`dofs>5`)** are ineligible: a data segment with options is never translated (so
  it is never checksummed from a fixed-20B header + zero residual — the exact pre-repair bug),
  and it makes **no register access**. Only `dofs==5` captures the residual.
- **SACK-permitted** is rejected *before the first insertion*: a SYN carrying options poisons
  `reg_delta` (sentinel `0xFFFFFFFF`), and `delta_openrmw` opens only if the stored value is
  exactly 0, so a poisoned flow is never covered.
- **Owner-qualified destructive ops.** `t_owner` is a full 5-tuple exact match; the register
  block is entirely under `if (owner)`. A foreign SYN/FIN/RST that hash-collides into the
  10-bit size array **cannot** reset the protected flow (the pre-repair `delta_reset` ran before
  ownership). SYN/RST manage the epoch only for the owner; a **FIN is translated but does not
  retire** (a first FIN must not strand the still-referenced offset).
- **MTU / malformed length** are range-gated (`e_mtu` opens only for `41..1484`; `e_haspay`
  classifies `<=40` as no-payload), so an over-MTU or truncated length is never opened.

Corpus scenarios `ipv4_fragment`, `ip_options`, `tcp_options_data`, `sack_permitted_reject`,
`mtu_exceeded`, `malformed_length`, `non_owner_collision`, `owner_unpopulated_failclosed` each
assert `touched_state == False` (or not-opened) and native passthrough. The legacy-mode control
shows the pre-repair semantics **corrupting** the non-owner-collision and ack-inside-pad vectors.

## FIX 3 — Ledger: honest bounded downgrade (option b), claims matched

The offline oracle (`transport_oracle.py`) is a general **multi-boundary** ledger whose reverse
direction needs an inverse cumulative-ack map over an unbounded set of insertion boundaries.
Tofino-1 cannot maintain that: one stateful access per register per packet, no loop over ledger
entries. So covering **every** response with a scalar delta is provably wrong in reverse (an ack
that lands between boundaries must subtract a partial delta, not the total — the pre-repair bug).

**Decision:** insert **one cover per connection** — a single boundary — which the scalar state
`{reg_delta, reg_b0}` represents **exactly**:
- forward: `seq += COVER_LEN` iff `seq` is strictly after `b0` (the opener and pre-boundary
  segments add 0; the cover rides inside the opener's segment at the front);
- reverse: `ack -= clamp(ack - b0, 0, COVER_LEN)` — the exact single-boundary inverse, with an
  in-pad snap;
- opener and its retransmits re-emit the identical cover (byte-stream invariant); later responses
  get no cover, only the +16 shift.
- `reg_delta ∈ {0, COVER_LEN, POISON}` doubles as the epoch valid bit, so a first response with
  **seq 0 is not misread as a retransmit** (a pre-repair defect).

This is the **depth-1 restriction** of the oracle, and the conformance suite runs the shared
corpus through the oracle at `ledger_depth=1` and confirms the ±16 deltas match the P4 emulator.
Covering every response (a stronger defense) is explicitly **future work** requiring a
multi-boundary ledger TF1 cannot host; it is **not** claimed here.

## FIX 4 — RELABELLED as FIXED +16 B ENLARGEMENT (not normalization)

The kernel adds a fixed 16-byte cover to one response; it does **not** select a cover length from
a target/template policy, so it does **not** normalize to a target size (the offline 45/18→63
convergence is a design-time result, not what this kernel does). The source, the evidence README,
and this decision all label it a **fixed enlargement of the first response**. The corpus tests the
two failure modes that a fixed enlargement must handle: an **unreachable** case (native+16 exceeds
the MTU → cover refused, native) and a **malformed length** (bounded by the range gates). A
control-plane cover-template policy is a documented, unimplemented extension.

## FIX 5 — Shared conformance corpus through reference AND P4 model

`offline/conformance_corpus.py` is a machine-readable corpus of 19 scenarios / 49 vectors:
seq-zero first response; 2–3 responses then retransmit resp1; retransmit/OOO of the opener and of
a later response; ACK inside the pad (snap); SYN / FIN / final-ACK / RST / tuple-reuse; non-owner
collision; TCP options / IP options / fragments / malformed length / SACK-permitted SYN / MTU
edge; sequence wrap. `offline/test_cover_conformance.py` runs it through the P4 behavioral
emulator (`offline/p4_cover_emulator.py`) **and** an independent front-cover reference, requiring
matching seq/ack/cover/outcome/state, valid emitted IPv4+TCP checksums, exact golden cover bytes,
byte-exact FWD reconstruction, and depth-1-oracle agreement. **PASS.**

## COMPILE

`bf-p4c 9.13.1`, exit 0, 0 errors, 3 inherited warnings, ingress 12 / egress 12 stages, max
physical stage 11 of 12, `tofino.bin` produced. Full provenance and text logs (no build
artifacts) in `evidence/cover_kernel_repair/` (`manifest.json`, `compile.stderr`,
`table_summary.log`, `mau.resources.log`, `metrics.json`, PHV summaries). The ingress is
byte-identical to the frozen Case-A timing core (all edits egress/comment-only; one inert
`tbl_predecessor` gateway re-placement under egress resource competition).

## Control-plane — fail-closed until `t_owner` is populated

`t_owner`'s const default is `clr_owner`, so with **no entry the kernel is all-native** (owner
never set → no cover, no translation). The corpus proves this (`owner_unpopulated_failclosed`:
every packet native, `touched_state=False`). The control plane installs the one protected flow's
direction-normalized 5-tuple:

```python
# bfrt_python — install the single protected flow (both directions fold to this key)
t = bfrt.defense4_cover_kernel.pipe.Egress.t_owner
t.add_with_set_owner(nm_ip=MASTER_IP, nr_ip=OUTSTATION_IP, nm_pt=MASTER_PORT, nr_pt=20000)
# with NO such add, t_owner default = clr_owner => fail closed (verified in the corpus).
```

## Honest limits (not proven here)
- No silicon: not loaded, not run. Checksum arithmetic, byte-identical delivery, and the
  transport translation are validated only offline.
- **One protected flow.** The hash-indexed size registers assume a single owner; N owners would
  need owner-disjoint indexing.
- **One insertion per connection.** Only the first response of a connection is enlarged; later
  responses pass at native size. This is a real but partial size perturbation, labelled as such.
- FIN teardown reclaims state on the next owner SYN/RST (or CP re-provision), not on both-FIN-ack.
