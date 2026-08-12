# READ↔SBO normalizer — size + segmentation + structure + request-direction parity

A software reference that makes a **READ** transaction and a **Select-Before-Operate (SBO)**
transaction indistinguishable to a passive on-path observer, byte-preserving on the real content.
It realizes Philip's split+pad idea and folds in the two domain-expert designs. This is the model
that a Tofino-1 kernel and a hardware proof are built against — it is NOT itself on hardware.

## Files
- `readsbo_normalizer.py` — frame-level split+pad. CRC-16/DNP (verified against the golden cover
  bytes `0xC750`/`0x2ED8`), DNP3 link framing, `split_at_crc` (byte-preserving segmentation on
  18-byte CRC blocks), `pad_user_to` (block-aligned pad, real APDU kept as a verbatim prefix).
- `test_readsbo_normalizer.py` — proves byte-preservation, CRC validity, and that O_count +
  segmentation converge; **asserts the residual stays distinct** so the model can never silently
  claim structure is hidden.
- `transaction_template.py` — the full transaction: three observer models (O1 counting / O2
  single-packet DPI / O3 stateful) and the READ/SBO templates with non-actuating parity decoys.
- `test_transaction_template.py` — proves O1 and O2 indistinguishable, the decoy safety invariants,
  and **asserts O3 still separates them** (the honest boundary).

Run: `python3 test_readsbo_normalizer.py && python3 test_transaction_template.py` (both exit 0).

## Result (what the model proves)
| Observer | READ vs SBO | Status |
|---|---|---|
| O1 (frame counts, sizes, segmentation) | identical | **indistinguishable** |
| O2 (O1 + per-frame func code + object-group multiset; no reassembly/state) | identical: req `{0x01,0x03,0x04}`, resp `{G12:2, G30:1}` | **indistinguishable — the committed observer** |
| O3 (O2 + TCP reassembly, req/resp pairing, link addresses, physical after-effect) | actuations 0 vs 1; phantom/real addresses differ | **still separates — honest residual** |

## The two-expert design it encodes
- **power-systems-expert** (OpenDNP3 3.1.2 source-verified): the READ-response parser is *permissive*
  (an unrecognized decoy object is counted-and-ignored, READ still SUCCESS, nothing reaches SOE), but
  the SBO echo parser is *whitelisted* to control groups. So a decoy **G12 CROB is safe inline in a
  READ**, while the SBO side's **G30 decoy must ride out-of-band** (a phantom-addressed fragment the
  real endpoint link-drops → never actuates). "**Pad = decoy**": the size pad is realized as the parity
  decoy, so structure parity costs ≈0 extra bytes.
- **p4-dataplane-engineer**: the **split is transport-stateless** (no seq/ack ledger; per-segment seq =
  base + constant), the **pad** is a small delta over the cover kernel's single-insertion epoch, packet
  multiplication is **clone/mirror**, and it lands as a **sibling kernel** (frozen ingress + lean split
  egress). Fail-open rides TCP's own retransmission.

## Honest scope
This is a **feature-level** model: it proves the mechanism's structure and its safety invariants. It
does **not** execute the real DNP3 stack. The claim that OpenDNP3 actually ignores the decoy CROB and
link-drops the phantom frames rests on the expert's source reading (`MeasurementHandler.h:53`,
`IAPDUHandler.cpp:399`, `CommandSetOps.cpp:97`). Demonstrating it is the next step —
`HARDWARE_PROOF_PLAN.md`.

## Open decision
**Observer commitment.** O2 (full DPI parity) needs the phantom SELECT/OPERATE decoy requests; O1
(counting-only) stays strictly read-only. The hardware proof is designed for O2 (the committed model).
