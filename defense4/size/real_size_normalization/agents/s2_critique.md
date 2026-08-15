# S2 Architecture and Security Critique

Owner: `s2_critic` lane
Scope: S2 design artifacts only; no live hardware access or mutation
Verdict: **OKAY**

## Evidence checked

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/size/real_size_normalization/SIZE_SECURITY_DEFINITION.md`
- `defense4/size/real_size_normalization/OBSERVER_MODEL.md`
- `defense4/size/real_size_normalization/ONE_SIDED_IMPOSSIBILITY.md`
- `defense4/size/real_size_normalization/CURRENT_SIZE_CLAIM_CORRECTION.md`
- `defense4/size/real_size_normalization/SIZE_TOPOLOGY_CAPABILITY_AUDIT.md`
- `defense4/size/real_size_normalization/SIZE_DESIGN_OPTIONS.md`
- `defense4/size/real_size_normalization/SIZE_SELECTED_DESIGN.md`
- `defense4/size/real_size_normalization/SIZE_THREAT_MODEL_V2.md`
- `defense4/size/real_size_normalization/SIZE_ARCHITECTURE.svg`
- `defense4/size/real_size_normalization/SIZE_ARCHITECTURE.pdf`
- `defense4/size/real_size_normalization/agents/crypto_options.md`
- `defense4/size/real_size_normalization/agents/trace_inventory.md`
- `defense4/size/native_parity/evidence/E_FINAL/scripts/size_reconstruct.py`
- `defense4/size/native_parity/p4/defense4_rrc_bor_unified12.p4`
- `defense4/size/native_parity/p4/defense4_rrc_bor_unified12_setup.py`
- `defense4/size/offline/transport_oracle.py`

## Verdict

The S2 design is actionable as a conditional architecture decision. It does not prove deployability, and it does not claim real size-normalization evidence yet. It correctly stops before S3 implementation and asks the author to approve one conditional decision:

```text
Proceed after S2 with the packet-preserving Layer-2 AEAD cell bridge,
targeting RN-L first, while treating the Tofino CPU punt/reinject path
as a hard S6 feasibility condition and accepting that failure ends the
mechanism on the current testbed.
```

No blocking S2 design issues were found.

## Review findings

### Mission fit

Pass.

The selected design uses only Vision, the installed UFISpace Tofino-1/onboard CPU, and the existing `dp64` SEL/ION relay leg. It explicitly excludes Hulk, added hosts, SmartNICs, gateways, P4 cryptography, standard tunnels without fixed records, and the historical `[28,21]` segmentation result as public size-hiding evidence.

### Observer model consistency

Pass.

The design removes inner IP/TCP/DNP3 metadata from the observed Vision-to-`dp9` link and exposes only fixed-format AEAD cells. Public fields are fixed-size and do not encode true inner length, type, occupancy, or final-cell state. The schedule requires fixed cell counts, directions, and slots, matching the S0 `ObsSize` invariant.

### Endpoint transparency

Pass, conditional.

The design carries complete inner Ethernet frames rather than terminating the master-relay TCP session. This preserves endpoint TCP sequence/ACK semantics in principle and avoids the dual-TCP-proxy failure mode. The condition is explicit: the UFISpace CPU path must prove endpoint-transparent punt and reinject semantics before hardware use.

### RRC/BOR ordering

Pass.

The selected response path keeps the mechanisms separate:

```text
relay response
-> RRC/BOR timing release
-> CPU cellization
-> fixed cells to dp9
-> Vision decellization
-> master receives original frame
```

This avoids putting the historical `[28,21]` carve or clear relay response bytes on the public protected transcript.

### Loss, replay, and overflow

Pass for S2.

The design forbids public retransmission, NACK, or adaptive recovery. Missing, duplicated, invalid, overflow, or late cells drop the inner epoch while the public schedule continues with valid cover if the shim remains alive. This is the right direction for avoiding data-dependent recovery transcripts. S3/S4 must still implement and test the bounded reorder window, replay checks, deadline behavior, and byte-exact recovery.

### AEAD and nonce safety

Pass for S2.

The design uses reviewed software AEAD and rejects P4 cryptography. It specifies direction-separated keys and nonce spaces, a reviewed injective 96-bit nonce layout, rekey before counter reset/exhaustion, replay protection, and out-of-band prototype keys. The threat model correctly classifies nonce reuse as critical.

### CPU-path conditionality

Pass.

The design does not treat `ens1` or `bf_kpkt` as proof of a relay-edge boundary. It states that failure to prove exact bidirectional CPU punt/reinject, metadata semantics, compile/resource fit, timing, queueing, and fail-closed behavior returns the phase to blocked by current topology. This preserves the S0 impossibility result.

### Diagram and figure readiness

Pass.

`SIZE_ARCHITECTURE.svg` is valid XML, and `SIZE_ARCHITECTURE.pdf` exists as a single-page Inkscape export. The PDF page size is 515.52 x 240.48 pt, matching a 7.16-inch double-column width, and embedded TrueType fonts are present. The diagram labels the observed link, trusted zones, fixed-cell path, and unproven CPU boundary.

## Representative task simulations

1. **Passive observer on Vision-`dp9`:** the observer sees fixed EtherType cells only. If implementation enforces the cell-exclusive physical interface and fixed schedule, TCP novel-byte reconstruction no longer exposes inner DNP3 length on the observed link.

2. **Relay response path:** a relay response is first handled by the clear trusted RRC/BOR timing path, then diverted to CPU cellization before `dp9`. This preserves the existing timing separation and avoids public clear response leakage, provided the later CPU/P4 proof succeeds.

3. **Cell loss or overflow:** no public retransmission or variable spill is allowed. The epoch drops internally, cover continues where possible, and inner TCP can only recover through a later full fixed-volume epoch.

4. **CPU-path failure:** if punt/reinject cannot be proven, the design blocks rather than degrading to resegmentation, ordinary tunneling, or filterable chaff.

## Non-blocking follow-up risks

- Future RN-L `PASS` wording must distinguish offline/synthetic S3 evidence from hardware observer-link evidence.
- S3 must include startup, reconnect, teardown, idle, ACK-only, and link-control behavior, not just established DNP3 payload packets.
- S6 must not combine CPU-path proof with relay actuation; the initial hardware proof can remain READ-only and cell-path focused.

## Stop condition

S2 can be presented for author approval. Do not begin S3 implementation until the author approves or rejects the single conditional architecture decision in `SIZE_SELECTED_DESIGN.md`.
