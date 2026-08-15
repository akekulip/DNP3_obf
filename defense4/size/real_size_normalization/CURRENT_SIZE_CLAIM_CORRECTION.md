# Current Size-Claim Correction

Gate: S0
Status: reviewed S0 correction

## Correct baseline statement

The completed Defense 4 hardware phase demonstrated a fixed **TCP segment shape** for one eligible 49-byte response class:

```text
native:   [49]
defended: [28,21]
reassembled application total: 49 bytes in both cases
```

The defended segments are sequence-contiguous, CRC-valid, and IP/TCP-checksum-valid, and the frozen campaign reports zero unsplit 49-byte escapes. This is a real silicon result, but not total DNP3 length hiding: a TCP-aware observer reconstructs all 49 application bytes.

## Claim-status matrix

| Property | Current status | Correct language |
| --- | --- | --- |
| Master-facing CLRT normalization | Demonstrated on silicon | Native READ/SELECT CLRT was replaced by an approximately 4.001 ms policy value for measured classes. |
| Eligible-response segment vector | Demonstrated on silicon | Every measured eligible 49-byte response was emitted as `[28,21]`. |
| Total application-length hiding | Not achieved | **SEGMENT SHAPE ONLY**; `28+21=49`. |
| Different-length transcript equality | Not evaluated | Requires the new fixed-volume mechanism and multiple inner lengths. |
| Inner function/type concealment | Not achieved | Current DNP3 remains clear and parseable. |
| Multi-device indistinguishability | Not demonstrated | Only one SEL-751 was tested; this is signature replacement. |
| Source-byte identity | Not demonstrated | Frozen evidence establishes valid reconstruction, not a paired source-boundary oracle. |
| BOR relay-facing exactly-once/T0+J | Not directly observed | Preserve the inferred-only limitation. |

## Allowed frozen-phase language

- “fixed `[28,21]` segmentation”
- “fixed per-packet segment shape for eligible 49-byte responses”
- “49-byte sequence-contiguous reconstruction”
- “segment-shape and packet-count normalization for the measured 49-byte class”
- “CLRT normalization demonstrated on silicon”

## Prohibited frozen-phase language

- “total-size normalization”
- “response length hidden”
- “size-fingerprint elimination across lengths or devices”
- “indistinguishable DNP3 transaction classes”
- “byte-identical to the relay source”

## Preservation rule

The prior implementation, captures, manifests, and reports remain frozen. This phase does not overwrite or relabel them. New claims and evidence remain under `defense4/size/real_size_normalization/` until a later reviewed integration changes repository authority.

## Evidence anchors

- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/csv/size_verdict.csv`
- `defense4/size/native_parity/evidence/E_FINAL/CLAIM_MATRIX.md`
- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
