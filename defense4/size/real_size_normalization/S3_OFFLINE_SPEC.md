# Gate S3 Offline Fixed-Cell Specification

Status: implementation contract after author approval

Scope: deterministic offline construction only. This document does not prove the Tofino CPU path, a live protected link, or a hardware size-security result.

## Policy S3-RNL-256-v1

The first offline policy deliberately uses one conservative Ethernet cell size and enough response capacity to carry the largest committed software trace without a jumbo-MTU assumption.

| Parameter | Provisional value | Meaning |
| --- | ---: | --- |
| Complete captured outer frame `C` | 256 bytes | Ethernet header through AEAD tag; physical FCS excluded |
| Outer Ethernet header | 14 bytes | Fixed source/destination MAC roles and EtherType `0x88B5` |
| Public cell header | 18 bytes | Magic, version, policy, key epoch, and counter |
| AEAD tag | 16 bytes | ChaCha20-Poly1305 tag |
| Encrypted plaintext | 208 bytes | Private metadata, inner chunk, and deterministic test padding |
| Private metadata | 28 bytes | Encrypted epoch/slot/index/count/frame/length/offset/type state |
| Inner chunk `P` | 180 bytes | Bytes available per cell after private metadata |

Slot schedule:

| Slot | Direction | Cells | Nominal offsets from public epoch start |
| --- | --- | ---: | --- |
| request | Vision -> Tofino | 4 | 0, 250, 500, 750 us |
| ACK/control | Tofino -> Vision | 2 | 1000, 1250 us |
| response | Tofino -> Vision | 14 | 200000 through 203250 us in 250-us steps |
| tail/ACK | Vision -> Tofino | 2 | 203500, 203750 us |

Every epoch therefore exposes exactly 22 cells and 5,632 captured outer bytes. The complete size vector, direction sequence, and relative timing vector are fixed.

## Public format

```text
outer destination MAC [6]
outer source MAC      [6]
EtherType 0x88B5      [2]
magic "D4C1"          [4]
version               [1]
policy identifier     [1]
key epoch             [4]
cell counter          [8]
ciphertext + tag      [224]
```

Nonce layout is `key_epoch[32] || cell_counter[64]`, encoded in network byte order. The complete outer Ethernet and public headers are authenticated as AAD. Direction uses a separate key and nonce ledger and is also visible through the fixed outer MAC roles.

No public field contains protected length, transaction type, data/cover state, final-cell state, frame count, payload offset, or padding boundary.

## Encrypted private format

```text
epoch identifier          [8]
slot identifier           [1]
flags, including data bit [1]
cell index                [2]
configured slot count     [2]
inner frame count         [2]
serialized stream length  [4]
payload offset            [4]
payload length            [2]
protected type            [1]
reserved                  [1]
inner stream chunk       [0..180]
authenticated padding     [remaining bytes]
```

The inner stream serializes complete frames as repeated `uint32 length || frame bytes`. A valid decoder releases frames only after all configured cells authenticate and the complete stream parses exactly. No partial plaintext is released.

## Overflow and failure

- A slot overflow emits the same configured cell count as authenticated cover and records overflow only at the trusted evaluation boundary.
- Missing, conflicting duplicate, replayed, malformed, or unauthenticated cells fail the complete slot with no partial bytes.
- Reordering within the configured slot is accepted after authentication and index validation.
- The encrypted cell index must map to one contiguous public counter window, preventing authenticated cells from different emissions from being spliced into one slot.
- The receiver rejects repeated or decreasing encrypted epoch identifiers per direction and slot. A real restart must restore that accepted-epoch state or rotate to a fresh key epoch; the offline prototype does not supply production persistence.
- No cell-layer NACK, retransmission, escape cell, error packet, or clear fallback exists.
- Absolute counters and ciphertext vary, but counter allocation is independent of inner length. Structural observer features normalize counter start and retain the fixed stride pattern.

## Cryptographic scope

The codec calls the installed `cryptography` ChaCha20-Poly1305 implementation. It does not implement cryptography in P4 or by hand.

Evidence generation uses a named, explicitly public test-vector seed to derive non-secret offline keys and deterministic encrypted padding. Those values exist only to make generated artifacts byte-reproducible; they are not prototype or deployment secrets. S4+ prototype/live keys remain out of band and must never be committed or logged.

## Claim boundary

Passing S3 supports only:

> The offline codec constructs and reverses a fixed outer size/count/direction/slot transcript across the declared corpus, with protected metadata inside authenticated encryption.

It does not support a hardware-observed `PASS: real size normalization`, RN-T, multi-device indistinguishability, production cryptographic fitness, or the existence of the conditional Tofino CPU boundary.
