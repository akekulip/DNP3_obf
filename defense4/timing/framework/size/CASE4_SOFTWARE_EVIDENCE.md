# Case 4 bounded software size profile — 2026-10-06

The working candidate uses separate trailing G12V1 headers. Historical
`49→[28,21]` remains the default `RRC_49_CUT28` profile; endpoint-compatible
`57→[28,29]` is selected explicitly as `RRC_57_CUT28`. These are separate
profiles, not interchangeable evidence.

## Wire and transport evidence

`case4_padding.expand_control(frame, Decoy(index, body))` accepts one complete,
CRC-valid DNP3 frame containing one native G12V1 CROB, qualifier `0x28`, with a
complete transport/application fragment and SELECT or OPERATE function. The
native CROB, application/transport sequence and link addresses remain byte-exact.
The new header contains one externally configured decoy. The codec cannot
establish that an endpoint index is inert: verified configuration is a separate
admission prerequisite. Unsupported, malformed, bad-CRC and colliding-index
inputs pass unchanged before insertion.

| Encoding | APDU bytes | Transport + APDU | Complete TCP DNP3 payload |
|---|---:|---:|---:|
| Native command | 20 | 21 | 35 |
| Command + separate decoy header | 38 | 39 | 55 |
| Native control response | 22 | 23 | 37 |
| Echo with decoy header | 40 | 41 | 57 |

The 18 added application bytes cross a CRC-block boundary, adding two more
wire bytes: the request delta is **20 bytes**, not 18. All length fields and link
CRCs are regenerated. Packet carving checks the IP/TCP checksums and full-frame
DNP3 CRCs before producing segments; reassembled payload is exact.

`case4_transport.ControlConnection` admits one matching SELECT/OPERATE pair per
connection. Both requests must contain identical native object bytes and link
identity; the same immutable decoy is appended to each. `RequestLedger` caches
two actual native/transformed request images, including all changed link CRC
bytes. Retransmission replay covers whole frames, partial and overlapping
segments and changed segmentation; it does not append synthetic filler.
While any inserted tail remains unacknowledged, ACK inversion withholds the final
native byte. For the first 35→55 image, wire ACK offsets 35–54 map to native offset 34;
wire offset 55 releases native offset 35. For the second adjacent image, wire90–109 map to
native offset 69; wire offset 110 releases native offset 70. The receive-window right edge uses that same
monotone inverse: zero remains zero, and translated width cannot exceed the
original unscaled window.

This repairs the earlier premature-retirement defect: clamping an inserted-tail
ACK to the complete native request end could leave no outstanding upstream bytes
to retransmit a missing tail. Withholding keeps the final native byte owned by
the upstream sender. Replaying that one native byte produces the exact last 21
wire bytes from the cached image, including the growth. Tests reconstruct every
truncated inserted tail at both boundaries and across wrap, then release native
completion only after the full wire image is acknowledged. This is a modeled
sender-owned retransmission path; the helper performs no autonomous transmission
and the tests do not establish a kernel retransmission timer or real socket loss
recovery. BMv2 raw-packet evidence is a separate artifact.
Modular offsets support crossing TCP wrap while keeping the connection span
below the half-range.

Unsupported negotiated features (SACK, scaled windows, urgent/unknown options)
must be excluded before the first insertion. The current helper receives this
fact from its caller; it does not parse a handshake. After insertion, capacity or
eligibility refusal preserves all existing sequence/ACK translation and replay.
Conflicting overlapping original bytes raise an error without erasing the
ledger. RST is translated before explicit retirement. The caller owns connection
identity, FIN retirement, old-packet quarantine and rearm; these software helpers
do **not** establish those packet-level lifecycle mechanisms on a switch.

Reproduction:

```sh
python3 -m unittest discover -s defense4/timing/framework/tests -p test_case4_padding.py
python3 -m unittest discover -s defense4/timing/framework/tests -p test_case4_transport.py
python3 -m unittest discover -s defense4/timing/framework/tests -p test_rrc_split.py
```

The three suites passed 4, 12 and 21 tests respectively, with no skips. The split
suite includes historical capture re-analysis and current synthetic checks;
historical traces retain their historical meaning.

## Independent OpenDNP3 semantic gate

`endpoint_gate/run.py` builds real production master and outstation contexts from
clean pinned OpenDNP3 commit `4648fcb898456d1cb70b5baecc38cc256c859c2e` using `git
archive`. The dirty sibling checkout is read-only and its local modifications
are excluded. FetchContent dependency versions/hashes come from that pinned
source. The test uses the production master CommandSet serializer, the
production outstation SBO state machine and production CRC implementation.
No sockets, switch connection, relay connection or physical output is used.

Only the configured command handler was recovered from historical DNP3 revision
`ef82faed31a403fe0e13814d68c9e9c628d6d971`, file
`defense4/size/evidence/decoy_gate/src/DecoyGateCommandHandler.h`, SHA-256
`e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2`.
Its “physicalActuations” member is a software counter for the designated native
index. It is not physical actuation evidence.

The gate establishes:

- Production native SELECT serialization equals the codec input; transformed
  request APDU is exactly 38 bytes; actual control echoes are exactly 40 bytes.
- Both native and decoy objects return SUCCESS in SELECT and OPERATE. The master
  emits only its original object in OPERATE and reports the original point's
  SUCCESS status. The outstation delivers one callback per configured point;
  repeated OPERATE is deduplicated by its production application state machine.
- Native SELECT failure emits no OPERATE. A subsequent successful transaction
  completes using the same contexts.
- A decoy SELECT failure is **ignored by the native master**, which emits OPERATE.
  The outstation returns NO_SELECT for both objects and executes zero callbacks.
  The subsequent transaction recovers after the software handler clears the
  failure. Therefore verified successful decoy statuses are a required profile
  condition; trailing-header acceptance alone cannot establish success.
- The production OpenDNP3 CRC routine independently validates the transformed
  header and every data CRC block generated by the Python wire codec.

`CommandPointState::SUCCESS` means a matching OPERATE response was received;
it does not require `CommandStatus::SUCCESS`. The failure gate checks command
status explicitly. Master `ignoreRestartIIN=true` isolates SBO from unrelated
restart housekeeping; initial diagnostics retain the production IIN-triggered
WRITE that first exposed this fixture setup issue.

Reproduction:

```sh
python3 defense4/timing/framework/size/endpoint_gate/run.py
```

`OPENDNP3_SRC` can supply a read-only repository containing the pinned commit.
`CASE4_GATE_WORK` can select a disposable directory outside the source trees to
reuse build artifacts. Evidence lives in `endpoint_gate/evidence/`: build/configure
logs, actual semantic test output, generated vectors and source/binary manifest.
The standalone gate is separate from the framework's Python test count.

## Limits

This establishes wire encoding, bounded sequence accounting and pinned software
endpoint compatibility. It does not establish physical inert-point configuration,
relay firmware compatibility, real TCP socket loss behavior, live queue timing,
complete P4 translation correctness, complete joint Case 4 operation or hardware admission. The separately labelled current compiler coexistence probe in `../p4/STATUS.md` establishes narrow resource fit only.
Those gates remain separate. Do not promote a codec round-trip or historical
pre-enlarged-master capture into switch-side insertion evidence.
