# read_reencode_01: standards-conforming READ padding

Replaces the deployed READ filler with a re-encoding of the same points. The work follows
`defense4/DNP3_Claude_Completion_and_IEEE1815_Prompt_f813bc089.md` §2. Status on 2026-10-13:

- Gate 1 (standards regression, software oracle and real endpoint) passes.
- The P4 re-encoding in E compiles and passes the compiled model (`full_01`).
- Silicon has not been run.

## Findings

Clauses opened in IEEE Std 1815-2012 on 2026-10-13 (printed page, PDF page = printed + 42):

| clause | what it says | consequence |
|---|---|---|
| Table 4-8, p.35 | qualifier 06: "Not permitted in a response"; 00/01: static objects in a response | the deployed READ tail `29 01 06 29 02 06 29 03 06` is not conformant |
| Table 12-6, p.354; Table 14-2, p.398 | G10V2 RESPONSE uses qualifier 00 or 01; every subset level, Level 1 included, must parse it | two start/stop ranges of G10V2 are a legal response |
| Table 12-8, p.354 | the G12V1 SELECT/OPERATE response is "Echo request" | control responses carry the request objects |
| 4.4.4.3 Rule 8, p.51 | the master compares *all* octets after the IIN with *all* octets after the request function code; if they do not match exactly, it shall not issue the OPERATE | no nonempty filler F can make R‖F equal R |
| Annex E (informative), pp.773-774 | CRC initialised to 0, inverted at the end, low octet sent first; the table is the reflected form (entry 128 = 0xA6BC) | `dnp3_std.crc` reproduces it |
| A.20.1, p.615 | G41V1 is an INT32 value plus a status octet | 5 octets |

The prompt also cites G41V2-V4, 9.2.4.x framing, 4.2.2.7.3.3-.5, 4.4.2.1 and Clause 13. Those clauses
were not opened this session.

**Why the pinned OpenDNP3 master accepted the padded SELECT** (source at `4648fcb`):
`CommandSetOps::ProcessAny` returns `IINBit::PARAM_ERROR` for a response header whose index is beyond
the request's header count. That error only accumulates into `IAPDUHandler::errors`
(`IAPDUHandler.h:173`), and `CommandSetOps::ProcessSelectResponse` never reads it. It checks the parse
result and whether the request's own headers were all selected. The extra G41V3 header is therefore
dropped silently. The master performs a per-header prefix check, not the exact comparison Rule 8
requires. An OpenDNP3 pass is evidence about that implementation, not about the standard.

## The re-encoding

```text
native  H | 0a 02 00 00 16          | P0..P22                       33 user octets, 49-octet frame
new     H | 0a 02 01 00 00 03 00    | P0..P3
          | 0a 02 01 04 00 16 00    | P4..P22                       42 user octets, 58-octet frame
```

H (the transport, application control, function and IIN octets) and all 23 status octets are
unchanged. The first user block is exactly H, the first header and P0..P3. Any other response shape
stays native (`reencode.eligible`).

## SBO

Unchanged SELECT requests, a strict Rule 8 master and a longer SELECT response cannot all hold at once.
This directory builds the **strict policy**: READ is 58 octets and SELECT/OPERATE stay native. That
policy does **not** meet the equal-size target. The deployed all-58 build remains a labelled
endpoint-specific profile (accepted by the tested OpenDNP3) whose non-conformance is disclosed. Equal
size for SBO needs Philip to decide on a changed endpoint contract or protection boundary.

## Files and checks

- `dnp3_std.py` is an independent checker: CRC, LEN, legal response qualifiers per object,
  consumption of every octet, and the Rule 8 echo. It shares no code with `framework/size`.
- `reencode.py` is the software oracle for the P4 transform. `capture.py` reassembles TCP streams and
  splits them into link frames.
- `tests/test_standards.py` holds 18 tests, run with `python3 -m pytest -q tests`. It covers:
  - the prompt's two vectors, matched byte for byte;
  - 500 random status patterns;
  - rejection of misplaced, duplicated, missing and malformed objects, and of G10V2 responses using
    qualifiers 17/28/06;
  - the 20 native READs from `candidate56r_single_loss_03` (`out.pcap` sha256 `2f92bf16…`), each
    re-encoding to 58 octets with identical points;
  - the deployed READ filler being rejected;
  - the deployed control padding failing Rule 8, and no random filler satisfying it.

  Two mutations were applied to check that the suite can fail: a moved status octet, and qualifier 06
  allowed in responses. Both are caught.
- `run_endpoint.py` and `endpoint_proxy.py` run the pinned OpenDNP3 `4648fcb` master and outstation over
  real loopback TCP, with the re-encoding applied in transit.

  `evidence/endpoint_01` **passes**:
  - 20 READs on one persistent connection, every response re-encoded to 58 octets;
  - all 23 seeded points delivered on every READ;
  - then a native SELECT→OPERATE on the same connection, with one real callback each and no decoy
    touched;
  - the independent standards check on the tee reports 0 failures.

  The binary sha256 is `8d6f6ee3…`. It differs from the 2026-10-09 pad58b build (`0f0fbbd2…`); the
  cause was not investigated.

  The run's snapshot `sources/dnp3_std.py` predates the per-object qualifier tightening. Re-running
  `run_endpoint.check_tee` with the current checker on the same `tee.jsonl` also gives 0 failures
  (20 re-encoded READs, 2 native control responses).

  No P4, switch or physical endpoint was involved. This endpoint run used the alternating
  0x81/0x01 seed. Varied status patterns are tested offline only.

## P4 implementation (`generate.py`, E only)

Every status octet keeps its order, so the parser splits the native READ response at every boundary
that either layout needs (rh, robj, p03, p45, c0, p612, p1321, c1, p22, c2). Padding then moves no
data. It:

- validates the constant headers `ra`/`rbh` and their CRC headers `ca`/`cb`;
- invalidates `robj`, `c0` and `c1`;
- rewrites `c2` with the third block's CRC.

The input CRC validation of the native blocks is unchanged. The padded-case TCP checksum list names
exactly the emitted headers, because absent headers would add whatever shares their containers. The
image, accounting and reverse partition are unchanged: the frame grows by +9 octets and stays 58.

Input: the `rearm_56r` composite, `retx_passthrough_01/evidence/full_01/response_only.p4`
(sha256 `ec0dd7af…`). N and T are asserted byte-identical.

| build | options | local 9.13.1 stages (N / E / T) | diag model (519) | retx model (37) |
|---|---|---|---|---|
| `full_01` | block CRCs in stage 0 | 12 / 12 / 11 | **519/519** | **37/37** |
| `full_02` | `--late` (block CRCs after `derive_t`) | 11 / 12 / 11 | 154/519: SYN-ACK dropped | 15/37 |
| `full_03` | `--late --strict` | compiled, not run (inherits `full_02`'s defect) | | |
| `full_04` | `--strict` (controls native) | 12 / 12 / 11 | **519/519** (strict-frontier driver) | **37/37** (strict-frontier driver) |

The model runs use `model_drive_oracle.py` around the retained drivers. The wrapper swaps only the READ
oracle, so every padded-READ byte comparison checks the re-encoding. With
`CASE4_STRICT_CONTROLS=1` the control oracle returns the native frame.

**Strict policy (`full_04`).** Under the retained drivers unchanged, the strict build scores 498/519 and
32/37 (`model_diag_04`, `model_retx_04`). Every failure starts at the OPERATE: those drivers hardcode the
master's frontier after a 58-octet control image (7117/7175 and 1017). `model_drive_diag_strict.py` and
`model_drive_retx_strict.py` replace exactly those literals with the native-control frontier (7096/7133 and
996), asserting each one is found, and change nothing else. With them the strict build passes 519/519
and 37/37 (`model_diag_04_strict`, `model_retx_04_strict`). The native 37-octet SELECT and OPERATE
responses are sequence-translated behind the padded READs and are not padded. The strict policy keeps
Rule 8 echoes exact, but it does not give equal response sizes.

**N's stage count (12 vs 11).** `full_01` moves pipe-0 ingress (N, whose source is byte-identical) from
11 to 12 stages. N shares pipe 0's PHV and stage resources with E. Moving the two block-CRC hashes
later (`full_02`) restores 11, but that build is unsafe.

**Why `full_02` fails.** The SYN-ACK is aborted in N. The cause is the `epoch_t` stateful-ALU output's
action-bus layout in the compiled `.bfa`.

- `full_01` (line 9264) uses a single 32-bit slot: `112..115 : epoch(0..31)`.
- `full_02` (line 9506) mixes 8-bit, 16-bit and 32-bit slices over bytes 32..35, and the model loads
  `m.epoch` as `0x10000` instead of `0x1`.
- Moving only the egress applies re-ran pipe-wide PHV allocation, which split `m.epoch_diff` into
  B4/B5/H95.

Traces: model logs `model_diag_01` line 9859 vs `model_diag_02` line 9886. Whether silicon misreads
this layout is unknown. `full_02` and `full_03` are not candidates. A pinned 32-bit `m.epoch_diff`
could make the late placement safe, but that is untested.
