# Native-parity endpoint harness — SBO + READ, software-only evidence

The endpoint half of the native-parity size defense (Gate E). It proves the DNP3
**endpoint semantics** of the even-real / odd-decoy cover strategy on the real opendnp3
master + outstation stacks, and it **derives the exact serialized sizes from real bytes**
so the length-synthesis solver (`../length_synth.py`) is anchored to what opendnp3 actually
emits — not to remembered constants.

**Endpoint-assisted native cover generation, not switch-side padding.** The master itself
builds one native multi-CROB `CommandSet` (even real CROB + odd decoy CROBs) and its own
SELECT/OPERATE carry the whole set on the wire. The switch is never involved here. State it
honestly: this requires configured decoy points at both endpoints; it is a configured-decoy
gate, not an unmodified-outstation trick.

## Software only — no hardware, ever, in this run

Crafted APDU bytes and native `CommandSet` serializations are driven straight into a REAL
opendnp3 master context and a REAL opendnp3 outstation context (the production SELECT/OPERATE
+ SBO state machine, the `CommandSet` serializer, and the static-read path). No networking, no
hardware, no physical relay, no switch. This is the faithful substitute for a live pydnp3
master↔outstation loopback, which **SIGSTKFLTs in this sandbox** (the loopback relay processes
get killed); the native single-process C++ stack is clean and is stronger, because it drives
the exact production code paths.

`physicalActuations` / `inertActuations` are a **simulated** physical/inert mapping in the
`NativeParityCommandHandler` (software counters). No physical relay is touched. "Real fires
once" means the one wired handler ran once; it is not physical-relay evidence.

## Mandatory hardware prerequisite (future, NOT performed here)

Before ANY physical experiment, the odd (decoy) output points **must be proven physically
disconnected or unmapped from breaker control** — no wiring to a real output, no breaker
mapping in the relay logic. This run performs no relay configuration writes, no physical
SELECT, and no physical OPERATE. The wired point must additionally be configured **SBO-only**
so a bare DirectOperate (function 0x05) cannot bypass the select gate; opendnp3's `HandleOperate`
(function 0x04) already enforces the prior select, but `HandleDirectOperate` (0x05) does not.

## What is DERIVED from real bytes (deliverable 2)

Run over the real opendnp3 serializations; full tables in `evidence/derived_sizes.txt`.

**SBO — one shared header.** A native `CommandSet` built with a single `Add()` of K CROBs
serializes as exactly **ONE** shared Group12Var1 object header (`countG12Headers == 1`), not
repeated headers. This is the native single-header form, unlike the earlier transformer's
Encoding-A (separate trailing header).

**SBO — qualifier width is `MasterParams::controlQualifierMode`.**

| mode | qualifier | u_SBO(K) echo | matches relay anchors? |
|---|---|---|---|
| `allow_one_byte` (indices ≤ 255) | **0x17** (1-byte count + 1-byte prefix) | **u = 9 + 12K** | **YES** — 35 B (K=1), 49 B (K=2), 61 B (K=3) |
| `always_two_bytes` (opendnp3 default) | 0x28 (2-byte count + 2-byte prefix) | u = 10 + 13K | NO — 37/52/67 B (residual distinguisher) |
| any, but an index > 255 present | forced 0x28 | u = 10 + 13K | NO |

`link_size(u) = 10 + u + 2·ceil(u/16)`. The measured relay anchors (1-CROB echo 35 B, 2-CROB
49 B) are reproduced **exactly** only with `allow_one_byte`; the opendnp3 default (`always_two_bytes`)
does not, and that width difference is a real parser-visible residual to report.

**READ — per-object widths confirmed.**

| object | header | per point | u_READ(N) | confirmed |
|---|---|---|---|---|
| G30V1 analog | 5 B (grp,var,qual 0x00,start,stop) | 5 B (flag + i32) | **u = 10 + 5N** | yes, from bytes |
| G10V2 binary-output-status | 5 B | 1 B (flag octet) | **u = 10 + N** | yes, from bytes |

**Native-size intersections (from bytes).** For SBO K CROBs (relay 0x17 model, u = 9+12K):
G10V2 matches at **N = 12K−1** (integer for every K), G30V1 matches at **N = (12K−1)/5**
(integer iff K mod 5 = 3). Confirmed anchors: **49 B = SBO K=2 = G10V2 N=23**; **61 B = SBO
K=3 = G30V1 N=7**.

## Endpoint semantics proven (deliverable 3)

All on the real stacks; raw Catch2 output in `evidence/{sbo,semantics,read}.txt`.

- SELECT carries the exact even/odd set, in order, one shared header (`NativeParitySBOTestSuite`).
- OPERATE **repeats the SELECT object bytes byte-for-byte** (object portion identical).
- Every per-object status parsed (real + every decoy); the real (even, wired) callback fires
  exactly once; odd decoy callbacks are inert; no unrequested index actuates.
- **A failed decoy fails the whole parity operation** — opendnp3 caches the SBO selection only
  if every selected object is SUCCESS, so one failing decoy (or the real point) un-caches the
  SELECT: no OPERATE, real command safely lost (fail-safe, never a silent ignore). Same for a
  forced real-point failure.
- Rejections (crafted adversarial OPERATE into the real outstation, grounded in
  `ControlState::ValidateSelection`: OPERATE object bytes must be byte-identical — same length
  AND same CRC digest — to the cached SELECT, with app-seq = SELECT.seq+1): unconfigured point,
  missing decoy, added object, reordered object, value mismatch, control-code mismatch — all
  → NO_SELECT, nothing actuates.
- Duplicate SELECT / exact OPERATE retransmission → cached echo, no re-Select, no second
  actuation.
- Direct OPERATE (0x04) with no prior SELECT → NO_SELECT, nothing actuates.

**Result: 1276 assertions, 16 cases, 3 suites, 0 failures** (opendnp3-community 3.1.2, g++ 9.4.0,
cmake 3.16.3). `evidence/env.txt` + `evidence/sha256.txt` carry provenance.

## Files

- `outstation/NativeParityCommandHandler.h` — even=real(wired) / odd=decoy(inert) command
  handler; enforces the parity invariant at construction; per-point counters; forced-failure.
- `master/NativeParityPlan.h` — the K-CROB index plan (even real + odd decoys, all ≤ 255).
- `tests/NativeParityHelpers.h` — hex/wire helpers (`link_size`, CRC boundaries, header count,
  per-object status walk); everything derives from the emitted bytes.
- `tests/TestNativeParitySBO.cpp` — native `CommandSet` SBO round trip + size derivation + the
  happy-path endpoint semantics; emits `##VEC##` byte-vectors.
- `tests/TestNativeParitySemantics.cpp` — the rejection / SBO-enforcement cases.
- `tests/TestNativeParityReadSize.cpp` — G30V1 + G10V2 READ size derivation + master accept +
  intersection confirmation.
- `derive_sizes.py` — reduces the committed `##VEC##` lines into `evidence/derived_sizes.json`.
- `run.sh` — isolated build + run (see below).
- `evidence/` — raw Catch2 output, `vectors.jsonl`, `derived_sizes.{json,txt}`, `env.txt`,
  `sha256.txt`, `build.log`.

## Build model — ISOLATED, fork untouched

`run.sh` rsyncs a private throwaway COPY of the opendnp3 source into a work dir outside any
tracked tree, adds ONE standalone CMake target (`native_parity`) there, and builds only that
target. The shared opendnp3 checkout is never modified or rebuilt. Nothing is pushed and no git
state is touched.

## Reproduce

```bash
# opendnp3 source auto-resolved as a sibling of the repo root, or set explicitly.
# The build happens in an isolated COPY under a mktemp work dir (or $NP_WORK).
OPENDNP3_SRC=/path/to/opendnp3-community bash run.sh
# -> exits non-zero if any suite fails; evidence in evidence/.
```

## Honest limits

- opendnp3-community 3.1.2; pydnp3 embeds the older ChargePoint ~2.x. The command path,
  outstation SBO state machine, and static-read paths are materially unchanged across 2.0–3.1,
  so the result transfers, but the exact pydnp3 build was not exercised (its live loopback is
  blocked here by SIGSTKFLT).
- The size derivation is the opendnp3 serialization. The physical SEL-751's own SBO echo layout
  is characterised only by the measured anchors (35 B, 49 B), which match the `allow_one_byte`
  0x17 model — so the SEL-751 echoes with a 1-byte qualifier. Its exact READ variation defaults
  and its decoy-point behaviour are lab-gated and not confirmed here.
- This gate establishes native-size EQUALITY under a count+segmentation observer; a parser-aware
  observer still separates a G12V1 SBO from a G10V2/G30V1 READ (object type, function code, IIN).
  That residual is reported, never collapsed into a DPI-equality claim. No device-anonymity claim.
