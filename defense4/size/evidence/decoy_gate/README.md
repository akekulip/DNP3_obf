# Configured inert-decoy endpoint gate (SBO round trip + READ) — software-only evidence

This is the endpoint half of the DNP3 size-axis defense. It configures decoy points as
**real endpoint points with real handlers**, then shows three things on the real
opendnp3 command/outstation/master stack: the outstation executes only what it should, an
unmodified master still accepts the decoy-padded traffic, and the size axis behaves as
claimed on both the SBO path and the READ path.

Everything runs in software: crafted APDU bytes are driven straight into a real opendnp3
master context and a real opendnp3 outstation context. No networking, no hardware, no
relay, no switch. A live pydnp3 master↔outstation loopback SIGSTKFLTs in this environment;
the C++ stack path is the faithful substitute and is stronger, because it drives the exact
same production SELECT/OPERATE + SBO state machine and static-read code.

## Premise — endpoint preconfiguration is REQUIRED (state it in every claim)

The decoys are REAL, CONFIGURED endpoint points: valid indices, real handlers, status
SUCCESS. They are simply **not wired to a physical output**, so they execute with no
physical action. Exactly one CROB index is wired (the legitimate control). An index that
was never configured is rejected. This needs a firmware/relay configuration; it is **not**
compatible with a completely unmodified outstation. opendnp3's stock `SimpleCommandHandler`
returns one status for every index and never distinguishes configured from unconfigured
points, so the model lives in `src/DecoyGateCommandHandler.h`, which adds the
configured-index set, the wired/inert distinction, per-point counters, and an optional
forced-failure status for a configured decoy.

## What the callback counters mean

`physicalActuations` / `inertActuations` / `failedActuations` are a **simulated
physical/inert mapping** in software. No physical relay is touched. "Legit fires once"
means the one wired handler ran once; it is not physical-relay evidence.

## Correction to a prior claim (READ byte-identity)

An earlier version of the READ test asserted `analogSOE[i].meas == Analog(value, flags)`
and described it as "byte-for-byte unchanged." That comparison is over the **parsed**
measurement (value + quality flag), not the serialized response bytes, so the
"byte-for-byte" label was wrong. It is corrected here two ways:

- the supported semantic claim is stated plainly: *the unmodified master receives
  semantically equal real values and quality flags as decoys are added*;
- a real **per-object serialized** comparison is added: each real object's on-wire
  variation, index, quality byte, and value bytes are extracted and required byte-identical
  between the native and the decoy-padded response. The whole response is **not** required
  to be byte-identical — the header range/count/length legitimately change.

## Build model — ISOLATED, fork untouched

`run.sh` rsyncs a private throwaway COPY of the opendnp3 source into a work dir outside any
tracked tree, adds ONE standalone CMake target (`decoy_gate`) there, and builds only that
target. The shared opendnp3 checkout is never modified and never rebuilt, so the build is
immune to concurrent edits in that tree and nothing needs to be restored in it. The one
vendored change is `patches/standalone_target.patch` (adds the `decoy_gate` target); the
`.cpp`/`.h` are vendored in this directory. Nothing is pushed and no git state is touched.

## Result — every assertion PASSED (729 assertions, 14 cases, 4 suites, 0 failures)

opendnp3-community `3.1.2-29-g4648fcb89`, g++ 9.4.0, cmake 3.16.3. Raw logs in `out/`.

| Suite | file | assertions | cases |
|---|---|---|---|
| Part A — full SBO round trip | `out/partA_roundtrip.txt` | 323 | 4 |
| Part A — endpoint semantics  | `out/partA_endpoint.txt`  | 44  | 5 |
| Part A — master acceptance   | `out/partA_master.txt`    | 35  | 2 |
| Part B — READ                | `out/partB_read.txt`      | 327 | 3 |

### Part A — full SBO round trip (`out/partA_roundtrip.txt`)

One integrated in-memory transaction: unmodified master ↔ size-axis transformer ↔ configured
outstation. Swept over K = 1,2,3,5,8 decoys. The ten contracted steps, all PASS:

| # | step | observable | verdict |
|---|---|---|---|
| 1 | master SELECTs the legit CROB only | `C0 03 0C 01 28 01 00 01 00 <CROB>` (index 1 only) | PASS |
| 2 | transformer adds decoys (Encoding A) | separate trailing G12V1 header, K decoys | PASS |
| 3 | outstation receives expanded SELECT | parsed, per-object handled | PASS |
| 4 | every real+decoy SELECT status recorded | all `SUCCESS` (all configured) | PASS |
| 5 | master accepts, emits OPERATE (legit only) | `C1 04 0C 01 28 01 00 01 00 <CROB>` | PASS |
| 6 | transformer adds the EXACT decoys to OPERATE | byte-identical decoy header | PASS |
| 7 | outstation processes expanded OPERATE | SBO select-match SUCCESS | PASS |
| 8 | legit mapping fires EXACTLY once | `physicalActuations=1`, `operates(1)=1` | PASS |
| 9 | every decoy reaches ONLY its inert mapping | `inertActuations=K`, `operates(decoy)=1`, log has one PHYSICAL | PASS |
| 10 | master COMPLETES successfully | `TaskCompletion::SUCCESS`, index 1 `SUCCESS/SUCCESS` | PASS |

Extra cases (all PASS):

| case | observable | verdict |
|---|---|---|
| exact retransmission of transformed SELECT | duplicate → byte-identical cached echo; `selects(1)=1`; no actuation | PASS |
| exact retransmission of transformed OPERATE | duplicate → cached echo; `physicalActuations` stays 1; no 2nd actuation | PASS |
| SELECT/OPERATE decoy MISMATCH | OPERATE decoys ≠ SELECT decoys → every object `NO_SELECT`; nothing actuates | PASS (rejected safely) |
| unconfigured decoy in the stream | idx99 → `NOT_SUPPORTED` at SELECT; SELECT not cached; OPERATE all `NO_SELECT`; nothing actuates | PASS (fail-safe) |
| one configured decoy returns FAILURE | idx3 → `HARDWARE_ERROR` at SELECT; SELECT not cached; OPERATE all `NO_SELECT`; nothing actuates | PASS (fail-safe) |
| no unrequested index executes | operate log = {idx1 PHYSICAL} + K INERT, every entry ∈ requested set | PASS |
| status for every real+decoy object | echo walked; per-object (index,status) printed for SELECT and OPERATE | PASS |

**Honest limit surfaced by the round trip.** opendnp3 caches the SBO selection only if
*every* selected object returns SUCCESS (`HandleSelect` → `AllCommandsSuccessful()`). So a
single bad decoy — one that is unconfigured, or a configured decoy that reports an error —
makes the whole SELECT un-cached, and the following OPERATE fails `NO_SELECT`. Nothing
misactuates (fail-safe), but the **real command is lost**. Every decoy the transformer adds
must be a configured point that returns SUCCESS at SELECT time, or the legitimate control
does not go through. This is a real constraint on any Encoding-A SBO decoy scheme.

### Part A — endpoint semantics (`out/partA_endpoint.txt`)

Verbatim echoes from the run:
```
legit  SELECT  echo = C0 81 80 00 0C 01 17 01 01 01 01 01 00 00 00 01 00 00 00 00   (status 00 SUCCESS)
legit  OPERATE echo = C1 81 80 00 0C 01 17 01 01 01 01 01 00 00 00 01 00 00 00 00   (status 00 SUCCESS)
idx99  SELECT  echo = C0 81 80 04 0C 01 17 01 63 01 01 01 00 00 00 01 00 00 00 04   (status 04 NOT_SUPPORTED, IIN2.2)
idx99  OPERATE echo = C1 81 80 00 0C 01 17 01 63 01 01 01 00 00 00 01 00 00 00 02   (status 02 NO_SELECT)
```

### Part A — master acceptance (`out/partA_master.txt`)

| Encoding | K decoys | Master emits OPERATE? | Per-object result | SELECT echo size |
|---|---|---|---|---|
| A: separate trailing G12V1 header | 1,2,3,5,8 | YES (real index 1 only) | index 1 `SUCCESS/SUCCESS` | 40, 53, 66, 92, 131 B |
| B: merged header, count grown 1→1+K | 2,3 | NO | index 1 `INIT` (never executed) | rejected |

Encoding A is accepted; Encoding B is rejected. The accepted form emits **two** G12V1
headers, which no native device does — so SBO decoy padding buys device-independence, not
indistinguishability. This is the SBO↔READ asymmetry.

### Part B — READ (`out/partB_read.txt`)

**B1 — per-object invariance (semantic AND serialized), master accepts.** Real points 0..3 =
values 1000..1003, flag ONLINE (0x01). Native class-0 response:
```
C0 81 80 00 1E 01 00 00 03 01 E8 03 00 00 01 E9 03 00 00 01 EA 03 00 00 01 EB 03 00 00   (29 B)
```
Each real object (group/var `1E 01`, quality `01`, value LE) is byte-identical between the
native and the decoy-padded response as K grows (K = 0..16); the master parses the padded
response, delivers all real+decoy points, and every real value + quality flag is
semantically equal to the loaded value. The whole response is not byte-identical (range,
count, length change) — and is not required to be.

**B2 — common-target CONVERGENCE (the normalization gate).** Two software outstation profiles
with different native sizes are each padded with configured decoys to ONE declared common
public schema:

```
NATIVE (undefended):  P1 = 29 B, range [0..3]   P2 = 59 B, range [0..9]   -> DISTINGUISHABLE
PADDED to target 16:  P1: appBytes=89 variation=1E 01 qual=00 indexRange=[0..15] objCount=16 dnp3Frags=1 transportSegs=1
                      P2: appBytes=89 variation=1E 01 qual=00 indexRange=[0..15] objCount=16 dnp3Frags=1 transportSegs=1
VERDICT: 29 B and 59 B devices CONVERGE to one declared target (89 B, g30v1, [0..15], 16 objs) -> PASS
```

Both profiles reach the identical measured target at the declared layer (object variation,
qualifier, index range, object count, application bytes, fragment count), and each profile's
real objects stay byte-identical to their native serialization. This is convergence, not
mere growth.

**B3 — single-profile enlargement sweep.** One device's response simply gets larger with K
(29→349 B; application fragments and transport segments grow once the fragment size is
exceeded). This is recorded as a **contrast**: a bigger response is `size enlargement`, not
normalization. The normalization claim rests on B2, not B3.

## The bound this establishes

- SBO decoy padding is application-feasible and safe, but **not covert**: the accepted form
  (Encoding A) emits two G12V1 headers, which no native device does; the native one-header
  form is exactly the master-rejected Encoding B. And every decoy must succeed at SELECT or
  the real command is safely lost.
- READ decoy padding **is native-looking** and both value-preserving and master-accepted,
  and — with configured decoys chosen to hit a common declared schema — it makes two
  natively-different devices converge to one observable READ profile.
- Both require endpoint preconfiguration of the decoy points. State it plainly in any claim:
  this is a configured-decoy gate, not an unmodified-outstation gate.

## Files

- `src/DecoyGateCommandHandler.h` — configured-endpoint command handler (the premise, plus
  per-point counters and an optional forced-failure status). The one piece opendnp3 lacks.
- `tests/TestDecoyGateRoundTrip.cpp` — Part A full SBO round trip + extra cases.
- `tests/TestDecoyGateEndpoint.cpp` — Part A endpoint semantics.
- `tests/TestDecoyGateMasterAcceptance.cpp` — Part A master, A/B + decoy sweep.
- `tests/TestDecoyGateReadSize.cpp` — Part B READ (B1 per-object invariance, B2 convergence,
  B3 enlargement).
- `patches/standalone_target.patch` — the only opendnp3 change: adds the standalone
  `decoy_gate` target to the unit-test CMake. Applied to an isolated COPY, never to the fork.
- `out/` — raw Catch2 output, `env.txt`, `sha256.txt`, `build.log`.

## Reproduce

```bash
# opendnp3 source auto-resolved as a sibling of the repo root, or set explicitly.
# The build happens in an isolated COPY under a mktemp work dir (or $DECOY_GATE_WORK),
# NOT in the opendnp3 checkout.
OPENDNP3_SRC=/path/to/opendnp3-community bash run.sh
```

## Caveats

- opendnp3-community `3.1.2`; pydnp3 embeds the older ChargePoint ~2.x. The command path
  (`CommandResponseHandler`, `ControlState` SBO match), outstation SBO state machine, and
  static-read paths are materially unchanged across 2.0–3.1, so the result transfers, but
  the exact pydnp3 2.x build was not exercised (its live loopback is blocked here).
- The callback counters are a simulated physical/inert mapping. No physical relay is touched.
  The physical SEL-751's own SBO echo layout and its decoy-point behavior are lab-gated and
  not confirmed here.
- Transport/TCP segment counts in B are computed from the DNP3 transport rule (249 app bytes
  per segment), not captured on a wire; the offline stack has no TCP.
