# Configured inert-decoy endpoint gate (SBO + READ) — software-only evidence

This is the endpoint half of the DNP3 size-axis defense. The sibling directory
`../sbo_master_acceptance/` already showed that an unmodified master accepts a
SELECT/OPERATE echo padded with decoy CROBs (Encoding A) and rejects a merged
header (Encoding B). Here we go further: we configure the decoys as **real
endpoint points with real handlers**, prove the endpoint executes only what it
should, prove the unmodified master still accepts, and measure how the response
grows with decoy count — for both the SBO axis and the READ axis.

Everything runs on the real opendnp3-community command/outstation/master stack
with crafted APDU bytes driven straight into the code (no networking, no
hardware, no relay, no switch). A live pydnp3 master-outstation loopback is
blocked in this environment; the C++ stack path is the faithful substitute and
is stronger because it drives the exact same production parsing/command logic.

## Premise — endpoint preconfiguration is REQUIRED

The decoys are REAL, CONFIGURED endpoint control/measurement points: valid
indices, real handlers, status SUCCESS. They are simply **not wired to a physical
output**, so they execute with no physical action. Exactly one CROB index is
wired (the legitimate control). An index that was never configured is rejected.

This needs a firmware/relay configuration. It is **not** compatible with a
completely unmodified outstation. opendnp3's stock `SimpleCommandHandler` returns
one status for every index and never distinguishes configured from unconfigured
points, so the model lives in `src/DecoyGateCommandHandler.h`, which adds the
configured-index set, the wired/inert distinction, and per-point counters.

## Result — every assertion PASSED (151 assertions, 9 cases, 0 failures)

opendnp3-community `3.1.2-29-g4648fcb89`, g++ 9.4.0. Raw logs in `out/`.

### Part A — SBO endpoint (`out/partA_endpoint.txt`, 44 assertions)

| Claim | Observable | Verdict |
|---|---|---|
| Legit CROB executes exactly once | SELECT+OPERATE idx1 → `physicalActuations=1`, `operates(1)=1`; idx2/3/4 = 0 | PASS |
| Decoy is inert | SELECT+OPERATE idx2 → echo SUCCESS, `inertActuations=1`, `physicalActuations=0` | PASS |
| No unrequested point executes | interleaved 1,3,2,4 → each `operates=1`, `physical=1` (only wired), `inert=3` | PASS |
| Repeated SELECT / OPERATE safe | duplicate SELECT + duplicate OPERATE → `operates(1)=1`, `physicalActuations=1` | PASS |
| Unconfigured index fails safe | SELECT idx99 → `NOT_SUPPORTED` (status `04`, IIN2.2); OPERATE idx99 → `NO_SELECT` (`02`); actuations=0 | PASS |
| Per-object status recorded | echoes captured verbatim (see below) | PASS |

Serialized echoes (verbatim from the run):
```
legit  SELECT  echo = C0 81 80 00 0C 01 17 01 01 01 01 01 00 00 00 01 00 00 00 00   (status 00 SUCCESS)
legit  OPERATE echo = C1 81 80 00 0C 01 17 01 01 01 01 01 00 00 00 01 00 00 00 00   (status 00 SUCCESS)
idx99  SELECT  echo = C0 81 80 04 0C 01 17 01 63 01 01 01 00 00 00 01 00 00 00 04   (status 04 NOT_SUPPORTED, IIN2.2 set)
idx99  OPERATE echo = C1 81 80 00 0C 01 17 01 63 01 01 01 00 00 00 01 00 00 00 02   (status 02 NO_SELECT)
```
The unconfigured OPERATE never reaches the handler: the outstation blocks it at
select-matching (`NO_SELECT`, 0x02) because its SELECT failed. It cannot actuate.

### Part A — master acceptance (`out/partA_master.txt`, 35 assertions)

| Encoding | K decoys | Master emits OPERATE? | Per-object result | SELECT echo size |
|---|---|---|---|---|
| A: separate trailing G12V1 header | 1,2,3,5,8 | YES (real index 1 only) | index 1 `SUCCESS/SUCCESS` | 40, 53, 66, 92, 131 B |
| B: merged header, count grown 1→1+K | 2,3 | NO | index 1 `INIT` (never executed) | rejected |

Encoding A ACCEPTED across the sweep; Encoding B REJECTED. New evidence did not
change the A/B boundary — it is deterministic in the master's positional header
matching (traced in `../sbo_master_acceptance/README.md`). The OPERATE the master
emits carries only the real index; decoys never enter the master's command set.

### Part B — READ (`out/partB_read.txt`, 72 assertions)

B1 value/flag invariance + master acceptance. Real points 0..3 = values
1000..1003, flag ONLINE (0x01). Decoys are higher-index analog points. An
unmodified master issues the SAME `IntegrityPoll(0)` every time and receives the
outstation's decoy-augmented class-0 response:

```
K= 0  response= 29 B  TotalReceived=4   real[0..3]=(1000,1001,1002,1003) flags=0x1  UNCHANGED, ACCEPTED
K= 1  response= 34 B  TotalReceived=5   real[0..3]=(1000,1001,1002,1003) flags=0x1  UNCHANGED, ACCEPTED
K= 2  response= 39 B  TotalReceived=6   ...                                          UNCHANGED, ACCEPTED
K= 4  response= 49 B  TotalReceived=8   ...                                          UNCHANGED, ACCEPTED
K= 8  response= 69 B  TotalReceived=12  ...                                          UNCHANGED, ACCEPTED
K=16  response=109 B  TotalReceived=20  real[0..3]=(1000,1001,1002,1003) flags=0x1  UNCHANGED, ACCEPTED
```

Every real value and every real quality flag is identical as K grows; the master
accepts and delivers all real+decoy points.

B2 size / fragment / segment sweep (application bytes measured; transport
segments computed at 249 app bytes per DNP3 transport segment; under `TCP_NODELAY`
one transport segment maps to one link frame and one TCP segment; the on-wire TCP
count is otherwise bounded by `[1, transport_segments]` per MSS/Nagle):

```
maxTxFragSize=2048:  K=0..64  appBytes 29..349  dnp3AppFrags 1 (2 at K=64)  transportSegs 1 (2 at K=64)
maxTxFragSize=64  :  K=0..32  appBytes 29..216  dnp3AppFrags 1→2→4          transportSegs 1→2→4
```

Unlike SBO, the READ response is index-ordered and native-looking: decoys are
just higher-index points, so the padded response needs no non-native encoding.

## The bound this establishes

- SBO decoy padding is application-feasible but **not covert**: the accepted form
  (Encoding A) emits two G12V1 headers, which no native device does; the native
  one-header form is exactly the master-rejected Encoding B. It buys
  device-independence, not indistinguishability.
- READ decoy padding **is native-looking** and both value-preserving and
  master-accepted. This is the asymmetry between the two axes.
- Both require endpoint preconfiguration of the decoy points. State it plainly in
  any claim: the gate is a configured-decoy gate, not an unmodified-outstation
  gate.

## Files

- `src/DecoyGateCommandHandler.h` — configured-endpoint command handler (the
  premise, plus per-point counters). The one piece opendnp3 lacks.
- `tests/TestDecoyGateEndpoint.cpp` — Part A endpoint.
- `tests/TestDecoyGateMasterAcceptance.cpp` — Part A master, A/B + decoy sweep.
- `tests/TestDecoyGateReadSize.cpp` — Part B READ (B1 invariance, B2 size sweep).
- `patches/CMakeLists_unittests.patch` — the only edit to the opendnp3 tree
  (wires the three vendored sources into the `unittests` target). The `.cpp`/`.h`
  themselves are vendored here and copied in by `run.sh`; nothing is pushed.
- `out/` — raw Catch2 output, `env.txt`, `sha256.txt`, `build.log`.

## Reproduce

```bash
# opendnp3 source auto-resolved as a sibling of the repo root, or set explicitly:
OPENDNP3_SRC=/path/to/opendnp3-community bash run.sh
```

`run.sh` copies the vendored sources into `$OPENDNP3_SRC/cpp/tests/unit`, wires
them into the `unittests` target, builds **out of this repo's tracked tree** in
`$OPENDNP3_SRC/build`, and runs the three suites, teeing raw output to `out/`.

## Caveats

- opendnp3-community `3.1.2`; pydnp3 embeds the older ChargePoint ~2.x. The
  command (`CommandSetOps`, `TypedCommandHeader`, two-pass `APDUParser`),
  outstation SBO state machine, and static-read paths are materially unchanged
  across 2.0–3.1, so the result transfers, but the exact pydnp3 2.x build was not
  exercised (its live loopback is blocked here).
- `physicalActuations` is a software stand-in for "drives the wired output." No
  physical relay is touched. The physical SEL-751's own SBO echo layout and its
  decoy-point behavior are lab-gated and not confirmed here.
- TCP segment counts are computed from the DNP3 transport rule, not captured on a
  wire; the offline stack has no TCP.
