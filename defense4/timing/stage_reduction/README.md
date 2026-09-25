# Timing-only stage reduction

The candidate compiles to **8 ingress stages and 0 egress stages**, versus 12 and
6 for the request-anchored baseline. Removing sizing alone still uses 12 ingress
stages. The source remains an offline-validated candidate: packet execution and
hardware timing have not been validated.

| Build | Ingress | Egress | Critical path | Allocated tables |
|---|---:|---:|---:|---:|
| Request-anchored baseline | 12 | 6 | 12 | 113 |
| Sizing removed only | 12 | 0 | 12 | 98 |
| Optimized timing candidate | 8 | 0 | 8 | 75 |

Baseline: `../anchor_fix/src/defense4_rrc_bor_unified12.p4`, SHA256
`4bba0949489f2a36fde842335e9256aa0b3fbda107be5998d43ef90c26d8dc56`.
The initial recovery commit is `eb8f0ae7`; branch:
`optimize/timing-only-eight-stages`. Frozen sources, captures, and paper claims
are unchanged.

## What changed

- Removed packet size shaping and its parser, egress, multicast, and setup paths.
- Return first-ACK and ready-epoch predicates directly from their stateful actions.
- Match modular age words directly with `0x800000FF`; never substitute unsigned
  absolute-deadline comparison, which fails across timestamp wrap.
- Fold BOR terminal choices into the fresh/dequeued decision tables with the
  same priority, token budget updates, and generation ownership checks.
- Select deadline operands early, then perform ACK and response deadline accesses
  in parallel tables with identical decode keys and priorities. Separate tables
  are required because a single action cannot access both stateful resources.
- Arm/read the OPERATE deadline in the hold-decision action. Its returned age
  remains post-write, while ACK/response ages remain pre-write.
- Give the ACK-release record a separate result and use the current generation
  directly, removing the dependency on a reused write operand.
- Place response authorization and deadline selection at stage 3. These two
  hints prevent PHV overlay choices from introducing a ninth placement stage.

The terminal `tbl_commit` is still const-mapped with a fail-open default. Timing
parameters, packet bytes, queue choices, and recirculation budgets are preserved
by the source transformations; no new packet pass is introduced. The setup uses
program `defense4_timing`, five timing fields in `tbl_params`, and the original
outcome numbers with sizing holes 12, 32, and 34.

## Reproduce

From the repository root (choose a new output directory for each build):

```bash
python3 defense4/timing/stage_reduction/build.py \
  defense4/timing/stage_reduction/src/defense4_timing.p4 \
  /tmp/dnp3-timing-build --max-ingress 8
DNP3_BFRT_JSON=/tmp/dnp3-timing-build/out/bfrt.json \
  python3 -m pytest defense4/timing/stage_reduction/tests \
  defense4/timing/stage_reduction/control/tests -q
python3 defense4/timing/stage_reduction/control/defense4_timing_setup.py dry-run
python3 defense4/timing/stage_reduction/control/parameter_policy.py --selftest
python3 defense4/timing/stage_reduction/control/counter_map.py \
  --verify-p4 defense4/timing/stage_reduction/src/defense4_timing.p4
```

`build.py` uses Tofino-1/TNA and `-DU_BOR`; `--compiler` selects another SDE.
It snapshots the source, records its hash and compiler version, checks the final
placement against `context.json`, and fails if the stage target is missed.
The compiler appends placement retries: the **last** allocation is authoritative,
not the first. The final PHV report is retained too.

Evidence in `evidence/` contains build manifests, diagnostics, final placement
reports, and the generated candidate BFRT schema. Tests default to that schema;
set `DNP3_BFRT_JSON` to check a fresh build. The build manifests identify full
binary/context artifacts kept outside Git. The same candidate was compiled with
local SDE 9.13.1 and testbed SDE 9.13.2; remote compilation used a temporary
directory and did not load a pipeline.

## Validation boundaries and retained defects

Source-driven differential tests cover deadline selection, arm/disarm behavior,
first-ACK detection, BOR epoch/readiness, outcome priority, token watchdogs,
ACK-release recording, and timestamp wrap. Mutation controls check that changed
RegisterAction/action bodies cannot silently pass the reference model. These are
fragment tests, not complete packet-sequence or concurrent-packet equivalence.
Control tests check the generated BFRT interface and sizing-free dry-run setup.
BFRT schema presence does not prove physical default-entry readback.

The local model probe is blocked by missing `CAP_NET_RAW`/root privileges.
It generates packet vectors and checks config parsing; it **does not execute
packet behavior**. See `model/latest_model_smoke_report.json` for its exact source
hash and evidence. Historical measurements in inherited source comments apply to
the frozen program, not this candidate.

Two baseline issues are deliberately not repaired in this optimization:

- The early OPERATE deadline override reads `hold_ok` before its later hold
  computation. Tests preserve the old result for both early values 0 and 1;
  they do not establish how uninitialized metadata behaves on hardware.
- A released OPERATE retains its spent generation and suppresses a matching
  retransmission. Exactly-once delivery/loss recovery is not established.

The compiler still reports the inherited uninitialized parser metadata warning,
six unused telemetry/counter warnings, and two parser-unrolling warnings.
No hardware traffic, ports, queues, mirrors, packet generators, or switch daemon
were changed. Read-only inspection found the unrelated `mvm_tna` program running.
Independent architecture review was unavailable because the installed reviewer
model could not start; this is not a merge-ready or deployment-ready approval.
