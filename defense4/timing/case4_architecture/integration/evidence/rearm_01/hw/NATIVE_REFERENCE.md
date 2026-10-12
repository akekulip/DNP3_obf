# Native software-path reference

`native_reference.py` plans three 20-READ + one-SBO blocks through the running
`case4_response_path` program. It installs only the software-endpoint vEPA slot
with padding disabled (`switch_slot.py vepa --enable 0`), reflecting dev 9 to dev
9. It does not copy/install an N/T composite, restart `bf_switchd`, or load a
new program. This reference includes the production transport mapper and the
software fixture; it is not a direct-link baseline.

The source configuration is
`protocol/hw_vepa/config/fourarm_separate_ack_14892.json`. Its controls endpoint
binary/library pins are verified in
`/home/decps/pad58b_rearm_controls_20261012`. The wrapper uses that configured
directory for identity, setup, traffic, and restoration; the historical runner
directory and binary are not used.

Fixed blocks use master ports 59400, 59401, and 59402; READ range 8 (23 points);
25 ms READ pause; gap/start delay 0; start seeds 12345, 12346, and 12347; one
SELECT/OPERATE; close grace 0; and the separate-ACK fixture with response delay
5 ms. Fresh source ports avoid a prior closed tuple's TIME-WAIT.

Default offline command plan, from the repository root:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 \
  defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/native_reference.py \
  --run-id native_reference_01
```

The sole hardware owner runs the same command with `--apply` and explicit
authorization:

```bash
env DEFENSE4_HW_AUTHORIZED=1 PYTHONDONTWRITEBYTECODE=1 python3 \
  defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/native_reference.py \
  --run-id native_reference_01 --apply
```

`--out DIRECTORY` selects the local parent evidence directory; the default is
`rearm_01/hw/native_runs/`. A real run refuses an existing run-id directory. The
active program must be observed as `case4_response_path` before row/profile
mutation. Baseline tools and Vision scripts are deployed and hash-checked;
the endpoint binary/library must match the source config pins. Slot readback
must prove padding off and dev-9 reflection before traffic starts.

Each block retains all Vision run artifacts (OUT/IN pcaps, endpoint/result JSON,
capture statistics, state, and logs), slot readback, before/after baseline mapper
counters, independent wire/timing outputs, and its verdict. The final manifest
retains endpoint identity, effective config, original config hash, source hashes,
collection/restoration outcomes, and hashes of retained files.

Success requires all three blocks, zero extractor errors, complete matching
READ seed values (23 points each), exactly one real SELECT and OPERATE and zero
decoy callbacks, native per-function lengths READ49/SELECT37/OPERATE37, zero
returned integrity errors and unmatched/duplicate frames, mapper growth 0 and
unacked 0, observed endpoint controls, and complete nonempty evidence. READ
piggyback fraction must remain within the separate-ACK window [0, 0.05]. Native
CLRT is recorded by the extractor; no target-gap precision qualification is
applied to this baseline.

After baseline-program admission, the `finally` path independently attempts
relay-slot restoration, Vision fixture/profile/NIC restoration, and the configured
relay-path ping, even if a prior restoration step fails. Every failure remains
in the result. A wrong initial program is a read-only refusal: no slot/profile
mutation or restoration mutation is attempted.

Offline tests use a fake process boundary and do not supply hardware claims:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/tests -v
```
