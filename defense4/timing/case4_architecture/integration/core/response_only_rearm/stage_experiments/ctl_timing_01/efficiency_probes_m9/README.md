# m9 audit reproduction and compile probes

Revision: 7637390c1a04ab06bf3012fe25972f611cc3a4a0.
Base P4: CT/evidence/m9_01/response_only.p4, SHA256
6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f.
CT means defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01.

These are offline compile experiments, not approved production candidates.
The scripts read the supplied repository; they never load hardware or modify its files.
Use an isolated checkout at the pinned revision, Python 3 and pytest installed.

```bash
python3 reproduce_acceptance.py /path/to/DNP3
python3 probe_candidates.py /path/to/DNP3 generated
python3 check_probes.py /path/to/DNP3 generated
python3 check_m9_reset_probes.py /path/to/DNP3 generated
python3 check_single_child_negative.py /path/to/DNP3 generated
```

The acceptance reproduction intentionally demonstrates current defects; its JSON reports
accepted counterexamples. It is not an assertion that those defects are corrected.

Checked here: 38 focused repository tests, 36 differential source-interpreter cases,
42 reset source-interpreter cases, three invalid-child parser checks. The reset checks
include preservation of a known limitation, not its correction.
No SDK compilation, compiled model or silicon run was performed here.

Compile the generated P4s separately with the project's existing compiler tooling and
retain placement/PHV/resource reports. Single-child needs matching CP schema changes before
model/hardware use. Do not overwrite the frozen m9 build. Do not claim stage savings until
compiler reports demonstrate them. Read REVIEW.md before applying any change.
