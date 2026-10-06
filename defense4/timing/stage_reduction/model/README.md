# Local model smoke harness

`model_smoke.py` is a conservative local probe for the stage-reduction
artifacts. It validates the baseline bundle and the final candidate bundle
(`/tmp/dnp3-stage-reduction/seven_verified/out` by default), writes
DNP3 SELECT/OPERATE/echo packet vectors using
`defense4/timing/implementation/harness/dnp3_wire.py`, and attempts two local
SDE probes for each bundle:

- `tofino-model` with `--no-port-monitor`, no veth setup, and no physical ports.
- `bf_switchd --background --skip-port-add` to prove the generated config and
  P4 profile can be parsed by the local switch daemon. This is startup/config
  evidence only, not packet validation.

Run:

```bash
python3 defense4/timing/stage_reduction/model/model_smoke.py
```

The harness writes full logs to a unique `/tmp/dnp3-model-*` directory and
copies the latest JSON report to `latest_model_smoke_report.json` in this
directory. A nonzero exit with a `CAP_NET_RAW` or sudo blocker means the local
process could not start the asic model as this user. Any other nonzero
`tofino-model` exit is treated as an unclassified model failure. Neither case
proves packet behavior.

This harness never creates veth devices, never touches physical interfaces, and
does not claim to prove real queue timing.
