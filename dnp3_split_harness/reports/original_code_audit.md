# Original Code Audit

Audit of the original pydnp3 scripts that seed this harness. The unmodified
copies are preserved verbatim in `archive_original/`. Nothing here was deleted.

All seven files pass `python -m py_compile` (syntax/imports valid at parse time;
actual execution requires the `pydnp3` native extension to be installed).

---

## Per-File Summary

### `master.py`
- **What it does:** Defines `MyMaster`, a TCP-client DNP3 master wrapper around
  `asiodnp3.DNP3Manager` + `AddTCPClient` + `AddMaster`. Also defines support
  classes `MyLogger`, `AppChannelListener`, `SOEHandler`, `MasterApplication`
  and command/restart callbacks. On startup it adds a 30-min all-classes "slow
  scan" and a 1-min class-1 "fast scan", enables the master, and sleeps 5s.
- **Reusable:** `SOEHandler` (visitor dispatch table), `MyLogger`,
  `AppChannelListener`, `MasterApplication`, callbacks, the overall AddTCPClient
  / MasterStackConfig / AddMaster flow.
- **Unsafe for baseline READ:** `send_direct_operate_command*` and
  `send_select_and_operate_command*` issue control writes — must be gated.
  The unconditional periodic scans generate background traffic that pollutes a
  clean READ/RESPONSE capture.
- **Hard-coded values:** `HOST = "127.0.0.1"`, `LOCAL = "0.0.0.0"`,
  `PORT = 20000`; `stack_config.link.RemoteAddr = 10`; response timeout 2s;
  slow=30min / fast=1min scan periods; `time.sleep(5)`.
- **Bug to fix in refactor:** the constructor accepts a `soe_handler` argument
  but `AddMaster` is called with a *fresh* `asiodnp3.PrintingSOEHandler().Create()`
  instead of `self.soe_handler` (master.py:72-75). The passed handler is ignored.
  The new `ExperimentMaster` must actually use the supplied handler.
- **Needs refactoring:** parameterize host/local/port/addresses/timeout; make
  periodic scans opt-in (`enable_periodic_scans`); add explicit READ actions
  (class0, all-classes, range, all-objects); gate controls behind warnings.

### `master_cmd.py`
- **What it does:** `MasterCmd(cmd.Cmd)` interactive shell over `MyMaster`,
  exposing `do_scan_all`, `do_scan_range`, `do_scan_fast`, `do_scan_slow`,
  `do_disable_unsol`, plus control commands `do_o1/o2/o3` (DirectOperate),
  `do_s1/s2` (SelectAndOperate), `do_restart` (cold restart), `do_write_time`.
- **Reusable:** the scan/disable-unsolicited command bodies and the `do_*`
  naming convention are the model for the new harness command methods.
- **Unsafe for baseline READ:** `do_o*`, `do_s*`, `do_restart` issue
  control/restart operations. Keep available only behind an explicit unsafe
  path; never in the baseline CLI.
- **Hard-coded values:** scan_range fixed to group 1 var 2, indexes 0..3;
  control indexes (5, 8, 10) and values baked into `do_*`.
- **Needs refactoring:** scan logic moves into reusable `ExperimentMaster`
  methods; interactive shell is replaced by a non-interactive argparse CLI for
  reproducibility.

### `outstation.py`
- **What it does:** `OutstationApplication(IOutstationApplication)` TCP server
  outstation. Configures a 10-point AllTypes database, 2 analog + 2 binary
  points at indexes 1,2 (Class2), enables the channel, holds a singleton
  outstation reference, supports `apply_update`.
- **Reusable:** stack/database configuration flow, `apply_update` /
  `UpdateBuilder` usage, singleton pattern, IIN/restart override style.
- **Unsafe for baseline READ:** `params.allowUnsolicited = True` (outstation.py:88)
  — produces background unsolicited responses that break clean READ/RESPONSE
  captures. `OutstationCommandHandler.Select`/`Operate` both
  return `CommandStatus.SUCCESS` unconditionally, silently accepting controls.
- **Hard-coded values:** `LOCAL_IP="0.0.0.0"`, `PORT=20000`; db size 10; event
  buffer 10; `LocalAddr=10`, `RemoteAddr=1`; points fixed at indexes 1,2 with
  Class2; KeepAliveTimeout=Max.
- **Needs refactoring:** parameterize db size / point counts / addresses;
  default `allowUnsolicited=False`; default command handler to `NOT_SUPPORTED`
  unless controls are explicitly allowed; add bulk/initial value helpers and a
  `--hold` run loop.

### `outstation_cmd.py`
- **What it does:** `OutstationCmd(cmd.Cmd)` interactive shell to push
  measurement updates to the master (`do_a`, `do_b`, `do_c`, `do_d`, etc.).
- **Reusable:** the `apply_update` call patterns for Analog/Binary/Counter/
  DoubleBitBinary; line-parsing helpers.
- **Unsafe for baseline READ:** none directly (these are measurement updates),
  but interactive operation is not reproducible.
- **Hard-coded values:** demo indexes (4, 6) in `do_a2`/`do_b0`.
- **Needs refactoring:** value injection becomes deterministic
  `apply_initial_values` / `apply_bulk_updates` on the outstation harness.

### `simple_master.py`
- **What it does:** `SimpleMaster` (cmd-shell code commented out) that builds a
  `MyMaster` and, in `main()`, **sends a SelectAndOperate (`do_s1`) by default**.
- **Unsafe for baseline READ:** `main()` issues a control by default — must NOT
  be used as-is for baseline experiments. Listed as a cautionary example only.
- **Needs refactoring:** replaced by `experiment_master.py` READ-only CLI.

### `simple_outstation.py`
- **What it does:** `SimpleOutstation` wrapper that builds an
  `OutstationApplication` and waits for Enter. Inherits all of `outstation.py`'s
  defaults including `allowUnsolicited=True`.
- **Reusable:** the "construct + hold until input" run pattern (becomes
  `--hold` + Ctrl+C handling in the new outstation CLI).
- **Needs refactoring:** same as `outstation.py`.

### `visitors.py`
- **What it does:** Eight `IVisitorIndexed*` subclasses that collect
  `(index, value)` pairs from received measurement collections.
- **Reusable:** fully reusable as-is. The new `CSVSOEHandler` and the harness
  SOE handler dispatch on exactly these classes. Carried into
  `pydnp3_harness/visitors.py` unchanged.
- **Unsafe / hard-coded:** none.

---

## Cross-Cutting Findings

| Concern | Finding | Action in refactor |
|---|---|---|
| Ignored SOE handler | `master.py` passes a fresh `PrintingSOEHandler` to `AddMaster`, ignoring the ctor arg | Use the supplied handler in `ExperimentMaster` |
| Unsolicited responses | Enabled by default in `outstation.py` | Default `allow_unsolicited=False` |
| Control commands | Outstation returns SUCCESS; master/simple_master send controls | Default `NOT_SUPPORTED`; gate sends behind warnings/unsafe flag |
| Hard-coded network params | HOST/LOCAL/PORT/addresses baked in | Move to constructor args + argparse |
| Periodic scans | Always added in `MyMaster.__init__` | Opt-in via `enable_periodic_scans` |
| Reproducibility | Interactive `cmd.Cmd` shells only | Add non-interactive argparse entrypoints |

## Reusability Verdict
- **Keep mostly as-is:** `visitors.py`, `SOEHandler` dispatch logic, `MyLogger`,
  `AppChannelListener`, `MasterApplication`, IIN/restart overrides, the
  manager/channel/stack construction sequences, `apply_update`/`UpdateBuilder`.
- **Refactor heavily:** parameterization, scan-as-method, safety defaults.
- **Do not reuse directly:** `simple_master.py main()` (sends a control by
  default).
