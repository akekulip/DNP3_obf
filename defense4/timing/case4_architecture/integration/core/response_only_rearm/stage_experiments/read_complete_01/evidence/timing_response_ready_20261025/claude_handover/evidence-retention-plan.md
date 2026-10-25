# c67 evidence retention and clean-checkout plan

This is a read-only preparation report. Root owns archive creation, staging, commits, summary writes, and freezing. No evidence, source, Git index/history, models, or hardware were changed for this report.

## Existing procedure and current boundary

Use the existing `read_complete_01/restore_retained_logs.py`. It discovers every `read_complete_01/evidence/*_dependency_retention_*/manifest.json`, checks conflicting pins, and restores `ctl_timing_01/evidence/model_*_m12p_*/model_*.log.xz` and `model.out.xz`. Each record supplies repo-relative original/archive paths, original SHA-256, and archive SHA-256. A contention reset postcheck additionally pins its timestamped raw model log; both pins must agree. Existing raw files are checked and never overwritten. **Do not archive only `model.out`: the reset postcheck requires exactly one timestamped `model_*.log` after restoration.** The two raw streams differ slightly and must retain their own hashes.

At inspection time:

- Every c67 model-run file is untracked, including results, retained drivers, launch records, closures, and existing archives. No c67 model-run evidence is yet recoverable from Git alone.
- `read_complete_01/evidence/c67_dependency_retention_20261025/manifest.json` exists but is untracked. Its 12 log records cover only smoke01, packets01, rearm01, and response_ready01/02/03. Later completed attempts still need archives and pins. Preserve failed completed attempts as well as passing successors.
- The c67 build has 30 tracked files, including generated P4, inputs/profile, compile manifest/source snapshot, `compile.log`, `compile.log.xz`, loaded artifacts, and selected resource/layout reports. No new compile or P4 generation is needed to retain those bytes.
- Eleven resource-report files named by the compile manifest remain present but untracked under ignored `compile_local/out/`; see the exact list below.
- c67 has no `freeze_v3.json`. Its `reproduce.sh` entry has no `GEN_PIN`, `GATE_PIN`, or `FREEZE_PIN`. It uses the current committed tree and the fixed c67 source hash `e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1`.

Run the commands below from repository root. The shell variables resolve to absolute paths because `model_summary.py` interprets relative build arguments relative to its own directory:

```sh
STAGE="$PWD/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments"
CT="$STAGE/ctl_timing_01"
RC="$STAGE/read_complete_01"
BUILD="$CT/evidence/m12p_c67_sdk9132"
```

## Minimal retention commands and file sets

Run after the final batch owner reports completion. Do not archive live log files. There is an existing restore helper but no committed general archive-writing helper found in the inspected retention surfaces. The following bounded Python command produces that helper's existing manifest format, reuses existing valid archives, and preserves raw files. It selects only finished attempts with final launch JSON and one results JSON; no missing launch/result evidence is synthesized.

```sh
python3 - <<'PY'
import hashlib, json, lzma, pathlib
root = pathlib.Path.cwd()
stage = root / 'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments'
evidence = stage / 'ctl_timing_01/evidence'
manifest = stage / 'read_complete_01/evidence/c67_dependency_retention_20261025/manifest.json'
record = json.loads(manifest.read_text()) if manifest.exists() else {
    'candidate': 'm12p_c67_sdk9132',
    'scope': 'successful and failed completed attempts, raw logs byte-exact', 'logs': {}}
digest = lambda data: hashlib.sha256(data).hexdigest()
for run in sorted(evidence.glob('model_*_m12p_c67_sdk9132_[0-9][0-9]')):
    launch = run / 'launch_command.json'
    if not launch.exists():
        continue
    info = json.loads(launch.read_text())
    if type(info.get('exit_code')) is not int:
        continue
    assert len(list(run.glob('*_results.json'))) == 1, run
    assert (run / 'dependency_closure.json').is_file(), run
    logs = sorted(run.glob('model_*.log'))
    assert len(logs) == 1 and (run / 'model.out').is_file(), run
    closure = json.loads((run / 'dependency_closure.json').read_text())
    for log in [run / 'model.out'] + logs:
        raw = log.read_bytes()
        archive = pathlib.Path(str(log) + '.xz')
        if archive.exists():
            assert lzma.decompress(archive.read_bytes()) == raw, archive
        else:
            with archive.open('xb') as output:
                output.write(lzma.compress(raw, preset=3))
        packed = archive.read_bytes()
        item = dict(archive=str(archive.relative_to(root)), archive_bytes=len(packed),
                    archive_sha256=digest(packed), raw_bytes=len(raw), sha256=digest(raw))
        key = str(log.relative_to(root))
        if key in record['logs']:
            assert record['logs'][key] == item, key
        pin = closure.get('postchecks', {}).get('reset_application', {}).get('input_sha256', {}).get(log.name)
        assert pin is None or pin == item['sha256'], log
        record['logs'][key] = item
manifest.parent.mkdir(parents=True, exist_ok=True)
manifest.write_text(json.dumps(record, indent=1) + '\n')
PY
```

The existing c67 manifest uses precisely these five fields per log; the command deliberately refuses conflicting existing records instead of repinning historical bytes. Never edit launch SHA/closure/report pins to make mismatches disappear. A missing/failing dependency match needs the separately owned genuine rerun.

For each completed c67 attempt, retain this model evidence set:

- `launch_command.json`, `dependency_closure.json`, the single `*_results.json`, `driver_source.py`, and any `driver_dependency_*.py` copies;
- `t_params_written.json`, `ports.json`, and `session.log` (recorded stimulus/configuration and completion context);
- where present: `reset_application.json`, `reset_application.dependencies.json`, `committed_precondition.json`, diagnostic JSON outputs, and failure/resolution notes;
- both raw-log `.xz` archives; retain originals locally, but do not stage large `model_*.log` or `model.out` blobs.

Root can stage exactly this set after reviewing the finished attempt inventory, without a broad `git add` over the noisy workspace:

```sh
python3 - <<'PY'
import json, pathlib, subprocess
root = pathlib.Path.cwd()
stage = pathlib.Path('defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments')
paths = [stage / 'read_complete_01/evidence/c67_dependency_retention_20261025/manifest.json']
for run in sorted((stage / 'ctl_timing_01/evidence').glob('model_*_m12p_c67_sdk9132_[0-9][0-9]')):
    launch = run / 'launch_command.json'
    if not launch.is_file() or type(json.loads(launch.read_text()).get('exit_code')) is not int:
        continue
    for pattern in ('*.json', 'driver_source.py', 'driver_dependency_*.py', '*.md',
                    't_params_written.json', 'ports.json', 'session.log', 'model.out.xz', 'model_*.log.xz'):
        paths.extend(run.glob(pattern))
paths = sorted(set(str(p) for p in paths if p.is_file()))
subprocess.run(['git', 'add', '--'] + paths, check=True)
PY
```

Also commit the final current source files named by latest attempts' `dependency_closure.json` if changed, through Root's normal source review. V3 requires those repository-relative files to match their executed hashes. Retained per-run copies alone do not replace a missing or changed latest dependency.

For compile retention, the existing raw `compile.log` is only 21,579 bytes and already tracked along with its 2,340-byte archive; the restore helper does **not** restore compile logs. Keep both. The manifest already pins the original compile log. For a complete manifest report inventory, explicitly add these ignored files (all exist; all were untracked at inspection):

```sh
git add -f -- \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_0.log" \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_3.log" \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_history_0.log" \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_history_3.log" \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_summary_0.log" \
  "$BUILD/compile_local/out/p0/logs/phv_allocation_summary_3.log" \
  "$BUILD/compile_local/out/p0/logs/table_dependency_graph.log" \
  "$BUILD/compile_local/out/p1/logs/phv_allocation_5.log" \
  "$BUILD/compile_local/out/p1/logs/phv_allocation_history_5.log" \
  "$BUILD/compile_local/out/p1/logs/phv_allocation_summary_5.log" \
  "$BUILD/compile_local/out/p1/logs/table_dependency_graph.log"
```

All nine `artifact_sha256` files are already tracked. The additional 11 above close the manifest's resource-report pins; do not force-add the entire compiler `out/` tree. Regenerating a compiler manifest merely to align paths would change original evidence. `build.verify_evidence()` additionally checks compiler identity and original absolute source paths, so a different checkout path/compiler may limit that function independently of retained-byte availability; no compiler rerun is needed for the raw-log restoration/model-summary procedure.

## Clean-checkout reconstruction and verification

After Root commits the complete evidence/source set, these are the existing reconstruction commands, with no model launch:

```sh
python3 "$RC/restore_retained_logs.py"
python3 "$CT/model_summary.py" "$BUILD" --v3 --enforce
CANDIDATE=c67 bash "$RC/reproduce.sh" --candidate-info
CANDIDATE=c67 bash "$RC/reproduce.sh"
```

The full reproduction entry needs the existing research Python environment (`RESEARCH_PYTHON` can override its default `~/.venvs/research/bin/python`). It regenerates offline constants/templates, proves generator identity/source/profile parity, restores raw model logs, and recomputes v3 **without `--write`**. It neither launches models nor uses hardware. It is broader than the two-command archive/summary check, so Root should first establish the narrow check passes.

`restore_retained_logs.py` processes archives across all retained candidates, not just c67. Any added archive must have its own manifest or reset-closure pin; an unpinned `.xz` anywhere in that glob makes restoration fail. The helper's existing unit tests cover conflicting pins, archive tampering, raw tampering, and restoration without overwriting originals.

## Final reruns and freeze pins

Final reruns do **not** mutate any existing freeze automatically. They change the build's `latest_by_driver`, launch/closure/results evidence, and potentially the union of executed dependency files. `freeze_gate.py:candidate_binding` recomputes v3 and compares both qualification and `latest_by_driver`; therefore even a passing successor run after a freeze changes its binding and requires a newly reviewed freeze. Updating `model_summary_v3.json` also changes its frozen hash.

For c67 specifically, there is no freeze yet: finish all real reruns, retain/archive completed attempts, ensure the current 17-driver v3 gate passes, then write the model summary and the **first** c67 freeze using the existing interfaces:

```sh
python3 "$CT/model_summary.py" "$BUILD" --v3 --write --enforce
python3 defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/freeze_gate.py \
  write "$BUILD" -o "$BUILD/freeze_v3.json" --configs "$RC"/hw/config/rc01_m12p_c67_*.json
```

The retained config names currently contain `c67_sdk9132`, so that glob matches the current c67 set. Root must review the concrete config list and stage the intended evidence/source/config set before freezing if the freeze's `tracked` metadata should reflect their committed status. The freeze writer refuses a qualifying freeze while the live model gate is blocked. It pins the one local SDK-9.13.2 compile, loaded artifacts, summary hash/latest attempts, configs, hardware harness, acceptance scripts, and latest model dependency union.

Do not change c52's historical `FREEZE_PIN=ee7b7f47f` or c62's generator/gate pins for c67 reruns. No c67 commit pin needs editing today because its three optional pin variables are empty. If later work changes shared driver/generator files, a future historical pin should name the actual final c67 evidence commit; do not invent that hash before Root's commit exists.
