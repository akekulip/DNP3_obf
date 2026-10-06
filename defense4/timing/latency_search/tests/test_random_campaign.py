import json
import os
import sys
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defense4.timing.latency_search import configure, policy, random_campaign  # noqa: E402
from defense4.timing.latency_search.randomized import bfrt_random_table, policy_planner  # noqa: E402


class FakeTransport:
    def __init__(self):
        self.deployed = False
        self.uploads = []
        self.switch_commands = []
        self.vision_commands = []
        self.collected = []
        self.responders = []

    def deploy(self):
        self.deployed = True

    def upload_switch(self, files):
        self.uploads.append(("switch", [(Path(p).name, name) for p, name in files]))

    def upload_vision(self, files):
        self.uploads.append(("vision", [(Path(p).name, name) for p, name in files]))

    def add_switch_response(self, predicate, response):
        self.responders.append((predicate, response))

    def ssh_switch(self, command, **_kwargs):
        self.switch_commands.append(command)
        for predicate, response in self.responders:
            if predicate(command):
                return response(command) if callable(response) else response
        raise AssertionError(f"unexpected switch command: {command}")

    def ssh_vision(self, command, **_kwargs):
        self.vision_commands.append(command)
        return ""

    def collect_block(self, label, output):
        self.collected.append((label, Path(output)))
        block_dir = Path(output) / label
        block_dir.mkdir(parents=True, exist_ok=True)
        (block_dir/'raw_pcaps').mkdir(exist_ok=True)
        (block_dir/'raw_pcaps/traffic.pcap').touch()


def fake_requests():
    return [{'tcp_src_port':20001,'tcp_seq':100+i*100,
             'dnp3_func':(1,3,4)[i%3] if i<30 else 1}
            for i in range(32)]



def write_json(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def fixed_plan_doc(mode="D4", da=5, gap=1):
    p = policy.make_policy("test", "test", mode, da, gap, (0.25, 0.5, 1.0))
    return configure.plan_to_dict(configure.build_policy_plan(p))


def fixed_readback_for(plan_doc):
    return {
        "codebook": [dict(e) for e in plan_doc["codebook_entries"]],
        "audit": plan_doc["audit"],
        "tbl_params": dict(plan_doc["params_default"]),
        "tbl_bor_params": dict(plan_doc["bor_params_default"]),
    }


def random_readback_for(plan_doc):
    entries = [
        {
            "low": e["low"],
            "high": e["high"],
            "priority": e["priority"],
            "d_ticks": e["d_ticks"],
            "da_dr_ticks": e["da_dr_ticks"],
            "op_a_ticks": e["op_a_ticks"],
            "op_r_ticks": e["op_r_ticks"],
            "action_name": e.get("action_name", policy_planner.ACTION_NAME),
        }
        for e in plan_doc["entries"]
    ]
    return {
        "program": "defense4_timing",
        "table_name": policy_planner.TABLE_NAME,
        "entry_count": len(entries),
        "entries": sorted(entries, key=lambda e: (e["priority"], e["low"], e["high"])),
        "plan": plan_doc,
    }


def clear_readback():
    return {"cleared": True, "deleted": 16, "readback": [], "default_action":"NoAction"}


def identity_doc():
    return {
        "program": "defense4_timing",
        "source_sha256": "abc123",
        "ingress_stages": 7,
        "egress_stages": 0,
    }


def digest_text_for_first_entries(plan_doc):
    def digest(sport, seq, func, entry, rand8):
        return {
            "request_tcp_sport": sport,
            "request_tcp_seq": seq,
            "dnp3_func": func,
            "rand8": rand8,
            "selected_d_ticks": entry["d_ticks"],
            "selected_da_dr_ticks": entry["da_dr_ticks"],
            "selected_a_ticks": entry["op_a_ticks"],
            "selected_r_ticks": entry["op_r_ticks"],
        }

    rows = [{"event":"ready"}]
    for i, request in enumerate(fake_requests()):
        entry = plan_doc['entries'][i%16]
        rows.append(digest(request['tcp_src_port'],request['tcp_seq'],request['dnp3_func'],entry,entry['low']))
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def populate_switch_responses(transport, fixed_doc, off_doc, restore_doc, random_doc):
    transport.add_switch_response(lambda c: "configure.py apply" in c, "")
    transport.add_switch_response(lambda c: "bfrt_random_table.py apply-plan" in c, "")
    transport.add_switch_response(lambda c: "bfrt_random_table.py clear" in c, "")
    transport.add_switch_response(lambda c: c.startswith("cat ") and "_fixed_readback.json" in c, json.dumps(fixed_readback_for(fixed_doc)))
    transport.add_switch_response(lambda c: c.startswith("cat ") and "_random_readback.json" in c, json.dumps(random_readback_for(random_doc)))
    transport.add_switch_response(lambda c: c.startswith("cat ") and "restored_random_table.json" in c, json.dumps(clear_readback()))
    transport.add_switch_response(lambda c: c.startswith("cat ") and "restored_fixed_config.json" in c, json.dumps(fixed_readback_for(restore_doc)))
    transport.add_switch_response(lambda c: "telemetry_listener.py" in c, "")
    transport.add_switch_response(lambda c: "digest listener did not report ready" in c, "")
    transport.add_switch_response(lambda c: "digest listener recorded" in c, "")
    transport.add_switch_response(lambda c: "digest listener pid" in c, "")
    transport.add_switch_response(lambda c: "digest_listener.pid" in c, "")
    transport.add_switch_response(lambda c: c.startswith('cat ') and 'digest_listener.log' in c, '')
    transport.add_switch_response(lambda c: c.startswith("cat ") and "digests.jsonl" in c, digest_text_for_first_entries(random_doc))


def write_inputs(tmp_path):
    random_doc = policy_planner.plan_to_dict(policy_planner.build_plan(center_da_ms=12, center_gap_ms=4, amplitude_ms=0.5, mode="gap"))
    random_plan = tmp_path / "random.json"
    write_json(random_plan, random_doc)
    fixed_doc = fixed_plan_doc("D4", 5, 1)
    off_doc = fixed_plan_doc("OFF", 20, 4)
    restore_doc = fixed_plan_doc("D4", 20, 4)
    fixed = tmp_path / "fixed.json"; write_json(fixed, fixed_doc)
    off = tmp_path / "off.json"; write_json(off, off_doc)
    restore = tmp_path / "restore.json"; write_json(restore, restore_doc)
    identity = tmp_path / "identity.json"; write_json(identity, identity_doc())
    return random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity


def test_build_schedule_interleaves_off_reference_for_each_repeat(tmp_path):
    plans = []
    for idx in range(3):
        p = tmp_path / f"random_{idx}.json"
        policy_planner.write_plan(policy_planner.build_plan(center_da_ms=12, center_gap_ms=4, amplitude_ms=0.5, mode="gap"), p)
        plans.append(p)
    schedule = random_campaign.build_schedule(
        random_plan_paths=plans,
        repeats=2,
        seed=7,
        off_every=2,
        off_name="off_ref",
    )

    assert len(schedule) == 10
    assert [b.kind for b in schedule].count("off_reference") == 4
    assert all(b.replicate in (0, 1) for b in schedule)
    assert {b.random_plan_path for b in schedule if b.kind == "random_policy"} == set(plans)
    for rep in (0, 1):
        kinds = [b.kind for b in schedule if b.replicate == rep]
        assert kinds[2] == "off_reference"
        assert kinds[-1] == "off_reference"


def test_prepare_run_writes_schedule_provenance_and_upload_bundle(tmp_path):
    random_plan, _random_doc, fixed, _fixed_doc, off, _off_doc, restore, _restore_doc, identity = write_inputs(tmp_path)
    transport = FakeTransport()

    run = random_campaign.prepare_run(
        random_plan_paths=[random_plan],
        fixed_config_plan=fixed,
        off_config_plan=off,
        restore_config_plan=restore,
        identity_file=identity,
        output_root=tmp_path / "runs",
        phase="pilot",
        count=10,
        repeats=1,
        seed=11,
        transport=transport,
        timestamp="20260926T010203Z",
    )

    schedule = json.loads((run.run_dir / "schedule.json").read_text())
    provenance = json.loads((run.run_dir / "provenance.json").read_text())
    assert schedule["count_per_operation"] == 10
    assert schedule["digest_records_per_random_block"] == 32
    assert provenance["program_identity"]["program"] == "defense4_timing"
    assert provenance["program_identity"]["ingress_stages"] == 7
    assert provenance["source_sha256"]["random_campaign.py"]
    assert transport.deployed
    uploaded_names = {name for _host, files in transport.uploads for _src, name in files}
    assert "randomized/bfrt_random_table.py" in uploaded_names
    assert "randomized/telemetry_listener.py" in uploaded_names
    assert "randomized/telemetry_join.py" in uploaded_names
    assert "fixed_config.json" in uploaded_names
    assert "off_config.json" in uploaded_names
    assert "restore_config.json" in uploaded_names


def test_prepare_run_rejects_wrong_program_identity(tmp_path):
    random_plan, _random_doc, fixed, _fixed_doc, off, _off_doc, restore, _restore_doc, identity = write_inputs(tmp_path)
    write_json(identity, {"program": "defense4_timing_randomized", "source_sha256": "abc", "ingress_stages": 7, "egress_stages": 0})

    with pytest.raises(ValueError, match="defense4_timing"):
        random_campaign.prepare_run(
            random_plan_paths=[random_plan], fixed_config_plan=fixed, off_config_plan=off,
            restore_config_plan=restore, identity_file=identity, output_root=tmp_path / "runs",
            phase="pilot", count=10, repeats=1, seed=11, transport=FakeTransport(),
            timestamp="20260926T010203Z",
        )


def test_run_random_block_starts_bounded_listener_before_traffic_and_joins_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(random_campaign, 'extract_request_rows', lambda path: fake_requests())
    random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity = write_inputs(tmp_path)
    transport = FakeTransport()
    populate_switch_responses(transport, fixed_doc, off_doc, restore_doc, random_doc)
    run = random_campaign.prepare_run(
        random_plan_paths=[random_plan], fixed_config_plan=fixed, off_config_plan=off,
        restore_config_plan=restore, identity_file=identity, output_root=tmp_path / "runs",
        phase="pilot", count=10, repeats=1, seed=1, transport=transport,
        timestamp="20260926T010203Z",
    )
    block = next(b for b in run.schedule if b.kind == "random_policy")

    doc = random_campaign.run_block(block, run, transport=transport)

    switch = "\n".join(transport.switch_commands)
    vision = "\n".join(transport.vision_commands)
    assert "configure.py apply --policy" in switch
    assert "bfrt_random_table.py apply-plan" in switch
    assert "telemetry_listener.py" in switch
    assert "--max-digests" in switch and "32" in switch
    assert "run_block.py" in vision
    assert "--reads 10" in vision and "--sbo 10" in vision
    assert "telemetry_join.py" not in switch
    assert doc["join_counts"] == {
        "joined": 32,
        "missing_digest": 0,
        "missing_request": 0,
        "duplicate_requests": 0,
        "duplicate_digests": 0,
        "wrong_selection": 0,
    }
    joined_path = Path(doc["local_block_dir"]) / "joined_random_deadlines.json"
    assert joined_path.exists()
    digest_rows = [json.loads(line) for line in (Path(doc["local_block_dir"]) / "digests.jsonl").read_text().splitlines()]
    assert all(row.get("event") != "ready" for row in digest_rows)


def test_run_block_rejects_random_readback_mismatch_before_traffic(tmp_path):
    random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity = write_inputs(tmp_path)
    transport = FakeTransport()
    populate_switch_responses(transport, fixed_doc, off_doc, restore_doc, random_doc)
    bad = random_readback_for(random_doc)
    bad["entry_count"] = 0
    good_random = json.dumps(random_readback_for(random_doc))
    transport.responders = [item for item in transport.responders if item[1] != good_random]
    transport.add_switch_response(lambda c: c.startswith("cat ") and "_random_readback.json" in c, json.dumps(bad))
    run = random_campaign.prepare_run(
        random_plan_paths=[random_plan], fixed_config_plan=fixed, off_config_plan=off,
        restore_config_plan=restore, identity_file=identity, output_root=tmp_path / "runs",
        phase="pilot", count=10, repeats=1, seed=1, transport=transport,
        timestamp="20260926T010203Z",
    )
    block = next(b for b in run.schedule if b.kind == "random_policy")

    with pytest.raises(RuntimeError, match="entry_count"):
        random_campaign.run_block(block, run, transport=transport)
    assert not any("run_block.py" in cmd for cmd in transport.vision_commands)


def test_run_campaign_requires_authorization_even_with_injected_transport(tmp_path, monkeypatch):
    random_plan, _random_doc, fixed, _fixed_doc, off, _off_doc, restore, _restore_doc, identity = write_inputs(tmp_path)
    monkeypatch.delenv("DEFENSE4_HW_AUTHORIZED", raising=False)

    with pytest.raises(RuntimeError, match="DEFENSE4_HW_AUTHORIZED"):
        random_campaign.run_campaign(
            random_plan_paths=[random_plan], fixed_config_plan=fixed, off_config_plan=off,
            restore_config_plan=restore, identity_file=identity, output_root=tmp_path / "runs",
            phase="pilot", count=10, repeats=1, seed=1, transport=FakeTransport(),
            timestamp="20260926T010203Z",
        )


def test_run_campaign_restores_fixed_config_and_clears_random_table_on_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE4_HW_AUTHORIZED", "1")
    random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity = write_inputs(tmp_path)
    transport = FakeTransport()
    populate_switch_responses(transport, fixed_doc, off_doc, restore_doc, random_doc)

    def fail_vision(command, **kwargs):
        transport.vision_commands.append(command)
        if "run_block.py" in command:
            raise RuntimeError("traffic failed")
        return ""

    transport.ssh_vision = fail_vision

    with pytest.raises(RuntimeError, match="traffic failed"):
        random_campaign.run_campaign(
            random_plan_paths=[random_plan], fixed_config_plan=fixed, off_config_plan=off,
            restore_config_plan=restore, identity_file=identity, output_root=tmp_path / "runs",
            phase="pilot", count=10, repeats=1, seed=1, transport=transport,
            timestamp="20260926T010203Z",
        )

    switch = "\n".join(transport.switch_commands)
    assert "bfrt_random_table.py clear" in switch
    assert "restore_config.json" in switch
    progress = json.loads(next((tmp_path / "runs").glob("*/failure.json")).read_text())
    assert progress["completed_blocks"] == 0


def test_listener_launch_tracks_and_stops_actual_process(tmp_path, monkeypatch):
    monkeypatch.setattr(random_campaign, 'REMOTE', str(tmp_path))
    folder=tmp_path/'randomized';folder.mkdir()
    script=folder/'telemetry_listener.py'
    script.write_text("import json,time\nprint(json.dumps({'event':'ready'}),flush=True)\ntime.sleep(30)\n")
    try:
        subprocess.run(random_campaign._start_listener_command('owned_probe',32),shell=True,check=True,timeout=5)
        subprocess.run(random_campaign._wait_listener_ready_command('owned_probe',2),shell=True,check=True,timeout=5)
        owner=json.loads((tmp_path/'owned_probe/digest_listener.pid').read_text())
        assert str(script).encode() in Path('/proc/%d/cmdline'%owner['pid']).read_bytes().split(bytes([0]))
    finally:
        subprocess.run(random_campaign._stop_listener_command('owned_probe',1),shell=True,check=True,timeout=5)
    subprocess.run(random_campaign._wait_listener_exit_command('owned_probe',1),shell=True,check=True,timeout=3)


def test_capture_glob_deduplicates_same_file(tmp_path):
    raw=tmp_path/'raw_pcaps';raw.mkdir()
    capture=raw/'traffic.pcapng';capture.touch()
    assert random_campaign._find_pcap(tmp_path)==capture


def test_listener_ready_failure_stops_listener_and_never_sends_traffic(tmp_path):
    random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity=write_inputs(tmp_path)
    transport=FakeTransport()
    populate_switch_responses(transport,fixed_doc,off_doc,restore_doc,random_doc)
    def fail(command):
        raise RuntimeError('ready failed')
    transport.responders.insert(0,(lambda c:'digest listener did not report ready' in c,fail))
    run=random_campaign.prepare_run(random_plan_paths=[random_plan],fixed_config_plan=fixed,
        off_config_plan=off,restore_config_plan=restore,identity_file=identity,output_root=tmp_path/'runs',
        phase='pilot',count=10,repeats=1,transport=transport)
    with pytest.raises(RuntimeError,match='ready failed'):
        random_campaign.run_block(run.schedule[0],run,transport=transport)
    assert not transport.vision_commands
    assert any('signal.SIGTERM' in cmd for cmd in transport.switch_commands)


def test_failed_traffic_is_stopped_before_restoration(tmp_path,monkeypatch):
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED','1')
    random_plan, random_doc, fixed, fixed_doc, off, off_doc, restore, restore_doc, identity=write_inputs(tmp_path)
    transport=FakeTransport()
    populate_switch_responses(transport,fixed_doc,off_doc,restore_doc,random_doc)
    stopped=[]
    original=transport.ssh_switch
    def switch(command,**kwargs):
        if 'restore_config.json' in command:
            assert stopped
        return original(command,**kwargs)
    def vision(command,**kwargs):
        if 'run_block.py' in command: raise RuntimeError('runner timed out')
        if 'stop_block.py' in command: stopped.append(command)
        return ''
    transport.ssh_switch=switch;transport.ssh_vision=vision
    with pytest.raises(RuntimeError,match='runner timed out'):
        random_campaign.run_campaign(random_plan_paths=[random_plan],fixed_config_plan=fixed,
            off_config_plan=off,restore_config_plan=restore,identity_file=identity,output_root=tmp_path/'runs',
            phase='pilot',count=10,repeats=1,transport=transport)
    assert stopped
