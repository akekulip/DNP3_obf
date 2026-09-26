from dataclasses import replace
from pathlib import Path
import subprocess
import sys

import pytest

from defense4.timing.latency_search.randomized import policy_planner as p
from defense4.timing.latency_search.randomized import telemetry_listener as listener


def plan():
    return p.build_plan(center_da_ms=12, center_gap_ms=4, amplitude_ms=.5, mode='joint')


def test_forged_descriptive_delay_cannot_hide_unsafe_actual_ticks():
    value = plan()
    bad = replace(value.entries[0], d_ticks=256, op_a_ticks=256)
    with pytest.raises(ValueError):
        p.validate_plan(replace(value, entries=(bad,) + value.entries[1:]))


def test_actual_zero_gap_is_rejected():
    value = plan()
    entry = value.entries[0]
    bad = replace(entry, da_dr_ticks=entry.d_ticks, op_r_ticks=entry.d_ticks)
    with pytest.raises(ValueError):
        p.validate_plan(replace(value, entries=(bad,) + value.entries[1:]))


def test_reported_center_must_describe_installed_distribution():
    with pytest.raises(ValueError):
        p.validate_plan(replace(plan(), center_da_ms=5))


def test_direct_campaign_entrypoint_imports_on_supported_python():
    script = Path(__file__).resolve().parents[2] / 'random_campaign.py'
    result = subprocess.run([sys.executable, str(script), '--help'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_listener_releases_binding_when_schema_lookup_fails(monkeypatch):
    class Client:
        closed = False
        def bfrt_info_get(self, program):
            raise ValueError('schema unavailable')
        def tear_down_stream(self):
            self.closed = True
    client = Client()
    monkeypatch.setattr(listener, 'open_interface', lambda *a: client)
    with pytest.raises(ValueError, match='schema unavailable'):
        listener.main([])
    assert client.closed
