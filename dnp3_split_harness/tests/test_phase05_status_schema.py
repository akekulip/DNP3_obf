"""Phase 05 status-schema consistency guard.

Fails when the authoritative phase_status.json / closeout are internally inconsistent, specifically:
  1. status is CONDITIONAL_PASS while open_blockers is empty and every in-scope component is PASS;
  2. status_reason describes an in-scope PASS component as deferred / not started;
  3. stale "no rig / no physical NIC / defended-wire (or rig) eval is deferred" language remains in
     the closeout after a two-host rig run is recorded as PASS;
  4. the provenance evidence-commit field is missing.

    python3 -m pytest tests/test_phase05_status_schema.py
"""
import json
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE = os.path.join(HERE, "reports", "phases", "phase_05_ack_mode_normalization")
STATUS = os.path.join(PHASE, "phase_status.json")
CLOSEOUT = os.path.join(PHASE, "phase_05_ack_mode_normalization.md")

IN_SCOPE_PASS = ("PASS", "PASS_SUPPORTING")


def _status():
    with open(STATUS) as fh:
        return json.load(fh)


def _in_scope(value):
    return not (value.startswith("DEFERRED") or value.startswith("OUT_OF_SCOPE"))


def test_status_pass_when_all_in_scope_components_pass():
    d = _status()
    comps = d["components"]
    scoped = {k: v for k, v in comps.items() if _in_scope(v)}
    all_pass = scoped and all(v in IN_SCOPE_PASS for v in scoped.values())
    if all_pass and not d.get("open_blockers"):
        assert d["status"] == "PASS", (
            "all in-scope components PASS and no open blockers, but status=%r "
            "(must be PASS, not CONDITIONAL_PASS)" % d["status"])


def test_status_reason_does_not_call_pass_component_deferred():
    d = _status()
    reason = (d.get("status_reason", "") or "").lower()
    comps = d["components"]
    if comps.get("per_profile_loopback_defended_wire_eval") == "PASS":
        assert not re.search(r"loopback[^.]*deferred", reason), \
            "status_reason calls the loopback defended-wire eval deferred while it is PASS"
    if comps.get("two_host_rig_replay_eval") == "PASS":
        assert not re.search(r"rig[^.]*(deferred|unfinished|not (started|done))", reason), \
            "status_reason calls the two-host rig eval deferred while it is PASS"


def test_no_stale_no_rig_language_in_closeout():
    d = _status()
    if d["components"].get("two_host_rig_replay_eval") != "PASS":
        return
    with open(CLOSEOUT) as fh:
        text = fh.read().lower()
    forbidden = [
        "no two-host rig",
        "no physical nic was used",
        "no real nic",
        "rig evaluation is deferred",
        "rig eval is deferred",
        "per-device defended-wire evaluation is deferred",
        "defended-wire evaluation is deferred",
    ]
    hits = [p for p in forbidden if p in text]
    assert not hits, "stale contradictory language remains in the closeout: %r" % hits


def test_provenance_evidence_commit_present():
    d = _status()
    prov = d.get("provenance", {})
    assert isinstance(prov.get("evidence_commit"), str) and prov["evidence_commit"], \
        "provenance.evidence_commit must be a non-empty string (the authoritative evidence commit)"


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
