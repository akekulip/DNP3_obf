#!/usr/bin/env python
"""Generate ``registry.yaml`` from the committed Defense-4 timing evidence.

This is the authoring authority: the pinned per-dataset metadata lives here as
reviewable Python, and the sha256 of every referenced raw block is computed from
disk at generation time (never hand-copied). The analysis tool re-verifies those
hashes independently at load, so the registry cannot silently drift from the raw.

Run:  $RESEARCH_PYTHON make_registry.py    (writes registry.yaml beside this file)
No hardware, no network, read-only over the evidence tree.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tpa import repo  # noqa: E402

EVID = "defense4/timing/evidence"

# --- shared pins for every corrected-binary SEL-751 campaign -----------------
COMMON = dict(
    device="SEL-751",
    device_role="outstation_caseA_separate_ack",
    firmware="UNPINNED (relay firmware/config revision not recorded in raw evidence)",
    binary_sha256="97175e7dc1a77c3cdbe235baa13b906e18d3227bf09cb84cfacfee6f0a928a19",
    sde="BF-SDE 9.13.2 (p4c 9.13.2 SHA 1baf055)",
    capture_point="master_facing_single_capture (Vision enp59s0f0np0)",
    timestamp_source=(
        "libpcap/tcpdump at master NIC; TSO/GSO/GRO on, LRO off; response is a "
        "single 134B frame so first-byte CLRT is intact (accounted, not disabled)"
    ),
    traffic_class="READ",
    state="steady (sustained 60-READ connection, 0.4s poll gap; poll-0 not an outlier)",
    unit_clrt="ms",
    poll_period_s=0.4,
    t_A_def="master-facing pure TCP ACK timestamp for the READ (row t_ack, epoch s)",
    t_R_def="master-facing first byte of the matching DNP3 response (row t_resp, epoch s)",
)
NATIVE_C_DEF = "native CLRT C = t_resp - t_ack (OFF passthrough), reported as clrt_ms"
DEFENDED_C_DEF = "master-facing CLRT_out = t_resp_released - t_ack_released, reported as clrt_ms"


def _blocks(repo_root: Path, reldir: str, pattern: str) -> list[dict]:
    d = repo_root / reldir
    out = []
    for p in sorted(d.glob(pattern)):
        j = json.loads(p.read_text())
        out.append(
            {
                "path": str(p.relative_to(repo_root)),
                "sha256": repo.sha256_file(p),
                "label": j["label"],
                "mode": j["mode"],
                "n": len(j["rows"]),
                "block_d_a_ms": j.get("d_a_ms"),
                "block_d_r_ms": j.get("d_r_ms"),
            }
        )
    if not out:
        raise SystemExit(f"no blocks matched {reldir}/{pattern}")
    return out


def _policy_from_mode(mode: str, blocks: list[dict]) -> tuple:
    """Return (d_a_ms, d_r_ms) pins for a dataset, pinned from the raw block."""
    if mode == "OFF":
        return "native", "native"
    if mode == "D1":
        return "event", "event"
    da = int(float(blocks[0]["block_d_a_ms"]))
    dr = int(float(blocks[0]["block_d_r_ms"]))
    for b in blocks:
        if int(float(b["block_d_a_ms"])) != da or int(float(b["block_d_r_ms"])) != dr:
            raise SystemExit(f"mixed policy within dataset for mode {mode}")
    return da, dr


def _ds(dsid, campaign, reldir, pattern, measures, c_def, role, notes,
        poolable_with, budget, repo_root, d_a=None, d_r=None):
    blks = _blocks(repo_root, reldir, pattern)
    mode = blks[0]["mode"]
    if d_a is None or d_r is None:
        d_a, d_r = _policy_from_mode(mode, blks)
    entry = dict(COMMON)
    entry.update(
        id=dsid,
        campaign=campaign,
        mode=mode,
        measures=measures,
        c_def_note=c_def,
        role=role,
        notes=notes,
        d_a_ms=d_a,
        d_r_ms=d_r,
        budget=budget,
        poolable_with=poolable_with,
        transaction_count=sum(b["n"] for b in blks),
        filters="valid rows: ack_before_resp AND not rst AND not order_inconclusive; clean block-end FIN kept (matches accepted campaign n); no other exclusions",
        blocks=[{k: b[k] for k in ("path", "sha256", "n")} for b in blks],
    )
    # Rename generic def fields to the registry's C_def key.
    entry["C_def"] = c_def
    del entry["c_def_note"]
    return entry


def build(repo_root: Path) -> dict:
    ds = []
    # ---- NATIVE (design distribution) --------------------------------------
    frA = "defense4/timing/evidence/final_run/campaignA_corrected_binary"
    frB = "defense4/timing/evidence/final_run/campaignB_corrected_binary_seed20260807"
    fixA = f"{EVID}/campaign_fixA_20260807T175525Z"
    fixB = f"{EVID}/campaign_fixB_20260807T180227Z"
    recal = f"{EVID}/campaign_d4recal_20260807T175148Z"
    fo = f"{EVID}/campaign_fixfailopen_20260807T180923Z"

    ds.append(_ds("nat_off_frA", "final_run/A", frA, "block_CA_OFF_*.json",
                  "native_clrt", NATIVE_C_DEF, "paper_accepted",
                  "native C, paper campaign A (fixed order)", ["nat_off_frB"],
                  "native", repo_root))
    ds.append(_ds("nat_off_frB", "final_run/B", frB, "block_CB_OFF_*.json",
                  "native_clrt", NATIVE_C_DEF, "paper_accepted",
                  "native C, paper campaign B (seed 20260807)", ["nat_off_frA"],
                  "native", repo_root))
    ds.append(_ds("nat_off_fixA", "fixA", fixA, "block_FA_OFF_*.json",
                  "native_clrt", NATIVE_C_DEF, "validation",
                  "native C, fix-verification campaign A (heavier tail; see report)",
                  ["nat_off_fixB"], "native", repo_root))
    ds.append(_ds("nat_off_fixB", "fixB", fixB, "block_FB_OFF_*.json",
                  "native_clrt", NATIVE_C_DEF, "validation",
                  "native C, fix-verification campaign B", ["nat_off_fixA"],
                  "native", repo_root))

    # ---- DEFENDED deadline modes (paper A<->B, validation fixA<->fixB) ------
    for mode in ("D1", "D2", "D3", "D4"):
        ds.append(_ds(f"def_{mode}_frA", "final_run/A", frA, f"block_CA_{mode}_*.json",
                      "defended_clrt_out", DEFENDED_C_DEF, "paper_accepted",
                      f"defended {mode} output, paper A", [f"def_{mode}_frB"],
                      18000, repo_root))
        ds.append(_ds(f"def_{mode}_frB", "final_run/B", frB, f"block_CB_{mode}_*.json",
                      "defended_clrt_out", DEFENDED_C_DEF, "paper_accepted",
                      f"defended {mode} output, paper B", [f"def_{mode}_frA"],
                      18000, repo_root))
        ds.append(_ds(f"def_{mode}_fixA", "fixA", fixA, f"block_FA_{mode}_*.json",
                      "defended_clrt_out", DEFENDED_C_DEF, "validation",
                      f"defended {mode} output, fix A", [f"def_{mode}_fixB"],
                      18000, repo_root))
        ds.append(_ds(f"def_{mode}_fixB", "fixB", fixB, f"block_FB_{mode}_*.json",
                      "defended_clrt_out", DEFENDED_C_DEF, "validation",
                      f"defended {mode} output, fix B", [f"def_{mode}_fixA"],
                      18000, repo_root))

    # ---- d4recal policy sweep (measured CLRT_out per (D_A,D_R); singletons) --
    for pat in sorted((repo_root / recal).glob("block_r_*.json")):
        name = pat.stem.replace("block_r_", "")  # e.g. da4_dr10
        ds.append(_ds(f"probe_{name}", "d4recal_175148", recal, pat.name,
                      "defended_clrt_out", DEFENDED_C_DEF, "policy_probe",
                      "measured CLRT_out for a probed (D_A,D_R); single 40-READ block",
                      [], 18000, repo_root))

    # ---- fail-open budget sweep (distinct regime; base<->recover poolable) --
    fo_budget = {"fo_b800": 800, "fo_b1500": 1500, "fo_b3000": 3000,
                 "fo_base": 18000, "fo_recover": 18000}
    for pat in sorted((repo_root / fo).glob("block_fo_*.json")):
        name = pat.stem.replace("block_", "")   # e.g. fo_b800
        budget = fo_budget[name]
        peers = (["failopen_fo_recover"] if name == "fo_base"
                 else ["failopen_fo_base"] if name == "fo_recover" else [])
        ds.append(_ds(f"failopen_{name}", "fixfailopen", fo, pat.name,
                      "defended_clrt_out_failopen", DEFENDED_C_DEF, "failopen_probe",
                      f"fail-open regime at budget {budget} (forces early bounded release)",
                      peers, budget, repo_root, d_a=4, d_r=10))

    return {
        "registry_version": "1.0",
        "generated_by": "make_registry.py (sha256 computed from committed raw at gen time)",
        "protection_domain": "SEL-751 Case-A (separate-ACK) outstation, READ, corrected binary 97175e7d",
        # FIX 4 (audit M5): every timing-relevant ceiling is a SEPARATE constraint with
        # its own provenance. The timing evidence was produced by the RAW-SOCKET driver
        # defense4/timing/control/deploy/campaign_driver.py (a hand-crafted DNP3 READ over
        # socket.SOCK_STREAM), NOT an OpenDNP3 application-layer master. So there is no
        # evidenced DNP3 application response timeout in this evidence path; the evidenced
        # ceiling is the driver's socket recv timeout.
        "evidenced_constraints": {
            # poll gap 0.4 s: recorded in every native block header (gap_s) AND passed to
            # campaign_driver.py as its GAP argv (argv[3]); dual-sourced, evidenced.
            "poll_period_ms": "400.0 (from native block header gap_s and campaign_driver.py GAP argv[3])",
            # Master socket response-wait ceiling that ACTUALLY governed the evidence:
            # campaign_driver.py line 80  ->  s.settimeout(4.0); got = s.recv(4096)
            "master_socket_recv_timeout_ms": "4000.0 (defense4/timing/control/deploy/campaign_driver.py:80 s.settimeout(4.0) before s.recv; raw-socket DNP3 driver)",
            # Master socket connect ceiling: campaign_driver.py line 69 s.settimeout(8).
            "master_socket_connect_timeout_ms": "8000.0 (defense4/timing/control/deploy/campaign_driver.py:69 s.settimeout(8) before connect)",
            # DNP3 application-layer response timeout: UNKNOWN. 2000 ms is NEITHER a DNP3
            # protocol constant NOR the OpenDNP3 3.1.2 default. The reusable Python harness
            # configures a 2 s application timeout, but that harness did NOT produce this
            # evidence -- the raw-socket driver did, and it has no DNP3 application timeout.
            # No DNP3 application-timeout margin can be attributed to the timing evidence.
            "dnp3_response_timeout_ms": (
                "UNKNOWN (no OpenDNP3 application-layer master in the evidence path; the "
                "timing evidence came from the raw-socket driver campaign_driver.py, which "
                "has no DNP3 application response timeout. 2000 ms is not a DNP3 protocol "
                "constant and not the OpenDNP3 3.1.2 default; the reusable 2 s Python "
                "harness did not produce this evidence.)"
            ),
            # AUDIT CORRECTION 3: the fail-open horizon is NOT established as t_A-anchored
            # in the committed raw. A 30.8 ms figure at budget 18000 was asserted, but the
            # failopen blocks show normal ~10 ms normalization at budget 18000 (no fail-open
            # release at that horizon), so the value cannot be used as a t_A-anchored bound.
            "fail_open_horizon_ms_at_budget_18000": (
                "UNKNOWN (not t_A-anchored in committed raw; a 30.8 ms figure at budget "
                "18000 was asserted but no fail-open release at that horizon appears in "
                "the failopen blocks, which normalize to ~10 ms at budget 18000)"
            ),
            "tcp_rto_ms": "UNKNOWN (value not evidenced in committed raw; 0 retransmits observed up to ~18.8 ms applied hold)",
            "reservoir_horizon_ms": "UNKNOWN (R11 carried OPEN in EXPERIMENTAL_EVIDENCE_FREEZE.md)",
            "budget_to_failopen_horizon": "the budget sweep (failopen_*) shows shrinking budget shortens the fail-open horizon and collapses normalization when the horizon < D_R (b800/b1500 medians fall below D_R); the horizon's t_A-anchored magnitude in ms is not established in the committed raw",
        },
        "percentile_convention": "nearest (empirical order statistic); reproduces paper anchors",
        "datasets": ds,
    }


def main() -> int:
    repo_root = repo.find_repo_root(Path(__file__))
    reg = build(repo_root)
    out = Path(__file__).resolve().parent / "registry.yaml"
    with open(out, "w") as f:
        yaml.safe_dump(reg, f, sort_keys=False, default_flow_style=False, width=100)
    n_ds = len(reg["datasets"])
    n_tx = sum(d["transaction_count"] for d in reg["datasets"])
    print(f"wrote {out.relative_to(repo_root)}: {n_ds} datasets, {n_tx} transactions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
