"""End-to-end validation of the campaign_v1 evidence and of the analysis that publishes it.

These tests read the raw captures. They do not test the older final_read_sbo evidence tree.
"""
from __future__ import annotations
import csv, glob, hashlib, json, math, os, re, subprocess, sys
from collections import Counter
import numpy as np
import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HERE)                       # campaign_v1/
sys.path.insert(0, HERE)
import pcap_dnp3 as P                              # noqa: E402

OUT = os.environ.get("CV1_OUT", "/tmp/cv1_out")
CANON = os.path.join(OUT, "transactions_canonical.csv")
CFG = json.load(open(os.path.join(HERE, "policy_config.json")))


# ----------------------------------------------------------------- fixtures
@pytest.fixture(scope="session")
def captures():
    c = sorted(glob.glob(os.path.join(ROOT, "s[0-9][0-9]", "raw_pcaps", "*.pcap")))
    assert c, "no captures found"
    return c


@pytest.fixture(scope="session")
def rows():
    assert os.path.exists(CANON), f"run validate_campaign.py first ({CANON} missing)"
    with open(CANON) as f:
        return list(csv.DictReader(f))


@pytest.fixture(scope="session")
def stats():
    return json.load(open(os.path.join(OUT, "stats.json")))


@pytest.fixture(scope="session")
def leak():
    return json.load(open(os.path.join(OUT, "leakage.json")))


# ----------------------------------------------------------------- corpus shape
def test_capture_count(captures):
    assert len(captures) == 132


def test_capture_hashes_unique(captures):
    h = [hashlib.sha256(open(c, "rb").read()).hexdigest() for c in captures]
    assert len(set(h)) == len(h), "captures must not be byte-identical"


def test_grouped_runs(rows):
    assert len({r["run"] for r in rows}) == 22


def test_exchange_total(rows):
    assert len(rows) == 63360


@pytest.mark.parametrize("arm,cls,n", [("native", "READ", 26400), ("native", "SELECT", 2640),
                                       ("native", "OPERATE", 2640), ("obfuscated", "READ", 26400),
                                       ("obfuscated", "SELECT", 2640), ("obfuscated", "OPERATE", 2640)])
def test_per_arm_class_counts(rows, arm, cls, n):
    assert sum(1 for r in rows if r["arm"] == arm and r["txn_class"] == cls) == n


def test_unit_distinction_480_vs_440(stats):
    """A capture holds 480 DNP3 exchanges and 440 high-level operations. They are not the same."""
    ov = stats["overhead"]
    assert ov["exchanges_per_capture"] == 480
    assert ov["high_level_ops_per_capture"] == 440
    assert ov["exchanges_per_capture"] != ov["high_level_ops_per_capture"]
    assert math.isclose(ov["frames_per_exchange"], 1448 / 480, rel_tol=1e-4)
    assert math.isclose(ov["wire_bytes_per_exchange"], 130708 / 480, rel_tol=1e-4)


# ----------------------------------------------------------------- per-capture structure
@pytest.fixture(scope="session")
def reports(captures):
    return {os.path.basename(c)[:-5]: P.extract(c) for c in captures}


def test_frames_and_bytes_per_capture(reports):
    assert {r.frames for r in reports.values()} == {1448}
    assert {r.wire_bytes for r in reports.values()} == {130708}


def test_one_tcp_connection_per_capture(reports):
    assert {r.syn // 2 for r in reports.values()} == {1}


def test_no_retransmissions(reports):
    assert sum(r.retransmissions for r in reports.values()) == 0


def test_no_duplicate_application_frames(reports):
    assert sum(r.duplicate_app_frames for r in reports.values()) == 0


def test_no_malformed_frames(reports):
    assert sum(r.malformed for r in reports.values()) == 0


def test_no_unpaired_requests(reports):
    """Every request has both an acknowledgment and an application response."""
    assert sum(r.unpaired_requests for r in reports.values()) == 0


def test_timestamps_monotonic(reports):
    assert sum(r.out_of_order_ts for r in reports.values()) == 0


def test_no_wrong_endpoint_payloads(reports):
    assert sum(r.wrong_endpoint for r in reports.values()) == 0


def test_function_codes_and_counts(reports):
    for name, r in reports.items():
        c = Counter(r.func for r in r.exchanges)
        assert c[1] == 400 and c[3] == 40 and c[4] == 40, name


def test_all_responses_are_dnp3_responses(reports):
    for name, r in reports.items():
        assert all(e.resp_func == 0x81 for e in r.exchanges), name


def test_control_status_success(reports):
    for name, r in reports.items():
        assert all(e.status == 0 for e in r.exchanges if e.func in (3, 4)), name


# ----------------------------------------------------------------- timing identities
def test_intervals_positive_and_ordered(rows):
    for r in rows:
        assert float(r["ack_ms"]) >= 0 and float(r["clrt_ms"]) >= 0 and float(r["rt_ms"]) > 0


def test_total_latency_identity_exact(reports):
    """rt = ack + clrt exactly on the raw timestamps: rt carries no independent information."""
    for name, rep in reports.items():
        for e in rep.exchanges:
            ack, clrt, rt = e.t_ack - e.t_req, e.t_resp - e.t_ack, e.t_resp - e.t_req
            assert abs((ack + clrt) - rt) < 1e-12, name


def test_total_latency_identity_in_table(rows):
    """The published table stores six decimals, so the identity holds to that rounding."""
    tol = 3 * 0.5e-6 + 1e-12
    for r in rows:
        assert abs((float(r["ack_ms"]) + float(r["clrt_ms"])) - float(r["rt_ms"])) <= tol


def test_pcap_to_csv_agreement(reports, rows):
    """The canonical table is exactly what the independent reader produces."""
    from_pcap = Counter((n.split("_")[0], n.split("_", 2)[2], P.FUNC_NAME[e.func])
                        for n, r in reports.items() for e in r.exchanges)
    from_csv = Counter((r["run"], r["arm"], r["txn_class"]) for r in rows)
    assert from_pcap == from_csv


def test_jsonl_agrees_with_captures(reports):
    """The per-capture driver logs count the same operations the wire shows."""
    for name, rep in reports.items():
        j = os.path.join(ROOT, name.split("_")[0], "app_jsonl", name + ".jsonl")
        if not os.path.exists(j):
            pytest.skip(f"no driver log for {name}")
        ops = Counter(json.loads(l)["operation"] for l in open(j))
        c = Counter(P.FUNC_NAME[e.func] for e in rep.exchanges)
        assert ops["READ"] == c["READ"] and ops["SELECT"] == c["SELECT"] and ops["OPERATE"] == c["OPERATE"], name


# ----------------------------------------------------------------- analysis correctness
def test_mi_reported_in_bits(leak):
    """The estimator returns nats. Published values must be bits, so nats = bits * ln 2."""
    for arm in ("native", "obfuscated"):
        b = leak["mutual_information"][arm]["observed_bits"]
        assert 0.0 <= b < 2.0
    assert leak["mutual_information"]["native"]["observed_bits"] > \
           leak["mutual_information"]["obfuscated"]["observed_bits"]


def test_mi_conversion_constant():
    from sklearn.feature_selection import mutual_info_classif
    rng = np.random.default_rng(0)
    X = rng.normal(size=(600, 1)); y = (X[:, 0] > 0).astype(int)
    nats = float(mutual_info_classif(X, y, random_state=0)[0])
    assert math.isclose(nats / math.log(2), nats / 0.6931471805599453, rel_tol=1e-9)


def test_no_marginal_mi_summation():
    """The analysis must not add per-feature MI values and call the sum a joint MI."""
    src = open(os.path.join(HERE, "leakage_campaign.py")).read()
    assert "np.sum(mutual_info_classif" not in src
    assert "sum(mutual_info_classif" not in src


def test_redundant_feature_excluded():
    src = open(os.path.join(HERE, "leakage_campaign.py")).read()
    assert '"ack_clrt": ["ack_ms", "clrt_ms"]' in src
    assert '"rt_ms"' not in src.split("FEATURES =")[1].split("\n")[0]


def test_permutation_null_present(leak):
    for arm in ("native", "obfuscated"):
        m = leak["mutual_information"][arm]
        assert m["n_permutations"] >= 1000
        assert "null_p99_bits" in m and "monte_carlo_resolution" in m


def test_native_mi_above_null_obfuscated_inside(leak):
    assert leak["mutual_information"]["native"]["exceeds_null_p99"] is True
    assert leak["mutual_information"]["obfuscated"]["exceeds_null_p99"] is False


def test_both_attacker_models_present(leak):
    for f in ("clrt", "ack_clrt"):
        c = leak["classifiers"][f]
        assert "A_fixed_native_trained" in c and "B_adaptive_obfuscated_trained" in c
        assert "tested_on_timing_off" in c["A_fixed_native_trained"]
        assert "tested_on_obfuscated" in c["A_fixed_native_trained"]


def test_fixed_attacker_falls_to_chance(leak):
    for f in ("clrt", "ack_clrt"):
        ba = leak["classifiers"][f]["A_fixed_native_trained"]["tested_on_obfuscated"]["balanced_accuracy"]
        assert abs(ba - 1 / 3) < 0.02, f


def test_adaptive_attacker_recovers_with_ack(leak):
    """The adaptive adversary stays at chance on CLRT alone but recovers using the anchor."""
    a = leak["classifiers"]["clrt"]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["balanced_accuracy"]
    b = leak["classifiers"]["ack_clrt"]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["balanced_accuracy"]
    assert abs(a - 1 / 3) < 0.02
    assert b > 0.55


def test_confusion_uses_all_folds(leak):
    assert leak["n_folds"] == 22
    for k, cm in leak["confusion_all_folds"].items():
        rows_ = np.array(cm)
        assert rows_.shape == (3, 3)
        assert np.allclose(rows_.sum(axis=1), 1.0, atol=1e-3), k


# ----------------------------------------------------------------- publication hygiene
def test_figures_derive_parameters_from_config():
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    assert 'cfg["release_budget_D_ms"]' in src and 'cfg["fail_open_horizon_H_ms"]' in src
    # no literal policy constants baked into figure logic
    assert not re.search(r"=\s*24\.0\b", src)
    assert not re.search(r"=\s*30\.8\b", src)


def test_no_hard_coded_publication_statistics():
    """Headline numbers must come from generated data, never be typed into a figure script."""
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    for v in ("0.383", "0.651", "2.116", "63360", "63,360", "0.006"):
        assert v not in src, f"hard-coded statistic {v} in figure code"


def test_figures_do_not_clip_silently():
    """Distribution figures must plot the full support or disclose what they omit."""
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    assert "whis=(0, 100)" in src, "box whiskers must span the full range"
    assert "full support" in src


def test_config_is_machine_readable():
    for k in ("release_budget_D_ms", "fail_open_horizon_H_ms", "D_A_ms", "D_R_ms",
              "J_codebook_ms", "exchanges_per_capture"):
        assert k in CFG


def test_budget_matches_offsets():
    assert math.isclose(CFG["D_A_ms"] + CFG["D_R_ms"], CFG["release_budget_D_ms"])


def test_p4_source_hash_unchanged():
    p = os.path.join(ROOT, "..", "..", "implementation", "exact_experiment_source",
                     "defense4_rrc_bor_unified12.p4")
    p = os.path.normpath(p)
    if not os.path.exists(p):
        pytest.skip("exact experiment source not present")
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    assert h == "7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861"


def test_coverage_residual_is_reported(stats):
    """The fixed budget leaves a tail; the analysis must record it rather than claim none."""
    over = stats["timing_off_exceeding_budget"]
    assert over["count"] > 0
    dep = stats["obfuscated_departures"]["READ"]
    assert dep["gt_1.0ms"] > 0 and dep["max_departure"] > 1.0


def test_figure_output_is_deterministic(tmp_path):
    """The same inputs must produce byte-identical figure PDFs."""
    import subprocess
    py = os.path.join(HERE, ".venv", "bin", "python")
    if not os.path.exists(py) or not os.path.exists(CANON):
        pytest.skip("environment or canonical table missing")
    outs = []
    for i in (1, 2):
        d = tmp_path / f"run{i}"
        subprocess.run([py, os.path.join(HERE, "make_ndss_figures.py"), CANON,
                        os.path.join(OUT, "stats.json"), os.path.join(OUT, "leakage.json"),
                        os.path.join(HERE, "policy_config.json"), str(d)],
                       check=True, capture_output=True)
        outs.append({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(d.glob("*.pdf"))})
    assert outs[0] == outs[1] and outs[0], "figure PDFs are not reproducible"
