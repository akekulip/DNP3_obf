"""End-to-end validation of the campaign_v1 evidence and of the analysis that publishes it.

These tests read the raw captures. They do not test the older final_read_sbo evidence tree.

Expected dataset-level values are asserted as consequences of the raw captures, never forced into
the scripts. Where a corrected definition legitimately changed a published number — the read-lane
coverage denominator, and the sweep's response-time median — the test asserts the corrected
quantity and names the reason.
"""
from __future__ import annotations
import csv, glob, hashlib, json, math, os, re, subprocess, sys
from collections import Counter
import numpy as np
import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HERE)                       # campaign_v1/
REPO = os.path.normpath(os.path.join(ROOT, "..", "..", "..", ".."))
sys.path.insert(0, HERE)
import pcap_dnp3 as P                              # noqa: E402

OUT = os.environ.get("CV1_OUT", "/tmp/cv1_out")
CANON = os.path.join(OUT, "transactions_canonical.csv")
CFG = json.load(open(os.path.join(HERE, "policy_config.json")))
PUB_FIGS = os.path.join(REPO, "paper", "rewrite", "figures", "ndss")
FIGURES = ["fig_policy_coverage_cost", "fig_distributions", "fig_feature_overlap",
           "fig_leakage", "fig_stability"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


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


@pytest.fixture(scope="session")
def sweep():
    return json.load(open(os.path.join(OUT, "sweep_summary.json")))


@pytest.fixture(scope="session")
def sweep_report():
    return json.load(open(os.path.join(OUT, "sweep_report.json")))


@pytest.fixture(scope="session")
def validation():
    return json.load(open(os.path.join(OUT, "validation_report.json")))


@pytest.fixture(scope="session")
def reports(captures):
    return {os.path.basename(c)[:-5]: P.extract(c) for c in captures}


# ----------------------------------------------------------------- corpus shape
def test_capture_count(captures):
    assert len(captures) == 132


def test_capture_hashes_unique(captures):
    h = [sha256(c) for c in captures]
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


# ----------------------------------------------------------------- dataset manifests
def test_all_22_dataset_manifests_verified(validation):
    assert validation["dataset_manifests_verified"] == 22
    assert validation["dataset_manifest_entries_verified"] > 0
    assert validation["problems"] == []


def test_dataset_manifests_cover_every_capture(captures):
    """Every capture must appear in the manifest of its own run, with a matching hash."""
    recorded = {}
    for man in sorted(glob.glob(os.path.join(ROOT, "s[0-9][0-9]", "provenance",
                                             "DATASET.sha256"))):
        run_dir = os.path.dirname(os.path.dirname(man))
        for line in open(man):
            if line.strip():
                h, rel = line.split(None, 1)
                recorded[os.path.normpath(os.path.join(run_dir, rel.strip()))] = h
    for c in captures:
        key = os.path.normpath(c)
        assert key in recorded, f"{os.path.basename(c)} is not in any DATASET.sha256"
        assert recorded[key] == sha256(c), f"{os.path.basename(c)} hash differs from its manifest"


# ----------------------------------------------------------------- per-capture structure
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
    assert sum(r.unpaired_requests for r in reports.values()) == 0


def test_timestamps_monotonic(reports):
    assert sum(r.out_of_order_ts for r in reports.values()) == 0


def test_no_wrong_endpoint_payloads(reports):
    assert sum(r.wrong_endpoint for r in reports.values()) == 0


def test_function_codes_and_counts(reports):
    for name, r in reports.items():
        c = Counter(e.func for e in r.exchanges)
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


# ----------------------------------------------------------------- exact row agreement
def test_canonical_table_has_stable_keys(rows):
    """Row-level comparison needs an identity per transaction, not just a group count."""
    for col in ("run", "block", "arm", "capture", "idx", "txn_class",
                "t_req", "t_ack", "t_resp", "resp_func", "status"):
        assert col in rows[0], f"canonical table is missing {col}"
    keys = {(r["capture"], r["idx"]) for r in rows}
    assert len(keys) == len(rows), "capture+idx is not unique"


def test_pcap_to_csv_exact_row_agreement(reports, rows):
    """Every regenerated transaction must match the canonical table field by field.

    This compares identity, ordering and every stored value, not grouped counts. The tolerance is
    one unit in the last stored decimal place and is justified by nothing else.
    """
    TOL = 1e-6
    by_capture = {}
    for r in rows:
        by_capture.setdefault(r["capture"], []).append(r)
    assert set(by_capture) == set(reports), "capture sets differ"
    for name, rep in reports.items():
        got = by_capture[name]
        assert len(got) == len(rep.exchanges), f"{name}: row count differs"
        for i, (e, r) in enumerate(zip(rep.exchanges, got)):
            assert int(r["idx"]) == i, f"{name}: ordering broken at {i}"
            assert r["capture"] == name
            assert r["run"], r["arm"]
            assert r["txn_class"] == P.FUNC_NAME.get(e.func, str(e.func)), f"{name} #{i}: class"
            assert int(r["func"]) == e.func, f"{name} #{i}: function code"
            assert int(r["resp_func"]) == e.resp_func, f"{name} #{i}: response function code"
            # READ has no control status; the table stores that as an empty field. SELECT and
            # OPERATE must carry SUCCESS, and any other value is a real status to be surfaced.
            if e.status is None:
                expect_status = ""
                assert e.func == 1, f"{name} #{i}: only READ may lack a control status"
            else:
                expect_status = "SUCCESS" if e.status == 0 else str(e.status)
            assert r["status"] == expect_status, f"{name} #{i}: control status"
            assert float(r["t_req"]) == e.t_req, f"{name} #{i}: request timestamp"
            assert float(r["t_ack"]) == e.t_ack, f"{name} #{i}: acknowledgment timestamp"
            assert float(r["t_resp"]) == e.t_resp, f"{name} #{i}: response timestamp"
            for col, val in (("ack_ms", (e.t_ack - e.t_req) * 1e3),
                             ("clrt_ms", (e.t_resp - e.t_ack) * 1e3),
                             ("rt_ms", (e.t_resp - e.t_req) * 1e3)):
                assert abs(float(r[col]) - val) <= TOL, f"{name} #{i}: {col}"


def test_frozen_table_compared_row_by_row(validation, rows):
    """The publication path must really compare against the frozen table, not just count rows."""
    assert validation["frozen_table_rows_compared"] == len(rows) == 63360


def test_jsonl_agrees_with_captures(reports):
    for name, rep in reports.items():
        j = os.path.join(ROOT, name.split("_")[0], "app_jsonl", name + ".jsonl")
        # every capture in this corpus has a driver log; a missing one is a defect, not a skip
        assert os.path.exists(j), f"no driver log for {name}"
        ops = Counter(json.loads(l)["operation"] for l in open(j))
        c = Counter(P.FUNC_NAME[e.func] for e in rep.exchanges)
        assert ops["READ"] == c["READ"] and ops["SELECT"] == c["SELECT"] \
            and ops["OPERATE"] == c["OPERATE"], name


# ----------------------------------------------------------------- hardware sweep
def test_sweep_manifest_verified(sweep_report):
    assert sweep_report["manifest_entries_verified"] > 0
    assert sweep_report["problems"] == []


def test_sweep_point_count(sweep):
    assert len(sweep) == 19


def test_sweep_pcap_to_table_agreement(sweep):
    """Recomputing each sweep point from its capture must reproduce the published table."""
    pub = {r["point"]: r for r in
           csv.DictReader(open(os.path.join(ROOT, "sweep", "sweep_points.csv")))}
    assert set(pub) == {s["point"] for s in sweep}
    for s in sweep:
        p = pub[s["point"]]
        assert abs(s["read_clrt_med_ms"] - float(p["clrt_med_ms"])) <= 0.0015, s["point"]
        assert abs(s["read_ack_med_ms"] - float(p["ack_med_ms"])) <= 0.0015, s["point"]
        assert s["read_n"] == int(p["n_read"]), s["point"]
        # the published sd column uses the population convention; recorded, not silently changed
        assert abs(s["read_clrt_sd_pop_ms"] - float(p["clrt_sd_ms"])) <= 0.0015, s["point"]


def test_sweep_response_time_median_is_a_real_median(sweep):
    """rt_med_ms must be the median of t_resp - t_req, not the sum of two medians.

    The published sweep table gave the sum. Both are emitted here under names that say which is
    which, and they must not be confused: for at least one point they differ measurably.
    """
    for s in sweep:
        assert "read_rt_med_ms" in s and "read_sum_of_interval_medians_ms" in s
    diffs = [abs(s["read_rt_med_ms"] - s["read_sum_of_interval_medians_ms"]) for s in sweep]
    assert max(diffs) > 0.005, ("the two quantities are indistinguishable in this data, so the "
                                "test cannot show the correction is real")


def test_sweep_published_rt_med_was_the_sum(sweep):
    """Documents precisely what the published column contained."""
    for s in sweep:
        assert abs(s["published_rt_med_ms"] - s["read_sum_of_interval_medians_ms"]) <= 0.0015, \
            s["point"]


def test_sweep_fixed_budget_tracks_target(sweep):
    """At a fixed total budget, the visible CLRT follows the configured D_R."""
    fixed = [s for s in sweep if s["mode"] == "D4" and not s["is_control_point"]
             and s["D_ms"] == 24.0]
    assert len(fixed) >= 6
    for s in fixed:
        assert abs(s["read_clrt_med_ms"] - s["D_R_ms"]) < 0.01, s["point"]


def test_sweep_offsets_not_inferred_from_filenames(sweep_report):
    assert "sweep_points.csv" in sweep_report["offsets_provenance"]
    assert "readback" in sweep_report["offsets_provenance"]


# ----------------------------------------------------------------- lane separation
def test_read_lane_coverage_excludes_operate(stats):
    """OPERATE is request-anchored and must never enter the read-budget denominator."""
    cov = stats["read_lane_coverage"]
    assert cov["classes"] == ["READ", "SELECT"]
    assert "OPERATE" not in cov["per_class"]
    assert cov["n"] == 29040, "denominator must be READ + SELECT only"
    assert cov["above_budget"] == 29
    assert abs(cov["percent_covered"] - 99.9001) < 0.001


def test_read_lane_denominator_matches_rows(rows, stats):
    n = sum(1 for r in rows if r["arm"] == "native" and r["txn_class"] in ("READ", "SELECT"))
    assert stats["read_lane_coverage"]["n"] == n


def test_control_lane_reported_on_its_own_terms(stats):
    c = stats["control_lane"]
    assert "R - A" in c["observable"]
    assert c["budget_note"].startswith("the read-path budget D is not")
    assert "not observable" in c["J_observability"]


def test_no_pooled_budget_statistic(stats):
    """The old pooled 'timing_off_exceeding_budget' key mixed the two anchors and must be gone."""
    assert "timing_off_exceeding_budget" not in stats


def test_lane_definitions_declared(stats):
    ld = stats["lane_definition"]
    assert ld["read_lane"]["budget_applies"] is True
    assert ld["control_lane"]["budget_applies"] is False
    assert ld["control_lane"]["classes"] == ["OPERATE"]


# ----------------------------------------------------------------- analysis correctness
def test_mi_reported_in_bits(leak):
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
    src = open(os.path.join(HERE, "leakage_campaign.py")).read()
    assert "np.sum(mutual_info_classif" not in src
    assert "sum(mutual_info_classif" not in src


def test_redundant_feature_excluded():
    src = open(os.path.join(HERE, "leakage_campaign.py")).read()
    assert '"ack_clrt": ["ack_ms", "clrt_ms"]' in src
    assert '"rt_ms"' not in src.split("FEATURES =")[1].split("\n")[0]


def test_permutation_null_and_p_value_present(leak):
    for arm in ("native", "obfuscated"):
        m = leak["mutual_information"][arm]
        assert m["n_permutations"] >= 1000
        assert "null_p95_bits" in m and "null_p99_bits" in m
        assert "p_value_empirical" in m and "p_value_resolution" in m
        # the (1+r)/(1+n) correction can never yield exactly zero
        assert m["p_value_empirical"] >= m["p_value_resolution"]


def test_native_mi_above_null_obfuscated_inside(leak):
    assert leak["mutual_information"]["native"]["exceeds_null_p99"] is True
    assert leak["mutual_information"]["obfuscated"]["exceeds_null_p99"] is False
    assert leak["mutual_information"]["obfuscated"]["inside_null"] is True


def test_no_published_mi_interval(leak):
    """The jackknife interval was not defensible and must not be published as an interval."""
    for arm in ("native", "obfuscated"):
        m = leak["mutual_information"][arm]
        for banned in ("jackknife_ci95_bits", "jackknife_se_bits",
                       "jackknife_bias_corrected_bits"):
            assert banned not in m, f"{arm}: {banned} is published at the top level"
        rej = m["rejected_estimators"]["grouped_run_jackknife"]
        assert rej["status"].startswith("REJECTED")
        assert "never plotted" in rej["status"]


def test_mi_figure_plots_no_error_bar():
    """The figure must not draw an interval around the MI point estimate.

    Only the plotting code is inspected. The caption and the method note deliberately explain
    that a jackknife interval was rejected, so scanning them for the word would be meaningless.
    """
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    plotting = src.split("def fig_leakage")[1].split("F.save(")[0]
    assert "jackknife" not in plotting.lower(), "figure plots a jackknife quantity"
    assert "1.96" not in plotting, "figure draws a normal-approximation interval"
    # the MI panel must not attach an error bar to the point estimate at all
    mi_panel = plotting.split("mi = leak[")[1].split("# (c)")[0]
    assert "yerr" not in mi_panel, "an error bar is attached to the MI estimate"


def test_classifier_spread_is_descriptive_not_a_ci(leak):
    """Bootstrapping dependent fold scores is not a confidence interval and must not be claimed."""
    for f in ("clrt", "ack_clrt"):
        for grp, keys in (("A_fixed_native_trained", ("tested_on_timing_off", "tested_on_obfuscated")),
                          ("B_adaptive_obfuscated_trained", ("tested_on_obfuscated",))):
            for k in keys:
                d = leak["classifiers"][f][grp][k]
                assert "ci95" not in d, "a confidence interval is still published"
                for need in ("mean", "median", "min", "max", "iqr_lo", "iqr_hi", "n_runs"):
                    assert need in d
                assert d["n_runs"] == 22
                assert "not a confidence interval" in d["interpretation"]


def test_no_naive_bootstrap_in_source():
    src = open(os.path.join(HERE, "leakage_campaign.py")).read()
    assert "def boot_ci" not in src
    assert "N_BOOT" not in src


def test_classifier_scope_declared(leak):
    assert "Random-Forest" in leak["classifier_scope"]
    assert "do not generalise" in leak["classifier_scope"]


def test_both_attacker_models_present(leak):
    for f in ("clrt", "ack_clrt"):
        c = leak["classifiers"][f]
        assert "A_fixed_native_trained" in c and "B_adaptive_obfuscated_trained" in c
        assert "tested_on_timing_off" in c["A_fixed_native_trained"]
        assert "tested_on_obfuscated" in c["A_fixed_native_trained"]


def test_fixed_attacker_falls_to_chance(leak):
    for f in ("clrt", "ack_clrt"):
        ba = leak["classifiers"][f]["A_fixed_native_trained"]["tested_on_obfuscated"]["mean"]
        assert abs(ba - 1 / 3) < 0.02, f


def test_adaptive_attacker_recovers_with_ack(leak):
    a = leak["classifiers"]["clrt"]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["mean"]
    b = leak["classifiers"]["ack_clrt"]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["mean"]
    assert abs(a - 1 / 3) < 0.02
    assert b > 0.55


def test_expected_headline_values(leak, stats):
    """The values the manuscript quotes, as consequences of the captures."""
    mi = leak["mutual_information"]
    assert abs(mi["native"]["observed_bits"] - 0.38315) < 5e-4
    assert abs(mi["obfuscated"]["observed_bits"] - 0.00394) < 5e-4
    c = leak["classifiers"]
    assert abs(c["clrt"]["A_fixed_native_trained"]["tested_on_timing_off"]["mean"] - 0.6515) < 5e-3
    assert abs(c["clrt"]["A_fixed_native_trained"]["tested_on_obfuscated"]["mean"] - 0.3332) < 5e-3
    assert abs(c["ack_clrt"]["A_fixed_native_trained"]["tested_on_timing_off"]["mean"] - 0.7328) < 5e-3
    assert abs(c["ack_clrt"]["A_fixed_native_trained"]["tested_on_obfuscated"]["mean"] - 0.3337) < 5e-3
    assert abs(c["ack_clrt"]["B_adaptive_obfuscated_trained"]["tested_on_obfuscated"]["mean"] - 0.6510) < 5e-3
    for k in ("obfuscated/READ", "obfuscated/SELECT", "obfuscated/OPERATE"):
        assert abs(stats["per_arm_class"][k]["median"] - 4.000) < 1e-3


def test_no_added_frames_or_bytes(stats):
    ov = stats["overhead"]
    assert ov["frames_per_capture"] == 1448 and ov["wire_bytes_per_capture"] == 130708


def test_confusion_uses_all_folds(leak):
    assert leak["n_folds"] == 22
    for k, cm in leak["confusion_all_folds"].items():
        rows_ = np.array(cm)
        assert rows_.shape == (3, 3)
        assert np.allclose(rows_.sum(axis=1), 1.0, atol=1e-3), k


# ----------------------------------------------------------------- claim boundaries in source
SOURCES = ["make_ndss_figures.py", "stats_campaign.py", "leakage_campaign.py",
           "validate_campaign.py", "validate_sweep.py"]


def _all_source_text():
    return "\n".join(open(os.path.join(HERE, s)).read() for s in SOURCES)


def test_no_per_transaction_J_claim():
    """The realized per-transaction hold was never observed and must not be claimed."""
    txt = _all_source_text().lower()
    for banned in ("insensitive to the codebook", "measured per j", "per-transaction j was",
                   "observed j", "j was measured"):
        assert banned not in txt, banned


def test_no_relay_facing_observation_claim():
    txt = _all_source_text().lower()
    for banned in ("relay-facing release was observed", "observed at t0+j",
                   "relay-facing hold varied", "exactly once"):
        assert banned not in txt, banned


def test_j_observability_declared_unobserved():
    assert "not observable" in CFG["J_observability"]


def test_no_size_claims_in_analysis():
    txt = _all_source_text().lower()
    for banned in ("padding", "segmentation", "size normalization", "size normalisation",
                   "size class"):
        assert banned not in txt, banned


def test_no_stale_final_read_sbo_values():
    """Values from the retired six-capture dataset must not appear in the active analysis."""
    txt = _all_source_text()
    for stale in ("4.001", "0.424", "0.592", "999", "488", "599", "499"):
        assert stale not in txt, f"stale final_read_sbo value {stale} in active analysis source"


# ----------------------------------------------------------------- publication hygiene
def test_figures_derive_parameters_from_config():
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    assert 'cfg["release_budget_D_ms"]' in src and 'cfg["fail_open_horizon_H_ms"]' in src
    assert not re.search(r"=\s*24\.0\b", src)
    assert not re.search(r"=\s*30\.8\b", src)


def test_no_hard_coded_publication_statistics():
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    for v in ("0.383", "0.651", "2.116", "63360", "63,360", "0.006", "29040", "99.9"):
        assert v not in src, f"hard-coded statistic {v} in figure code"


def test_figures_do_not_clip_silently():
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
    p = os.path.normpath(os.path.join(ROOT, "..", "..", "implementation",
                                      "exact_experiment_source",
                                      "defense4_rrc_bor_unified12.p4"))
    assert os.path.exists(p), "the exact experiment source must be present"
    assert sha256(p) == "7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861"


def test_coverage_residual_is_reported(stats):
    cov = stats["read_lane_coverage"]
    assert cov["above_budget"] > 0
    dep = stats["obfuscated_departures"]["READ"]
    assert dep["gt_1.0ms"] > 0 and dep["max_departure"] > 1.0


# ----------------------------------------------------------------- figure artefacts
@pytest.mark.parametrize("stem", FIGURES)
def test_figure_artefact_set_generated(stem):
    d = os.path.join(OUT, "figs")
    for suf in (".pdf", ".png", "_data.csv", ".provenance.json",
                ".caption.md", ".method.md", ".limitations.md"):
        p = os.path.join(d, stem + suf)
        assert os.path.exists(p) and os.path.getsize(p) > 0, f"missing {stem}{suf}"


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_data_csv_has_rows(stem):
    with open(os.path.join(OUT, "figs", f"{stem}_data.csv")) as f:
        assert len(list(csv.DictReader(f))) > 0


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_provenance_is_complete(stem):
    p = json.load(open(os.path.join(OUT, "figs", f"{stem}.provenance.json")))
    for k in ("figure", "caption", "generation_command", "source_commit", "deterministic_seed",
              "analysis_script", "style_module", "inputs", "outputs",
              "figure_dimensions_in", "method_note", "limitation_note"):
        assert k in p and p[k] is not None, f"{stem}: provenance is missing {k}"
    assert p["inputs"], f"{stem}: no inputs recorded"
    assert not p["missing_inputs"], f"{stem}: {p['missing_inputs']}"
    for i in p["inputs"]:
        # repository-relative path plus a hash, never a bare basename
        assert "/" in i["path"], f"{stem}: unresolved input path {i['path']!r}"
        assert len(i["sha256"]) == 64
    for key in ("pdf", "png"):
        assert len(p["outputs"][key]["sha256"]) == 64
    assert p["outputs"]["data_csv"] is not None
    assert len(p["analysis_script"]["sha256"]) == 64
    assert len(p["style_module"]["sha256"]) == 64


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_provenance_hashes_match_outputs(stem):
    d = os.path.join(OUT, "figs")
    p = json.load(open(os.path.join(d, f"{stem}.provenance.json")))
    assert p["outputs"]["pdf"]["sha256"] == sha256(os.path.join(d, stem + ".pdf"))
    assert p["outputs"]["png"]["sha256"] == sha256(os.path.join(d, stem + ".png"))
    assert p["outputs"]["data_csv"]["sha256"] == sha256(os.path.join(d, stem + "_data.csv"))


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_dimensions_are_ndss_widths(stem):
    p = json.load(open(os.path.join(OUT, "figs", f"{stem}.provenance.json")))
    w = p["figure_dimensions_in"]["width"]
    assert abs(w - 7.16) < 0.01 or abs(w - 3.5) < 0.01, f"{stem}: width {w} in"


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_pdf_has_no_type3_fonts(stem):
    data = open(os.path.join(OUT, "figs", stem + ".pdf"), "rb").read()
    assert b"Type3" not in data, f"{stem}: Type 3 font present"


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_pdf_mediabox_matches_declared_size(stem):
    d = os.path.join(OUT, "figs")
    p = json.load(open(os.path.join(d, f"{stem}.provenance.json")))
    data = open(os.path.join(d, stem + ".pdf"), "rb").read()
    m = re.search(rb"/MediaBox *\[([^\]]*)\]", data)
    assert m, f"{stem}: no MediaBox"
    x0, y0, x1, y1 = (float(v) for v in m.group(1).split())
    assert abs((x1 - x0) / 72.0 - p["figure_dimensions_in"]["width"]) < 0.02
    assert abs((y1 - y0) / 72.0 - p["figure_dimensions_in"]["height"]) < 0.02


def test_no_figure_text_below_8pt():
    """Enforced at generation time; assert the guard exists and its threshold is 8 pt."""
    src = open(os.path.join(HERE, "figstyle_ndss.py")).read()
    assert "MIN_PT = 8.0" in src
    assert "check_min_font" in src
    assert "raise SystemExit" in src


def test_greyscale_distinguishability_uses_style_not_only_colour():
    src = open(os.path.join(HERE, "make_ndss_figures.py")).read()
    assert "LS_CLASS" in src, "classes must differ by line style, not colour alone"
    assert "hatch=F.HATCH" in src, "arms must differ by hatch, not colour alone"


def test_figure_output_is_deterministic(tmp_path):
    """The same inputs must produce byte-identical figure PDFs and PNGs."""
    py = os.path.join(HERE, ".venv", "bin", "python")
    if not os.path.exists(py) or not os.path.exists(CANON):
        pytest.skip("environment or canonical table missing")
    outs = []
    for i in (1, 2):
        d = tmp_path / f"run{i}"
        subprocess.run([py, os.path.join(HERE, "make_ndss_figures.py"), CANON,
                        os.path.join(OUT, "stats.json"), os.path.join(OUT, "leakage.json"),
                        os.path.join(HERE, "policy_config.json"), str(d),
                        os.path.join(OUT, "sweep_summary.json")],
                       check=True, capture_output=True)
        outs.append({p.name: sha256(p) for p in sorted(d.glob("*.pdf"))})
    assert outs[0] == outs[1] and outs[0], "figure PDFs are not reproducible"


@pytest.mark.parametrize("stem", FIGURES)
def test_regenerated_figure_matches_committed(stem):
    """What the repository publishes must be what this pipeline produces."""
    a = os.path.join(OUT, "figs", stem + ".pdf")
    b = os.path.join(PUB_FIGS, stem + ".pdf")
    assert os.path.exists(b), f"{stem}.pdf is not published"
    assert sha256(a) == sha256(b), f"{stem}.pdf differs from the committed copy"


def test_published_manifest_lists_authoritative_artefacts():
    """The manifest gates the vector PDF and the figure data, and nothing else."""
    man = os.path.join(PUB_FIGS, "FIGURES.sha256")
    assert os.path.exists(man), "FIGURES.sha256 must be published"
    listed = {l.split()[1] for l in open(man)
              if l.strip() and not l.lstrip().startswith("#")}
    for stem in FIGURES:
        assert stem + ".pdf" in listed, f"{stem}.pdf must be gated"
        assert stem + "_data.csv" in listed, f"{stem}_data.csv must be gated"


def test_png_preview_is_not_hash_gated():
    """A raster preview is not byte-reproducible across interpreter builds.

    The PNG is produced by the Agg backend, whose output depends on the FreeType and libpng
    bundled with the interpreter build. Two environments satisfying the same lock file were
    observed to differ by a few hundred pixels while the vector PDF was byte-identical. Gating
    the preview therefore failed a correct rebuild, so it is recorded but never gated.
    """
    man = os.path.join(PUB_FIGS, "FIGURES.sha256")
    listed = {l.split()[1] for l in open(man)
              if l.strip() and not l.lstrip().startswith("#")}
    for stem in FIGURES:
        assert stem + ".png" not in listed, f"{stem}.png must not be in the gated manifest"
    src = open(os.path.join(HERE, "publication_gate.py")).read()
    assert 'PREVIEW = [".png"]' in src
    # the preview must still be produced and published
    for stem in FIGURES:
        p = os.path.join(PUB_FIGS, stem + ".png")
        assert os.path.exists(p) and os.path.getsize(p) > 0, f"{stem}.png must still be published"


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_provenance_marks_authority(stem):
    """Provenance must say which outputs are authoritative and which are previews."""
    p = json.load(open(os.path.join(OUT, "figs", f"{stem}.provenance.json")))
    o = p["outputs"]
    assert o["pdf"]["authoritative"] is True
    assert o["data_csv"]["authoritative"] is True
    assert o["png"]["authoritative"] is False
    assert "not guaranteed" in o["png"]["note"]


@pytest.mark.parametrize("stem", FIGURES)
def test_figure_data_csv_uses_lf_endings(stem):
    """CRLF in a generated CSV makes every added line look like trailing whitespace to git."""
    raw = open(os.path.join(OUT, "figs", f"{stem}_data.csv"), "rb").read()
    assert b"\r\n" not in raw, f"{stem}_data.csv uses CRLF line endings"


def test_retired_figure_is_not_published():
    """fig_budget_cost pooled the two anchors and was replaced; it must not still be shipped."""
    assert not os.path.exists(os.path.join(PUB_FIGS, "fig_budget_cost.pdf"))


# ----------------------------------------------------------------- environment
def test_environment_recorded():
    p = os.path.join(OUT, "environment.json")
    if not os.path.exists(p):
        pytest.skip("environment.json not present (run reproduce.sh)")
    env = json.load(open(p))
    for k in ("python_version", "dependencies", "platform", "git_commit",
              "deterministic_seeds"):
        assert k in env and env[k] is not None
    assert env["python_version"].startswith("3.13")
    for dep in ("numpy", "scipy", "scikit-learn", "matplotlib", "joblib"):
        assert dep in env["dependencies"]


def test_lockfile_committed():
    assert os.path.exists(os.path.join(HERE, "uv.lock")), "uv.lock must be committed"


def test_reproduce_uses_frozen_sync():
    src = open(os.path.join(HERE, "reproduce.sh")).read()
    assert "uv sync --frozen --python 3.13" in src
    assert "publication_gate.py" in src, "reproduce.sh must run the publication gate"
