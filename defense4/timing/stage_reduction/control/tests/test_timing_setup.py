import importlib.util
import json
import os
from pathlib import Path


CONTROL_DIR = Path(__file__).resolve().parents[1]
STAGE_REDUCTION_DIR = CONTROL_DIR.parent
SETUP_PATH = CONTROL_DIR / "defense4_timing_setup.py"
CASEA_PATH = CONTROL_DIR / "defense4_caseA_setup.py"
PARAM_POLICY_PATH = CONTROL_DIR / "parameter_policy.py"
DEFAULT_BFRT_PATH = STAGE_REDUCTION_DIR / "evidence" / "candidate" / "bfrt.json"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_bfrt():
    path = Path(os.environ.get("DNP3_BFRT_JSON", DEFAULT_BFRT_PATH))
    if not path.is_file():
        raise AssertionError(
            "BFRT schema not found at %s. Build the timing candidate and copy its generated "
            "bfrt.json to defense4/timing/stage_reduction/evidence/candidate/bfrt.json, "
            "or set DNP3_BFRT_JSON=/path/to/bfrt.json for this test run." % path
        )
    return json.loads(path.read_text())


def tables_by_short_name(bfrt):
    out = {}
    for table in bfrt["tables"]:
        name = table["name"]
        out[name] = table
        out[name.split(".")[-1]] = table
    return out


def action_by_short_name(table):
    actions = {}
    for action in table.get("action_specs", []):
        name = action["name"]
        actions[name] = action
        actions[name.split(".")[-1]] = action
    return actions


def action_fields(action):
    return {field["name"]: field for field in action.get("data", [])}


def key_fields(table):
    return {field["name"]: field for field in table.get("key", [])}


def test_commit_map_is_timing_only_sparse():
    setup = load_module(SETUP_PATH, "timing_setup_commit")
    chk = setup.Checks()

    setup.verify_commit_map(chk)

    assert chk.n_fail == 0
    assert {12, 32, 34}.isdisjoint(set(setup.COMMIT_MAP))
    assert "cmt_shape" not in set(setup.COMMIT_MAP.values())
    assert set(range(1, 44)) - set(setup.OUT.values()) == {12, 32, 34}


def test_model_configure_has_no_size_or_pre_state():
    setup = load_module(SETUP_PATH, "timing_setup_model")
    args = setup.build_argparser().parse_args(["dry-run"])
    chk = setup.Checks()

    setup.validate_bor_deadlines(args, chk)
    store = setup.model_configure_all(args, chk)

    assert chk.n_fail == 0
    assert chk.n_warn == 0
    assert store.tbl_params == {
        "mode": setup.caseA.MODE["D4"],
        "d_ticks": 20_000_000,
        "da_dr": 24_000_000,
        "read_len": args.read_len,
        "budget": args.budget,
    }
    assert not hasattr(store, "pre_mgid")
    assert not hasattr(store, "pre_node")


def test_sequence_text_names_timing_only_steps():
    setup = load_module(SETUP_PATH, "timing_setup_sequence")
    args = setup.build_argparser().parse_args(["dry-run"])

    text = setup.sequence_text(args)

    assert "pktgen enabled LAST" in text
    assert "tbl_params timing fields only" in text
    assert "shape_enable" not in text
    assert "PRE" not in text


def test_casea_default_program_is_timing_candidate():
    text = CASEA_PATH.read_text()

    assert '--program", default="defense4_timing"' in text


def test_generated_bfrt_tbl_params_interface_keeps_read_len():
    # This proves read_len survived in the compiled BFRT action schema. It does not
    # prove a physical default-entry readback on hardware; that remains a live readback
    # check in defense4_timing_setup.py once the program is loaded.
    bfrt = load_bfrt()
    params = tables_by_short_name(bfrt)["tbl_params"]
    set_params = action_by_short_name(params)["set_params"]
    fields = action_fields(set_params)

    assert set(fields) == {"d_ticks", "read_len", "budget", "mode", "da_dr"}
    assert fields["read_len"]["type"]["width"] == 32
    assert fields["read_len"]["mandatory"] is True
    assert "shape_enable" not in fields


def test_generated_bfrt_matches_setup_programmable_interfaces():
    setup = load_module(SETUP_PATH, "timing_setup_bfrt")
    bfrt = load_bfrt()
    tables = tables_by_short_name(bfrt)

    bor_params = tables["tbl_bor_params"]
    assert key_fields(bor_params) == {}
    assert set(action_fields(action_by_short_name(bor_params)["set_bor_params"])) == {
        "a_ticks",
        "r_ticks",
        "anchor_req",
    }

    codebook = tables["tbl_bor_codebook"]
    codebook_keys = key_fields(codebook)
    assert codebook_keys["hdr.tcp.dst_port"]["match_type"] == "Exact"
    assert codebook_keys["meta.rand8"]["match_type"] == "Range"
    assert codebook_keys["$MATCH_PRIORITY"]["match_type"] == "Exact"
    assert set(action_fields(action_by_short_name(codebook)["set_j"])) == {"j_ticks"}

    session = tables["tbl_session"]
    assert set(key_fields(session)) == {
        "hdr.ipv4.src_addr",
        "hdr.ipv4.dst_addr",
        "hdr.tcp.src_port",
        "hdr.tcp.dst_port",
        "$MATCH_PRIORITY",
    }
    assert {"sess_relay", "sess_master", "sess_none"} <= set(action_by_short_name(session))

    commit = tables["tbl_commit"]
    assert key_fields(commit)["meta.outcome"]["type"]["width"] == 16
    commit_actions = set(action_by_short_name(commit))
    assert set(setup.COMMIT_MAP.values()) <= commit_actions
    assert "cmt_shape" not in commit_actions


def test_generated_bfrt_has_required_state_objects_and_no_size_interfaces():
    bfrt = load_bfrt()
    tables = tables_by_short_name(bfrt)

    for register in (
        "reg_tag",
        "reg_failopen",
        "reg_deadline",
        "reg_tresp",
        "reg_bor_epoch",
        "reg_bor_ready",
        "reg_bor_gen",
        "reg_bor_topj",
        "reg_ack_rel",
        "reg_exp_relay_seq",
        "reg_session_port",
        "reg_exp_ack",
    ):
        table = tables[register]
        assert table["table_type"] == "Register"
        assert key_fields(table)["$REGISTER_INDEX"]["type"]["type"] == "uint32"

    for counter in ("ctr_fresh", "ctr_deq"):
        table = tables[counter]
        assert table["table_type"] == "Counter"
        assert key_fields(table)["$COUNTER_INDEX"]["type"]["type"] == "uint32"

    value_set = tables["pgen_recirc"]
    assert value_set["table_type"] == "ParserValueSet"
    assert key_fields(value_set)["f1"]["match_type"] == "Ternary"
    assert key_fields(value_set)["f1"]["type"]["width"] == 8

    serialized = json.dumps(bfrt)
    assert "shape_enable" not in serialized
    assert "cmt_shape" not in serialized
    assert "RRC_MGID" not in serialized


def test_legacy_parameter_policy_writer_is_disabled_for_five_field_interface():
    policy = load_module(PARAM_POLICY_PATH, "timing_parameter_policy")

    try:
        policy.write_params(None, None, {"ok": True}, None)
    except RuntimeError as exc:
        assert "defense4_timing" in str(exc)
    else:
        raise AssertionError("legacy three-field tbl_params writer must stay disabled")
