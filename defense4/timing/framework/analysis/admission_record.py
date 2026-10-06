"""Assemble the admission inputs for the response-ready candidate from evidence files only, with the provenance each number really has, and run
defense4/timing/active_control/delay_admission.evaluate on them. Nothing is estimated here: a quantity with no measurement on this build is marked UNAVAILABLE or
INHERITED, and the module decides what that is worth. Usage: admission_record.py OUT.json"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "size"))
import rrc  # noqa: E402
from defense4.timing.active_control import delay_admission as da  # noqa: E402

RES = Path(__file__).resolve().parents[1] / "results"
CONN, BUILD = "vision-sel751-20000", "defense4_timing-df5991016285"
CTX = da.PolicyContext(connection_id=CONN, build_id=BUILD)
P = da.Provenance
APP = lambda direction="", timer="": da.Applicability(connection_id=CONN, build_id=BUILD, direction=direction, timer=timer)   # noqa: E731


def smoke():
    pk = [(t, rrc.parse(r)) for t, r in rrc.read_records(RES / "hw_smoke_20261006/cand_off_30/traffic.pcapng")]
    pk = [(t, p) for t, p in pk if p]
    rows = []
    for ts, rq in [(t, p) for t, p in pk if p.dport == 20000 and p.payload]:
        end = rq.seq + len(rq.payload)
        a = next((t for t, p in pk if p.sport == 20000 and not p.payload and p.ack == end and t >= ts), None)
        r = next((t for t, p in pk if p.sport == 20000 and p.payload and p.ack == end and t >= ts), None)
        if a and r:
            rows.append(((a - ts) / 1e6, (r - ts) / 1e6, (r - a) / 1e6))
    return rows


def build(hold_ms, gap_ms=1.0):
    rows = smoke()
    rto = json.loads((RES / "master_rto_20261006/master_rto_cand_20261006.json").read_text())
    idle = rto["tcp_info_idle"]
    obs = "2026-10-06T17:05:00Z"

    def bound(name, v, prov, src, applies=None, at=obs):
        return da.Bound(name=name, value_ms=v, provenance=prov, source=src, observed_at=at, applies_to=applies)
    smoke_src = "framework/results/hw_smoke_20261006/cand_off_30 (31 exchanges, candidate loaded, release block disabled)"
    return da.AdmissionInputs(
        d_a_ms=hold_ms, clrt_new_ms=gap_ms,
        master_rto_ms=bound("master_rto_ms", idle["rto_us"] / 1000, P.MEASURED_THIS_CONNECTION,
                            "framework/results/master_rto_20261006 (TCP_INFO rto on the DNP3 socket; first repeat on the wire at 204.4 ms)",
                            APP("master_to_outstation", "master_rto")),
        outstation_rto_ms=bound("outstation_rto_ms", 3000.0, P.MEASURED_OTHER_SETTING,
                                "2026-09-15 relay measurement (about 3 s), frozen program, outstation-to-master direction", None, "2026-09-15T00:00:00Z"),
        application_deadline_ms=bound("application_deadline_ms", 500.0, P.OPERATOR_SUPPLIED, "the driver's per-transaction budget (--budget-ms 500)"),
        clrt_original_ms=bound("clrt_original_ms", min(r[2] for r in rows), P.MEASURED_THIS_CONNECTION, smoke_src + ": smallest native CLRT", APP()),
        master_feedback_path_ms=bound("master_feedback_path_ms", (idle["rtt_us"] + 4 * idle["rttvar_us"]) / 1000, P.MEASURED_THIS_CONNECTION,
                                      "TCP_INFO rtt + 4 rttvar on the idle DNP3 socket (includes the outstation's ACK latency, so an upper bound)",
                                      APP("master_to_outstation")),
        outstation_feedback_path_ms=bound("outstation_feedback_path_ms", None, P.UNAVAILABLE,
                                          "needs a relay-facing observation point; none exists", None),
        native_request_to_response_ms=bound("native_request_to_response_ms", max(r[1] for r in rows), P.MEASURED_THIS_CONNECTION,
                                            smoke_src + ": largest request-to-response", APP()),
        ack_latency_bound_ms=bound("ack_latency_bound_ms", max(r[0] for r in rows), P.MEASURED_THIS_CONNECTION,
                                   smoke_src + ": largest request-to-ACK at the master port", APP()),
        detect_ms=bound("detect_ms", None, P.UNAVAILABLE, "no instrumented measurement on this build (the 2026-09-15 value is from the frozen build)", None),
        release_tail_ms=bound("release_tail_ms", None, P.UNAVAILABLE, "no instrumented measurement on this build (2026-09-15: 1.705 us, frozen build)", None),
        safety_margin_ms=3.0, policy_cap_ms=40.0, context=CTX)


if __name__ == "__main__":
    hold = 18000 * 1711 / 1e6                                        # the watchdog horizon, the worst-case hold (profiles.hold_bound_ms)
    inp = build(hold)
    v = da.evaluate(inp)
    Path(sys.argv[1]).write_text(json.dumps(v, indent=1, default=str))
    print("verdict:", v["verdict"])
    for c in v.get("checks", []):
        print(" ", "ok " if c.get("ok") else "NOT", c.get("constraint"), "|", str(c.get("detail", ""))[:150])
    for k in ("problems", "input_errors", "substitutions", "statement"):
        if v.get(k):
            print(k + ":", json.dumps(v[k], default=str)[:600])
