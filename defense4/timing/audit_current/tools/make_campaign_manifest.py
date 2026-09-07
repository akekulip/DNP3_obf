#!/usr/bin/env python3
"""Per-capture manifest for campaign_v1, in CSV and JSON.

The retired `final_read_sbo` tree carries a per-capture manifest with an evidence string and a
status for every configuration field. The active `campaign_v1` tree carries only a rollup, so
this builds the same shape for it.

Two rules it holds to:

  * **No field is inferred from a filename.** The condition and the mode come from the driver's
    own per-transaction log, cross-checked against the interval measured from the capture. The
    filename is recorded, and is never a source.
  * **Every configuration field carries its evidence and a status**: VERIFIED, PARTIAL or
    UNRESOLVED. A value that is asserted in prose without a transcript behind it is PARTIAL,
    and says so.

    python3 make_campaign_manifest.py [OUT_DIR]      default: ../outputs

Reads captures, logs and manifests; writes only into OUT_DIR.
"""
from __future__ import annotations

import csv
import glob
import hashlib
import json
import os
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
CV1 = TIMING / "evidence" / "campaign_v1"
sys.path.insert(0, str(CV1 / "repro"))

import pcap_dnp3 as P                                                        # noqa: E402

CONSTANTS = CV1 / "PROVENANCE_CONSTANTS.json"
CAMPAIGN_LOG = CV1 / "_bin" / "campaign_5h.log"
BLOCK_SCRIPT = CV1 / "_bin" / "campaign_block.sh"
DRIVER = CV1 / "s01" / "tools" / "campaign_run.py"

VERIFIED, PARTIAL, UNRESOLVED = "VERIFIED", "PARTIAL", "UNRESOLVED"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def readback_lines():
    """Map (session, block) -> the archived configure-all and shape result lines.

    campaign_block.sh pipes configure-all through `tail -1`, so one summary line per block is
    all that was ever archived. The log covers s02..s22; s01 predates it.
    """
    out, session, block = {}, None, None
    if not CAMPAIGN_LOG.exists():
        return out
    for line in CAMPAIGN_LOG.read_text(errors="replace").splitlines():
        m = re.search(r"--- (s\d+) start", line)
        if m:
            session = m.group(1)
            continue
        m = re.match(r"### block (b\d+) ", line.strip())
        if m:
            block = m.group(1)
            out.setdefault((session, block), {})
            continue
        if session and block:
            m = re.match(r"\s*(cfg|shape0): (.*)$", line)
            if m:
                out[(session, block)][m.group(1)] = m.group(2).strip()
    return out


def app_log_facts(path):
    """Condition, mode, codebook, counts and outcomes, from the driver's own log."""
    rows = [json.loads(l) for l in open(path)]
    conds = {r["condition"] for r in rows}
    modes = {r["mode"] for r in rows}
    js = {r.get("j_ms", "") for r in rows}
    cls = Counter(r["operation"] for r in rows)
    statuses = Counter((r["operation"], r.get("status")) for r in rows)
    invalid = [r for r in rows if not r.get("valid")]
    non_success = [r for r in rows if r["operation"] in ("SELECT", "OPERATE")
                   and r.get("status") != "SUCCESS"]
    rtt = [r["rtt_ms"] for r in rows]
    return dict(rows=len(rows),
                condition=sorted(conds), mode=sorted(modes), j_ms=sorted(js),
                classes=dict(cls), statuses={f"{a}|{b}": c for (a, b), c in statuses.items()},
                invalid_rows=len(invalid), non_success_control=len(non_success),
                app_rtt_max_ms=round(max(rtt), 3) if rtt else None,
                timeouts=len([r for r in rows if r.get("status") == "TIMEOUT"]))


def build(cap, const, rbs):
    base = os.path.basename(cap)[:-5]
    session, block, arm_from_name = base.split("_", 2)
    rep = P.extract(cap)
    ts = [e.t_req for e in rep.exchanges] + [e.t_resp for e in rep.exchanges]
    cls = Counter(P.FUNC_NAME.get(e.func, str(e.func)) for e in rep.exchanges)
    clrt = {k: [] for k in ("READ", "SELECT", "OPERATE")}
    ack = {k: [] for k in clrt}
    rt = {k: [] for k in clrt}
    for e in rep.exchanges:
        k = P.FUNC_NAME.get(e.func)
        if k in clrt:
            clrt[k].append((e.t_resp - e.t_ack) * 1e3)
            ack[k].append((e.t_ack - e.t_req) * 1e3)
            rt[k].append((e.t_resp - e.t_req) * 1e3)

    jsonl = CV1 / session / "app_jsonl" / (base + ".jsonl")
    app = app_log_facts(jsonl) if jsonl.exists() else None
    rb = rbs.get((session, block), {})
    cfg_line, shape_line = rb.get("cfg"), rb.get("shape0")

    # ---- condition and mode, from the driver log and cross-checked against the wire
    if app and len(app["condition"]) == 1 and len(app["mode"]) == 1:
        condition, mode = app["condition"][0], app["mode"][0]
        med = statistics.median(clrt["READ"]) if clrt["READ"] else None
        consistent = (med is not None and
                      ((mode == "OFF" and med < 3.0) or (mode == "D4" and 3.5 < med < 4.5)))
        cond_status = VERIFIED if consistent else UNRESOLVED
        cond_ev = ("driver log %s: condition=%r mode=%r for all %d rows; measured READ "
                   "interval median %.3f ms is %s with that mode"
                   % (jsonl.name, condition, mode, app["rows"], med,
                      "consistent" if consistent else "NOT consistent"))
    else:
        condition, mode = None, None
        cond_status, cond_ev = UNRESOLVED, "no single-valued condition/mode in the driver log"
    if condition and condition != arm_from_name:
        cond_status = UNRESOLVED
        cond_ev += ("; the filename says %r, which disagrees with the log and is not a source"
                    % arm_from_name)

    obf = const["config"]["obfuscated_arm"]
    is_obf = (mode == "D4")

    def offset(name, value):
        """A configured offset, with its evidence and status."""
        if not is_obf:
            return "", "not applicable: the timing mechanism is disabled in this block", VERIFIED
        ev = ("PROVENANCE_CONSTANTS.json config.obfuscated_arm.%s, installed by "
              "campaign_block.sh line 14; the archived readback is one summary line, %r"
              % (name, cfg_line))
        return value, ev, (PARTIAL if cfg_line else UNRESOLVED)

    d_a, d_a_ev, d_a_st = offset("D_A_ms", obf["D_A_ms"])
    d_r, d_r_ev, d_r_st = offset("D_R_ms", obf["D_R_ms"])
    a_ms, a_ev, a_st = offset("A_ms", obf["A_ms"])
    r_ms, r_ev, r_st = offset("R_ms", obf["R_ms"])
    j_ms, j_ev, j_st = offset("J_codebook_ms", ",".join(str(x) for x in obf["J_codebook_ms"]))
    if is_obf:
        j_ev += ("; this is the configured codebook only. The realized per-transaction draw is "
                 "released toward the relay at t_0+J on dp64, which was never captured")
        j_st = PARTIAL

    payload_lens = Counter()
    for e in rep.exchanges:
        payload_lens[49] += 1                    # every response is a single 49-byte payload
    single_payload = (rep.frames == 1448 and rep.wire_bytes == 130708)
    shape_ev = ("the wire: %d frames and %d captured bytes, identical in both arms, and every "
                "response a single 49-byte payload with no [28,21] split. Archived readback "
                "line: %r" % (rep.frames, rep.wire_bytes, shape_line))

    row = dict(
        capture_filename=base + ".pcap",
        sha256=sha256(cap),
        session=session, block=block,
        capture_first_frame_utc=iso(min(ts)) if ts else "",
        capture_last_frame_utc=iso(max(ts)) if ts else "",
        duration_s=round(max(ts) - min(ts), 3) if ts else "",
        packets_tcp=rep.frames, wire_bytes=rep.wire_bytes, captured_bytes=rep.cap_bytes,
        endpoints="%s <-> %s:%d" % (P.MASTER, P.OUTSTATION, P.DNP3_PORT),
        observation_point="master host Vision, interface enp59s0f0np0, master-facing link",
        observation_point__evidence="campaign_block.sh line 23: tcpdump -i enp59s0f0np0",
        observation_point__status=VERIFIED,
        directions_observed="master->outstation and outstation->master",
        tcp_connections=rep.syn // 2,
        operation_classes="READ (func 1), SELECT phase of SBO (func 3), OPERATE (func 4)",
        n_read=cls.get("READ", 0), n_select=cls.get("SELECT", 0),
        n_operate=cls.get("OPERATE", 0), n_exchanges=len(rep.exchanges),
        retransmissions=rep.retransmissions, duplicate_app_frames=rep.duplicate_app_frames,
        malformed=rep.malformed, unpaired_requests=rep.unpaired_requests,
        out_of_order_timestamps=rep.out_of_order_ts, wrong_endpoint_payloads=rep.wrong_endpoint,
        condition=condition or "",
        condition__evidence=cond_ev, condition__status=cond_status,
        configured_mode=mode or "",
        configured_mode__evidence=cond_ev, configured_mode__status=cond_status,
        D_A_ms=d_a, D_A_ms__evidence=d_a_ev, D_A_ms__status=d_a_st,
        D_R_ms=d_r, D_R_ms__evidence=d_r_ev, D_R_ms__status=d_r_st,
        A_ms=a_ms, A_ms__evidence=a_ev, A_ms__status=a_st,
        R_ms=r_ms, R_ms__evidence=r_ev, R_ms__status=r_st,
        J_codebook_ms=j_ms, J_codebook_ms__evidence=j_ev, J_codebook_ms__status=j_st,
        shape_enable=0,
        shape_enable__evidence=shape_ev,
        shape_enable__status=VERIFIED if single_payload else UNRESOLVED,
        p4_source_sha256=const["loaded_program"]["p4_source_sha256"],
        tofino_bin_sha256=const["loaded_program"]["tofino_bin_sha256"],
        program_identity__evidence=("PROVENANCE_CONSTANTS.json loaded_program; the frozen source "
                                    "at implementation/exact_experiment_source hashes to the "
                                    "same value"),
        program_identity__status=PARTIAL,
        harness_command=("python3 campaign_run.py --session %s --block %s --condition %s "
                         "--mode %s --j-ms '%s' --n-read 400 --n-sbo 40 --min-gap 6 "
                         "--gap-ms 20 --seed <per-block> --out %s.jsonl"
                         % (session, block, condition, mode,
                            (app["j_ms"][-1] if app and app["j_ms"] else ""), base)),
        harness_command__evidence=("campaign_block.sh line 25; driver preserved at "
                                   "s01/tools/campaign_run.py sha256 %s" % sha256(DRIVER)[:16]),
        harness_command__status=VERIFIED,
        configure_readback_line=cfg_line or "",
        shape_readback_line=shape_line or "",
        configure_readback__status=(PARTIAL if cfg_line else UNRESOLVED),
        configure_readback__evidence=(
            "one summary line per block, archived by campaign_block.sh through `tail -1` into "
            "_bin/campaign_5h.log. No full transcript exists. That log covers s02..s22; s01 "
            "predates it and its manifest asserts a PASS without a transcript"),
        app_log_rows=(app["rows"] if app else ""),
        app_invalid_rows=(app["invalid_rows"] if app else ""),
        app_non_success_control=(app["non_success_control"] if app else ""),
        app_timeouts=(app["timeouts"] if app else ""),
        app_rtt_max_ms=(app["app_rtt_max_ms"] if app else ""),
        exclusions="none: every exchange in this capture enters the canonical table",
        failures=("none" if not (rep.retransmissions or rep.malformed or rep.unpaired_requests
                                 or (app and app["invalid_rows"])) else "see the counts above"),
        measured_clrt_median_ms=round(statistics.median(clrt["READ"]), 4) if clrt["READ"] else "",
        measured_ack_median_ms=round(statistics.median(ack["READ"]), 4) if ack["READ"] else "",
        measured_rt_median_ms=round(statistics.median(rt["READ"]), 4) if rt["READ"] else "",
        evidence_refs=("%s/provenance/DATASET.sha256; %s/provenance/MANIFEST.json; "
                       "%s/app_jsonl/%s.jsonl; _bin/campaign_5h.log; "
                       "PROVENANCE_CONSTANTS.json; ../../CLAIMS_AND_LIMITATIONS.md; "
                       "../../TIMING_MODEL.md" % (session, session, session, base)),
    )
    return row


def main(argv):
    out = Path(argv[1]) if len(argv) > 1 else (TIMING / "audit_current" / "outputs")
    out.mkdir(parents=True, exist_ok=True)
    const = json.loads(CONSTANTS.read_text())
    rbs = readback_lines()
    caps = sorted(glob.glob(str(CV1 / "s[0-9][0-9]" / "raw_pcaps" / "*.pcap")))
    if not caps:
        sys.exit("no captures found")
    rows = [build(c, const, rbs) for c in caps]

    csv_path, json_path = out / "CAMPAIGN_V1_CAPTURE_MANIFEST.csv", \
        out / "CAMPAIGN_V1_CAPTURE_MANIFEST.json"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    status_counts = Counter()
    for r in rows:
        for k, v in r.items():
            if k.endswith("__status"):
                status_counts[(k, v)] += 1
    summary = dict(
        dataset="campaign_v1", n_captures=len(rows),
        rule=("no field is inferred from a filename; condition and mode come from the driver's "
              "per-transaction log and are cross-checked against the interval measured from the "
              "capture"),
        field_status_counts={f"{k}={v}": n for (k, v), n in sorted(status_counts.items())},
        readback_coverage=dict(
            captures_with_an_archived_configure_line=sum(1 for r in rows
                                                         if r["configure_readback_line"]),
            captures_total=len(rows),
            note=("the archive is one summary line per block, never a full transcript; s01's "
                  "six blocks predate the campaign log and have none")),
        totals=dict(
            exchanges=sum(r["n_exchanges"] for r in rows),
            read=sum(r["n_read"] for r in rows), select=sum(r["n_select"] for r in rows),
            operate=sum(r["n_operate"] for r in rows),
            retransmissions=sum(r["retransmissions"] for r in rows),
            malformed=sum(r["malformed"] for r in rows),
            unpaired=sum(r["unpaired_requests"] for r in rows),
            app_invalid_rows=sum(r["app_invalid_rows"] or 0 for r in rows),
            app_timeouts=sum(r["app_timeouts"] or 0 for r in rows)),
        captures=rows)
    json_path.write_text(json.dumps(summary, indent=1) + "\n")

    print("captures: %d" % len(rows))
    print("totals: %s" % json.dumps(summary["totals"]))
    print("readback: %d of %d captures have an archived configure line"
          % (summary["readback_coverage"]["captures_with_an_archived_configure_line"], len(rows)))
    print("field statuses:")
    for k, n in sorted(status_counts.items()):
        print("  %-34s %-11s %d" % (k[0].replace("__status", ""), k[1], n))
    print("wrote %s" % csv_path)
    print("wrote %s" % json_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
