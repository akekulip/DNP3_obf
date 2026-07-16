"""phase02_normalize_experiment.py -- Phase 02 combined-response timing normalization.

Exercises the EXISTING normalization mechanism (timing_policy.py native/fixed/bounded via
split_server.py) over the request-aware replay, and measures it end-to-end on loopback.
Per transaction it records the server-side timing decision (selected target, added hold,
visible delay, deadline miss, bypass, queue depth) from the server's timing_decisions.jsonl
AND the client-observed visible request->response time (time-to-first-byte) plus byte
identity.

SCOPE / HONESTY: this is a LOOPBACK, application-level measurement. It verifies the
mechanism, byte preservation, and that the visible request->response time tracks the target
and decorrelates from response size. It is NOT a sniffer PCAP: separate-vs-combined ACK
after normalization and exact wire timestamps require packet capture (unavailable on this
host: dumpcap is not group-executable for this user) or the two-host rig. Those remain the
Phase 02 open items. No timing/ACK/split code is modified here.

    python3 phase02_normalize_experiment.py --reps 30
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests"))
import loopback_smoke as LS          # noqa: E402  (driving helpers: load_groups/wait_listening/recv_exact)
import phase01_stats as st           # noqa: E402
import run_manifest                  # noqa: E402

HARNESS = os.path.dirname(os.path.abspath(__file__))

# (label, delivery, timing_args, expect_bypass)
CONFIGS = [
    ("native/full", "full", ["--timing-mode", "native"], False),
    ("fixed25/full", "full", ["--timing-mode", "fixed", "--target-delay-ms", "25"], False),
    # NOTE: bounded configs get a UNIQUE per-repetition timing seed injected at run time
    # (rep_seed below). A fixed --timing-seed here would reset the PRNG in every server
    # subprocess and couple the target to transaction position -- the Phase 02 defect fixed
    # in this closeout.
    ("bounded20-30/full", "full",
     ["--timing-mode", "bounded", "--target-min-ms", "20", "--target-max-ms", "30"], False),
    ("native/crc-split", "crc-boundary", ["--timing-mode", "native"], False),
    ("fixed25/crc-split", "crc-boundary", ["--timing-mode", "fixed", "--target-delay-ms", "25"], False),
    ("bounded20-30/crc-split", "crc-boundary",
     ["--timing-mode", "bounded", "--target-min-ms", "20", "--target-max-ms", "30"], False),
    # fail-open: a target above the RTO-safe bound must bypass (send immediately)
    ("fixed300-rto105/full (bypass)", "full",
     ["--timing-mode", "fixed", "--target-delay-ms", "300", "--rto-safe-ms", "105"], True),
]


def rep_seed(run_seed: int, config_idx: int, rep_idx: int) -> int:
    """Deterministic, unique PRNG seed per (run_seed, config, repetition).

    Depends ONLY on the top-level run seed, the config index, and the repetition index --
    never on request/response size, function code, device identity, or native time. Two runs
    with the same run_seed reproduce the whole target sequence; a different run_seed changes
    it. Because the seed varies per repetition, a given transaction position no longer maps
    to a fixed target across repetitions.
    """
    h = (int(run_seed) & 0xFFFFFFFF) * 2654435761
    h = (h + (config_idx + 1) * 40503 + (rep_idx + 1) * 2246822519) & 0x7FFFFFFF
    return h


def run_rep(port: int, delivery: str, timing_args: List[str], log_dir: str) -> List[dict]:
    """Launch the server, drive one exchange, merge client + server-side records."""
    cmd = [sys.executable, os.path.join(HARNESS, "split_server.py"),
           "--host", LS.HOST, "--port", str(port), "--delivery", delivery,
           "--replay-dir", "payloads/replay", "--log-dir", log_dir,
           "--request-timeout-sec", "8", "--hold-after-response-sec", "1"] + timing_args
    proc = subprocess.Popen(cmd, cwd=HARNESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conn = LS.wait_listening(proc, port)
    if not conn:
        proc.kill()
        raise RuntimeError("server did not come up on port %d" % port)

    client = []
    groups = LS.load_groups()
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for req, expected in groups:
            t_send = time.monotonic_ns()
            conn.sendall(req)
            data, t_first = LS.recv_exact(conn, len(expected), time.time() + 6.0)
            visible_ms = ((t_first - t_send) / 1e6) if t_first else None
            client.append({"resp_len": len(expected), "recv_len": len(data),
                           "byte_identical": data == expected,
                           "client_visible_ms": round(visible_ms, 4) if visible_ms else None})
    finally:
        conn.close()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()

    # read the server-side timing decisions for this rep
    server = []
    jpath = os.path.join(log_dir, "timing_decisions.jsonl")
    if os.path.exists(jpath):
        with open(jpath) as fh:
            server = [json.loads(ln) for ln in fh if ln.strip()]

    merged = []
    for i, c in enumerate(client):
        s = server[i] if i < len(server) else {}
        merged.append({**c, "server": s, "txn": i + 1})
    return merged


ROW_COLS = ["config", "delivery", "timing_mode", "rep", "txn", "request_size",
            "response_size", "selected_target_ms", "native_ready_ms", "added_hold_ms",
            "server_visible_ms", "client_visible_ms", "deadline_missed", "bypassed",
            "bypass_reason", "queue_depth", "byte_identical", "recv_len",
            "retransmission_count", "ack_mode_pcap", "dnp3_success"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reps", type=int, default=30, help="reps per config (>=30 per plan)")
    ap.add_argument("--run-seed", type=int, default=20260716,
                    help="top-level run seed; per-rep bounded seeds derive from it (recorded)")
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--out-dir", default=HARNESS)
    ap.add_argument("--start-port", type=int, default=20200)
    args = ap.parse_args()

    import scapy  # noqa: F401
    scapy_version = getattr(scapy, "__version__", "present")

    inputs = [os.path.join(HARNESS, "payloads", "replay", "metadata.json")]
    try:
        run = run_manifest.RunContext.start(
            phase="phase_02", short_name="combined_timing_normalization",
            inputs=inputs, argv=sys.argv, run_dir=args.run_dir, base_dir=args.out_dir,
            config=vars(args), extra_tool_versions={"scapy": scapy_version,
                                                    "pcap_capture": "UNAVAILABLE (dumpcap not group-exec; no rig)"})
    except run_manifest.RunDirectoryError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2

    tables = run.subdir("tables")
    reports = run.subdir("reports")
    run.subdir("logs")
    stdout_log = open(os.path.join(run.run_dir, "stdout.log"), "w")

    def emit(m):
        print(m); stdout_log.write(m + "\n"); stdout_log.flush()

    emit("Phase 02 run: %s  (reps=%d, run_seed=%d)" % (run.run_id, args.reps, args.run_seed))
    emit("PCAP capture UNAVAILABLE this host -> loopback application-level measurement only")

    all_rows: List[dict] = []
    port = args.start_port
    for cfg_idx, (label, delivery, targs, expect_bypass) in enumerate(CONFIGS):
        mode = targs[targs.index("--timing-mode") + 1]
        for rep in range(args.reps):
            # bounded gets a UNIQUE per-rep seed so target != f(position); native/fixed ignore it
            targs_rep = list(targs)
            if mode == "bounded":
                targs_rep += ["--timing-seed", str(rep_seed(args.run_seed, cfg_idx, rep))]
            # cfg_idx makes the log dir UNIQUE per config: two configs with the same mode
            # prefix (e.g. bounded/full and bounded/crc-split) must not share a dir, or the
            # server's append-mode timing_decisions.jsonl would cross-contaminate.
            log_dir = os.path.join(run.run_dir, "logs", "cfg%02d_%s_rep%03d" % (
                cfg_idx, label.split("/")[0].split(" ")[0], rep))
            try:
                merged = run_rep(port, delivery, targs_rep, log_dir)
            except Exception as exc:  # noqa: BLE001 - record the failure, keep going
                emit("  %-26s rep %d ERROR: %s" % (label, rep, exc))
                port += 1
                continue
            port += 1
            for m in merged:
                s = m["server"]
                all_rows.append({
                    "config": label, "delivery": delivery, "timing_mode": mode, "rep": rep,
                    "txn": m["txn"], "request_size": s.get("request_size"),
                    "response_size": m["resp_len"],
                    "selected_target_ms": s.get("selected_target_delay_ms"),
                    "native_ready_ms": s.get("native_ready_delay_ms"),
                    "added_hold_ms": s.get("hold_delay_ms"),
                    "server_visible_ms": s.get("visible_delay_ms"),
                    "client_visible_ms": m["client_visible_ms"],
                    "deadline_missed": s.get("deadline_missed"),
                    "bypassed": s.get("bypassed"), "bypass_reason": s.get("bypass_reason"),
                    "queue_depth": s.get("queue_depth"),
                    "byte_identical": m["byte_identical"], "recv_len": m["recv_len"],
                    "retransmission_count": "na_no_pcap",
                    "ack_mode_pcap": "not_captured",
                    "dnp3_success": m["byte_identical"],   # byte-identity proxy (no real DNP3 master here)
                })
        # per-config progress line
        cfg_rows = [r for r in all_rows if r["config"] == label]
        big = [r for r in cfg_rows if r["response_size"] == 2407]
        vis = [r["client_visible_ms"] for r in big if r["client_visible_ms"] is not None]
        byp = sum(1 for r in cfg_rows if r["bypassed"])
        emit("  %-26s n=%d  READ client-visible med=%s ms  bypassed=%d  bytesOK=%d/%d" % (
            label, len(cfg_rows),
            ("%.2f" % st.describe(vis)["median"]) if vis else "n/a",
            byp, sum(1 for r in cfg_rows if r["byte_identical"]), len(cfg_rows)))

    # write transaction log
    tx_csv = os.path.join(tables, "phase02_transaction_log.csv")
    with open(tx_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ROW_COLS, extrasaction="ignore")
        w.writeheader()
        for r in all_rows:
            w.writerow(r)
    emit("wrote %s (%d rows)" % (os.path.relpath(tx_csv, run.run_dir), len(all_rows)))

    _write_analysis(all_rows, tables, reports, run)
    stdout_log.close()
    run.finish(exit_status=0)
    print("Run manifest:", run.manifest_path)
    print("Run directory:", run.run_dir)
    return 0


def _write_analysis(rows, tables_dir, reports_dir, run):
    import numpy as np
    configs = []
    seen = []
    for r in rows:
        if r["config"] not in seen:
            seen.append(r["config"]); configs.append(r["config"])

    # per-config summary of the big READ (2407B) client-visible time + byte identity + bypass
    summ = {}
    for cfg in configs:
        cr = [r for r in rows if r["config"] == cfg]
        big = [r["client_visible_ms"] for r in cr if r["response_size"] == 2407 and r["client_visible_ms"] is not None]
        summ[cfg] = {
            "n_txns": len(cr),
            "byte_identical_rate": round(sum(1 for r in cr if r["byte_identical"]) / len(cr), 4) if cr else None,
            "bypassed": sum(1 for r in cr if r["bypassed"]),
            "deadline_missed": sum(1 for r in cr if r["deadline_missed"]),
            "read_client_visible_ms": st.describe(big),
            "read_client_visible_ci_median": st.bootstrap_ci(big, "median", seed=12345),
        }
    with open(os.path.join(tables_dir, "phase02_config_summary.json"), "w") as fh:
        json.dump(summ, fh, indent=2)

    # decorrelation: correlation of client-visible time with response_size and native_ready,
    # per timing mode (native vs fixed vs bounded), on the full-delivery configs.
    def corr(xs, ys):
        x = np.array(xs, float); y = np.array(ys, float)
        if x.size < 3 or np.std(x) == 0 or np.std(y) == 0:
            return None
        return round(float(np.corrcoef(x, y)[0, 1]), 4)

    decor = {}
    for cfg in configs:
        cr = [r for r in rows if r["config"] == cfg
              and r["client_visible_ms"] is not None and r["response_size"] is not None]
        vis = [r["client_visible_ms"] for r in cr]
        size = [r["response_size"] for r in cr]
        native = [r["native_ready_ms"] for r in cr if r["native_ready_ms"] is not None]
        vis_n = [r["client_visible_ms"] for r in cr if r["native_ready_ms"] is not None]
        decor[cfg] = {
            "n": len(cr),
            "corr_visible_vs_response_size": corr(size, vis),
            "corr_visible_vs_native_ready": corr(native, vis_n),
        }
    with open(os.path.join(tables_dir, "phase02_decorrelation.json"), "w") as fh:
        json.dump(decor, fh, indent=2)

    # report
    L = ["# Phase 02 — Combined-Response Timing Normalization (loopback measurement)", "",
         "_Run `%s`. Mechanism: existing `timing_policy` native/fixed/bounded via "
         "`split_server`. **Loopback, application-level** measurement — not a sniffer PCAP. "
         "PCAP wire timing and ACK-mode-after-normalization are unavailable on this host "
         "(dumpcap not group-executable; no rig) and remain the open items._" % run.run_id,
         "", "## Per-config summary (big Class-0 READ = 2407 B)",
         "", "| config | n txns | byte-identical | bypassed | deadline miss | READ client-visible med (ms) | CI |",
         "|---|---:|---:|---:|---:|---:|---|"]
    for cfg in configs:
        s = summ[cfg]; d = s["read_client_visible_ms"]; ci = s["read_client_visible_ci_median"]
        med = "n/a" if d["median"] is None else "%.2f" % d["median"]
        cistr = "n/a" if ci["lo"] is None else "[%.2f, %.2f]" % (ci["lo"], ci["hi"])
        L.append("| %s | %d | %.1f%% | %d | %d | %s | %s |" % (
            cfg, s["n_txns"], 100 * (s["byte_identical_rate"] or 0), s["bypassed"],
            s["deadline_missed"], med, cistr))
    L += ["", "## Decorrelation of visible time (client-observed)",
          "Correlation of the visible request→response time with response size and with the "
          "native response-ready delay, per config. Normalization should DROP the "
          "size/native correlation vs native mode.", "",
          "| config | n | corr(visible, resp size) | corr(visible, native-ready) |",
          "|---|---:|---:|---:|"]
    for cfg in configs:
        dd = decor[cfg]
        L.append("| %s | %d | %s | %s |" % (
            cfg, dd["n"],
            "n/a" if dd["corr_visible_vs_response_size"] is None else "%.3f" % dd["corr_visible_vs_response_size"],
            "n/a" if dd["corr_visible_vs_native_ready"] is None else "%.3f" % dd["corr_visible_vs_native_ready"]))
    L += ["", "> Loopback/application-level results. Byte identity and the mechanism are "
          "verified here; whether a normalized target induces a *separate* pure ACK, and the "
          "exact wire timing, require packet capture or the rig — the Phase 02 open items.", ""]
    with open(os.path.join(reports_dir, "phase02_combined_timing_normalization.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
