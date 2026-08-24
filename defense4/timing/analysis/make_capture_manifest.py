#!/usr/bin/env python3
"""Build CAPTURE_MANIFEST.csv / .json for the timing evidence package.

Measured fields (hashes, times, endpoints, function-code counts, transaction pairing,
segmentation) are computed here from the raw pcaps. Configuration fields (mode, A, R, J,
shape_enable, program hashes, drivers) come from the curated PROVENANCE table below, and
every one of them carries the evidence file that establishes it. Nothing is inferred from
a filename.

Usage:  make_capture_manifest.py <evidence_dir>
"""
import csv, hashlib, json, subprocess, sys, datetime
from pathlib import Path

MASTER, RELAY = "192.168.10.1", "192.168.10.7"
FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}

# --------------------------------------------------------------------------------------
# Curated configuration provenance. Each entry: value + the evidence that establishes it.
# status: VERIFIED | PARTIAL | UNRESOLVED | CONTRADICTED
# --------------------------------------------------------------------------------------
COMMON_EVIDENCE = {
    "p4_source_sha256": (
        "7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861",
        "audit/E0_testbed_preservation.md ('unified P4 source sha256'); independently "
        "reproduced: git blob c1871384:defense4/size/native_parity/p4/"
        "defense4_rrc_bor_unified12.p4 hashes to this value",
        "VERIFIED"),
    "loaded_binary_sha256": (
        "33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa",
        "audit/E0_testbed_preservation.md ('loaded tofino.bin sha256', with matching "
        "'expect' value); build record hw_campaign_20260813T172014Z/h3_prep/compile_v2/"
        "{BUILD_SUMMARY.txt,tofino_bin_sha256.txt}. NOT independently read back at capture "
        "time; the earlier phase8_closeout/final_state.txt (~18:37, before these captures) "
        "records the superseded v1 binary 550b5b97",
        "PARTIAL"),
    "source_git_commit": (
        "c18713840e8376c065909749d451a6bc9e6c5c4d",
        "audit/E0_testbed_preservation.md ('branch/source SHA (repo HEAD)'); commit is "
        "dated 2026-08-13 19:38:27 -0400, 11 minutes before the first capture in this set",
        "VERIFIED"),
    "host": ("Vision (master endpoint)",
             "audit/E0_testbed_preservation.md topology; capture command in the frozen "
             "E_FINAL/README.md is run on the master", "VERIFIED"),
    "interface": ("enp59s0f0np0",
                  "frozen E_FINAL/README.md reproduction line (dumpcap -i enp59s0f0np0). "
                  "Not recorded per-capture in any per-run log", "PARTIAL"),
    "observation_point": (
        "master-facing: on the master host, on the master<->switch link (switch dp9 side)",
        "audit/E0_testbed_preservation.md port map (master = Vision on dp9); the relay-facing "
        "side (dp68) is internal and was not captured", "VERIFIED"),
    "tcp_timestamps": ("0 (disabled)",
                       "audit/E0_testbed_preservation.md; independently confirmed here: no "
                       "TCP timestamp option present on any packet in these captures",
                       "VERIFIED"),
}

PROVENANCE = {
    "e1_native.pcap": {
        "operation_class": "READ (func 1) + SELECT phase of SBO (func 3)",
        "condition": "native",
        "configured_mode": ("OFF (timing defense disabled)",
            "frozen E_FINAL/README.md ('Native baseline (defense OFF timing): configure "
            "--mode OFF'); corroborated by the measured CLRT here (median 1.272 ms READ / "
            "2.120 ms SELECT with std 1.5-3.2 ms), which is incompatible with the 4.001 ms "
            "policy hold observed in every defended capture", "VERIFIED"),
        "A_ms": ("n/a", "BOR OPERATE hold not exercised (no func 4 in this capture)", "VERIFIED"),
        "R_ms": ("n/a", "as above", "VERIFIED"),
        "D_A_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "D_R_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "J_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "shape_enable": ("1 (size carve ACTIVE)",
            "DIRECT OBSERVATION in this capture: every relay response is delivered as two "
            "TCP payloads of 28 and 21 bytes. hw_campaign_20260813T172014Z/tools/shape_set.py "
            "documents 'shape=1 -> responses split [28,21] via PRE; shape=0 -> native "
            "pass-through (no replicas)'. A shape_enable=0 capture of the same relay "
            "(h1a_defoff_100.pcap) shows a single 49-byte payload", "VERIFIED"),
        "driver": ("relay_read_g10_23.py N ; relay_sbo_operate_guarded.py --select-only --count N",
            "frozen E_FINAL/README.md reproduction line. The exact N values were not logged",
            "PARTIAL"),
        "expected_transactions": ("not recorded",
            "no per-run driver log was archived for the E-phase captures", "UNRESOLVED"),
    },
    "e2_def_read.pcap": {
        "operation_class": "READ (func 1)",
        "condition": "defended",
        "configured_mode": ("D4 (timing defense enabled)",
            "frozen E_FINAL/README.md ('Defended: configure --mode D4 --op-a-ms 20 "
            "--op-r-ms 24 --j-set \"<J>\" --read-len 0'); corroborated by the measured CLRT "
            "(median 4.001 ms, std 0.022 ms)", "VERIFIED"),
        "A_ms": ("20 (configured)", "audit/E0_testbed_preservation.md Policies; not exercised "
                 "here (no func 4)", "VERIFIED"),
        "R_ms": ("24 (configured)", "audit/E0_testbed_preservation.md Policies; not exercised "
                 "here (no func 4)", "VERIFIED"),
        "D_A_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "D_R_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "J_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "shape_enable": ("1 (size carve ACTIVE)",
            "DIRECT OBSERVATION: every response delivered as 28+21 byte TCP payloads "
            "(see e1_native.pcap entry for the shape_set.py semantics)", "VERIFIED"),
        "driver": ("relay_read_g10_23.py N", "frozen E_FINAL/README.md", "PARTIAL"),
        "expected_transactions": ("not recorded", "no per-run driver log archived", "UNRESOLVED"),
    },
    "e2_def.pcap": {
        "operation_class": "SELECT phase of SBO (func 3)",
        "condition": "defended",
        "configured_mode": ("D4 (timing defense enabled)",
            "frozen E_FINAL/README.md; corroborated by measured CLRT (median 4.001 ms, "
            "std 0.021 ms)", "VERIFIED"),
        "A_ms": ("20 (configured)", "audit/E0_testbed_preservation.md Policies; not exercised "
                 "here (no func 4)", "VERIFIED"),
        "R_ms": ("24 (configured)", "audit/E0_testbed_preservation.md Policies; not exercised "
                 "here (no func 4)", "VERIFIED"),
        "D_A_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "D_R_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "J_ms": ("n/a", "no OPERATE transactions", "VERIFIED"),
        "shape_enable": ("1 (size carve ACTIVE)", "DIRECT OBSERVATION: 28+21 byte payloads",
                         "VERIFIED"),
        "driver": ("relay_sbo_operate_guarded.py --select-only --count N",
                   "frozen E_FINAL/README.md", "PARTIAL"),
        "expected_transactions": ("not recorded", "no per-run driver log archived", "UNRESOLVED"),
    },
}
for J in (2, 6, 12):
    PROVENANCE["sbo_j%d.pcap" % J] = {
        "operation_class": "SELECT phase of SBO (func 3) + OPERATE (func 4)",
        "condition": "defended",
        "configured_mode": ("D4 (timing defense enabled)",
            "frozen E_FINAL/README.md; corroborated by measured SELECT CLRT ~4.00 ms",
            "VERIFIED"),
        "A_ms": ("20 (configured)",
            "audit/E0_testbed_preservation.md Policies ('A = 20 ms (T0->ACK release)'); the "
            "master-visible A median here is ~21 ms, i.e. configured 20 ms plus a ~1 ms "
            "master-facing path/capture offset (audit/VERDICT.json bor_operate_timing.note)",
            "VERIFIED"),
        "R_ms": ("24 (configured)",
            "audit/E0_testbed_preservation.md Policies ('R = 24 ms (T0->echo release)'); "
            "master-visible R median ~25 ms with the same ~1 ms offset", "VERIFIED"),
        "D_A_ms": ("20 (deadline that releases the ACK, = A)",
            "implementation/control/defense4_rrc_bor_unified12_setup.py A_DEFAULT_TICKS "
            "= 20000000 ns; readbacks/hw_config_readback.txt asserts A quantization and "
            "admissibility", "VERIFIED"),
        "D_R_ms": ("24 (deadline that releases the echo, = R)",
            "implementation/control/defense4_rrc_bor_unified12_setup.py R_DEFAULT_TICKS "
            "= 24000000 ns; readbacks/hw_config_readback.txt asserts R quantization and "
            "admissibility", "VERIFIED"),
        "J_ms": ("%d (configured codebook value; switch-internal relay-facing release delay)" % J,
            "audit/E0_testbed_preservation.md ('J codebook: fixed passes {2,6,12} ms'); "
            "readbacks/hw_config_readback.txt asserts J[%d] stored without quantizing to 0. "
            "J was NOT observed on the relay-facing wire: dp68 is an internal pktgen/recirc "
            "port with no host-capturable tap" % J,
            "PARTIAL"),
        "shape_enable": ("1 (size carve ACTIVE)", "DIRECT OBSERVATION: 28+21 byte payloads",
                         "VERIFIED"),
        "driver": ("relay_sbo_operate_guarded.py (guarded SELECT->OPERATE, points {1,3})",
            "frozen E_FINAL/README.md and hw_campaign_20260813T172014Z/h3_operate/"
            "h3_operate_result.md (guarded {1,3} RB02/RB04, index 6 hard-refused)", "PARTIAL"),
        "expected_transactions": ("30 OPERATE (design intent)",
            "audit/VERDICT.json size.defended_SBO.n_per_J = 60 responses = 30 SELECT + 30 "
            "OPERATE per J", "VERIFIED"),
    }


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tshark_rows(pcap):
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src",
         "-e", "tcp.len", "-e", "tcp.flags", "-e", "tcp.payload", "-e", "tcp.options.timestamp.tsval",
         "-Y", "tcp"], capture_output=True, text=True, check=True).stdout
    rows = []
    for ln in out.splitlines():
        f = (ln.split("\t") + [""] * 6)[:6]
        if not f[0] or not f[1]:
            continue
        rows.append((float(f[0]), f[1], int(f[2] or 0), int(f[3], 16),
                     f[4].replace(":", ""), f[5]))
    return rows


def dnp3_func(hexpayload):
    if not hexpayload:
        return None
    b = bytes.fromhex(hexpayload)
    return b[12] if len(b) >= 13 and b[0] == 0x05 and b[1] == 0x64 else None


def measure(pcap):
    ev = tshark_rows(pcap)
    req_counts, paired, no_ack, no_resp = {}, {}, {}, {}
    seg_lens, has_ts = {}, False
    cold_first = True
    cold_rows = 0
    for i, (t, src, ln, fl, hx, ts) in enumerate(ev):
        if ts:
            has_ts = True
        if src == RELAY and ln > 0:
            seg_lens[ln] = seg_lens.get(ln, 0) + 1
        if src != MASTER:
            continue
        if fl & 0x02:
            cold_first = True
        f = dnp3_func(hx)
        if f not in FUNC:
            continue
        req_counts[f] = req_counts.get(f, 0) + 1
        if cold_first:
            cold_rows += 1
            cold_first = False
        t_ack = t_resp = None
        for (tt, s2, l2, f2, h2, _ts2) in ev[i + 1:]:
            if s2 != RELAY:
                continue
            if (f2 & 0x10) and t_ack is None:
                t_ack = tt
            if dnp3_func(h2) == 0x81 and t_resp is None:
                t_resp = tt
                break
        if t_ack is not None and t_resp is not None:
            paired[f] = paired.get(f, 0) + 1
        elif t_ack is None:
            no_ack[f] = no_ack.get(f, 0) + 1
        else:
            no_resp[f] = no_resp.get(f, 0) + 1
    t0, t1 = ev[0][0], ev[-1][0]
    fmt = lambda e: datetime.datetime.fromtimestamp(
        e, datetime.timezone(datetime.timedelta(hours=-4))).isoformat()
    return {
        "capture_start_local_utc_minus_4": fmt(t0),
        "capture_end_local_utc_minus_4": fmt(t1),
        "capture_start_epoch": "%.6f" % t0,
        "duration_s": "%.3f" % (t1 - t0),
        "packets_tcp": len(ev),
        "endpoints": "%s <-> %s:20000" % (MASTER, RELAY),
        "requests_by_func": {FUNC[k]: v for k, v in sorted(req_counts.items())},
        "extracted_transactions": {FUNC[k]: v for k, v in sorted(paired.items())},
        "unmatched_missing_ack": {FUNC[k]: v for k, v in sorted(no_ack.items())},
        "unmatched_missing_response": {FUNC[k]: v for k, v in sorted(no_resp.items())},
        "cold_start_rows_flagged": cold_rows,
        "response_payload_len_histogram": {str(k): v for k, v in sorted(seg_lens.items())},
        "tcp_timestamp_option_present": has_ts,
    }


def main():
    root = Path(sys.argv[1]).resolve()
    raw = root / "raw_pcaps"
    recs = []
    for name in ["e1_native.pcap", "e2_def_read.pcap", "e2_def.pcap",
                 "sbo_j2.pcap", "sbo_j6.pcap", "sbo_j12.pcap"]:
        p = raw / name
        prov = PROVENANCE[name]
        m = measure(p)
        statuses = [v[2] for k, v in prov.items() if isinstance(v, tuple)]
        statuses += [v[2] for v in COMMON_EVIDENCE.values()]
        overall = ("UNRESOLVED" if "UNRESOLVED" in statuses else
                   "PARTIAL" if "PARTIAL" in statuses else "VERIFIED")
        rec = {"filename": name, "sha256": sha256(p)}
        rec.update(m)
        rec["operation_class"] = prov["operation_class"]
        rec["condition_native_or_defended"] = prov["condition"]
        for key in ["configured_mode", "A_ms", "R_ms", "D_A_ms", "D_R_ms", "J_ms",
                    "shape_enable", "driver", "expected_transactions"]:
            val, ev_, st = prov[key]
            rec[key] = val
            rec[key + "__evidence"] = ev_
            rec[key + "__status"] = st
        for key, (val, ev_, st) in COMMON_EVIDENCE.items():
            rec[key] = val
            rec[key + "__evidence"] = ev_
            rec[key + "__status"] = st
        rec["provenance_status"] = overall
        recs.append(rec)

    with open(root / "CAPTURE_MANIFEST.json", "w") as f:
        json.dump({"generated_by": "defense4/timing/analysis/make_capture_manifest.py",
                   "evidence_root": "defense4/timing/evidence/final_read_sbo",
                   "captures": recs}, f, indent=2, sort_keys=False)
        f.write("\n")

    cols = list(recs[0].keys())
    flat = []
    for r in recs:
        row = {}
        for k in cols:
            v = r[k]
            row[k] = json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
        flat.append(row)
    with open(root / "CAPTURE_MANIFEST.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(flat)
    print("wrote CAPTURE_MANIFEST.{csv,json} for %d captures" % len(recs))
    for r in recs:
        print("  %-20s %s  txns=%s" % (r["filename"], r["provenance_status"],
                                       r["extracted_transactions"]))


if __name__ == "__main__":
    main()
