"""Entry point: re-executes itself inside `unshare -Urnm`, then runs one named step and prints JSON."""
import json
import os
import time
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BMV2 = HERE.parent


def compile_p4(name, out):
    src = BMV2 / "p4" / (name + ".p4")
    command=["p4c-bm2-ss", "--std", "p4-16", "-o", str(out / (name + ".json")), str(src)]
    r = subprocess.run(command, capture_output=True, text=True)
    (out / (name + ".compile.log")).write_text(r.stdout+r.stderr)
    (out / (name + ".compile_command.json")).write_text(json.dumps(command,indent=2)+"\n")
    if r.returncode:
        raise RuntimeError("p4c failed:\n" + r.stderr[-1500:])
    return out / (name + ".json")


def step1(lab, work):
    j = compile_p4("step1_forward", work)
    lab.up().start_switch(j)
    lab.cli("table_add dmac fwd 02:00:00:00:00:02 => 1\ntable_add dmac fwd 02:00:00:00:00:01 => 0\n")
    cap_m, cap_o = lab.capture("s0", "master_side.pcap"), lab.capture("s1", "outstation_side.pcap")
    lab.start_outstation(latency_ms=1.0)
    rows = lab.run_master(count=5)
    return {"outcomes": rows, "captures": [str(cap_m), str(cap_o)]}


def counters(lab, name, n):
    import re
    out = {}
    for i in range(n):
        txt = lab.cli("counter_read %s %d" % (name, i))
        m = re.search(r"\((\d+) bytes, (\d+) packets\)", txt)
        out[i] = int(m.group(2)) if m else None
    return out


def frames_by_src(path):
    sys.path.insert(0, str(BMV2.parent / "size"))
    import rrc
    d = {}
    for _, raw in rrc.read_records(path):
        if rrc.parse(raw) is not None:                              # TCP/IPv4 only: link noise is not under test
            d.setdefault(raw[6:12].hex(), []).append(raw)
    return d


def step3(lab, work, count=5):
    j = compile_p4("step3_roles", work)
    lab.up().start_switch(j)
    lab.cli("table_add dmac fwd 02:00:00:00:00:02 => 1\ntable_add dmac fwd 02:00:00:00:00:01 => 0\n")
    cap_m, cap_o = lab.capture("s0", "master_side.pcap"), lab.capture("s1", "outstation_side.pcap")
    lab.start_outstation(latency_ms=1.0)
    rows = lab.run_master(count=count)
    time.sleep(0.5)
    roles = counters(lab, "role_ctr", 8)
    lab.down_captures()
    m, o = frames_by_src(cap_m), frames_by_src(cap_o)
    same = {}
    for src in ("020000000001", "020000000002"):                     # master -> outstation, outstation -> master
        same[src] = sorted(m.get(src, [])) == sorted(o.get(src, []))
    return {"outcomes": [r["outcome"] for r in rows], "role_counters": roles, "bytes_unchanged": same,
            "frames": {k: len(v) for k, v in m.items()}}


def exp_priority(lab, work, rate_cmd="set_queue_rate 200 2"):
    j = compile_p4("exp_priority", work)
    lab.up(loop=True).start_switch(j, "--priority-queues", "2")
    lab.cli(rate_cmd + "\n")
    cap = lab.capture("s1", "out.pcap")
    # 10 frames at the lower-valued priority label first, then 10 at priority 0: who leaves first?
    lab.sh(sys.executable, "-B", str(HERE / "inject.py"), "m0", "02:00:00:00:00:02", "02:00:00:00:00:01", "5678:10", "1234:10", ns="m")
    time.sleep(1.5)
    lab.down_captures()
    sys.path.insert(0, str(BMV2.parent / "size"))
    import rrc
    seen = []
    for ts, raw in rrc.read_records(cap):
        if raw[12:14] in (b"\x12\x34", b"\x56\x78"):
            seen.append((raw[12:14].hex(), int.from_bytes(raw[14:16], "big"), ts))
    return {"order": [(e, n) for e, n, _ in seen], "span_ms": (seen[-1][2] - seen[0][2]) / 1e6 if seen else None}


def setup_policy(lab, mode, da_us, gap_us, budget, loop_pps, shape=0, dropreq=0, padding=0, token_loss=0):
    import re
    cmds = ["table_add dmac fwd 02:00:00:00:00:02 => 1", "table_add dmac fwd 02:00:00:00:00:01 => 0",
            "register_write p_mode 0 %d" % mode, "register_write p_da_us 0 %d" % da_us, "register_write p_gap_us 0 %d" % gap_us,
            "register_write p_budget 0 %d" % budget, "register_write p_shape 0 %d" % shape, "register_write p_mode_e 0 %d" % mode, "register_write p_dropreq 0 %d" % dropreq, "register_write e_budget 0 %d" % budget,
            "register_write p_readiness_us 0 30000",
            "register_write p_padding 0 %d" % padding, "register_write p_token_loss 0 %d" % token_loss,
            "set_queue_rate %d 2" % loop_pps, "mc_mgrp_create 1", "mc_mgrp_create 2"]
    lab.cli("\n".join(cmds) + "\n")
    for calculation in json.loads(lab.program.read_text())["calculations"]:
        if calculation["algo"] == "crc16_custom":
            result = lab.cli("set_crc16_parameters %s 0x3d65 0 0xffff true true" % calculation["name"])
            if "Error" in result:
                raise RuntimeError("DNP3 CRC configuration failed: " + result)
    handles = []
    for rid, port in ((1, 2), (2, 2), (3, 0)):
        out = lab.cli("mc_node_create %d %d" % (rid, port))   # clones: rid 1 = ACK token, rid 2 = response token, rid 3 = generated ACK to the master
        handles.append(int(re.search(r"handle (\d+)", out).group(1)))
    lab.cli("\n".join("mc_node_associate 1 %d" % h for h in handles) + "\nmirroring_add_mc 100 1\n")
    split = []
    for rid in (1, 2):
        out = lab.cli("mc_node_create %d 0" % rid)               # size split: two replicas to the master port, rid 1 prefix, rid 2 suffix
        split.append(int(re.search(r"handle (\d+)", out).group(1)))
    lab.cli("\n".join("mc_node_associate 2 %d" % h for h in split) + "\n")


def events_from_captures(cap_m, cap_o):
    """Per-transaction wire times: request at the master port, ACK/response arrivals from the outstation, and what the
    switch released toward the master. All from kernel timestamps on the two switch-side interfaces."""
    sys.path.insert(0, str(BMV2.parent / "size"))
    import rrc
    M, O = "020000000001", "020000000002"
    reqs, rel = [], []
    for ts, raw in rrc.read_records(cap_m):
        p = rrc.parse(raw)
        if not p:
            continue
        if raw[6:12].hex() == M and p.payload and p.dport == 20000:
            reqs.append((ts, p))
        elif raw[6:12].hex() == O and raw[12:14] == b"\x08\x00":
            rel.append((ts, p))
    arr = [(ts, rrc.parse(raw)) for ts, raw in rrc.read_records(cap_o)]
    arr = [(ts, p) for ts, p in arr if p and p.sport == 20000]
    # the outstation's own packets are the ones it SENT toward the switch: frames at s1 from mac O
    sent = [(ts, p) for ts, p in ((ts, rrc.parse(raw)) for ts, raw in rrc.read_records(cap_o)
                                  if raw[6:12].hex() == O) if p]
    wire_requests = [(ts, rrc.parse(raw)) for ts, raw in rrc.read_records(cap_o) if raw[6:12].hex() == M]
    wire_requests = [(ts,p) for ts,p in wire_requests if p and p.dport == 20000 and p.payload]
    txns = []
    seen_requests = set()
    for ts_req, rq in reqs:
        identity = (rq.sport,rq.seq,rq.payload)
        if identity in seen_requests:
            continue
        seen_requests.add(identity)
        wire = next((p for t,p in wire_requests if t >= ts_req and p.sport == rq.sport and
                     p.payload[10:13] == rq.payload[10:13]), rq)
        ack_end = (rq.seq + len(rq.payload)) & 0xffffffff
        wire_end = (wire.seq + len(wire.payload)) & 0xffffffff
        a = next(((t, p) for t, p in sent if not p.payload and p.ack == wire_end and t >= ts_req), None)
        r = next(((t, p) for t, p in sent if p.payload and p.ack == wire_end and t >= ts_req), None)
        ea = next(((t, p) for t, p in rel if not p.payload and p.ack == ack_end and t >= ts_req), None)
        er = next(((t, p) for t, p in rel if p.payload and p.ack == ack_end and t >= ts_req), None)
        txns.append({"t_req": ts_req, "t_A": a and a[0], "t_R": r and r[0], "e_A": ea and ea[0], "e_R": er and er[0],
                     "request_seq": rq.seq,"request_length":len(rq.payload),"wire_request_seq":wire.seq,
                     "wire_request_length":len(wire.payload),"app_seq":rq.payload[11]&15,
                     "operation":{1:"READ",3:"SELECT",4:"OPERATE"}.get(rq.payload[12],"unsupported")})
    return txns


def master_view(cap_m):
    """What a passive observer at the master port sees per request: every packet toward the master after the request,
    in order, with its time, flags, sequence/ack numbers and payload length. Retransmitted requests are listed too."""
    sys.path.insert(0, str(BMV2.parent / "size"))
    import rrc
    O, M = "020000000002", "020000000001"
    rows = []
    for ts, raw in rrc.read_records(cap_m):
        p = rrc.parse(raw)
        if not p:
            continue
        who = "M" if raw[6:12].hex() == M else "O" if raw[6:12].hex() == O else "?"
        rows.append({"t": ts, "from": who, "flags": p.flags, "seq": p.seq, "ack": p.ack, "len": len(p.payload),
                     "csum_ok": bool(rrc.ip_ok(p) and rrc.tcp_ok(p))})
    return rows


def request_padding_report(cap_m, cap_o):
    sys.path.insert(0,str(BMV2.parent / "size"))
    import rrc
    from case4_padding import Decoy, expand_control
    from case4_transport import ControlConnection
    native = [rrc.parse(raw) for _,raw in rrc.read_records(cap_m) if raw[6:12].hex() == "020000000001"]
    native = [p for p in native if p and len(p.payload) == 35]
    forwarded = [rrc.parse(raw) for _,raw in rrc.read_records(cap_o) if raw[6:12].hex() == "020000000001"]
    forwarded = [p for p in forwarded if p and p.payload]
    decoy = Decoy(201,bytes.fromhex("0101640000006400000000"))
    oracle = ControlConnection(native[0].seq,decoy) if native else None
    report = []
    for packet in native:
        wire = next((p for p in forwarded if p.payload[10:13] == packet.payload[10:13]),None)
        expected = oracle.forward(packet.seq,packet.payload)
        report.append(dict(native_length=len(packet.payload),wire_length=wire and len(wire.payload),
                           native_seq=packet.seq,wire_seq=wire and wire.seq,
                           equals_software_oracle=bool(wire and wire.payload == expected.payload and wire.seq == expected.seq),
                           dnp3_ok=bool(wire and rrc.dnp3_frame_ok(wire.payload)),
                           checksums_ok=bool(wire and rrc.ip_ok(wire) and rrc.tcp_ok(wire))))
    return report


def split_report(cap_m, cap_o):
    """What the master side saw of each response, against the original the outstation sent."""
    sys.path.insert(0, str(BMV2.parent / "size"))
    import rrc
    O = "020000000002"
    sent = [rrc.parse(raw) for _, raw in rrc.read_records(cap_o) if raw[6:12].hex() == O]
    originals = {p.seq: p for p in sent if p and p.payload}
    got = [(ts, rrc.parse(raw)) for ts, raw in rrc.read_records(cap_m) if raw[6:12].hex() == O]
    got = [(ts, p) for ts, p in got if p and p.payload]
    out = []
    for seq, orig in sorted(originals.items()):
        segs = [(ts, p) for ts, p in got if seq <= p.seq < seq + len(orig.payload)]
        by_seq = sorted(segs, key=lambda x: x[1].seq)
        whole = b"".join(p.payload for _, p in by_seq)
        profile="RRC_57_CUT28" if len(orig.payload) == 57 else "RRC_49_CUT28"
        # Validate carving separately from the ledger's reverse-ACK transformation.
        # Using the wire ACK as-is would incorrectly fail the padded-control oracle.
        translated=bytearray(orig.raw)
        if by_seq:
            import struct
            struct.pack_into(">I",translated,orig.tcp_off+8,by_seq[0][1].ack)
        translated=rrc._build(rrc.parse(bytes(translated)),orig.payload,orig.seq,orig.flags)
        carved=rrc.carve(translated,profile=profile)
        out.append({"orig_len": len(orig.payload), "seq_order": [len(p.payload) for _, p in by_seq],
                    "arrival_order": [len(p.payload) for _, p in segs],
                    "reassembled_equal": whole == orig.payload,
                    "contiguous": all(by_seq[i + 1][1].seq == by_seq[i][1].seq + len(by_seq[i][1].payload) for i in range(len(by_seq) - 1)),
                    "checksums_ok": all(rrc.ip_ok(p) and rrc.tcp_ok(p) for _, p in segs),
                    "prefix_flags_clear": all(not (p.flags & (rrc.PSH | rrc.FIN)) for _, p in by_seq[:-1]),
                    "dnp3_ok": rrc.dnp3_frame_ok(whole), "sequence_wraps": False,
                    "equals_software_carve": (lambda c: c is not None and [x[1].raw for x in by_seq] == list(c))(rrc.carve(orig.raw, profile=profile)),
                    "equals_software_carve_after_ack_translation": carved is not None and [p.raw for _,p in by_seq] == list(carved)})
    return out


def step5(lab, work, mode=4, da_us=10_000, gap_us=1_000, budget=300, loop_pps=5000, latency_ms=2.0, count=3, shape=0, force_points=0,
          dropreq=0, combined=False, gap_ms=300, budget_ms=2000, jitter_ms=0.0, seed=0, wait_fallback=False,
          operation="READ", padding=0, token_loss=0):
    if not 1 <= count <= 32:
        raise ValueError("per-transaction evidence capacity is 32")
    j = compile_p4("bmv2_rr", work)
    lab.up(loop=True).start_switch(j)
    if padding and (operation != "SBO" or count != 1):
        raise ValueError("fixed insertion profile supports one SELECT/OPERATE pair per connection")
    if padding:
        for ns in ("m", "o"):
            lab.sh("sysctl", "-qw", "net.ipv4.tcp_window_scaling=0", "net.ipv4.tcp_sack=0", "net.ipv4.tcp_timestamps=0", ns=ns)
    setup_policy(lab, mode, da_us, gap_us, budget, loop_pps, shape, dropreq, padding, token_loss)
    lab.heartbeat()
    cap_m, cap_o = lab.capture("s0", "master_side.pcap"), lab.capture("s1", "outstation_side.pcap")
    fallback_dir = None
    if wait_fallback:
        import threading
        import re
        fallback_dir = work / "observed_fallback"
        fallback_dir.mkdir()
        def observe_fallbacks():
            for index in range(count):
                deadline = time.monotonic() + budget_ms / 1000 + 5
                while time.monotonic() < deadline:
                    match = re.search(r"r_history\[\d+\]=\s*(\d+)", lab.cli("register_read r_history %d" % (index * 8 + 5)))
                    if match and int(match.group(1)):
                        (fallback_dir / (str(index) + ".json")).write_text(json.dumps({"transaction_id": index, "switch_timeout_us": int(match.group(1))}))
                        break
                    time.sleep(0.005)
                else:
                    return
        observer = threading.Thread(target=observe_fallbacks, daemon=True)
        observer.start()
    lab.start_outstation(latency_ms=latency_ms, force_points=force_points, combined=combined, jitter_ms=jitter_ms, seed=seed,
                         fallback_dir=fallback_dir)
    rows = lab.run_master(count=count, gap_ms=gap_ms, budget_ms=budget_ms, operation=operation)
    time.sleep(0.5)
    lab.down_captures()
    import re
    ev = {}
    for i in range(6):
        m = re.search(r"r_ev\[\d+\]=\s*(\d+)", lab.cli("register_read r_ev %d" % i))
        ev[i] = int(m.group(1)) if m else None
    txns = events_from_captures(cap_m, cap_o)
    for index, txn in enumerate(txns):
        events = {}
        for slot in range(6):
            match = re.search(r"r_history\[\d+\]=\s*(\d+)", lab.cli("register_read r_history %d" % (index * 8 + slot)))
            events[slot] = int(match.group(1)) if match else None
        txn.update(transaction_id=index, switch_ev_us=events,
                   release_outcome="fallback" if events[5] else "normal")
    import hashlib
    source = BMV2 / "p4" / "bmv2_rr.p4"
    heartbeat_stats={}
    for name in ("r_hb_last","r_hb_max_gap","r_hb_count"):
        match=re.search(r"%s\[0\]=\s*(\d+)" % name,lab.cli("register_read %s 0" % name))
        heartbeat_stats[name]=int(match.group(1)) if match else None
    result = {"outcomes": [r["outcome"] for r in rows], "txns": txns, "switch_ev_us": ev, "elapsed_ms": [r.get("elapsed_ms") for r in rows],
            "master_view": master_view(cap_m), "split": split_report(cap_m, cap_o),
            "request_padding":request_padding_report(cap_m,cap_o),
            "endpoint_responses":[json.loads(line) for line in (work / "endpoint_responses.jsonl").read_text().splitlines()],
            "artifact":dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                            compiled_sha256=hashlib.sha256(j.read_bytes()).hexdigest(), endpoint="Python codec emulator",
                            clock="BMv2 48-bit microseconds",heartbeat_period_us=1000,
                            heartbeat_observed=heartbeat_stats,
                            heartbeat_deviation="1ms software service; Tofino candidate requests100us",
                            transport_limit="initial segmented request and overlap beyond committed cache span unsupported"),
            "params": dict(mode=mode, da_us=da_us, gap_us=gap_us, budget=budget, loop_pps=loop_pps, latency_ms=latency_ms,
                           operation=operation,padding=padding,token_loss=token_loss,readiness_us=30000)}
    (work / "result.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def raw_profile(lab,work,frames,padding=1,mode=0):
    """Actual P4 transformations of explicit private-namespace wire fixtures."""
    j=compile_p4("bmv2_rr",work)
    lab.up(loop=True).start_switch(j)
    setup_policy(lab,mode,10000,1000,1000,20000,padding=padding)
    cap=lab.capture("s1","outstation_side.pcap")
    cap_m=lab.capture("s0","master_side.pcap")
    for index,frame in enumerate(frames):
        sender=frame.get("sender","m")
        if sender not in ("m","o"):
            raise ValueError("fixture sender must be an isolated endpoint namespace")
        source=work / ("input_%d.json" % index); source.write_text(json.dumps([frame]))
        lab.sh(sys.executable,"-B",str(HERE / "send_frames.py"),sender+"0",str(source),ns=sender)
    time.sleep(0.1); lab.down_captures()
    sys.path.insert(0,str(BMV2.parent / "size"))
    import rrc
    sent=[raw.hex() for _,raw in rrc.read_records(cap) if raw[6:12].hex() == "020000000001" and rrc.parse(raw)]
    reverse=[raw.hex() for _,raw in rrc.read_records(cap_m) if raw[6:12].hex() == "020000000002" and rrc.parse(raw)]
    return {"forwarded":sent,"reverse":reverse,"source":str(BMV2 / "p4" / "bmv2_rr.p4"),
            "service_enabled":False,"outcome_counters":counters(lab,"outcome",16) if mode else {}}


STEPS = {"step1": step1, "step3": step3, "exp_priority": exp_priority, "step5": step5,"raw_profile":raw_profile,
         "exp_priority_hi_only": lambda lab, work: exp_priority(lab, work, "set_queue_rate 100 2 0"),
         "exp_priority_lo_only": lambda lab, work: exp_priority(lab, work, "set_queue_rate 100 2 1")}


def main():
    if os.environ.get("BMV2_LAB_INNER") != "1":
        env = dict(os.environ, BMV2_LAB_INNER="1")
        return subprocess.call(["unshare", "-Urnm", sys.executable, "-B", __file__, *sys.argv[1:]], env=env)
    sys.path.insert(0, str(HERE))
    from lab import Lab
    step, work = sys.argv[1], Path(sys.argv[2])
    kw = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    work.mkdir(parents=True, exist_ok=True)
    lab = Lab(work)
    try:
        print(json.dumps(STEPS[step](lab, work, **kw), default=str))
    finally:
        lab.down()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
