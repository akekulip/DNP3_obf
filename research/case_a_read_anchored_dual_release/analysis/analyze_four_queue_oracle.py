#!/usr/bin/env python3
"""analyze_four_queue_oracle.py — offline verdict for the four-queue dequeue oracle.

OFFLINE ANALYSIS ONLY. Reads pcap / JSON evidence from disk; never contacts the switch
or any lab host.

The oracle preloads four Tofino-1 queues while scheduling is disabled and then releases
them; the frames loop through a switch-internal loopback and are captured on the host, so
the WIRE ORDER AT THE CAPTURE IS THE DEQUEUE ORDER. Strict priority under test:

    Q_ABLOCK(qid 7) > Q_ACK(qid 6) > Q_RBLOCK(qid 5) > Q_RESP(qid 4)
    roles           ABLOCK  >  HELD_ACK  >  RBLOCK  >  HELD_RESP

Reason codes are emitted in this precedence order (first failing one is the trial reason):
    UNEXPECTED_ROLE, PASS_FLAG, DUPLICATE, TM_DROP, COUNT_MISMATCH,
    ORDER_ACK_AFTER_ABLOCK, ORDER_RBLOCK_AFTER_ACK, ORDER_RESP_AFTER_RBLOCK

Exit status: 0 = every trial PASS; 1 = at least one trial FAIL (or no trials found);
2 = no FAIL but at least one INDETERMINATE trial (an order check could not be evaluated).

Usage:
  analyze_four_queue_oracle.py --evidence-dir DIR
  analyze_four_queue_oracle.py --pcap A.pcap [--pcap B.pcap] [--json rec.json ...]
  analyze_four_queue_oracle.py --self-test
"""
import argparse
import json
import logging
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ wire format (fixed)
ORACLE_ETHERTYPE = 0x88C2
ORACLE_FRAME_LEN = 64
OFF_DST_MAC = 0            # 6 bytes
OFF_SRC_MAC = 6            # 6 bytes
OFF_ETHERTYPE = 12         # uint16 BE
OFF_TRIAL_ID = 14          # uint16 BE
OFF_ROLE = 16              # uint8
OFF_PER_ROLE_SEQ = 17      # uint16 BE
OFF_GLOBAL_INJ_SEQ = 19    # uint16 BE
OFF_PASS = 21              # uint8
OFF_PAD = 22               # 42 bytes of padding to ORACLE_FRAME_LEN
ORACLE_MIN_LEN = OFF_PAD   # shortest frame that still carries every oracle field

ROLE_ABLOCK = 1
ROLE_HELD_ACK = 2
ROLE_RBLOCK = 3
ROLE_HELD_RESP = 4
ROLE_NAMES = {ROLE_ABLOCK: "ABLOCK", ROLE_HELD_ACK: "HELD_ACK",
              ROLE_RBLOCK: "RBLOCK", ROLE_HELD_RESP: "HELD_RESP"}
PASS_EXPECTED = 1          # every captured frame must have completed the loopback pass

DEFAULT_EXPECTED = {"ABLOCK": 64, "HELD_ACK": 1, "RBLOCK": 64, "HELD_RESP": 1}

# ------------------------------------------------------------------ verdicts / reasons
V_PASS = "PASS"
V_FAIL = "FAIL"
V_INDET = "INDETERMINATE"

R_OK = "OK"
R_UNEXPECTED_ROLE = "UNEXPECTED_ROLE"
R_PASS_FLAG = "PASS_FLAG"
R_DUPLICATE = "DUPLICATE"
R_TM_DROP = "TM_DROP"
R_COUNT_MISMATCH = "COUNT_MISMATCH"
R_ORDER_ACK = "ORDER_ACK_AFTER_ABLOCK"
R_ORDER_RBLOCK = "ORDER_RBLOCK_AFTER_ACK"
R_ORDER_RESP = "ORDER_RESP_AFTER_RBLOCK"
CHECK_PRECEDENCE = [R_UNEXPECTED_ROLE, R_PASS_FLAG, R_DUPLICATE, R_TM_DROP,
                    R_COUNT_MISMATCH, R_ORDER_ACK, R_ORDER_RBLOCK, R_ORDER_RESP]

# ------------------------------------------------------------------ pcap constants
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
               b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}
LINKTYPE_EN10MB = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


# ================================================================== frame pack / parse
def build_oracle_frame(trial_id: int, role: int, per_role_seq: int, global_inj_seq: int,
                       pass_flag: int = 1, dst_mac: bytes = b"\xff" * 6,
                       src_mac: bytes = b"\x00\x11\x22\x33\x44\x55") -> bytes:
    """Pack one 64-byte oracle frame in the exact injector/P4 layout."""
    if len(dst_mac) != 6 or len(src_mac) != 6:
        raise ValueError("MAC addresses must be exactly 6 bytes")
    head = (dst_mac + src_mac
            + struct.pack("!H", ORACLE_ETHERTYPE)
            + struct.pack("!H", trial_id & 0xFFFF)
            + struct.pack("!B", role & 0xFF)
            + struct.pack("!H", per_role_seq & 0xFFFF)
            + struct.pack("!H", global_inj_seq & 0xFFFF)
            + struct.pack("!B", pass_flag & 0xFF))
    return head + b"\x00" * (ORACLE_FRAME_LEN - len(head))


def parse_oracle_frame(frame: bytes) -> Optional[Dict[str, Any]]:
    """Return the oracle fields of an Ethernet frame, or None if it is not an oracle frame."""
    if len(frame) < ORACLE_MIN_LEN:
        return None
    if struct.unpack("!H", frame[OFF_ETHERTYPE:OFF_ETHERTYPE + 2])[0] != ORACLE_ETHERTYPE:
        return None
    role = frame[OFF_ROLE]
    return {
        "trial_id": struct.unpack("!H", frame[OFF_TRIAL_ID:OFF_TRIAL_ID + 2])[0],
        "role": role,
        "role_name": ROLE_NAMES.get(role, "UNKNOWN_%d" % role),
        "per_role_seq": struct.unpack("!H", frame[OFF_PER_ROLE_SEQ:OFF_PER_ROLE_SEQ + 2])[0],
        "global_inj_seq": struct.unpack("!H", frame[OFF_GLOBAL_INJ_SEQ:OFF_GLOBAL_INJ_SEQ + 2])[0],
        "pass_flag": frame[OFF_PASS],
        "frame_len": len(frame),
    }


# ================================================================== pcap readers
def read_pcap_frames(path: str) -> List[bytes]:
    """Pure-stdlib classic libpcap reader (both endiannesses). Returns link-layer frames."""
    frames = []  # type: List[bytes]
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise ValueError("%s: truncated pcap file header" % path)
        end = PCAP_MAGICS.get(gh[:4])
        if end is None:
            raise ValueError("%s: not a classic pcap (magic %r); pcapng is not supported" % (path, gh[:4]))
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            _ts_s, _ts_f, incl, _orig = struct.unpack(end + "IIII", rh)
            data = fh.read(incl)
            if len(data) < incl:
                logger.warning("%s: truncated final record, ignored", path)
                break
            frames.append(_normalize_link_frame(data, linktype))
    return [f for f in frames if f]


def _normalize_link_frame(data: bytes, linktype: int) -> bytes:
    """Convert a captured link-layer record to an Ethernet-style frame (dst zeroed for cooked)."""
    if linktype == LINKTYPE_EN10MB:
        return data
    if linktype == LINKTYPE_LINUX_SLL and len(data) >= 16:
        # [0:2]pkttype [2:4]arphrd [4:6]addrlen [6:14]addr [14:16]proto [16:]payload
        return b"\x00" * 6 + data[6:12] + data[14:16] + data[16:]
    if linktype == LINKTYPE_LINUX_SLL2 and len(data) >= 20:
        # [0:2]proto [2:4]rsv [4:8]ifindex [8:10]arphrd [10]pkttype [11]addrlen [12:20]addr
        return b"\x00" * 6 + data[12:18] + data[0:2] + data[20:]
    if linktype not in (LINKTYPE_EN10MB, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
        logger.warning("unhandled pcap linktype %d; frame passed through unmodified", linktype)
        return data
    return b""


def _scapy_frames(path: str) -> List[bytes]:
    """Optional scapy fallback (only used when the raw reader cannot open the file)."""
    from scapy.utils import RawPcapReader  # type: ignore  # noqa: F401  (optional dependency)
    out = []  # type: List[bytes]
    with RawPcapReader(path) as rdr:
        for pkt, _meta in rdr:
            out.append(bytes(pkt))
    return out


def load_frames(path: str) -> List[bytes]:
    """Load link-layer frames: stdlib reader first, scapy only if that cannot parse the file."""
    try:
        return read_pcap_frames(path)
    except ValueError as exc:
        logger.warning("%s", exc)
        try:
            frames = _scapy_frames(path)
        except ImportError:
            logger.error("%s: unreadable and scapy is not installed", path)
            return []
        except Exception as exc2:                      # noqa: BLE001 - report, do not crash
            logger.error("%s: scapy fallback failed: %s", path, exc2)
            return []
        logger.info("%s: parsed with the scapy fallback (%d frames)", path, len(frames))
        return frames


def oracle_frames_from_pcaps(paths: Sequence[str]) -> List[Dict[str, Any]]:
    """Parsed oracle frames from the given pcaps, in capture order (files in the given order)."""
    parsed = []  # type: List[Dict[str, Any]]
    for path in paths:
        n_before = len(parsed)
        for idx, frame in enumerate(load_frames(path)):
            rec = parse_oracle_frame(frame)
            if rec is None:
                continue
            rec["source"] = path
            rec["capture_index"] = idx
            parsed.append(rec)
        logger.info("%s: %d oracle frames", path, len(parsed) - n_before)
    return parsed


def group_by_trial(frames: Sequence[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """Group parsed frames by trial_id, preserving capture order inside each trial."""
    trials = {}  # type: Dict[int, List[Dict[str, Any]]]
    for rec in frames:
        trials.setdefault(rec["trial_id"], []).append(rec)
    return trials


# ================================================================== trial records (JSON)
def load_trial_records(paths: Sequence[str]) -> Dict[int, Dict[str, Any]]:
    """Load runner-written trial records keyed by trial_id. Malformed files are skipped."""
    records = {}  # type: Dict[int, Dict[str, Any]]
    for path in paths:
        try:
            with open(path, "r") as fh:
                blob = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning("%s: unreadable trial record (%s), skipped", path, exc)
            continue
        items = blob if isinstance(blob, list) else [blob]
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("trial_id"), int):
                continue
            if item["trial_id"] in records:
                logger.warning("%s: trial %d already had a record; the later one wins",
                               path, item["trial_id"])
            records[item["trial_id"]] = item
    return records


def expected_for_trial(record: Optional[Dict[str, Any]], defaults: Dict[str, int]) -> Dict[str, int]:
    """Expected per-role counts: the record's `expected` block overrides the CLI defaults."""
    exp = dict(defaults)
    raw = (record or {}).get("expected")
    if not isinstance(raw, dict):
        return exp
    alias = {"ABLOCK": "ABLOCK", "1": "ABLOCK",
             "ACK": "HELD_ACK", "HELD_ACK": "HELD_ACK", "2": "HELD_ACK",
             "RBLOCK": "RBLOCK", "3": "RBLOCK",
             "RESP": "HELD_RESP", "HELD_RESP": "HELD_RESP", "4": "HELD_RESP"}
    for key, val in raw.items():
        if isinstance(val, bool) or not isinstance(val, int):
            continue
        norm = str(key).strip().upper()
        for prefix in ("N_", "NUM_", "EXPECT_", "EXPECTED_"):
            if norm.startswith(prefix):
                norm = norm[len(prefix):]
        name = alias.get(norm)
        if name is None:
            logger.warning("trial record: ignoring unknown expected-count key %r", key)
            continue
        exp[name] = val
    return exp


def drop_total(record: Optional[Dict[str, Any]]) -> Optional[int]:
    """Total TM drop_count_packets reported by the runner, or None when not reported."""
    raw = (record or {}).get("drops")

    def _ints(obj: Any) -> List[int]:
        if isinstance(obj, bool):
            return []
        if isinstance(obj, int):
            return [obj]
        if isinstance(obj, dict):
            return [n for v in obj.values() for n in _ints(v)]
        if isinstance(obj, (list, tuple)):
            return [n for v in obj for n in _ints(v)]
        return []

    vals = _ints(raw)
    return sum(vals) if vals else None


# ================================================================== evaluation
def _check(code: str, status: str, detail: str) -> Dict[str, str]:
    """One named check result."""
    return {"code": code, "status": status, "detail": detail}


def _order_check(code: str, hi_name: str, lo_name: str,
                 positions: Dict[str, List[int]]) -> Dict[str, str]:
    """Strict priority: every `hi_name` packet must dequeue before every `lo_name` packet."""
    hi = positions.get(hi_name) or []
    lo = positions.get(lo_name) or []
    if not hi or not lo:
        missing = [n for n, ps in ((hi_name, hi), (lo_name, lo)) if not ps]
        return _check(code, V_INDET,
                      "cannot evaluate: no %s packet in this trial" % " or ".join(missing))
    last_hi, first_lo = max(hi), min(lo)
    if last_hi < first_lo:
        return _check(code, V_PASS, "last %s at pos %d precedes first %s at pos %d"
                      % (hi_name, last_hi, lo_name, first_lo))
    return _check(code, V_FAIL, "priority violation: first %s at pos %d precedes last %s at pos %d"
                  % (lo_name, first_lo, hi_name, last_hi))


def evaluate_trial(trial_id: int, frames: Sequence[Dict[str, Any]],
                   expected: Optional[Dict[str, int]] = None,
                   record: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Evaluate one trial's dequeue order and integrity. Returns the per-trial result dict."""
    expected = dict(DEFAULT_EXPECTED) if expected is None else dict(expected)
    record = record or {}
    counts = {}     # type: Dict[str, int]
    positions = {}  # type: Dict[str, List[int]]
    for pos, rec in enumerate(frames):
        name = rec["role_name"]
        counts[name] = counts.get(name, 0) + 1
        positions.setdefault(name, []).append(pos)

    checks = []  # type: List[Dict[str, str]]

    bad_roles = sorted({r["role"] for r in frames if r["role"] not in ROLE_NAMES})
    checks.append(_check(R_UNEXPECTED_ROLE, V_PASS if not bad_roles else V_FAIL,
                         "all role bytes in 1..4" if not bad_roles
                         else "role byte(s) outside 1..4: %s" % (bad_roles,)))

    bad_pass = ["pos %d %s pass=%d" % (p, frames[p]["role_name"], frames[p]["pass_flag"])
                for p in range(len(frames)) if frames[p]["pass_flag"] != PASS_EXPECTED]
    checks.append(_check(R_PASS_FLAG, V_PASS if not bad_pass else V_FAIL,
                         "all %d frames carry pass=%d" % (len(frames), PASS_EXPECTED) if not bad_pass
                         else "%d frame(s) without the loopback pass flag: %s"
                              % (len(bad_pass), ", ".join(bad_pass[:5]))))

    seen_rs = set()   # type: set
    seen_g = set()    # type: set
    dups = []         # type: List[str]
    for rec in frames:
        key = (rec["role"], rec["per_role_seq"])
        if key in seen_rs:
            dups.append("%s/per_role_seq=%d" % (rec["role_name"], rec["per_role_seq"]))
        seen_rs.add(key)
        if rec["global_inj_seq"] in seen_g:
            dups.append("global_inj_seq=%d" % rec["global_inj_seq"])
        seen_g.add(rec["global_inj_seq"])
    checks.append(_check(R_DUPLICATE, V_PASS if not dups else V_FAIL,
                         "no repeated (role, per_role_seq) or global_inj_seq" if not dups
                         else "%d duplicate(s): %s" % (len(dups), ", ".join(sorted(set(dups))[:5]))))

    drops = drop_total(record)
    if drops is None:
        logger.info("trial %d: no TM drop counter in the trial record", trial_id)
    else:
        checks.append(_check(R_TM_DROP, V_PASS if drops == 0 else V_FAIL,
                             "TM drop_count_packets = %d" % drops))

    mism = ["%s got=%d expected=%d" % (name, counts.get(name, 0), expected[name])
            for name in ("ABLOCK", "HELD_ACK", "RBLOCK", "HELD_RESP")
            if counts.get(name, 0) != expected.get(name, 0)]
    checks.append(_check(R_COUNT_MISMATCH, V_PASS if not mism else V_FAIL,
                         "per-role counts match %s" % (expected,) if not mism
                         else "; ".join(mism)))

    checks.append(_order_check(R_ORDER_ACK, "ABLOCK", "HELD_ACK", positions))
    checks.append(_order_check(R_ORDER_RBLOCK, "HELD_ACK", "RBLOCK", positions))
    checks.append(_order_check(R_ORDER_RESP, "RBLOCK", "HELD_RESP", positions))

    role_ranges = {}  # type: Dict[str, Dict[str, Any]]
    notes = []        # type: List[str]
    for name in sorted(positions):
        ps = positions[name]
        contiguous = (max(ps) - min(ps) + 1) == len(ps)
        role_ranges[name] = {"first": min(ps), "last": max(ps), "count": len(ps),
                             "contiguous": contiguous}
        if not contiguous:
            notes.append("INTERLEAVED: %s occupies pos %d-%d but holds only %d packets"
                         % (name, min(ps), max(ps), len(ps)))

    by_code = {c["code"]: c for c in checks}
    reason, detail, verdict = R_OK, "all checks passed", V_PASS
    for code in CHECK_PRECEDENCE:
        chk = by_code.get(code)
        if chk is not None and chk["status"] == V_FAIL:
            reason, detail, verdict = code, chk["detail"], V_FAIL
            break
    if verdict == V_PASS:
        for code in CHECK_PRECEDENCE:
            chk = by_code.get(code)
            if chk is not None and chk["status"] == V_INDET:
                reason, detail, verdict = code, chk["detail"], V_INDET
                break

    return {
        "trial_id": trial_id,
        "mode": record.get("mode", "-"),
        "seed": record.get("seed"),
        "n_packets": len(frames),
        "verdict": verdict,
        "reason": reason,
        "detail": detail,
        "counts": counts,
        "expected": expected,
        "role_ranges": role_ranges,
        "notes": notes,
        "checks": checks,
        "tm_drops": drops,
        "occupancy_before_release": record.get("occupancy_before_release"),
        "injection_sequence": record.get("injection_sequence"),
    }


def analyze(pcaps: Sequence[str], json_paths: Sequence[str],
            defaults: Dict[str, int]) -> List[Dict[str, Any]]:
    """Parse the evidence and evaluate every trial found, ordered by trial_id."""
    records = load_trial_records(json_paths)
    trials = group_by_trial(oracle_frames_from_pcaps(pcaps))
    results = []
    for trial_id in sorted(trials):
        rec = records.get(trial_id)
        results.append(evaluate_trial(trial_id, trials[trial_id],
                                      expected_for_trial(rec, defaults), rec))
    for trial_id in sorted(set(records) - set(trials)):
        logger.warning("trial record %d has no captured oracle frames", trial_id)
    return results


# ================================================================== reporting
def _trunc(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width - 3] + "..."


def print_report(results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Print the per-trial table plus the summary; return the summary dict."""
    header = "%-8s %-12s %-6s %-14s %-24s %s" % (
        "trial", "mode", "n_pkt", "verdict", "reason", "detail")
    print(header)
    print("-" * len(header))
    for res in results:
        print("%-8d %-12s %-6d %-14s %-24s %s" % (
            res["trial_id"], _trunc(str(res["mode"]), 12), res["n_packets"],
            res["verdict"], res["reason"], _trunc(res["detail"], 70)))
        for note in res["notes"]:
            print("%-8s %s" % ("", note))

    reasons = {}  # type: Dict[str, int]
    for res in results:
        if res["verdict"] == V_FAIL:
            reasons[res["reason"]] = reasons.get(res["reason"], 0) + 1
    summary = {
        "trials": len(results),
        "pass": sum(1 for r in results if r["verdict"] == V_PASS),
        "fail": sum(1 for r in results if r["verdict"] == V_FAIL),
        "indeterminate": sum(1 for r in results if r["verdict"] == V_INDET),
        "failure_reasons": reasons,
    }
    print("")
    print("trials=%d  PASS=%d  FAIL=%d  INDETERMINATE=%d"
          % (summary["trials"], summary["pass"], summary["fail"], summary["indeterminate"]))
    if reasons:
        for code in CHECK_PRECEDENCE:
            if code in reasons:
                print("  %-24s %d" % (code, reasons[code]))
    return summary


# ================================================================== self-test
def _synth(trial_id: int, role: int, per_role_seq: int, global_inj_seq: int,
           pass_flag: int = 1) -> Dict[str, Any]:
    """Build a frame with the packer and parse it back — the tests use the real wire path."""
    rec = parse_oracle_frame(build_oracle_frame(trial_id, role, per_role_seq,
                                                global_inj_seq, pass_flag))
    if rec is None:
        raise AssertionError("packer/parser disagree on the oracle frame format")
    return rec


def _correct_sequence(trial_id: int = 1, n_ablock: int = 64,
                      n_rblock: int = 64) -> List[Dict[str, Any]]:
    """The reference strict-priority dequeue order: ABLOCK*, HELD_ACK, RBLOCK*, HELD_RESP."""
    seq, gseq = [], 0
    for i in range(n_ablock):
        seq.append(_synth(trial_id, ROLE_ABLOCK, i, gseq))
        gseq += 1
    seq.append(_synth(trial_id, ROLE_HELD_ACK, 0, gseq))
    gseq += 1
    for i in range(n_rblock):
        seq.append(_synth(trial_id, ROLE_RBLOCK, i, gseq))
        gseq += 1
    seq.append(_synth(trial_id, ROLE_HELD_RESP, 0, gseq))
    return seq


def _mutated(defect: str) -> List[Dict[str, Any]]:
    """The reference dequeue order with exactly one deliberate defect applied.

    Reference positions: ABLOCK 0-63, HELD_ACK 64, RBLOCK 65-128, HELD_RESP 129.
    """
    seq = _correct_sequence()
    if defect == "response_before_ack":
        seq.insert(0, seq.pop())                       # HELD_RESP dequeues first
    elif defect == "ack_before_final_ablock":
        seq.insert(32, seq.pop(64))                    # HELD_ACK jumps ahead of 32 ABLOCKs
    elif defect == "dropped_packet":
        del seq[10]                                    # one ABLOCK never arrives
    elif defect == "duplicate_packet":
        seq.insert(20, dict(seq[5]))                   # same (role, per_role_seq) twice
    elif defect == "rblock_before_ack":
        seq.insert(64, seq.pop(65))                    # first RBLOCK overtakes HELD_ACK
    elif defect == "resp_before_last_rblock":
        seq.insert(128, seq.pop(129))                  # HELD_RESP overtakes the last RBLOCK
    elif defect == "bad_pass_flag":
        seq[7] = _synth(1, ROLE_ABLOCK, 7, 7, pass_flag=0)
    elif defect == "unexpected_role":
        seq[7] = _synth(1, 9, 7, 7)                     # role byte outside 1..4
    else:
        raise ValueError("unknown defect %r" % defect)
    return seq


def _round_trip_test() -> Tuple[bool, str]:
    """Guard the wire-format offsets: pack -> parse must preserve every field."""
    frame = build_oracle_frame(0xBEEF, ROLE_RBLOCK, 0xABCD, 0x1234, pass_flag=1)
    rec = parse_oracle_frame(frame)
    problems = []
    if len(frame) != ORACLE_FRAME_LEN:
        problems.append("frame_len=%d" % len(frame))
    if struct.unpack("!H", frame[OFF_ETHERTYPE:OFF_ETHERTYPE + 2])[0] != ORACLE_ETHERTYPE:
        problems.append("ethertype offset")
    if rec is None:
        problems.append("parse returned None")
    else:
        for field, want in (("trial_id", 0xBEEF), ("role", ROLE_RBLOCK), ("per_role_seq", 0xABCD),
                            ("global_inj_seq", 0x1234), ("pass_flag", 1)):
            if rec[field] != want:
                problems.append("%s=%r want %r" % (field, rec[field], want))
        if rec["role_name"] != "RBLOCK":
            problems.append("role_name=%s" % rec["role_name"])
    if parse_oracle_frame(b"\x00" * 12 + b"\x08\x00" + b"\x00" * 50) is not None:
        problems.append("non-oracle ethertype was accepted")
    return (not problems), ("all fields survive pack/parse" if not problems else "; ".join(problems))


def run_self_test() -> int:
    """Run the built-in unit tests. Returns 0 when every test passes."""
    cases = [
        ("correct", _correct_sequence(), V_PASS, R_OK),
        ("response_before_ack", _mutated("response_before_ack"), V_FAIL, R_ORDER_RESP),
        ("ack_before_final_ablock", _mutated("ack_before_final_ablock"), V_FAIL, R_ORDER_ACK),
        ("dropped_packet", _mutated("dropped_packet"), V_FAIL, R_COUNT_MISMATCH),
        ("duplicate_packet", _mutated("duplicate_packet"), V_FAIL, R_DUPLICATE),
        ("rblock_before_ack", _mutated("rblock_before_ack"), V_FAIL, R_ORDER_RBLOCK),
        ("resp_before_last_rblock", _mutated("resp_before_last_rblock"), V_FAIL, R_ORDER_RESP),
        ("bad_pass_flag", _mutated("bad_pass_flag"), V_FAIL, R_PASS_FLAG),
        ("unexpected_role", _mutated("unexpected_role"), V_FAIL, R_UNEXPECTED_ROLE),
    ]
    failures = 0
    for name, seq, want_verdict, want_reason in cases:
        res = evaluate_trial(1, seq)
        ok = (res["verdict"] == want_verdict and res["reason"] == want_reason)
        failures += 0 if ok else 1
        print("%-4s  %-26s expected=%-24s got=%-24s [%s%s]"
              % ("PASS" if ok else "FAIL", name, want_reason, res["reason"], res["verdict"],
                 "" if res["verdict"] == want_verdict else " want %s" % want_verdict))

    # A role that is legitimately absent must make its order checks INDETERMINATE, not PASS.
    seq = _correct_sequence()
    seq.pop()                                       # remove the single HELD_RESP
    res = evaluate_trial(1, seq, expected={"ABLOCK": 64, "HELD_ACK": 1, "RBLOCK": 64, "HELD_RESP": 0})
    ok = (res["verdict"] == V_INDET and res["reason"] == R_ORDER_RESP)
    failures += 0 if ok else 1
    print("%-4s  %-26s expected=%-24s got=%-24s [%s]"
          % ("PASS" if ok else "FAIL", "absent_role_indeterminate", R_ORDER_RESP,
             res["reason"], res["verdict"]))

    ok, detail = _round_trip_test()
    failures += 0 if ok else 1
    print("%-4s  %-26s expected=%-24s got=%s"
          % ("PASS" if ok else "FAIL", "frame_round_trip", "all fields preserved", detail))

    total = len(cases) + 2
    print("")
    print("self-test: %d/%d passed, %d failed" % (total - failures, total, failures))
    return 1 if failures else 0


# ================================================================== CLI
def _scan_evidence_dir(path: str) -> Tuple[List[str], List[str]]:
    """Recursively collect *.pcap and *.json under an evidence directory (sorted)."""
    pcaps, jsons = [], []
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            full = os.path.join(root, name)
            if name.endswith(".pcap"):
                pcaps.append(full)
            elif name.endswith(".json"):
                jsons.append(full)
            elif name.endswith(".pcapng"):
                logger.warning("%s: pcapng is not supported, skipped", full)
    return sorted(pcaps), sorted(jsons)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Offline four-queue dequeue oracle analyzer.")
    ap.add_argument("--evidence-dir", help="directory scanned for *.pcap and *.json trial records")
    ap.add_argument("--pcap", action="append", default=[], help="capture to analyze (repeatable)")
    ap.add_argument("--json", action="append", default=[], help="trial record file (repeatable)")
    ap.add_argument("--expect-ablock", type=int, default=DEFAULT_EXPECTED["ABLOCK"])
    ap.add_argument("--expect-rblock", type=int, default=DEFAULT_EXPECTED["RBLOCK"])
    ap.add_argument("--expect-ack", type=int, default=DEFAULT_EXPECTED["HELD_ACK"])
    ap.add_argument("--expect-resp", type=int, default=DEFAULT_EXPECTED["HELD_RESP"])
    ap.add_argument("--json-out", help="write the full machine-readable result here")
    ap.add_argument("--self-test", action="store_true", help="run the built-in unit tests and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    if args.self_test:
        return run_self_test()

    pcaps, jsons = list(args.pcap), list(args.json)
    if args.evidence_dir:
        found_p, found_j = _scan_evidence_dir(args.evidence_dir)
        pcaps.extend(found_p)
        jsons.extend(found_j)
    if not pcaps:
        ap.error("no pcap given: use --pcap, --evidence-dir, or --self-test")

    defaults = {"ABLOCK": args.expect_ablock, "HELD_ACK": args.expect_ack,
                "RBLOCK": args.expect_rblock, "HELD_RESP": args.expect_resp}
    results = analyze(pcaps, jsons, defaults)
    if not results:
        print("no oracle frames (ethertype 0x%04X) found in %d pcap(s)" % (ORACLE_ETHERTYPE, len(pcaps)))
        return 1
    summary = print_report(results)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({"summary": summary, "trials": results, "pcaps": pcaps,
                       "trial_records": jsons, "defaults": defaults}, fh, indent=2)
    if summary["fail"]:
        return 1
    return 2 if summary["indeterminate"] else 0


if __name__ == "__main__":
    sys.exit(main())
