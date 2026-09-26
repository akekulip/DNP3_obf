"""Analysis helpers for low-latency timing-policy searches.

The functions here consume fresh corrected-harness evidence: master-side captures,
application outcome JSONL, and per-block policy/status metadata.  They keep packet
size out of the feature set and evaluate only timing-derived attacker views.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import statistics
import struct
import sys
from typing import Iterable, Mapping, Sequence

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

HERE = Path(__file__).resolve()
TIMING_ANALYSIS = HERE.parents[1] / "analysis"
if str(TIMING_ANALYSIS) not in sys.path:
    sys.path.insert(0, str(TIMING_ANALYSIS))

from dnp3_timing import (  # noqa: E402
    DNP3_PORT,
    FUNC_NAME,
    FUNC_OPERATE,
    FUNC_READ,
    FUNC_SELECT,
    MASTER,
    NS_PER_MS,
    extract_transactions,
    iter_frames,
    read_packets,
    RELAY,
    TCP_ACK,
)

CLASSES = ("READ", "SELECT", "OPERATE")
BINARY_CLASSES = ("READ", "SELECT")
FUNC_BY_NAME = {"READ": FUNC_READ, "SELECT": FUNC_SELECT, "OPERATE": FUNC_OPERATE}
NAME_BY_FUNC = {FUNC_READ: "READ", FUNC_SELECT: "SELECT", FUNC_OPERATE: "OPERATE"}
DEFAULT_FEATURE_SET = "ack_clrt"
FEATURE_SETS = {
    "clrt": ("clrt_ms",),
    "ack_clrt": ("ack_ms", "clrt_ms"),
    "request_gap": ("request_gap_ms",),
    "ack_clrt_gap": ("ack_ms", "clrt_ms", "request_gap_ms"),
}


class AnalysisError(Exception):
    """Raised when evidence is incomplete or cannot support the requested analysis."""


@dataclass(frozen=True)
class Outcome:
    operation: str
    session: str | None
    block: str | None
    arm: str | None
    mode: str | None
    txn_id: int | None
    app_rtt_ms: float | None
    raw: Mapping[str, object]


@dataclass(frozen=True)
class CaptureTransaction:
    req_func: int
    t_req_ns: int
    t_ack_ns: int
    t_resp_ns: int
    app_seq: int | None

    @property
    def ack_ms(self):
        return (self.t_ack_ns - self.t_req_ns) / NS_PER_MS

    @property
    def clrt_ms(self):
        return (self.t_resp_ns - self.t_ack_ns) / NS_PER_MS

    @property
    def resp_ms(self):
        return (self.t_resp_ns - self.t_req_ns) / NS_PER_MS


def _float_or_none(value):
    if value is None or value == "":
        return None
    return float(value)


def _ok_outcome(record: Mapping[str, object]) -> bool:
    if record.get("ok") is False:
        return False
    if record.get("valid") is False:
        return False
    if record.get("error"):
        return False
    outcome = record.get("outcome")
    if outcome not in (None, "", "OK", "SUCCESS", "success", "ok"):
        return False
    if record.get("problems"):
        return False
    if int(record.get("stale_frames_discarded") or 0) != 0:
        return False
    if int(record.get("bytes_left_buffered") or 0) != 0:
        return False
    status = record.get("status")
    return status in (None, "", 0, "0", "OK", "SUCCESS", "success", "ok")


def load_outcomes(path: str | Path) -> list[Outcome]:
    """Load one application-outcome JSONL file.

    The loader preserves raw records, but normalizes the fields needed for joining
    with capture-derived transactions.
    """
    rows: list[Outcome] = []
    path = Path(path)
    with path.open() as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            op = raw.get("operation")
            if op not in FUNC_BY_NAME:
                raise AnalysisError(f"{path}:{line_no}: unsupported operation {op!r}")
            if raw.get("function") is not None and int(raw["function"]) != FUNC_BY_NAME[op]:
                raise AnalysisError(f"{path}:{line_no}: function does not match operation {op}")
            if not _ok_outcome(raw):
                raise AnalysisError(f"{path}:{line_no}: unsuccessful outcome for {op}")
            rows.append(
                Outcome(
                    operation=str(op),
                    session=raw.get("session_id") or raw.get("session"),
                    block=raw.get("block_id") or raw.get("block"),
                    arm=raw.get("condition") or raw.get("arm"),
                    mode=raw.get("mode"),
                    txn_id=raw.get("txn_id"),
                    app_rtt_ms=_float_or_none(raw.get("rtt_ms", raw.get("elapsed_ms"))),
                    raw=raw,
                )
            )
    return rows


def _load_all_outcomes(paths: Iterable[Path]) -> list[Outcome]:
    out: list[Outcome] = []
    for path in sorted(paths):
        out.extend(load_outcomes(path))
    if any("t_send" in o.raw for o in out):
        out.sort(key=lambda o: (float(o.raw.get("t_send", 0.0)), str(o.operation), o.txn_id or 0))
    return out


def _policy_fields(policy: Mapping[str, object] | None) -> dict[str, float]:
    if not policy:
        return {}
    out = {}
    if policy.get("name") not in (None, ""):
        out["policy_name"] = str(policy["name"])
    aliases = {
        "da_ms": "policy_da_ms",
        "D_A_ms": "policy_da_ms",
        "d_a_ms": "policy_da_ms",
        "new_clrt_ms": "policy_new_clrt_ms",
        "clrt_ms": "policy_new_clrt_ms",
        "new_CLRT_ms": "policy_new_clrt_ms",
    }
    for key, value in policy.items():
        if key == "name":
            continue
        if isinstance(value, bool):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        out[aliases.get(key, f"policy_{key}")] = number
    return out


def rows_from_transactions(
    transactions: Sequence[object],
    outcomes: Sequence[Outcome],
    *,
    session: str | None = None,
    block: str | None = None,
    arm: str | None = None,
    mode: str | None = None,
    policy: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Join capture-derived transactions to application outcomes by block order."""
    if len(transactions) != len(outcomes):
        raise AnalysisError(
            f"capture/outcome count mismatch: {len(transactions)} transactions, "
            f"{len(outcomes)} outcomes"
        )
    rows = []
    prev_req_ns = None
    policy_cols = _policy_fields(policy)
    for idx, (txn, out) in enumerate(zip(transactions, outcomes)):
        cls = NAME_BY_FUNC.get(txn.req_func, FUNC_NAME.get(txn.req_func))
        if cls != out.operation:
            raise AnalysisError(f"operation mismatch at row {idx}: capture {cls}, outcome {out.operation}")
        if txn.ack_ms is None or txn.clrt_ms is None or txn.resp_ms is None:
            raise AnalysisError(f"unpaired {cls} transaction at row {idx}")
        req_ns = getattr(txn, "t_req_ns", None)
        gap_ms = None if prev_req_ns is None or req_ns is None else (req_ns - prev_req_ns) / 1_000_000
        if req_ns is not None:
            prev_req_ns = req_ns
        row = {
            "session": session or out.session,
            "block": block or out.block,
            "arm": arm or out.arm,
            "mode": mode or out.mode,
            "txn_index": idx,
            "txn_class": cls,
            "func": txn.req_func,
            "ack_ms": float(txn.ack_ms),
            "clrt_ms": float(txn.clrt_ms),
            "rt_ms": float(txn.resp_ms),
            "app_rtt_ms": out.app_rtt_ms,
        }
        if gap_ms is not None:
            row["request_gap_ms"] = float(gap_ms)
        row.update(policy_cols)
        rows.append(row)
    return rows


def _find_one(root: Path, patterns: Sequence[str], label: str) -> Path:
    found = []
    for pattern in patterns:
        found.extend(root.glob(pattern))
    found = sorted(set(found))
    if len(found) != 1:
        raise AnalysisError(f"{root}: expected one {label}, found {len(found)}")
    return found[0]


def _read_optional_json(root: Path, patterns: Sequence[str]) -> dict:
    found = []
    for pattern in patterns:
        found.extend(root.glob(pattern))
    found = sorted(set(found))
    if not found:
        return {}
    if len(found) > 1:
        raise AnalysisError(f"{root}: multiple metadata files match {patterns}: {found}")
    return json.loads(found[0].read_text())


def _output_status_poll_times(pcap_path: Path) -> set[int]:
    """Return READ request timestamps for extra G10 output-status polls.

    The runner may poll output status before/after a block. Those safety polls request
    points 0..31 and are not application samples for the latency search.
    """
    return _output_status_poll_times_from_packets(read_packets(pcap_path))


def _output_status_poll_times_from_packets(packets) -> set[int]:
    times = set()
    for pkt in packets:
        if pkt.from_master and pkt.dnp3_func == FUNC_READ and len(pkt.payload) > 17:
            if pkt.payload[17] == 31:
                times.add(pkt.t_ns)
    return times


@dataclass(frozen=True)
class TcpPacket:
    t_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes

    @property
    def from_master(self):
        return self.src == MASTER and self.dst == RELAY and self.dport == DNP3_PORT

    @property
    def from_relay(self):
        return self.src == RELAY and self.dst == MASTER and self.sport == DNP3_PORT

    @property
    def dnp3_func(self):
        p = self.payload
        if len(p) >= 13 and p[0] == 0x05 and p[1] == 0x64:
            return p[12]
        return None

    @property
    def app_seq(self):
        if len(self.payload) > 11:
            return self.payload[11] & 0x0F
        return None


def _decode_tcp_packet(t_ns: int, frame: bytes) -> TcpPacket | None:
    if len(frame) < 34:
        return None
    ethertype, = struct.unpack_from("!H", frame, 12)
    off = 14
    while ethertype in (0x8100, 0x88A8):
        if len(frame) < off + 4:
            return None
        ethertype, = struct.unpack_from("!H", frame, off + 2)
        off += 4
    if ethertype != 0x0800:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl or frame[off + 9] != 6:
        return None
    total_len, = struct.unpack_from("!H", frame, off + 2)
    if len(frame) < off + total_len:
        raise AnalysisError("truncated IPv4 packet in capture")
    src = ".".join(str(b) for b in frame[off + 12: off + 16])
    dst = ".".join(str(b) for b in frame[off + 16: off + 20])
    toff = off + ihl
    if len(frame) < toff + 20:
        raise AnalysisError("truncated TCP header in capture")
    sport, dport, seq, ack = struct.unpack_from("!HHII", frame, toff)
    doff = (frame[toff + 12] >> 4) * 4
    if doff < 20:
        raise AnalysisError("TCP data offset below 20 bytes")
    if len(frame) < toff + doff:
        raise AnalysisError("truncated TCP header in capture")
    flags = frame[toff + 13]
    payload_len = max(0, total_len - ihl - doff)
    payload = frame[toff + doff: toff + doff + payload_len]
    if not ((src == MASTER and dst == RELAY) or (src == RELAY and dst == MASTER)):
        return None
    if sport != DNP3_PORT and dport != DNP3_PORT:
        return None
    return TcpPacket(t_ns, src, dst, sport, dport, seq, ack, flags, payload)


def _tcp_packets(pcap_path: Path) -> list[TcpPacket]:
    packets = []
    last_ns = None
    seen_payload_seq = set()
    for t_ns, frame in iter_frames(pcap_path):
        if last_ns is not None and t_ns < last_ns:
            raise AnalysisError(f"non-monotonic capture timestamp in {pcap_path}")
        last_ns = t_ns
        pkt = _decode_tcp_packet(t_ns, frame)
        if pkt is None:
            continue
        if pkt.payload:
            key = (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.seq, len(pkt.payload))
            if key in seen_payload_seq:
                raise AnalysisError(f"retransmitted payload packet in {pcap_path}")
            seen_payload_seq.add(key)
        packets.append(pkt)
    return packets


def _validated_transactions(pcap_path: Path, txns: Sequence[object]) -> list[CaptureTransaction]:
    """Return transactions whose ACK is the first TCP ACK covering request bytes."""
    packets = _tcp_packets(pcap_path)
    by_time = {p.t_ns: p for p in packets if p.from_master and p.dnp3_func in FUNC_BY_NAME.values()}
    out = []
    for txn in txns:
        req = by_time.get(txn.t_req_ns)
        if req is None:
            raise AnalysisError(f"missing TCP request packet for transaction at {txn.t_req_ns}")
        if req.app_seq is None:
            raise AnalysisError("unsupported DNP3 request without observable app sequence")
        req_end = req.seq + len(req.payload)
        candidates = [
            p for p in packets
            if p.from_relay
            and p.t_ns >= txn.t_req_ns
            and (txn.t_resp_ns is None or p.t_ns <= txn.t_resp_ns)
            and (p.flags & TCP_ACK)
            and p.ack >= req_end
        ]
        if not candidates:
            raise AnalysisError(f"no relay TCP ACK covers request bytes at {txn.t_req_ns}")
        if txn.t_resp_ns is None:
            raise AnalysisError(f"missing DNP3 response for transaction at {txn.t_req_ns}")
        out.append(
            CaptureTransaction(
                req_func=txn.req_func,
                t_req_ns=txn.t_req_ns,
                t_ack_ns=candidates[0].t_ns,
                t_resp_ns=txn.t_resp_ns,
                app_seq=req.app_seq,
            )
        )
    return out


def rows_from_capture(
    pcap_path: str | Path,
    outcomes: Sequence[Outcome],
    **metadata,
) -> list[dict[str, object]]:
    pcap_path = Path(pcap_path)
    safety_polls = _output_status_poll_times(pcap_path)
    extracted = [t for t in extract_transactions(pcap_path) if t.t_req_ns not in safety_polls]
    txns = _validated_transactions(pcap_path, extracted)
    tx_counts = defaultdict(int)
    for txn in txns:
        tx_counts[NAME_BY_FUNC.get(txn.req_func, str(txn.req_func))] += 1
    out_counts = defaultdict(int)
    for outcome in outcomes:
        out_counts[outcome.operation] += 1
    if dict(tx_counts) != dict(out_counts):
        raise AnalysisError(f"capture/outcome operation counts differ: {dict(tx_counts)} vs {dict(out_counts)}")
    for idx, (txn, outcome) in enumerate(zip(txns, outcomes)):
        expected = outcome.raw.get("app_seq")
        observed = txn.app_seq
        if expected is not None and observed is not None and int(expected) != observed:
            raise AnalysisError(
                f"app_seq mismatch at row {idx}: capture {observed}, outcome {expected}"
            )
    rows = rows_from_transactions(txns, outcomes, **metadata)
    for row in rows:
        row["excluded_output_status_polls"] = len(safety_polls)
    return rows


def load_block(block_dir: str | Path) -> list[dict[str, object]]:
    """Load one fresh runner block directory into canonical analysis rows."""
    block_dir = Path(block_dir)
    policy = _read_optional_json(block_dir, ("policy.json", "logs/policy.json"))
    status = _read_optional_json(block_dir, ("status.json", "logs/status.json"))
    if status.get("failed") or status.get("ok") is False or status.get("error"):
        raise AnalysisError(f"{block_dir}: status.json reports failure")
    if int(status.get("outputs_before", 0) or 0) != 0 or int(status.get("outputs_after", 0) or 0) != 0:
        raise AnalysisError(f"{block_dir}: output readback reported nonzero failures")
    cap_path = _find_one(block_dir, ("traffic.pcap*", "raw_pcaps/*.pcap*"), "traffic capture")
    outcomes = _load_all_outcomes(list(block_dir.glob("*.jsonl")) + list(block_dir.glob("app_jsonl/*.jsonl")))
    if not outcomes:
        raise AnalysisError(f"{block_dir}: no outcome JSONL files found")
    _validate_status_counts(block_dir, status, outcomes)
    return rows_from_capture(
        cap_path,
        outcomes,
        session=status.get("session") or policy.get("session"),
        block=status.get("block") or policy.get("block") or block_dir.name,
        arm=status.get("arm") or policy.get("arm") or policy.get("condition"),
        mode=status.get("mode") or policy.get("mode"),
        policy=policy,
    )


def _validate_status_counts(block_dir: Path, status: Mapping[str, object], outcomes: Sequence[Outcome]) -> None:
    if not status:
        return
    if int(status.get("capture_exit", 0) or 0) != 0:
        raise AnalysisError(f"{block_dir}: capture process failed")
    counts = defaultdict(int)
    for outcome in outcomes:
        counts[outcome.operation] += 1
    planned_read = status.get("read_count")
    completed_read = status.get("read_completed", planned_read)
    if planned_read is not None and int(completed_read) != int(planned_read):
        raise AnalysisError(f"{block_dir}: READ completed {completed_read} != planned {planned_read}")
    expected_read = planned_read if planned_read is not None else completed_read
    if expected_read is not None and counts["READ"] != int(expected_read):
        raise AnalysisError(f"{block_dir}: READ count {counts['READ']} != expected {expected_read}")
    planned_sbo = status.get("sbo_count")
    completed_sbo = status.get("sbo_completed", planned_sbo)
    if planned_sbo is not None and int(completed_sbo) != int(planned_sbo):
        raise AnalysisError(f"{block_dir}: SBO completed {completed_sbo} != planned {planned_sbo}")
    expected_sbo = planned_sbo if planned_sbo is not None else completed_sbo
    if expected_sbo is not None:
        expected_sbo = int(expected_sbo)
        if counts["SELECT"] != expected_sbo or counts["OPERATE"] != expected_sbo:
            raise AnalysisError(
                f"{block_dir}: SBO counts SELECT={counts['SELECT']} OPERATE={counts['OPERATE']} != expected {expected_sbo}"
            )


def feature_matrix(rows: Sequence[Mapping[str, object]], feature_set: str = DEFAULT_FEATURE_SET):
    cols = FEATURE_SETS.get(feature_set)
    if cols is None:
        raise AnalysisError(f"unknown feature set {feature_set!r}")
    return np.array([[np.nan if r.get(c) is None else float(r[c]) for c in cols] for r in rows])


def latency_summary(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, dict[str, float]]]:
    out: dict[str, dict[str, dict[str, float]]] = {}
    for cls in CLASSES:
        selected = [r for r in rows if r.get("txn_class") == cls]
        if not selected:
            continue
        out[cls] = {}
        for metric in ("ack_ms", "clrt_ms", "rt_ms", "request_gap_ms"):
            vals = [float(r[metric]) for r in selected if r.get(metric) is not None]
            if not vals:
                continue
            out[cls][metric] = {
                "n": len(vals),
                "median": statistics.median(vals),
                "mean": statistics.fmean(vals),
                "min": min(vals),
                "max": max(vals),
                "p95": float(np.percentile(vals, 95)),
                "p99": float(np.percentile(vals, 99)),
            }
    return out


def validate_completeness(
    rows: Sequence[Mapping[str, object]],
    *,
    classes: Sequence[str] = CLASSES,
    arms: Sequence[str] = ("native", "obfuscated"),
    min_per_class: int = 1,
) -> None:
    problems = []
    sessions = sorted({r.get("session") for r in rows})
    for session in sessions:
        for arm in arms:
            for cls in classes:
                n = sum(
                    1
                    for r in rows
                    if r.get("session") == session and r.get("arm") == arm and r.get("txn_class") == cls
                )
                if n < min_per_class:
                    problems.append(f"missing {session}/{arm}/{cls}: {n} < {min_per_class}")
    if problems:
        raise AnalysisError("; ".join(problems[:8]))


def pooled_rows(rows: Sequence[Mapping[str, object]], pool_size: int) -> list[dict[str, object]]:
    if pool_size == 1:
        return [dict(r) for r in rows]
    groups: dict[tuple[object, object, object, object], list[Mapping[str, object]]] = defaultdict(list)
    for r in rows:
        groups[(r.get("session"), r.get("block"), r.get("arm"), r.get("txn_class"))].append(r)
    out = []
    for (session, block, arm, cls), group in sorted(groups.items(), key=lambda item: item[0]):
        group = sorted(group, key=lambda r: int(r.get("txn_index", 0)))
        for start in range(0, len(group) - pool_size + 1, pool_size):
            window = group[start:start + pool_size]
            pooled = {
                "session": session,
                "block": block,
                "arm": arm,
                "txn_class": cls,
                "pool_size": pool_size,
                "pool_start": start,
            }
            for metric in ("ack_ms", "clrt_ms", "rt_ms", "request_gap_ms"):
                vals = [float(r[metric]) for r in window if r.get(metric) is not None]
                if not vals:
                    continue
                arr = np.asarray(vals, dtype=float)
                pooled[f"{metric}_mean"] = float(arr.mean())
                pooled[f"{metric}_std"] = float(arr.std(ddof=0))
                pooled[f"{metric}_min"] = float(arr.min())
                pooled[f"{metric}_max"] = float(arr.max())
            out.append(pooled)
    return out


def _pooled_feature_matrix(rows: Sequence[Mapping[str, object]], feature_set: str):
    cols = FEATURE_SETS[feature_set]
    if rows and "pool_size" in rows[0] and rows[0]["pool_size"] != 1:
        expanded = []
        for base in cols:
            expanded.extend([f"{base}_mean", f"{base}_std", f"{base}_min", f"{base}_max"])
        cols = tuple(expanded)
    return np.array([[np.nan if r.get(c) is None else float(r[c]) for c in cols] for r in rows])


def _has_observed_feature(rows: Sequence[Mapping[str, object]], feature_set: str) -> bool:
    x = _pooled_feature_matrix(rows, feature_set)
    return x.size > 0 and bool(np.isfinite(x).any())


def _model(name: str):
    if name == "rf":
        return make_pipeline(
            SimpleImputer(strategy="median"),
            RandomForestClassifier(
                n_estimators=200,
                min_samples_leaf=3,
                random_state=0,
                n_jobs=-1,
                class_weight="balanced",
            ),
        )
    if name == "logistic":
        return make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced", multi_class="auto"),
        )
    if name == "rbf_svm":
        return make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            SVC(kernel="rbf", C=1.0, gamma="scale", class_weight="balanced"),
        )
    raise AnalysisError(f"unknown classifier {name!r}")


def _summary(scores: Sequence[float]) -> dict[str, float | int]:
    if not scores:
        return {"n_folds": 0, "mean_balanced_accuracy": float("nan")}
    arr = np.asarray(scores, dtype=float)
    return {
        "n_folds": int(arr.size),
        "mean_balanced_accuracy": float(arr.mean()),
        "median_balanced_accuracy": float(np.median(arr)),
        "min": float(arr.min()),
        "max": float(arr.max()),
    }


def _score_or_none(model_name, train_rows, test_rows, feature_set):
    if not test_rows:
        return None
    return _fit_score(model_name, train_rows, test_rows, feature_set)


def _fit_score(model_name, train_rows, test_rows, feature_set):
    x_train = _pooled_feature_matrix(train_rows, feature_set)
    y_train = np.array([r["txn_class"] for r in train_rows])
    x_test = _pooled_feature_matrix(test_rows, feature_set)
    y_test = np.array([r["txn_class"] for r in test_rows])
    keep = np.isfinite(x_train).any(axis=0)
    if not bool(keep.any()):
        raise AnalysisError(f"no observed training values for feature set {feature_set}")
    x_train = x_train[:, keep]
    x_test = x_test[:, keep]
    clf = _model(model_name).fit(x_train, y_train)
    return balanced_accuracy_score(y_test, clf.predict(x_test))


def _screening_bounds(task_result, group_field, iterations, seed, confidence):
    entries = []
    units = set()
    scenarios = ("adaptive_on_obfuscated", "fixed_on_obfuscated")
    for model_name, by_feature in task_result["classifiers"].items():
        for feature_set, by_pool in by_feature.items():
            for pool_key, record in by_pool.items():
                if record.get("available") is False:
                    continue
                for scenario in scenarios:
                    fold_scores = []
                    for fold in record["folds"]:
                        if scenario not in fold:
                            continue
                        fold_scores.append((fold["test_group"], float(fold[scenario])))
                        units.add(fold["test_group"])
                    if fold_scores:
                        entries.append((model_name, feature_set, pool_key, scenario, fold_scores))
    if not entries:
        return {
            "unit": group_field,
            "confidence": confidence,
            "n_units": 0,
            "n_bootstrap": iterations,
            "max_observed_balanced_accuracy": float("nan"),
            "max_upper_bound_balanced_accuracy": float("nan"),
            "included_scenarios": list(scenarios),
            "method": "centered_group_bootstrap_max_deviation",
            "note": "no classifier fold scores available",
        }
    observed = [statistics.fmean(score for _, score in fold_scores) for *_, fold_scores in entries]
    observed_by_attack = np.asarray(observed, dtype=float)
    attack_scores = []
    common_units = sorted(set.intersection(*[set(group for group, _ in fold_scores)
                                             for *_, fold_scores in entries]))
    if not common_units:
        raise AnalysisError("no common held-out groups across attacks for simultaneous screening")
    for *_head, fold_scores in entries:
        by_group = dict(fold_scores)
        attack_scores.append([by_group[group] for group in common_units])
    attack_scores = np.asarray(attack_scores, dtype=float)
    rng = np.random.default_rng(seed)
    max_deviations = []
    for _ in range(iterations):
        idx = rng.integers(0, len(common_units), len(common_units))
        replicate_means = attack_scores[:, idx].mean(axis=1)
        max_deviations.append(float(np.max(replicate_means - observed_by_attack)))
    margin = max(0.0, float(np.percentile(max_deviations, 100 * confidence)))
    upper = min(1.0, float(max(observed) + margin))
    note = "screening only; centered group bootstrap max-deviation bound across protected attacks"
    if len(units) <= 5:
        note += "; only %d %s units" % (len(units), group_field)
    return {
        "unit": group_field,
        "confidence": confidence,
        "n_units": len(units),
        "n_bootstrap": iterations,
        "method": "centered_group_bootstrap_max_deviation",
        "included_scenarios": list(scenarios),
        "max_observed_balanced_accuracy": float(max(observed)),
        "max_upper_bound_balanced_accuracy": upper,
        "note": note,
    }


def _evaluate_task(
    rows: Sequence[Mapping[str, object]],
    *,
    task_name: str,
    classes: Sequence[str],
    group_field: str,
    pools: Sequence[int] = (1, 5, 20),
    classifiers: Sequence[str] = ("rf", "logistic", "rbf_svm"),
    feature_sets: Sequence[str] = ("clrt", "ack_clrt", "request_gap", "ack_clrt_gap"),
    min_train_per_class: int = 5,
) -> dict[str, object]:
    task_rows = [r for r in rows if r.get("txn_class") in classes]
    validate_completeness(task_rows, classes=classes)
    groups = sorted({r.get(group_field) for r in task_rows})
    result = {
        "task": task_name,
        "classes": list(classes),
        "group_field": group_field,
        "chance_balanced_accuracy": 1.0 / len(classes),
        "feature_sets": {k: list(FEATURE_SETS[k]) for k in feature_sets},
        "classifiers": {},
    }
    for model_name in classifiers:
        result["classifiers"][model_name] = {}
        for feature_set in feature_sets:
            result["classifiers"][model_name][feature_set] = {}
            for pool_size in pools:
                pooled = pooled_rows(task_rows, pool_size)
                if not _has_observed_feature(pooled, feature_set):
                    result["classifiers"][model_name][feature_set][f"pool{pool_size}"] = {
                        "available": False,
                        "reason": f"no observed values for feature set {feature_set}",
                    }
                    continue
                folds = []
                fixed_native_scores = []
                fixed_obf_scores = []
                adaptive_obf_scores = []
                for group in groups:
                    train_native = [
                        r for r in pooled if r.get(group_field) != group and r.get("arm") == "native"
                    ]
                    train_obf = [
                        r for r in pooled if r.get(group_field) != group and r.get("arm") == "obfuscated"
                    ]
                    test_native = [
                        r for r in pooled if r.get(group_field) == group and r.get("arm") == "native"
                    ]
                    test_obf = [
                        r for r in pooled if r.get(group_field) == group and r.get("arm") == "obfuscated"
                    ]
                    for label, candidate in (("native train", train_native), ("obfuscated train", train_obf)):
                        counts = {c: sum(1 for r in candidate if r.get("txn_class") == c) for c in classes}
                        if min(counts.values()) < min_train_per_class:
                            raise AnalysisError(f"{label} for held-out {group} lacks training rows: {counts}")
                    fixed_native = _score_or_none(model_name, train_native, test_native, feature_set)
                    fixed_obf = _score_or_none(model_name, train_native, test_obf, feature_set)
                    adaptive_obf = _score_or_none(model_name, train_obf, test_obf, feature_set)
                    test_sessions = sorted({r.get("session") for r in test_native + test_obf})
                    fold = {
                        "test_group": group,
                        "test_session": test_sessions[0] if len(test_sessions) == 1 else None,
                        "train_groups_fixed": sorted({r.get(group_field) for r in train_native}),
                        "train_groups_adaptive": sorted({r.get(group_field) for r in train_obf}),
                        "train_sessions_fixed": sorted({r.get("session") for r in train_native}),
                        "train_sessions_adaptive": sorted({r.get("session") for r in train_obf}),
                        "n_test_native": len(test_native),
                        "n_test_obfuscated": len(test_obf),
                    }
                    if fixed_native is not None:
                        fixed_native_scores.append(fixed_native)
                        fold["fixed_on_native"] = float(fixed_native)
                    if fixed_obf is not None:
                        fixed_obf_scores.append(fixed_obf)
                        fold["fixed_on_obfuscated"] = float(fixed_obf)
                    if adaptive_obf is not None:
                        adaptive_obf_scores.append(adaptive_obf)
                        fold["adaptive_on_obfuscated"] = float(adaptive_obf)
                    folds.append(fold)
                result["classifiers"][model_name][feature_set][f"pool{pool_size}"] = {
                    "available": True,
                    "folds": folds,
                    "summary": {
                        "fixed_on_native": _summary(fixed_native_scores),
                        "fixed_on_obfuscated": _summary(fixed_obf_scores),
                        "adaptive_on_obfuscated": _summary(adaptive_obf_scores),
                    },
                }
    return result


def evaluate_attackers(
    rows: Sequence[Mapping[str, object]],
    *,
    group_field: str = "block",
    pools: Sequence[int] = (1, 5, 20),
    classifiers: Sequence[str] = ("rf", "logistic", "rbf_svm"),
    feature_sets: Sequence[str] = ("clrt", "ack_clrt", "request_gap", "ack_clrt_gap"),
    tasks: Sequence[str] = ("three_class",),
    min_train_per_class: int = 5,
    bootstrap_iterations: int = 500,
    bootstrap_seed: int = 20260926,
    confidence: float = 0.95,
) -> dict[str, object]:
    """Evaluate fixed and adaptive attackers with grouped held-out splits."""
    task_defs = {
        "three_class": CLASSES,
        "read_select": BINARY_CLASSES,
    }
    out = {"tasks": {}}
    for task in tasks:
        if task not in task_defs:
            raise AnalysisError(f"unknown task {task!r}")
        task_result = _evaluate_task(
            rows,
            task_name=task,
            classes=task_defs[task],
            group_field=group_field,
            pools=pools,
            classifiers=classifiers,
            feature_sets=feature_sets,
            min_train_per_class=min_train_per_class,
        )
        task_result["simultaneous_screening"] = _screening_bounds(
            task_result, group_field, bootstrap_iterations, bootstrap_seed, confidence
        )
        out["tasks"][task] = task_result
    if "three_class" in out["tasks"]:
        out["classes"] = out["tasks"]["three_class"]["classes"]
        out["chance_balanced_accuracy"] = out["tasks"]["three_class"]["chance_balanced_accuracy"]
        out["feature_sets"] = out["tasks"]["three_class"]["feature_sets"]
        out["classifiers"] = out["tasks"]["three_class"]["classifiers"]
        out["simultaneous_screening"] = out["tasks"]["three_class"]["simultaneous_screening"]
    return out


def _policy_key(row: Mapping[str, object]) -> str:
    for key in ("policy_name", "policy", "mode"):
        if row.get(key) not in (None, ""):
            return str(row[key])
    parts = []
    for key in ("policy_da_ms", "policy_new_clrt_ms", "policy_gap_ms"):
        if row.get(key) is not None:
            parts.append(f"{key.replace('policy_', '')}={row[key]}")
    return ",".join(parts) if parts else "unlabeled"


def _is_native_policy(policy: str, rows: Sequence[Mapping[str, object]]) -> bool:
    if policy.lower() in ("off", "native", "ref_off", "timing_off"):
        return True
    return all(r.get("arm") == "native" for r in rows)


def analyse_rows(
    rows: Sequence[Mapping[str, object]],
    *,
    group_field: str = "block",
    pools: Sequence[int] = (1, 5, 20),
    classifiers: Sequence[str] = ("rf", "logistic", "rbf_svm"),
    feature_sets: Sequence[str] = ("clrt", "ack_clrt", "request_gap", "ack_clrt_gap"),
    tasks: Sequence[str] = ("three_class",),
    min_train_per_class: int = 5,
    bootstrap_iterations: int = 500,
    bootstrap_seed: int = 20260926,
) -> dict[str, object]:
    per_policy = {}
    grouped = defaultdict(list)
    for row in rows:
        grouped[_policy_key(row)].append(row)
    native_rows = []
    for policy, policy_rows in grouped.items():
        if _is_native_policy(policy, policy_rows):
            native_rows.extend(policy_rows)
    for policy, policy_rows in sorted(grouped.items()):
        if _is_native_policy(policy, policy_rows):
            continue
        paired_rows = list(native_rows) + list(policy_rows)
        effective_group_field = "session" if native_rows else group_field
        per_policy[policy] = {
            "n_rows": len(paired_rows),
            "protected_rows": len(policy_rows),
            "native_rows": len(native_rows),
            "latency_summary": latency_summary(paired_rows),
            "attackers": evaluate_attackers(
                paired_rows,
                group_field=effective_group_field,
                pools=pools,
                classifiers=classifiers,
                feature_sets=feature_sets,
                tasks=tasks,
                min_train_per_class=min_train_per_class,
                bootstrap_iterations=bootstrap_iterations,
                bootstrap_seed=bootstrap_seed,
            ),
        }
    return {
        "n_rows": len(rows),
        "latency_summary": latency_summary(rows),
        "per_policy": per_policy,
    }


def analyse_blocks(block_dirs: Iterable[str | Path], **kwargs) -> dict[str, object]:
    rows = [row for block in block_dirs for row in load_block(block)]
    return {
        **analyse_rows(rows, **kwargs),
        "attackers": evaluate_attackers(rows, **kwargs),
    }
