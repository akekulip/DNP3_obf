"""phase01_reconstruct.py -- rich per-transaction reconstruction for Phase 01.

Reuses the *canonical* tshark packet parsing and COMBINED/SEPARATE/OTHER classification
from characterize_ack_traces.py (the authorized canonical extractor) and enriches each
transaction with the full Phase 01 field set (§4): request/first-reverse/pure-ACK/response
frames, timestamps, seq/ack, TCP+IP lengths, flags, the four inter-event delays, anomaly
counts, a missing-response flag, an ambiguity reason, and a classification confidence.

Nothing here modifies timing, ACK, or split behavior; it only reads PCAPs.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, asdict
from typing import List, Optional

import characterize_ack_traces as C

REFERENCE_IP = C.REFERENCE_IP
DNP3_PORT = C.DNP3_PORT


@dataclass
class RichTransaction:
    capture: str
    device_label: str
    is_reference: bool
    master_ip: str
    master_port: int
    outstation_ip: str
    outstation_port: int
    tcp_stream: int
    connection_id: str
    # request
    req_frame: int
    req_time_epoch: float
    req_seq: int
    req_ack: int
    req_flags: str
    req_tcp_len: int
    req_ip_len: int
    req_func: Optional[int]
    # first reverse-direction packet
    first_rev_frame: Optional[int]
    first_rev_time_epoch: Optional[float]
    first_rev_tcp_len: Optional[int]
    first_rev_flags: Optional[str]
    # pure TCP ACK (defined only for SEPARATE_ACK_RESPONSE)
    pure_ack_present: bool
    pure_ack_frame: Optional[int]
    pure_ack_time_epoch: Optional[float]
    pure_ack_seq: Optional[int]
    pure_ack_ack: Optional[int]
    # DNP3 response
    resp_frame: Optional[int]
    resp_time_epoch: Optional[float]
    resp_tcp_len: Optional[int]
    resp_ip_len: Optional[int]
    resp_flags: Optional[str]
    resp_func: Optional[int]
    # delays (ms)
    req_to_first_rev_ms: Optional[float]
    req_to_pure_ack_ms: Optional[float]
    pure_ack_to_resp_ms: Optional[float]
    req_to_resp_ms: Optional[float]
    # anomalies
    retransmission_count: int
    duplicate_ack_count: int
    out_of_order: bool
    reset: bool
    missing_response: bool
    # per-transaction shape (request through response inclusive)
    packet_count: int
    transaction_ip_bytes: int
    # classification
    classification: str
    classification_confidence: str
    ambiguity_reason: str
    # refined orthogonal decomposition (reviewer request): ACK mode is definable even for a
    # multi-segment (crc-split) response, so it is kept separate from how the bytes were delivered.
    ack_mode: str            # COMBINED / SEPARATE / UNDETERMINED
    response_delivery: str   # FULL / MULTI_SEGMENT / AMBIGUOUS


def _ms(a: Optional[float], b: Optional[float]) -> Optional[float]:
    if a is None or b is None:
        return None
    return round((a - b) * 1000.0, 6)


def build_rich_transactions(packets, pcap: str, device_label: str) -> List[RichTransaction]:
    """Mirror characterize_ack_traces.build_transactions classification, enriched."""
    flows = {}
    for p in packets:
        flows.setdefault(p.stream, []).append(p)

    out: List[RichTransaction] = []
    for stream, pkts in sorted(flows.items()):
        pkts.sort(key=lambda p: p.frame)

        out_ip = out_port = mst_ip = mst_port = None
        for p in pkts:
            if p.dst_port == DNP3_PORT:
                out_ip, out_port, mst_ip, mst_port = p.dst_ip, p.dst_port, p.src_ip, p.src_port
                break
            if p.src_port == DNP3_PORT:
                out_ip, out_port, mst_ip, mst_port = p.src_ip, p.src_port, p.dst_ip, p.dst_port
                break
        if out_ip is None:
            continue

        def is_request(p):
            return p.dst_ip == out_ip and p.dst_port == DNP3_PORT and p.tlen > 0 and p.dnp3_present

        def is_reverse(p):
            return p.src_ip == out_ip and p.src_port == DNP3_PORT

        req_idx = [i for i, p in enumerate(pkts) if is_request(p)]
        for k, i in enumerate(req_idx):
            req = pkts[i]
            end = req_idx[k + 1] if k + 1 < len(req_idx) else len(pkts)
            window = pkts[i + 1:end]

            rev = [p for p in window if is_reverse(p)]
            first_rev = rev[0] if rev else None
            first_ack = next((p for p in rev if p.ackf), None)
            first_resp = next((p for p in rev if p.tlen > 0 and p.dnp3_present), None)
            first_pure_ack = next((p for p in rev if C._is_pure_tcp_ack(p)), None)

            retrans_count = sum(1 for p in window if p.retrans)
            dup_ack_count = sum(1 for p in window if p.dup_ack)
            reset = any(p.rst for p in window)
            ooo = any(p.ooo for p in window)

            first_rev_pure = bool(first_rev and C._is_pure_tcp_ack(first_rev))

            # --- canonical classification (identical to characterize_ack_traces) ----
            reason = ""
            if first_resp is None:
                cls = C.CLS_OTHER
                reason = "no DNP3 response found in window"
            elif first_rev is not None and (first_rev.syn or first_rev.fin or first_rev.rst):
                cls = C.CLS_OTHER
                reason = "first reverse packet is a TCP control (SYN/FIN/RST)"
            elif first_rev_pure:
                if first_resp is not first_rev:
                    cls = C.CLS_SEPARATE
                else:
                    cls = C.CLS_OTHER
                    reason = "pure-ACK packet also flagged as response (inconsistent)"
            elif first_rev is not None and first_rev.tlen > 0 and first_rev.dnp3_present:
                if first_resp is first_rev:
                    cls = C.CLS_COMBINED
                else:
                    cls = C.CLS_OTHER
                    reason = "first reverse payload differs from first DNP3 response"
            else:
                cls = C.CLS_OTHER
                reason = "first reverse packet neither pure ACK nor DNP3 payload"

            # pure ACK is meaningful only for the SEPARATE class
            pure_present = cls == C.CLS_SEPARATE and first_pure_ack is not None
            pack = first_pure_ack if pure_present else None

            # per-transaction packet span: request through response inclusive
            if first_resp is not None:
                span = [req] + [p for p in window if p.frame <= first_resp.frame]
            else:
                span = [req] + list(window)
            packet_count = len(span)
            transaction_ip_bytes = sum(p.frame_len for p in span)

            anomalous = retrans_count or dup_ack_count or reset or ooo
            if cls == C.CLS_OTHER:
                confidence = "low"
            elif anomalous:
                confidence = "medium"
            else:
                confidence = "high"

            # --- refined orthogonal decomposition (reviewer request) -----------------
            # ack_mode depends ONLY on whether a standalone pure TCP ACK precedes the FIRST
            # payload-bearing reverse segment -- independent of how many segments the response
            # arrives in -- so a multi-segment (crc-split) response is no longer "unknowable".
            payload_revs = [p for p in rev if p.tlen > 0]
            first_payload = payload_revs[0] if payload_revs else None
            if first_payload is None:
                ack_mode = "UNDETERMINED"
                response_delivery = "AMBIGUOUS"
            else:
                if first_rev is not None and (first_rev.syn or first_rev.fin or first_rev.rst):
                    response_delivery = "AMBIGUOUS"
                elif len(payload_revs) == 1:
                    response_delivery = "FULL"
                else:
                    response_delivery = "MULTI_SEGMENT"
                pure_before = next((p for p in rev if C._is_pure_tcp_ack(p)
                                    and p.frame < first_payload.frame), None)
                ack_mode = "SEPARATE" if pure_before is not None else "COMBINED"

            out.append(RichTransaction(
                capture=os.path.basename(pcap),
                device_label=device_label,
                is_reference=(out_ip == REFERENCE_IP),
                master_ip=mst_ip, master_port=mst_port,
                outstation_ip=out_ip, outstation_port=out_port,
                tcp_stream=stream,
                connection_id="{}:{}<->{}:{}#s{}".format(mst_ip, mst_port, out_ip, out_port, stream),
                req_frame=req.frame, req_time_epoch=req.t, req_seq=req.seq, req_ack=req.ack,
                req_flags=req.flags, req_tcp_len=req.tlen, req_ip_len=req.frame_len, req_func=req.dnp3_func,
                first_rev_frame=(first_rev.frame if first_rev else None),
                first_rev_time_epoch=(first_rev.t if first_rev else None),
                first_rev_tcp_len=(first_rev.tlen if first_rev else None),
                first_rev_flags=(first_rev.flags if first_rev else None),
                pure_ack_present=pure_present,
                pure_ack_frame=(pack.frame if pack else None),
                pure_ack_time_epoch=(pack.t if pack else None),
                pure_ack_seq=(pack.seq if pack else None),
                pure_ack_ack=(pack.ack if pack else None),
                resp_frame=(first_resp.frame if first_resp else None),
                resp_time_epoch=(first_resp.t if first_resp else None),
                resp_tcp_len=(first_resp.tlen if first_resp else None),
                resp_ip_len=(first_resp.frame_len if first_resp else None),
                resp_flags=(first_resp.flags if first_resp else None),
                resp_func=(first_resp.dnp3_func if first_resp else None),
                req_to_first_rev_ms=_ms(first_rev.t if first_rev else None, req.t),
                req_to_pure_ack_ms=_ms(pack.t if pack else None, req.t),
                pure_ack_to_resp_ms=_ms(first_resp.t if (pure_present and first_resp) else None,
                                        pack.t if pack else None),
                req_to_resp_ms=_ms(first_resp.t if first_resp else None, req.t),
                retransmission_count=retrans_count,
                duplicate_ack_count=dup_ack_count,
                out_of_order=ooo, reset=reset,
                missing_response=(first_resp is None),
                packet_count=packet_count, transaction_ip_bytes=transaction_ip_bytes,
                classification=cls, classification_confidence=confidence,
                ambiguity_reason=reason,
                ack_mode=ack_mode, response_delivery=response_delivery,
            ))
    return out


def reconstruct_all(traffic_dir: str):
    """Reconstruct rich transactions across every *.pcap under traffic_dir.

    Returns (transactions, pcap_paths). Deterministic ordering.
    """
    pcaps = sorted(glob.glob(os.path.join(traffic_dir, "*.pcap")))
    all_txns: List[RichTransaction] = []
    for pcap in pcaps:
        name = os.path.basename(pcap)
        device = C.device_from_pcap(pcap)
        packets = C.run_tshark(pcap)
        all_txns += build_rich_transactions(packets, pcap, device)
    all_txns.sort(key=lambda t: (t.capture, t.tcp_stream, t.req_frame))
    return all_txns, pcaps


RICH_COLUMNS = list(RichTransaction.__annotations__.keys())


def to_row(t: RichTransaction) -> dict:
    return asdict(t)
