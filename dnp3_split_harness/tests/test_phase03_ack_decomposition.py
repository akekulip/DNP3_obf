"""Unit tests for the refined ACK-mode / response-delivery decomposition
(phase01_reconstruct.build_rich_transactions).

Reviewer requirement: a multi-segment (crc-split) response must NOT make the ACK mode
unknowable. ack_mode depends only on whether a standalone pure TCP ACK precedes the FIRST
payload-bearing reverse segment; response_delivery separately records FULL / MULTI_SEGMENT.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import characterize_ack_traces as C  # noqa: E402
import phase01_reconstruct as R      # noqa: E402

PORT = R.DNP3_PORT
MST, OUT = "10.0.0.3", "10.0.0.9"    # non-reference outstation IP


def pkt(frame, stream, to_out, tlen, *, dnp3=False, ackf=True, pure=False):
    """Build a Packet. to_out=True is a master->outstation request direction."""
    src_ip, dst_ip = (MST, OUT) if to_out else (OUT, MST)
    src_port, dst_port = (40000, PORT) if to_out else (PORT, 40000)
    return C.Packet(
        frame=frame, t=frame * 0.001, stream=stream, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, seq=frame, ack=frame, tlen=tlen,
        flags="0x0010", syn=False, fin=False, rst=False, ackf=ackf,
        retrans=False, dup_ack=False, ooo=False,
        dnp3_func=(129 if dnp3 else None), dnp3_present=dnp3, frame_len=tlen + 54)


def _one(packets):
    txns = R.build_rich_transactions(packets, "synthetic.pcap", "synthetic")
    assert len(txns) == 1, "expected exactly one reconstructed transaction"
    return txns[0]


def test_full_combined():
    t = _one([pkt(1, 1, True, 20, dnp3=True),           # request
              pkt(2, 1, False, 40, dnp3=True)])          # response carries the ACK
    assert t.classification == C.CLS_COMBINED
    assert t.ack_mode == "COMBINED"
    assert t.response_delivery == "FULL"


def test_full_separate():
    t = _one([pkt(1, 2, True, 20, dnp3=True),            # request
              pkt(2, 2, False, 0, pure=True),            # standalone pure ACK
              pkt(3, 2, False, 40, dnp3=True)])          # response later
    assert t.classification == C.CLS_SEPARATE
    assert t.ack_mode == "SEPARATE"
    assert t.response_delivery == "FULL"


def test_multi_segment_combined_was_other():
    # First chunk is a payload segment tshark does NOT tag as DNP3 -> old scheme = OTHER,
    # but ack_mode is still COMBINED (no pure ACK precedes the first payload segment).
    t = _one([pkt(1, 3, True, 20, dnp3=True),            # request
              pkt(2, 3, False, 18, dnp3=False),          # chunk 1 (payload, no dnp3 header)
              pkt(3, 3, False, 18, dnp3=True)])          # chunk 2 (dnp3 header)
    assert t.classification == C.CLS_OTHER                # old scheme could not classify
    assert t.ack_mode == "COMBINED"                       # but ack_mode IS determinable
    assert t.response_delivery == "MULTI_SEGMENT"


def test_multi_segment_separate():
    t = _one([pkt(1, 4, True, 20, dnp3=True),            # request
              pkt(2, 4, False, 0, pure=True),            # standalone pure ACK first
              pkt(3, 4, False, 18, dnp3=False),          # chunk 1
              pkt(4, 4, False, 18, dnp3=True)])          # chunk 2
    assert t.ack_mode == "SEPARATE"
    assert t.response_delivery == "MULTI_SEGMENT"


def test_missing_response_is_undetermined():
    t = _one([pkt(1, 5, True, 20, dnp3=True),            # request
              pkt(2, 5, False, 0, pure=True)])           # only a bare ACK, no payload ever
    assert t.ack_mode == "UNDETERMINED"
    assert t.response_delivery == "AMBIGUOUS"
    assert t.missing_response is True
