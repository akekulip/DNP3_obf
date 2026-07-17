"""Unit tests for full logical-response reconstruction (Phase 05 defended-wire extractor).

Covers: single-segment response, multi-segment ordering by TCP sequence, retransmitted-segment
de-duplication, transaction-boundary detection, and exact source-vs-replay byte equality.

    python3 -m pytest tests/test_response_reconstruction.py
    python3 tests/test_response_reconstruction.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import characterize_ack_traces as C
import phase05_defended_wire_eval as DW


def _pkt(frame, seq, src_port, tlen, dnp3=True):
    """Minimal Packet; src_port==20000 => outstation->master (a response segment)."""
    dst_port = 111 if src_port == C.DNP3_PORT else C.DNP3_PORT
    return C.Packet(frame=frame, t=0.0, stream=0, src_ip="o", dst_ip="m",
                    src_port=src_port, dst_port=dst_port, seq=seq, ack=0, tlen=tlen,
                    flags="", syn=False, fin=False, rst=False, ackf=True,
                    retrans=False, dup_ack=False, ooo=False,
                    dnp3_func=(129 if dnp3 else None), dnp3_present=dnp3, frame_len=tlen + 54)


def test_single_segment():
    data, n = DW.reconstruct_response([(1000, 6, b"\x05\x64hello")])
    assert n == 1 and data == b"\x05\x64hello"


def test_multi_segment_ordered_by_seq():
    # supplied out of frame order; TCP sequence defines byte order
    data, n = DW.reconstruct_response([(2000, 7, b"WORLD"), (1000, 6, b"HELLO")])
    assert n == 2 and data == b"HELLOWORLD"


def test_retransmit_deduplicated():
    segs = [(1000, 6, b"HELLO"), (1000, 8, b"HELLO"), (2000, 7, b"WORLD")]  # seq 1000 retransmitted
    data, n = DW.reconstruct_response(segs)
    assert n == 2 and data == b"HELLOWORLD"


def test_transaction_boundary():
    # response segments belong to the window [resp_frame, next_req_frame); later segments excluded
    packets = [
        _pkt(5, 500, 111, 20),                 # request
        _pkt(6, 1000, C.DNP3_PORT, 30),        # response seg 1 (resp_frame=6)
        _pkt(7, 1030, C.DNP3_PORT, 10),        # response seg 2
        _pkt(9, 600, 111, 20),                 # NEXT request (frame 9)
        _pkt(10, 1040, C.DNP3_PORT, 40),       # belongs to the next transaction -> excluded
    ]
    payloads = {6: b"A" * 30, 7: b"B" * 10, 10: b"C" * 40}
    segs = DW._collect_response_segments(packets, payloads, stream=0, resp_frame=6, next_req_frame=9)
    data, n = DW.reconstruct_response(segs)
    assert n == 2 and data == b"A" * 30 + b"B" * 10


def test_source_replay_byte_equality():
    payload = b"\x05\x64\x1f\x81" + bytes(range(60))
    data, n = DW.reconstruct_response([(1000, 6, payload)])
    assert n == 1 and data == payload


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)


if __name__ == "__main__":
    _run()
