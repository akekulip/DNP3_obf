"""event_clear: class-2 poll + application CONFIRM; emits only READ/CONFIRM."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import event_clear as ec  # noqa: E402
from dnp3_codec import crc_le, parse_frame  # noqa: E402


def response(seq, iin1, con, objects=b''):
    app = bytes([0xC0 | (0x20 if con else 0) | seq, 0x81, iin1, 0x00]) + objects
    user = bytes([0xC0]) + app
    header = bytes([0x05, 0x64, 5 + len(user), 0x44, 0x01, 0x00, 0x00, 0x00])
    out = header + crc_le(header)
    for i in range(0, len(user), 16):
        out += user[i:i + 16] + crc_le(user[i:i + 16])
    return out


class FakeSock:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def sendall(self, frame):
        self.sent.append(frame)

    def settimeout(self, _):
        pass

    def recv(self, _):
        if not self.replies:
            raise OSError('timeout')
        return self.replies.pop(0)


class FakeSession:
    def __init__(self, sock):
        self.sock = sock


def test_confirm_frame_is_a_valid_confirm():
    frame = ec.confirm_frame(5)
    parsed, rest = parse_frame(frame)
    assert parsed is not None and not rest
    assert frame[11] == 0xC5 and frame[12] == 0x00


def test_events_confirmed_then_cleared():
    sock = FakeSock([response(0, 0x84, True, b'\x02\x01\x17\x01\x00\x01'), response(1, 0x80, False),
                     response(2, 0x80, False)])
    result = ec.clear(FakeSession(sock))
    assert result['ok'] is True and result['final_iin'] == '8000'
    functions = [frame[12] for frame in sock.sent]
    assert functions == [0x01, 0x00, 0x01, 0x01]            # class-2 READ, CONFIRM, class-2 READ, class-0 READ
    assert sock.sent[1][11] == 0xC0                          # confirm echoes the response sequence 0
    assert result['functions_sent'] == [0x00, 0x01]


def test_still_pending_after_max_polls_is_not_ok():
    sock = FakeSock([response(i, 0x84, True) for i in range(ec.MAX_POLLS)] + [response(3, 0x84, False)])
    result = ec.clear(FakeSession(sock))
    assert result['ok'] is False and len(result['polls']) == ec.MAX_POLLS


def test_refuses_any_other_function():
    import pytest
    bad = bytearray(ec.confirm_frame(0)); bad[12] = 0x04
    with pytest.raises(ValueError):
        ec._send(FakeSock([]), bytes(bad), [])
