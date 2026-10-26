"""event_clear: class-2 poll + application CONFIRM; emits only READ/CONFIRM."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import event_clear as ec  # noqa: E402
from dnp3_codec import crc_le, parse_frame  # noqa: E402


def response(seq, iin1, con, objects=b'', *, control=None, function=0x81):
    if control is None:
        control = 0xC0 | (0x20 if con else 0) | seq
    app = bytes([control, function, iin1, 0x00]) + objects
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


class ReplyOnReadSock(FakeSock):
    """Release each response's TCP chunks only after its READ is sent."""
    def __init__(self, responses):
        super().__init__([])
        self.responses = iter(responses)

    def sendall(self, frame):
        super().sendall(frame)
        if frame[12] == 0x01:
            self.replies.extend(next(self.responses, []))


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
    bad = bytearray(ec.confirm_frame(0)); bad[12] = 0x04
    with pytest.raises(ValueError):
        ec._send(FakeSock([]), bytes(bad), [])


@pytest.mark.parametrize('delivery', ['separate', 'coalesced', 'split'])
def test_multifragment_events_confirm_each_fragment_and_advance_next_read(delivery):
    first = response(0, 0x84, True, b'\x02\x01\x17\x01\x00\x01', control=0xA0)
    final = response(1, 0x80, True, control=0x61)
    chunks = [first, final] if delivery == 'separate' else [first + final]
    if delivery == 'split':
        chunks = [bytes([octet]) for octet in first + final]
    sock = ReplyOnReadSock([chunks, [response(2, 0x80, False)]])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is True and result['final_iin'] == '8000'
    assert len(result['polls']) == 1
    assert [item['control'] for item in result['polls'][0]['fragments']] == [0xA0, 0x61]
    assert [item['control'] for item in result['class0_check']] == [0xC2]
    assert [(frame[12], frame[11]) for frame in sock.sent] == [
        (0x01, 0xC0), (0x00, 0xC0), (0x00, 0xC1), (0x01, 0xC2)]


def test_leftover_class2_final_cannot_replace_missing_class0_response():
    sock = ReplyOnReadSock([
        [response(0, 0x80, True, control=0xA0), response(1, 0x80, True, control=0x61)],
        [],
    ])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is False
    assert result['class0_check'] == [] and result['final_iin'] is None
    assert [frame[11] for frame in sock.sent if frame[12] == 0x01] == [0xC0, 0xC2]


@pytest.mark.parametrize(('control', 'function'), [
    (0xC0, 0x81),  # stale response to the class-2 READ
    (0xC2, 0x81),  # wrong sequence for the class-0 READ
    (0xC1, 0x01),  # matching sequence, wrong function
    (0xD1, 0x81),  # unsolicited control bit
    (0xD1, 0x82),  # unsolicited response function
    (0x41, 0x81),  # final fragment without a first fragment
    (0x81, 0x81),  # first fragment without a final fragment
])
def test_class0_rejects_unmatched_or_incomplete_response(control, function):
    sock = ReplyOnReadSock([
        [response(0, 0x80, False)],
        [response(1, 0x80, False, control=control, function=function)],
    ])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is False and result['final_iin'] is None


@pytest.mark.parametrize(('control', 'function'), [(0x63, 0x81), (0x62, 0x82), (0xF2, 0x81)])
def test_class0_continuation_must_match_sequence_function_and_solicited_flags(control, function):
    sock = ReplyOnReadSock([
        [response(0, 0x80, False)],
        [response(1, 0x80, True, control=0xA1),
         response(2, 0x80, True, control=control, function=function)],
    ])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is False and result['final_iin'] is None
    assert [frame[11] for frame in sock.sent if frame[12] == 0x00] == [0xC1]


def test_class0_accepts_complete_multifragment_response():
    sock = ReplyOnReadSock([
        [response(0, 0x80, False)],
        [response(1, 0x84, True, control=0xA1) + response(2, 0x80, True, control=0x62)],
    ])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is True and result['final_iin'] == '8000'
    assert [item['control'] for item in result['class0_check']] == [0xA1, 0x62]
    assert [frame[11] for frame in sock.sent if frame[12] == 0x00] == [0xC1, 0xC2]


def test_stale_and_unsolicited_fragments_are_skipped_before_class0_response():
    sock = ReplyOnReadSock([
        [response(0, 0x80, False)],
        [response(0, 0x84, True) + response(1, 0x84, True, control=0xF1, function=0x82)
         + response(1, 0x80, False)],
    ])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is True and result['final_iin'] == '8000'
    assert [item['control'] for item in result['class0_check']] == [0xC1]
    assert result['functions_sent'] == [0x01]


def test_truncated_link_frame_cannot_verify_class0():
    sock = ReplyOnReadSock([[response(0, 0x80, False)], [response(1, 0x80, False)[:-1]]])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is False and result['final_iin'] is None


def test_application_fragment_sequence_wraps_before_next_read():
    fragments = [response(0, 0x84, True, control=0xA0)]
    fragments.extend(response(seq, 0x84, True, control=0x20 | seq) for seq in range(1, 16))
    fragments.append(response(0, 0x80, True, control=0x60))
    sock = ReplyOnReadSock([fragments, [response(1, 0x80, False)]])

    result = ec.clear(FakeSession(sock))

    assert result['ok'] is True
    assert len(result['polls']) == 1 and len(result['polls'][0]['fragments']) == 17
    assert [frame[11] for frame in sock.sent if frame[12] == 0x01] == [0xC0, 0xC1]
    assert [frame[11] for frame in sock.sent if frame[12] == 0x00] == list(range(0xC0, 0xD0)) + [0xC0]
