#!/usr/bin/env python3
"""Offline tests for the corrected harness. No socket, no hardware, no capture is touched.

The suite is adversarial on purpose: most cases feed the codec or the session something
wrong and assert that it is rejected. A test that only feeds good input cannot show that a
validating parser validates.

    python3 tests/test_active_harness.py            # or: python3 -m pytest tests -q
"""
from __future__ import annotations

import os
import socket
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import dnp3_codec as codec                                                  # noqa: E402
from dnp3_codec import (Reassembler, FrameError, parse_frame, parse_response,   # noqa: E402
                        validate_response, crc_le, FUNC_SELECT, FUNC_OPERATE,
                        FUNC_RESPONSE, FUNC_READ)
import frozen_builders as fb                                                # noqa: E402
import session as sess                                                      # noqa: E402
import sbo_driver                                                           # noqa: E402

# The reference SEL-751A response embedded in the frozen dnp3_wire.py self-check: a 2-CROB
# G12V1 response for points 0 and 1, both status 0.
REFERENCE_RESPONSE = bytes.fromhex(
    "05642644010000002f77e0c08184000c011702000101c8000000f05a"
    "0000000000010101c80000000000000097da00ffff")


def build_response(app_seq: int, points, statuses, *, func=FUNC_RESPONSE,
                   iin=b"\x84\x00", group=0x0C, variation=0x01, qualifier=0x17,
                   count=None):
    """Assemble a well-formed response frame with per-block CRCs."""
    obj = bytes([group, variation, qualifier,
                 len(points) if count is None else count])
    for idx, st in zip(points, statuses):
        crob = bytearray([0x01, 0x01, 0xC8, 0, 0, 0, 0, 0, 0, 0, 0])
        crob[codec.CROB_STATUS_OFFSET] = st
        obj += bytes([idx]) + bytes(crob)
    user = bytes([0xE0, 0xC0 | (app_seq & 0x0F), func]) + iin + obj
    ln = 5 + len(user)
    hdr = bytes([0x05, 0x64, ln, 0x44, 0x01, 0x00, 0x00, 0x00])
    out = bytearray(hdr + crc_le(hdr))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + crc_le(blk)
    return bytes(out)


class FakeSocket:
    """A scripted stand-in for a connected socket. Never touches the network."""

    def __init__(self, script):
        # script entries: bytes -> delivered; "timeout" -> raise socket.timeout;
        # "close" -> return b""; float -> the peer stays silent for that many seconds
        self.script = list(script)
        self.sent = []
        self.timeout = None
        self.timeouts = []            # every value settimeout was called with, in order

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, t):
        self.timeout = t
        self.timeouts.append(t)

    def recv(self, _n):
        """Honour the configured timeout, the way a real socket does."""
        while self.script:
            item = self.script.pop(0)
            if item == "timeout":
                raise socket.timeout()
            if item == "close":
                return b""
            if isinstance(item, float):
                # the peer is silent for `item` seconds; if that outlasts the timeout the
                # receive fails, and the unspent remainder of the silence stays scheduled
                if self.timeout is not None and item > self.timeout:
                    time.sleep(self.timeout)
                    self.script.insert(0, item - self.timeout)
                    raise socket.timeout()
                time.sleep(item)
                continue
            return item
        raise socket.timeout()

    def close(self):
        pass


def make_session(script):
    s = sess.Session("192.0.2.1", 20000)
    s.sock = FakeSocket(script)
    return s


class TestCodecAgainstFrozenReference(unittest.TestCase):
    def test_reference_response_parses_and_crcs_validate(self):
        frame, rest = parse_frame(REFERENCE_RESPONSE)
        self.assertIsNotNone(frame)
        self.assertEqual(rest, b"")
        r = parse_response(frame.user_data)
        self.assertEqual(r.function, FUNC_RESPONSE)
        self.assertEqual(r.iin, 0x0084)
        self.assertEqual((r.group, r.variation, r.qualifier, r.count), (12, 1, 0x17, 2))
        self.assertEqual(r.points, [(0, 0), (1, 0)])
        self.assertEqual(r.problems, [])

    def test_iin_is_skipped_so_the_qualifier_is_read_correctly(self):
        """The frozen SBO decoder read obj[2] as the qualifier; with the IIN present that
        octet is the object group. This records the difference explicitly."""
        frame, _ = parse_frame(REFERENCE_RESPONSE)
        u = frame.user_data
        self.assertEqual(u[3:5], b"\x84\x00", "IIN is at user_data[3:5]")
        self.assertEqual(u[5], 0x0C, "object group follows the IIN")
        frozen_view = u[3:]
        self.assertNotEqual(frozen_view[2], 0x17,
                            "obj=user_data[3:] makes obj[2] the group, not the qualifier")
        self.assertEqual(frozen_view[2], 0x0C)

    def test_guarded_builders_pass_the_codec(self):
        for func, builder in ((FUNC_SELECT, fb.build_select), (FUNC_OPERATE, fb.build_operate)):
            frame = builder(3, (1, 3))
            parsed, rest = parse_frame(frame)
            self.assertIsNotNone(parsed)
            self.assertEqual(rest, b"")
            self.assertEqual(parsed.user_data[2], func)


class TestCrcValidation(unittest.TestCase):
    def test_header_crc_corruption_is_detected(self):
        bad = bytearray(REFERENCE_RESPONSE)
        bad[8] ^= 0xFF
        with self.assertRaises(FrameError):
            parse_frame(bytes(bad))

    def test_user_block_crc_corruption_is_detected(self):
        bad = bytearray(REFERENCE_RESPONSE)
        bad[26] ^= 0xFF                  # inside the first user-data block CRC
        with self.assertRaises(FrameError):
            parse_frame(bytes(bad))

    def test_payload_corruption_is_detected(self):
        bad = bytearray(REFERENCE_RESPONSE)
        bad[12] ^= 0x01                  # flip a payload bit; its block CRC no longer matches
        with self.assertRaises(FrameError):
            parse_frame(bytes(bad))

    def test_crc_failure_is_counted_and_the_parser_resynchronises(self):
        good = build_response(1, [1, 3], [0, 0])
        bad = bytearray(build_response(2, [1, 3], [0, 0]))
        bad[12] ^= 0x01
        rx = Reassembler()
        rx.feed(bytes(bad) + good)
        frames = list(rx.frames())
        self.assertGreaterEqual(rx.crc_failures, 1)
        self.assertEqual([parse_response(f.user_data).app_seq for f in frames], [1],
                         "the corrupted frame is dropped and the good one still parses")


class TestReassembly(unittest.TestCase):
    def test_frame_split_across_every_boundary(self):
        good = build_response(4, [1, 3], [0, 0])
        for cut in range(1, len(good)):
            rx = Reassembler()
            rx.feed(good[:cut])
            self.assertEqual(list(rx.frames()), [], "must not yield a partial frame at %d" % cut)
            rx.feed(good[cut:])
            frames = list(rx.frames())
            self.assertEqual(len(frames), 1, "split at %d" % cut)
            self.assertEqual(parse_response(frames[0].user_data).app_seq, 4)

    def test_byte_at_a_time_delivery(self):
        good = build_response(5, [1, 3], [0, 0])
        rx = Reassembler()
        seen = []
        for b in good:
            rx.feed(bytes([b]))
            seen.extend(rx.frames())
        self.assertEqual(len(seen), 1)

    def test_excess_bytes_are_preserved_not_discarded(self):
        a = build_response(6, [1, 3], [0, 0])
        b = build_response(7, [1, 3], [0, 0])
        rx = Reassembler()
        rx.feed(a + b[:5])
        frames = list(rx.frames())
        self.assertEqual(len(frames), 1)
        self.assertEqual(rx.pending_bytes, 5, "the head of the next frame must be kept")
        rx.feed(b[5:])
        self.assertEqual([parse_response(f.user_data).app_seq for f in rx.frames()], [7])

    def test_two_coalesced_frames_in_one_read(self):
        rx = Reassembler()
        rx.feed(build_response(8, [1, 3], [0, 0]) + build_response(9, [1, 3], [0, 0]))
        self.assertEqual([parse_response(f.user_data).app_seq for f in rx.frames()], [8, 9])

    def test_leading_garbage_is_skipped_and_counted(self):
        rx = Reassembler()
        rx.feed(b"\x00\x01\x02" + build_response(10, [1, 3], [0, 0]))
        frames = list(rx.frames())
        self.assertEqual(len(frames), 1)
        self.assertEqual(rx.dropped_leading, 3)

    def test_a_lone_start_octet_is_not_dropped(self):
        rx = Reassembler()
        rx.feed(b"\x05")
        self.assertEqual(list(rx.frames()), [])
        rx.feed(b"\x64")
        self.assertEqual(list(rx.frames()), [])
        self.assertEqual(rx.pending_bytes, 2, "a split start pattern must survive")


class TestResponseValidation(unittest.TestCase):
    def test_sequence_mismatch_is_rejected(self):
        r = parse_response(build_response(5, [1, 3], [0, 0])[10:])
        problems = validate_response(parse_response(
            parse_frame(build_response(5, [1, 3], [0, 0]))[0].user_data),
            expect_seq=6, expect_function=FUNC_SELECT, expect_points=[1, 3])
        self.assertTrue(any("sequence" in p for p in problems), problems)
        self.assertIsNotNone(r)

    def test_wrong_points_are_rejected(self):
        f, _ = parse_frame(build_response(1, [1, 2], [0, 0]))
        problems = validate_response(parse_response(f.user_data), expect_seq=1,
                                     expect_function=FUNC_SELECT, expect_points=[1, 3])
        self.assertTrue(any("points" in p for p in problems), problems)

    def test_nonzero_crob_status_is_rejected_when_success_required(self):
        f, _ = parse_frame(build_response(1, [1, 3], [0, 2]))   # NO_SELECT on point 3
        problems = validate_response(parse_response(f.user_data), expect_seq=1,
                                     expect_function=FUNC_OPERATE, expect_points=[1, 3],
                                     require_success=True)
        self.assertTrue(any("NO_SELECT" in p for p in problems), problems)

    def test_every_defined_status_name_is_reported(self):
        for code, name in codec.STATUS_NAMES.items():
            if code == 0:
                continue
            f, _ = parse_frame(build_response(1, [1, 3], [code, 0]))
            problems = validate_response(parse_response(f.user_data), expect_seq=1,
                                         expect_function=FUNC_OPERATE,
                                         expect_points=[1, 3], require_success=True)
            self.assertTrue(any(name in p for p in problems), (code, name, problems))

    def test_wrong_function_is_rejected(self):
        f, _ = parse_frame(build_response(1, [1, 3], [0, 0], func=0x82))
        problems = validate_response(parse_response(f.user_data), expect_seq=1,
                                     expect_function=FUNC_SELECT)
        self.assertTrue(any("0x82" in p for p in problems), problems)

    def test_wrong_group_variation_qualifier_are_rejected(self):
        for kw, needle in (dict(group=0x0A), "group"), (dict(variation=0x02), "variation"), \
                          (dict(qualifier=0x00), "qualifier"):
            f, _ = parse_frame(build_response(1, [1, 3], [0, 0], **kw))
            problems = validate_response(parse_response(f.user_data), expect_seq=1,
                                         expect_function=FUNC_OPERATE, expect_points=[1, 3])
            self.assertTrue(any(needle in p for p in problems), (kw, problems))

    def test_truncated_object_block_is_reported(self):
        f, _ = parse_frame(build_response(1, [1], [0], count=2))
        r = parse_response(f.user_data)
        self.assertTrue(any("truncated" in p for p in r.problems), r.problems)


class TestSessionDeadlines(unittest.TestCase):
    def test_valid_response_completes(self):
        s = make_session([build_response(0, [1, 3], [0, 0])])
        out = s.transaction(operation="SELECT", frame=fb.build_select(0, (1, 3)),
                            function=FUNC_SELECT, app_seq=0, budget_ms=200,
                            expect_points=[1, 3], require_success=True)
        self.assertTrue(out.ok, out.problems)
        self.assertEqual([st for _, st in out.points], ["SUCCESS", "SUCCESS"])
        self.assertEqual(out.ack_evidence, sess.ACK_NOT_OBSERVABLE)

    def test_timeout_is_an_explicit_outcome(self):
        s = make_session(["timeout"])
        out = s.transaction(operation="READ", frame=fb.read_frame(0), function=FUNC_READ,
                            app_seq=0, budget_ms=50)
        self.assertEqual(out.outcome, sess.OUTCOME_TIMEOUT)
        self.assertTrue(out.problems)

    def test_peer_close_is_distinguished_from_timeout(self):
        s = make_session(["close"])
        out = s.transaction(operation="READ", frame=fb.read_frame(0), function=FUNC_READ,
                            app_seq=0, budget_ms=50)
        self.assertEqual(out.outcome, sess.OUTCOME_PEER_CLOSED)

    def test_invalid_response_is_distinguished_from_timeout(self):
        s = make_session([build_response(0, [1, 3], [0, 8])])   # TOO_MANY_OPS
        out = s.transaction(operation="OPERATE", frame=fb.build_operate(0, (1, 3)),
                            function=FUNC_OPERATE, app_seq=0, budget_ms=200,
                            expect_points=[1, 3], require_success=True)
        self.assertEqual(out.outcome, sess.OUTCOME_INVALID)
        self.assertTrue(any("TOO_MANY_OPS" in p for p in out.problems), out.problems)

    def test_the_budget_bounds_the_transaction_not_one_read(self):
        """Trickled bytes that never complete a frame must not renew the budget.

        Each scripted pause is shorter than the budget, so a per-read timeout would let the
        transaction run indefinitely. Only a deadline computed once can stop it.
        """
        script = []
        for octet in b"\x05\x64\x26\x44\x00\x00\x00\x00":
            script += [bytes([octet]), 0.03]
        s = make_session(script * 4)
        t0 = time.monotonic()
        out = s.transaction(operation="READ", frame=fb.read_frame(0), function=FUNC_READ,
                            app_seq=0, budget_ms=60)
        elapsed = (time.monotonic() - t0) * 1e3
        self.assertEqual(out.outcome, sess.OUTCOME_TIMEOUT)
        self.assertLess(elapsed, 250, "elapsed %.1f ms against a 60 ms budget; the deadline "
                                      "must bound the whole transaction" % elapsed)

    def test_each_receive_gets_a_strictly_smaller_timeout(self):
        """The direct witness that the remaining budget is passed down, not the full one."""
        script = []
        for octet in b"\x05\x64\x26\x44":
            script += [bytes([octet]), 0.01]
        fake = FakeSocket(script)
        s = sess.Session("192.0.2.1", 20000)
        s.sock = fake
        out = s.transaction(operation="READ", frame=fb.read_frame(0), function=FUNC_READ,
                            app_seq=0, budget_ms=120)
        self.assertEqual(out.outcome, sess.OUTCOME_TIMEOUT)
        self.assertGreaterEqual(len(fake.timeouts), 3,
                                "expected several receives, saw %r" % fake.timeouts)
        for earlier, later in zip(fake.timeouts, fake.timeouts[1:]):
            self.assertLess(later, earlier,
                            "timeouts must shrink; saw %r" % (fake.timeouts,))
        self.assertLessEqual(max(fake.timeouts), 0.120 + 1e-6)

    def test_remaining_budget_is_passed_to_the_receive(self):
        fake = FakeSocket([build_response(0, [1, 3], [0, 0])])
        s = sess.Session("192.0.2.1", 20000)
        s.sock = fake
        s.transaction(operation="SELECT", frame=fb.build_select(0, (1, 3)),
                      function=FUNC_SELECT, app_seq=0, budget_ms=100,
                      expect_points=[1, 3], require_success=True)
        self.assertIsNotNone(fake.timeout)
        self.assertLessEqual(fake.timeout, 0.1 + 1e-6,
                             "the receive must get the remaining budget, not a fresh one")

    def test_a_stale_response_does_not_complete_the_transaction(self):
        stale = build_response(9, [1, 3], [0, 0])       # a different sequence number
        good = build_response(2, [1, 3], [0, 0])
        s = make_session([stale + good])
        out = s.transaction(operation="SELECT", frame=fb.build_select(2, (1, 3)),
                            function=FUNC_SELECT, app_seq=2, budget_ms=200,
                            expect_points=[1, 3], require_success=True)
        self.assertTrue(out.ok, out.problems)
        self.assertEqual(out.stale_frames_discarded, 1)

    def test_only_a_stale_response_times_out(self):
        s = make_session([build_response(9, [1, 3], [0, 0]), "timeout"])
        out = s.transaction(operation="SELECT", frame=fb.build_select(2, (1, 3)),
                            function=FUNC_SELECT, app_seq=2, budget_ms=60,
                            expect_points=[1, 3], require_success=True)
        self.assertEqual(out.outcome, sess.OUTCOME_TIMEOUT)
        self.assertEqual(out.stale_frames_discarded, 1)

    def test_corrupt_bytes_give_a_framing_outcome(self):
        bad = bytearray(build_response(0, [1, 3], [0, 0]))
        bad[12] ^= 0x01
        s = make_session([bytes(bad), "timeout"])
        out = s.transaction(operation="SELECT", frame=fb.build_select(0, (1, 3)),
                            function=FUNC_SELECT, app_seq=0, budget_ms=60,
                            expect_points=[1, 3], require_success=True)
        self.assertIn(out.outcome, (sess.OUTCOME_FRAME_ERROR, sess.OUTCOME_TIMEOUT))
        self.assertTrue(out.problems)

    def test_leftover_bytes_are_reported_and_kept(self):
        good = build_response(0, [1, 3], [0, 0])
        s = make_session([good + b"\x05\x64"])
        out = s.transaction(operation="SELECT", frame=fb.build_select(0, (1, 3)),
                            function=FUNC_SELECT, app_seq=0, budget_ms=200,
                            expect_points=[1, 3], require_success=True)
        self.assertTrue(out.ok, out.problems)
        self.assertEqual(out.bytes_left_buffered, 2)


class TestSelectGate(unittest.TestCase):
    def test_operate_is_not_attempted_after_a_failed_select(self):
        for script, why in (([build_response(0, [1, 3], [2, 0])], "NO_SELECT status"),
                            (["timeout"], "no response"),
                            ([build_response(7, [1, 3], [0, 0]), "timeout"], "wrong sequence")):
            s = make_session(list(script))
            sel, op = sbo_driver.one_sbo(s, 0, 1, [1, 3], budget_ms=60, select_only=False)
            self.assertFalse(sel.ok, why)
            self.assertEqual(op.outcome, sess.OUTCOME_NOT_ATTEMPTED, why)
            self.assertEqual(len(s.sock.sent), 1,
                             "only the SELECT may have been sent when %s" % why)

    def test_operate_follows_a_valid_select(self):
        s = make_session([build_response(0, [1, 3], [0, 0]),
                          build_response(1, [1, 3], [0, 0])])
        sel, op = sbo_driver.one_sbo(s, 0, 1, [1, 3], budget_ms=200, select_only=False)
        self.assertTrue(sel.ok, sel.problems)
        self.assertTrue(op.ok, op.problems)
        self.assertEqual(len(s.sock.sent), 2)

    def test_select_only_never_sends_an_operate(self):
        s = make_session([build_response(0, [1, 3], [0, 0])])
        sel, op = sbo_driver.one_sbo(s, 0, 1, [1, 3], budget_ms=200, select_only=True)
        self.assertTrue(sel.ok, sel.problems)
        self.assertEqual(op.outcome, sess.OUTCOME_NOT_ATTEMPTED)
        self.assertEqual(len(s.sock.sent), 1)

    def test_select_and_operate_use_different_sequence_numbers(self):
        s = make_session([build_response(0, [1, 3], [0, 0]),
                          build_response(1, [1, 3], [0, 0])])
        sel, op = sbo_driver.one_sbo(s, 0, 1, [1, 3], budget_ms=200, select_only=False)
        self.assertNotEqual(sel.app_seq, op.app_seq,
                            "reusing one sequence number is what produced NO_SELECT")


class TestSafetyGuardsPreserved(unittest.TestCase):
    def test_authorized_set_is_exactly_one_and_three(self):
        self.assertEqual(sorted(fb.AUTHORIZED_POINTS), [1, 3])

    def test_breaker_close_index_is_refused_at_construction(self):
        for points in ((6,), (1, 6), (1, 3, 6), (0,), (2,), ()):
            with self.assertRaises(fb.ForbiddenPointError, msg="points=%r" % (points,)):
                fb.build_operate(0, points)

    def test_guarded_helper_refuses_a_forbidden_index(self):
        with self.assertRaises(fb.ForbiddenPointError):
            sbo_driver.guarded(FUNC_OPERATE, 0, [6])

    def test_driver_refuses_an_index_set_that_is_not_the_authorized_set(self):
        for args in (["--indices", "1"], ["--indices", "1,3,6"], ["--indices", "6"]):
            self.assertEqual(sbo_driver.main(args + ["--dry-run"]), 2, args)

    def test_dry_run_is_the_default_and_sends_nothing(self):
        self.assertEqual(sbo_driver.main([]), 0)

    def test_live_refuses_without_the_authorization_variable(self):
        saved = os.environ.pop("DEFENSE4_HW_AUTHORIZED", None)
        try:
            self.assertEqual(sbo_driver.main(["--live", "--count", "1"]), 2)
        finally:
            if saved is not None:
                os.environ["DEFENSE4_HW_AUTHORIZED"] = saved

    def test_frozen_files_are_not_importable_as_writable_copies(self):
        """The bridge must read the frozen directory, not a local duplicate."""
        self.assertTrue(fb.FROZEN_HARNESS.endswith(os.path.join("implementation", "harness")))
        for name in ("relay_operate_guarded.py", "relay_read_g10_23.py", "dnp3_wire.py"):
            self.assertTrue(os.path.isfile(os.path.join(fb.FROZEN_HARNESS, name)), name)
            self.assertFalse(os.path.exists(os.path.join(ROOT, name)),
                             "%s must not be duplicated into the active tree" % name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
