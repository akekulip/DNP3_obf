#!/usr/bin/env python3
"""test_hardening_fix124.py — off-switch unit tests for the Case-A pre-scale hardening (FIX 1+2+4).

Faithful Python mirror of dcrn_ackA.p4's per-flow reverse-path DECISION logic (the hardened version,
sha 6e1b659b): FIX 1 exact pure-ACK qualification, FIX 2 transaction-lifecycle clear (on complete AND
pure-RST/FIN abort), FIX 4 binary occupancy. Mirrors these P4 sites exactly:
  arm            : armed=1; expected_ack = req.seq + req.payload_len; flow_has_held_ack=0
  pure-ACK path  : armed = armed_get_absclr (read; clear if abort);  amatch = (expected_ack==ack_no);
                   qual = armed && flags_ok((flags&0x17)==0x10) && amatch;  hold only FIRST (fha_tas)
  response path  : armed_getclr; held = fha_getclr (read+clear occupancy);
                   admit iff held && not_abort ((flags&0x05)==0)
Invariant under test (FIX 2's real goal): occupancy AND armed return to 0 after every completed OR
aborted transaction, so no FIN / keepalive / next transaction inherits stale state.

Run: python3 tests/test_hardening_fix124.py   (or pytest)
"""


class Flow:
    """Per-flow register state (reg_armed, reg_expected_ack, flow_has_held_ack)."""
    def __init__(self):
        self.armed = 0
        self.expected_ack = None
        self.fha = 0          # flow_has_held_ack (binary occupancy)


def arm(f, req_seq, req_payload_len):
    """P4 ARM block: FC-allowlisted request seen (dir 0)."""
    f.armed = 1
    f.expected_ack = (req_seq + req_payload_len) & 0xffffffff
    f.fha = 0                 # fha_clr: fresh occupancy


def _flags_ok(fl):    # (flags & 0x17) == 0x10  -> ACK=1, SYN=RST=FIN=0
    return fl["ACK"] and not fl["SYN"] and not fl["RST"] and not fl["FIN"]


def _not_abort(fl):   # (flags & 0x05) == 0  -> no FIN, no RST
    return not fl["FIN"] and not fl["RST"]


def reverse_frame(f, fl, payload_len, ack_no):
    """P4 reverse-path (dir 1, src:20000) decision. Returns the action taken."""
    if payload_len == 0:
        # ---- pure-ACK branch: armed_get_absclr reads armed, clears it if this frame is an abort ----
        armed = f.armed
        if not _not_abort(fl):
            f.armed = 0                              # FIX2: pure FIN/RST clears armed
        amatch = (f.expected_ack == ack_no)
        qual = (armed == 1) and _flags_ok(fl) and amatch
        if qual:
            already = f.fha
            f.fha = 1                                # fha_tas test-and-set
            return "HELD_ACK" if already == 0 else "FORWARD_DUP"
        return "FORWARD"
    else:
        # ---- response / payload-bearing reverse frame ----
        f.armed = 0                                  # FIX2: armed_getclr (commits or aborts the txn)
        held = f.fha
        f.fha = 0                                    # fha_getclr: release occupancy (FIX4)
        if held == 1 and _not_abort(fl):
            return "HELD_RESP"                        # separate-mode response admitted
        return "BYPASS"                               # combined / abort-with-data


ACKONLY = {"ACK": True, "SYN": False, "RST": False, "FIN": False}
SYN     = {"ACK": False, "SYN": True, "RST": False, "FIN": False}
SYNACK  = {"ACK": True, "SYN": True, "RST": False, "FIN": False}
FINACK  = {"ACK": True, "SYN": False, "RST": False, "FIN": True}
RSTF    = {"ACK": False, "SYN": False, "RST": True, "FIN": False}


def _armed_flow(seq=1000, rlen=22):
    f = Flow(); arm(f, seq, rlen); return f, (seq + rlen)   # expected ack = seq+rlen


# ---- FIX 1: exact pure-ACK qualification ---------------------------------------------------------

def test_fix1_holds_exact_pure_ack():
    f, exp = _armed_flow()
    assert reverse_frame(f, ACKONLY, 0, exp) == "HELD_ACK"
    assert f.fha == 1

def test_fix1_fin_not_held():
    f, exp = _armed_flow()
    assert reverse_frame(f, FINACK, 0, exp) == "FORWARD"     # FIN -> flags_ok false -> forwarded
    assert f.fha == 0                                        # occupancy never set (accumulation root cause gone)

def test_fix1_rst_not_held():
    f, exp = _armed_flow()
    assert reverse_frame(f, RSTF, 0, exp) == "FORWARD"
    assert f.fha == 0

def test_fix1_synack_not_held():
    f, exp = _armed_flow()
    assert reverse_frame(f, SYNACK, 0, exp) == "FORWARD"

def test_fix1_wrong_ack_not_held():
    f, exp = _armed_flow()
    assert reverse_frame(f, ACKONLY, 0, exp + 7) == "FORWARD"   # keepalive/window-update: wrong ack
    assert f.fha == 0

def test_fix1_second_qualifying_ack_not_held():
    f, exp = _armed_flow()
    assert reverse_frame(f, ACKONLY, 0, exp) == "HELD_ACK"
    assert reverse_frame(f, ACKONLY, 0, exp) == "FORWARD_DUP"   # one-shot: dup ACK forwarded

def test_fix1_unarmed_flow_holds_nothing():
    f = Flow()                                                 # never armed
    assert reverse_frame(f, ACKONLY, 0, 1234) == "FORWARD"


# ---- FIX 2 + FIX 4: lifecycle + occupancy return-to-zero -----------------------------------------

def test_completed_txn_returns_state_to_zero():
    f, exp = _armed_flow()
    assert reverse_frame(f, ACKONLY, 0, exp) == "HELD_ACK"     # ACK held
    assert reverse_frame(f, ACKONLY, 54, exp) == "HELD_RESP"   # response admitted (payload>0)
    assert f.armed == 0 and f.fha == 0                         # FIX2/FIX4: state back to 0

def test_pure_fin_abort_clears_armed():
    f, exp = _armed_flow()                                     # armed, no ACK held yet
    assert reverse_frame(f, FINACK, 0, exp) == "FORWARD"
    assert f.armed == 0 and f.fha == 0                         # FIX2: abort cleared armed

def test_abort_after_ack_held_releases_occupancy():
    f, exp = _armed_flow()
    reverse_frame(f, ACKONLY, 0, exp)                          # ACK held (fha=1)
    # a payload-bearing RST/FIN (abort-with-data) hits the response path -> armed_getclr + fha_getclr
    assert reverse_frame(f, FINACK, 10, exp) == "BYPASS"       # not_abort false -> not admitted
    assert f.armed == 0 and f.fha == 0                         # occupancy released, armed cleared

def test_no_stale_state_across_100_txns():
    """Continuous single-flow: 100 sequential transactions, occupancy must never leak."""
    f = Flow()
    seq = 1000
    for i in range(100):
        arm(f, seq, 22)
        exp = seq + 22
        assert reverse_frame(f, ACKONLY, 0, exp) == "HELD_ACK"
        assert f.fha == 1
        assert reverse_frame(f, ACKONLY, 54, exp) == "HELD_RESP"
        assert f.armed == 0 and f.fha == 0, "state leaked at txn %d" % i
        seq += 22 + 54                                         # advance seq like a real connection

def test_close_fin_after_completed_txn_not_held():
    """The exact accumulation scenario: a session-close FIN after the last txn must NOT be held."""
    f = Flow(); arm(f, 1000, 22); exp = 1022
    reverse_frame(f, ACKONLY, 0, exp); reverse_frame(f, ACKONLY, 54, exp)   # txn completes
    assert f.armed == 0                                        # armed already cleared by the response
    assert reverse_frame(f, FINACK, 0, 2000) == "FORWARD"      # close FIN -> forwarded, not held
    assert f.fha == 0


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn(); passed += 1
        print("  PASS %s" % fn.__name__)
    print("== %d/%d FIX 1+2+4 unit tests passed ==" % (passed, len(fns)))


if __name__ == "__main__":
    _run_all()
