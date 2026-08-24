#!/usr/bin/env python3
"""Offline tests for the Defense 4 setup control layer (B1/B2). No hardware.

Covers: ms->word quantization authority, the deadline-word unit (ns, not ms), mode-specific
parameter constraints, the transaction-active refusal guard, and that clear-evidence never
touches transaction state. Run: python3 test_setup_offline.py
"""
import importlib.util, os, sys, types

HERE = os.path.dirname(os.path.abspath(__file__))
SETUP = os.path.join(HERE, "..", "defense4_caseA_setup.py")
spec = importlib.util.spec_from_file_location("d4setup", SETUP)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
d3 = S.d3

FAILS = []
def check(name, cond):
    print(("[PASS] " if cond else "[FAIL] ") + name)
    if not cond:
        FAILS.append(name)

class A:  # minimal args namespace
    def __init__(self, **kw):
        self.d_a_ms = self.d_r_ms = None
        self.d_a = self.d_r = 0
        self.poll_ms = 400.0
        self.budget = 18000
        for k, v in kw.items():
            setattr(self, k, v)

# --- B2: ms -> deadline word (ns) via the quantization authority ---------------
da, dr, dadr, bd = S.resolve_delays(A(d_a_ms=3.0, d_r_ms=5.0))
check("3 ms -> D_A word 2,999,808 ns (256 ns grid)", da == 2999808)
check("5 ms -> D_R word 4,999,936 ns", dr == 4999936)
check("da_dr = D_A + D_R word", dadr == da + dr)
check("D_A word low byte zero", (da & 0xFF) == 0 and (dr & 0xFF) == 0 and (dadr & 0xFF) == 0)
check("breakdown realized_ms ~ 3 ms", abs(bd["D_A"]["realized_ms"] - 3.0) < 0.001)
check("breakdown reports da_dr vs poll", "poll" in bd["da_dr_vs_poll"])

# --- the unit bug the audit found: raw word 0x8000 is 32.768 us, NOT ms --------
da2, _, _, bd2 = S.resolve_delays(A(d_a=0x8000, d_r=0x8000))
check("raw word 0x8000 = 32768 ns = 0.032768 ms (not ms-scale)", da2 == 32768 and abs(bd2["D_A"]["realized_ms"] - 0.032768) < 1e-9)

# --- B2: mode-specific constraints --------------------------------------------
def nfail(mode, d_a, d_r):
    c = d3.Checks(); S.validate_params(mode, d_a, d_r, c); return c.n_fail
check("D2 requires D_A==0 (D_A>0 fails)", nfail("D2", 2999808, 4999936) >= 1)
check("D2 with D_A==0 passes", nfail("D2", 0, 4999936) == 0)
check("D3 requires D_R==0 (D_R>0 fails)", nfail("D3", 2999808, 4999936) >= 1)
check("D3 with D_R==0 passes", nfail("D3", 2999808, 0) == 0)
check("D4 requires both>0", nfail("D4", 2999808, 4999936) == 0 and nfail("D4", 0, 4999936) >= 1)
check("half-range: da_dr >= 2^31 fails", nfail("D4", (1 << 31), 256) >= 1)

# --- B1: transaction-active refusal guard -------------------------------------
# txn_active reads reg_tag via d3.reg_read; monkeypatch it to exercise both states.
_orig = d3.reg_read
d3.reg_read = lambda bi, tgt, name, **kw: 0x00           # INACTIVE
check("txn_active False when reg_tag == TAG_INACTIVE", S.txn_active(None, None) is False)
d3.reg_read = lambda bi, tgt, name, **kw: 0xC3           # a live generation
check("txn_active True when reg_tag is a live generation", S.txn_active(None, None) is True)
def _boom(*a, **k):
    raise RuntimeError("read failed")
d3.reg_read = _boom
check("txn_active fail-safe True when reg_tag unreadable", S.txn_active(None, None) is True)
d3.reg_read = _orig

# --- B1: clear-evidence must NOT touch reg_tag / deadlines / trackers ----------
touched = []
_ow, _oz = d3.reg_write, d3.ctr_zero
d3.reg_write = lambda bi, tgt, name, val, **kw: touched.append(("reg_write", name))
d3.ctr_zero = lambda bi, tgt, name, idx: touched.append(("ctr_zero", name))
c = d3.Checks(); S.clear_evidence_only(None, None, c)
regs_written = {n for k, n in touched if k == "reg_write"}
protected = {"reg_tag", "reg_deadline", "reg_tresp", "reg_ack_rel",
             "reg_exp_ack", "reg_exp_relay_seq", "reg_session_port"}
check("clear-evidence zeroes counters (ctr_fresh/ctr_deq)", any(k == "ctr_zero" for k, _ in touched))
check("clear-evidence does NOT write reg_tag/deadlines/trackers", not (regs_written & protected))
check("clear-evidence only writes ts_* registers", all(n.startswith("reg_ts_") for n in regs_written))
d3.reg_write, d3.ctr_zero = _ow, _oz

print("\nRESULT: %s (%d failures)" % ("PASS" if not FAILS else "FAIL", len(FAILS)))
sys.exit(1 if FAILS else 0)
