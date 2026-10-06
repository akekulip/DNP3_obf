"""Pass-level trace simulator that drives the P4's own tables and register actions.

Scope (READ, MODE_D4_DUAL, read_release=1, anchor_req=1), wired from the source as read on 2026-10-06:
the order of owner -> tag -> state decode -> response deadline -> decision follows the apply block.
Every decision comes from parsing defense4_response_ready.p4; nothing about release timing is
hard-coded here. Abstractions, stated so they are not mistaken for coverage:
  * The three association registers (expected seq / sport / ack) are not simulated. A packet's
    `match` flag stands for "all three diffs are zero".
  * The 64-token ring of each slot is one token looping every `tau_ns`; the real queue empties
    within about one loop of the first token dropping, so release times carry a tau tolerance.
  * Parser, clone-to-pktgen latency (`adm_delay_ns`) and queue service are idealised.
"""
import heapq
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "response_ready" / "tests"))
sys.path.insert(0, str(ROOT.parents[1]))
from test_p4_release import SOURCE, sem  # noqa: E402
from test_p4_recovery import execute  # noqa: E402

import functools  # noqa: E402

# The repository's source parsers re-scan the whole P4 on every call; cache them (pure functions).
for _name in ("extract_consts", "extract_register_action_block", "extract_named_block", "_extract_block_after"):
    setattr(sem, _name, functools.lru_cache(maxsize=None)(getattr(sem, _name)))

MASK32 = 0xFFFFFFFF
GEN = 0xC1                      # generation byte stamped at arming (0xCn when the owner was free)
REG_OF = {"owner": "reg_owner", "tag": "reg_tag", "deadline": "reg_deadline",
          "tresp": "reg_tresp", "ack_rel": "reg_ack_rel"}


def now_word(t_ns):
    """(ts32 & 0xFFFFFF00) | 1: a 256 ns grid with bit 0 as the ARMED marker."""
    return ((t_ns & MASK32) & 0xFFFFFF00) | 1


class P4Sim:
    def __init__(self, da_ns, gap_ns, tau_ns=1711, budget=18000, adm_delay_ns=5000, t_offset_ns=0, mode="MODE_D4_DUAL"):
        self.src = SOURCE.read_text()
        self.c = sem.extract_consts(self.src)
        self.tables = {n: sem.parse_const_table(self.src, n, self.c) for n in (
            "tbl_state_decode", "tbl_resp_deadline", "tbl_txn_active", "tbl_resp_authorise",
            "tbl_decide_fresh", "tbl_decide_deq", "tbl_owner_admission", "tbl_owner_valid",
            "tbl_build_cand_resp")}
        # control.py floors both to the 256 ns grid; the P4's due test needs the low byte of D to be zero
        self.da, self.gap = (da_ns // 256) * 256, (gap_ns // 256) * 256
        self.tau, self.budget, self.mode = tau_ns, budget, mode
        self.adm_delay, self.off = adm_delay_ns, t_offset_ns
        self.regs = {v: 0 for v in REG_OF.values()}
        self.outs, self.counters, self.trace = [], {}, []
        self.held = {"ACK": None, "RESP": None}          # arrival times of packets in the hold queues
        self.slot_open = {"ACK": None, "RESP": None}      # time a slot's token left (queue ungated)
        self.tokens = {}
        self.cookie = 0x80000001                          # owner word written by the latest arming
        self.queue, self._n = [], 0

    # ---- plumbing ---------------------------------------------------------------------
    def count(self, k):
        self.counters[k] = self.counters.get(k, 0) + 1

    def reg(self, name, t, **meta):
        """Run one RegisterAction against its register; returns rv, updates the register."""
        key = REG_OF[name.split("_")[0]]
        rv, new = execute(self.src, name, self.regs[key], now_word=now_word(t + self.off), **meta)
        self.regs[key] = new
        return rv

    def table(self, name, **meta):
        t = self.tables[name]
        fields = {k: meta.get(k, 0) for k in t.keys}
        for row in t.rows:
            if all((fields[k] & m) == v for k, (v, m) in zip(t.keys, row.matches)):
                return row.action, row.argument
        return t.default_action, t.default_argument

    def candidate(self, action, t):
        """Evaluate `meta.X = meta.now_word + meta.Y;` of a build_* action from the source."""
        m = re.search(r"meta\.\w+\s*=\s*meta\.now_word\s*\+\s*meta\.(\w+)\s*;", self.body(action))
        addend = {"seq_m": self.da, "read_gap_ticks": self.gap, "da_dr": 0}[m.group(1)]
        return (now_word(t + self.off) + addend) & MASK32

    def body(self, action):
        return sem.extract_named_block(self.src, action)

    def run_action(self, action, t, meta):
        """Execute `meta.X = REG.execute(0);`, `REG.execute(0);` and `meta.verdict = V_*;` of an action."""
        text = self.body(action)
        out = {}
        for lhs, reg in re.findall(r"(?:meta\.(\w+)\s*=\s*)?(\w+)\.execute\(0\)", text):
            rv = self.reg(reg, t, **meta)
            if lhs:
                out[lhs] = rv
        for v in re.findall(r"meta\.verdict\s*=\s*(V_\w+)", text):
            out["verdict"] = self.c[v]
        for lhs, const in re.findall(r"meta\.(\w+)\s*=\s*(TAG_\w+)", text):
            out[lhs] = self.c[const]
        for lhs, n in re.findall(r"meta\.(\w+)\s*=\s*8w(\d+)\s*;", text):
            out[lhs] = int(n)
        return out

    def base(self):
        return dict(read_release=1, anchor_req=1, mode=self.c[self.mode], bor_pc=0, hold_ok=0)

    # ---- external packets (fresh pass) -----------------------------------------------
    def _owner_pass(self, t, meta, cookie_in):
        act, _ = self.table("tbl_owner_admission", **meta)
        return act, self.run_action(act, t, dict(meta, cookie_in=cookie_in))["owner"]

    def _valid(self, m):
        m["owner_valid"] = 1 if self.table("tbl_owner_valid", **m)[0] == "owner_accept" else 0

    def request(self, t, match=True):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_ARM"], role=c["ROLE_ARM"], sess=c["SESS_MASTER"])
        act, prior = self._owner_pass(t, m, 0)
        self.admitted = act == "owner_admit"
        m["owner"] = prior
        self._valid(m)
        free = (prior & 0x80000000) == 0 and (prior & 0xFFFF) != 0xFFFF        # tracker_write
        self.reg("tag_rmw", t, gen_in=GEN, tag_val=GEN if free else c["TAG_NO_WRITE"])
        m["tag_diff"] = GEN if free else 1                                       # forced after the access
        if free:
            self.cookie = self.regs["reg_owner"]
        dec, _ = self.table("tbl_state_decode", **m)
        r = self.run_action(dec, t, dict(m, dl_val=self.candidate("build_cand", t)))
        m.update(verdict=r["verdict"])
        rdl, _ = self.table("tbl_resp_deadline", **m)
        self.run_action(rdl, t, m)
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("REQ", t, dec, outcome))
        if outcome == "OUT_ARM_FRESH":
            self.count("arm_fresh")
            self.slot_open = {"ACK": None, "RESP": None}            # a new transaction has new tokens
            self._push(t + self.adm_delay, "ADMIT", "ACK")
            self._push(t + self.adm_delay, "ADMIT", "RESP")
        else:
            self.count(outcome.lower())          # busy / dup: bypassed unchanged
        return outcome

    def pure_ack(self, t, match=True):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_ACK"], role=c["ROLE_ACK"], sess=c["SESS_RELAY"],
                 seq_diff=0 if match else 1, ack_diff=0, sport_diff=0)
        _, m["owner"] = self._owner_pass(t, m, 0)
        self._valid(m)
        m["tag_diff"] = self.reg("tag_rmw", t, gen_in=0, tag_val=c["TAG_NO_WRITE"])
        dec, _ = self.table("tbl_state_decode", **m)
        r = self.run_action(dec, t, dict(m, dl_val=self.candidate("build_cand", t)))
        m.update(verdict=r["verdict"], ack_first=r.get("ack_first", 0))
        rdl, _ = self.table("tbl_resp_deadline", **m)
        self.run_action(rdl, t, dict(m, dl_val_resp=self.candidate(self.table("tbl_build_cand_resp", **m)[0], t)))
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("ACK", t, dec, outcome))
        if outcome in ("OUT_ACK_HOLD", "OUT_ACK_DUP_HOLD"):
            if self.slot_open["ACK"] is not None:           # queue already ungated: leaves at once
                self._ack_release(t, self.slot_open["ACK"])
            else:
                self.held["ACK"] = t
        elif outcome == "OUT_ACK_FWD_ARM":
            self.outs.append(("ACK", t, "forwarded")); self.count("ack_forwarded_armed")
        else:
            self.outs.append(("ACK", t, "unmatched_forwarded")); self.count("ack_unmatched")

    def response(self, t, match=True):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_RESP"], role=c["ROLE_RESP"], sess=c["SESS_RELAY"],
                 seq_diff=0 if match else 1, ack_diff=0, sport_diff=0)
        _, m["owner"] = self._owner_pass(t, m, 0)
        self._valid(m)
        auth, _ = self.table("tbl_resp_authorise", **m)
        m["tag_val"] = self.run_action(auth, t, m).get("tag_val", 0)
        cur = self.reg("tag_read_or_mark", t, tag_val=m["tag_val"])
        m["cur_gen"] = cur
        m["rel_diff"] = (cur - self.regs["reg_ack_rel"]) & 0xFF
        dec, _ = self.table("tbl_state_decode", **m)
        m["verdict"] = self.run_action(dec, t, m).get("verdict", 0)
        rdl, _ = self.table("tbl_resp_deadline", **m)
        self.run_action(rdl, t, m)
        tx, _ = self.table("tbl_txn_active", **m)
        m["txn_active"] = self.run_action(tx, t, m)["txn_active"]
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("RESP", t, dec, outcome))
        if outcome in ("OUT_RESP_HOLD_EARLY", "OUT_RESP_HOLD_LATE"):
            self.held["RESP"] = t
        elif outcome == "OUT_RESP_DUP_SUPP":
            self.count("dup_response_dropped")
        else:
            self.outs.append(("RESP", t, "forwarded_unchanged")); self.count("resp_" + outcome.lower())

    # ---- tokens -----------------------------------------------------------------------
    def _push(self, t, kind, slot):
        self._n += 1
        heapq.heappush(self.queue, (t, 1, self._n, kind, slot))

    def admit(self, t, slot):
        m = self.base(); c = self.c
        m.update(role=c["ROLE_BLOCK"], is_pktgen=1, pgen_slot=1 if slot == "ACK" else 2,
                 pkt_class=c["CLASS_OTHER"], dequeued=0)
        _, m["owner"] = self._owner_pass(t, m, self.cookie)
        m["owner_valid"] = 1 if self.table("tbl_owner_valid", **m)[0] == "owner_accept" else 0
        cur = self.reg("tag_read_or_mark", t, tag_val=0)
        m["cur_gen"] = cur
        m["txn_active"] = self.run_action(self.table("tbl_txn_active", **m)[0], t, m)["txn_active"]
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("ADMIT_" + slot, t, "", outcome))
        if outcome in ("OUT_ADMIT_ACK", "OUT_ADMIT_RESP"):
            self.tokens[slot] = dict(seq=self.budget, gen=cur)
            self._push(t + self.tau, "PASS", slot)
        else:
            self.count("admission_" + outcome.lower())

    def token_pass(self, t, slot):
        tok = self.tokens.get(slot)
        if tok is None:
            return
        c = self.c
        m = self.base()
        m.update(role=c["ROLE_BLOCK"], dequeued=1, pkt_class=c["CLASS_BLOCK_DEQ"], budget_zero=int(tok["seq"] == 0),
                 token_slot=c["SLOT_ACK"] if slot == "ACK" else c["SLOT_RESP"], is_resp_blk=int(slot == "RESP"))
        act, _ = self.table("tbl_owner_admission", **m)
        m["owner"] = self.run_action(act, t, dict(m, cookie_in=self.cookie))["owner"]
        m["owner_valid"] = 1 if self.table("tbl_owner_valid", **m)[0] == "owner_accept" else 0
        m["tag_diff"] = self.reg("tag_rmw", t, gen_in=tok["gen"], tag_val=c["TAG_NO_WRITE"])
        dec, _ = self.table("tbl_state_decode", **m)
        r = self.run_action(dec, t, m)
        m.update(verdict=r.get("verdict", 0), age=r.get("age", 0))
        rdl, _ = self.table("tbl_resp_deadline", **m)
        m["age_resp"] = self.run_action(rdl, t, m).get("age_resp", 0)
        _, outcome = self.table("tbl_decide_deq", **m)
        self.trace.append(("TOK_" + slot, t, "", outcome))
        if outcome in ("OUT_AB_LOOP", "OUT_RB_LOOP"):
            tok["seq"] -= 1
            self._push(t + self.tau, "PASS", slot)
            return
        del self.tokens[slot]
        self.slot_open[slot] = "normal" if outcome in ("OUT_AB_DL", "OUT_RB_DL") else "forwarded_ungated"
        if outcome in ("OUT_AB_DL", "OUT_AB_TMO"):
            self.count("ack_" + outcome[-2:].lower())
            if self.held["ACK"] is not None:
                self._ack_release(t, "normal" if outcome == "OUT_AB_DL" else "watchdog")
        elif outcome in ("OUT_RB_DL", "OUT_RB_TMO"):
            self.count("resp_" + outcome[-2:].lower())
            if self.held["RESP"] is not None:
                self.held["RESP"] = None
                self.outs.append(("RESP", t, "normal" if outcome == "OUT_RB_DL" else "watchdog"))
                self._resp_release(t)
        else:
            self.count("token_" + outcome.lower())

    def lose_token(self, t, slot):
        """Fault injection: the slot's token vanishes (queue ungated, no timeout pass will ever run)."""
        if self.tokens.pop(slot, None) is None:
            return
        self.slot_open[slot] = "tokens_lost"
        self.count("token_lost_" + slot.lower())
        if slot == "ACK" and self.held["ACK"] is not None:
            self._ack_release(t, "tokens_lost")
        elif slot == "RESP" and self.held["RESP"] is not None:
            self.held["RESP"] = None
            self.outs.append(("RESP", t, "tokens_lost"))

    def _ack_release(self, t, reason):
        """The held ACK leaves; its released pass arms the response deadline (tresp_arm_once)."""
        self.held["ACK"] = None
        self.outs.append(("ACK", t, reason))
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_ACK_REL"], held_valid=1, role=c["ROLE_ACK"], seq_diff=0, ack_diff=0,
                 sport_diff=0, dequeued=1)
        _, m["owner"] = self._owner_pass(t, m, self.cookie)
        rdl, _ = self.table("tbl_resp_deadline", **m)
        self.run_action(rdl, t, dict(m, dl_val_resp=self.candidate(self.table("tbl_build_cand_resp", **m)[0], t)))

    def _resp_release(self, t):
        """The released response completes the transaction: owner retired, generation cleared."""
        m = self.base(); c = self.c
        m.update(role=c["ROLE_RESP"], held_valid=1, dequeued=1, pkt_class=c["CLASS_OTHER"])
        act, _ = self.table("tbl_owner_admission", **m)
        assert act == "owner_release", act
        self.run_action(act, t, dict(m, cookie_in=self.cookie))
        self.reg("tag_rmw", t, gen_in=0, tag_val=c["TAG_INACTIVE"])
        self.slot_open = {"ACK": None, "RESP": None}
        self.count("completed")

    # ---- driver -----------------------------------------------------------------------
    def run(self, events):
        """events: list of (t_ns, 'REQ'|'ACK'|'RESP', match:bool)."""
        for t, kind, match in events:
            self._n += 1
            heapq.heappush(self.queue, (t, 0, self._n, kind, match))
        while self.queue:
            t, _, _, kind, arg = heapq.heappop(self.queue)
            if kind == "REQ":
                self.request(t, arg)
            elif kind == "ACK":
                self.pure_ack(t, arg)
            elif kind == "RESP":
                self.response(t, arg)
            elif kind == "ADMIT":
                self.admit(t, arg)
            elif kind == "PASS":
                self.token_pass(t, arg)
            elif kind == "LOSE":
                self.lose_token(t, arg)
        return self
