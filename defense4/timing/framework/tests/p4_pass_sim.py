"""Pass-level trace simulator that drives the P4's own tables and register actions.

Scope: READ timing and admitted packet association, source register actions and
const tables. Real-byte events use rrc.parse for flow/TCP/application fields;
legacy boolean-match events retain their weaker association abstraction.
The aggregate token per reservoir, configured session lookup, pulse scheduling,
parser classification subset and hold-queue service are idealised. This does not
prove P4 parser/CRC behavior, connection incarnations/FIN/RST, BOR OPERATE, full
64-token ring service, physical queue drain or wire departure. Expiry is disabled
by default, preserving the explicitly tested legacy two-reservoir-loss limit.
"""
import heapq
import socket
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "response_ready" / "tests"))
sys.path.insert(0, str(ROOT.parents[1]))
from test_p4_release import SOURCE, sem  # noqa: E402
from test_p4_recovery import execute  # noqa: E402

import functools  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "size"))
import rrc  # noqa: E402

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
    def __init__(self, da_ns, gap_ns, tau_ns=1711, budget=18000, adm_delay_ns=5000, t_offset_ns=0, mode="MODE_D4_DUAL",
                 configured_flow=("192.168.10.1", "192.168.10.7", 40000, 20000), expiry_enabled=0,
                 heartbeat_ns=100_000, source=None):
        self.src = Path(source or SOURCE).read_text()
        self.c = sem.extract_consts(self.src)
        self.tables = {n: sem.parse_const_table(self.src, n, self.c) for n in (
            "tbl_state_decode", "tbl_resp_deadline", "tbl_txn_active", "tbl_resp_authorise",
            "tbl_decide_fresh", "tbl_decide_deq", "tbl_owner_admission", "tbl_owner_valid",
            "tbl_build_cand_resp", "tbl_tracker_admission", "tbl_guarded_seq", "tbl_guarded_sport",
            "tbl_guarded_ack", "tbl_guarded_app", "tbl_app_association", "tbl_ready_expiry",
            "tbl_case4_expiry_decide", "tbl_case4_held_release")}
        # control.py floors both to the 256 ns grid; the P4's due test needs the low byte of D to be zero
        self.da, self.gap = (da_ns // 256) * 256, (gap_ns // 256) * 256
        self.tau, self.budget, self.mode = tau_ns, budget, mode
        self.adm_delay, self.off = adm_delay_ns, t_offset_ns
        self.regs = {name: int(value, 0) for value, name in re.findall(
            r'Register<[^;]+>\(1,\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s+(reg_\w+)\s*;', self.src)}
        self.action_regs = {name: reg for reg, name in re.findall(
            r'RegisterAction<[^;]+>\((reg_\w+)\)\s+(\w+)\s*=\s*\{', self.src)}
        self.ra_src = self.src.replace('hdr.tcp.seq_no', 'meta.packet_seq').replace('hdr.tcp.ack_no', 'meta.packet_ack')
        flags = re.search(r'\(8w(0x[0-9a-fA-F]+)\s*&&&\s*8w(0x[0-9a-fA-F]+),\s*4w5,\s*16w53', self.src)
        if flags is None:
            raise ValueError('source has no supported DNP3 parser flags row')
        self.dnp3_flags = tuple(int(x, 0) for x in flags.groups())
        self.flow, self.expiry_enabled, self.heartbeat = configured_flow, expiry_enabled, heartbeat_ns
        self.packet_outs, self.held_packets = [], {"ACK": [], "RESP": []}
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
        key = self.action_regs[name]
        fields = dict(packet_seq=0, packet_ack=0, app_seq=0, mport=0, sport_w=0, seq_w=0,
                      exp_ack_cand=0, cookie_in=0, expiry_cand=0)
        fields.update(meta)
        rv, new = execute(self.ra_src, name, self.regs[key], now_word=now_word(t + self.off), **fields)
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
        for lhs, n in re.findall(r"meta\.(\w+)\s*=\s*\d+w(\d+)\s*;", text):
            out[lhs] = int(n)
        return out

    def base(self):
        return dict(read_release=1, anchor_req=1, mode=self.c[self.mode], bor_pc=0, hold_ok=0, expiry_enabled=self.expiry_enabled)

    def _emit(self, kind, t, reason, raw=None):
        self.outs.append((kind, t, reason))
        if raw is not None:
            self.packet_outs.append((kind, t, raw, reason))

    def _hold(self, slot, t, raw):
        if self.held[slot] is None:
            self.held[slot] = t
        self.held_packets[slot].append({'raw': raw, 'cookie': self.cookie})

    def _packet_fields(self, raw, role):
        c = self.c
        p = rrc.parse(raw)
        if p is None:
            raise ValueError('packet event needs a parsable IPv4/TCP fixture')
        src, dst = (socket.inet_ntoa(raw[26:30]), socket.inet_ntoa(raw[30:34]))
        master, relay, _client, server = self.flow
        session = (c['SESS_MASTER'] if (src, dst, p.dport) == (master, relay, server)
                   else c['SESS_RELAY'] if (src, dst, p.sport) == (relay, master, server) else c['SESS_NONE'])
        app = p.payload[11] if len(p.payload) >= 13 else 0
        function = p.payload[12] if len(p.payload) >= 13 else 0
        fields = dict(sess=session, gen_in=app, app_seq=app & 15, packet_seq=p.seq, packet_ack=p.ack,
                      mport=p.sport if session == c['SESS_MASTER'] else p.dport,
                      sport_w=p.sport if session == c['SESS_MASTER'] else 0,
                      seq_w=p.ack if session == c['SESS_MASTER'] else 0)
        # Read the source's per-function request-length action. This deliberately
        # exposes fixed-length admission limits; actual frame eligibility is separate.
        block = sem.extract_named_block(self.src, 'tbl_build_exp_ack')
        action = 'build_exp_ack_none'
        for fc, name in re.findall(r'(DNP3_FC_\w+)\s*:\s*(build_exp_ack_\w+)\(\)', block):
            if self.c[fc] == function:
                action = name
        rhs = re.search(r'meta.exp_ack_cand\s*=\s*hdr.tcp.seq_no(?:\s*\+\s*32w(\d+))?', self.body(action))
        fields['exp_ack_cand'] = (p.seq + int(rhs.group(1) or 0)) & MASK32
        fields['pkt_class'] = (c['CLASS_ARM'] if role == c['ROLE_ARM'] and session == c['SESS_MASTER']
                              else c['CLASS_ACK'] if role == c['ROLE_ACK'] and session == c['SESS_RELAY']
                              else c['CLASS_RESP'] if role == c['ROLE_RESP'] and session == c['SESS_RELAY']
                              else c['CLASS_OTHER'])
        return fields

    def _track(self, t, m, raw):
        m.update(self.run_action(self.table('tbl_tracker_admission', **m)[0], t, m))
        if raw is not None:
            for table in ('tbl_guarded_seq', 'tbl_guarded_sport', 'tbl_guarded_ack', 'tbl_guarded_app', 'tbl_app_association'):
                m.update(self.run_action(self.table(table, **m)[0], t, m))
        if self.expiry_enabled:
            m.update(self.run_action(self.table('tbl_ready_expiry', **m)[0], t, m))

    def packet(self, t, raw):
        p = rrc.parse(raw)
        if p is None:
            raise ValueError('packet event needs a parsable IPv4/TCP fixture')
        # Only the admitted parser subset is represented; CRC checking is outside
        # this simulator, and no connection epoch/FIN/RST semantics are invented.
        if p.ihl != 20 or int.from_bytes(raw[20:22], 'big') & 0xbfff:
            self.count('parser_subset_bypass'); return
        if not p.payload and p.flags & 0x3f == 0x10:
            return self.pure_ack(t, raw=raw)
        flag_value, flag_mask = self.dnp3_flags
        if (p.flags & flag_mask == flag_value & flag_mask and len(p.payload) >= 13 and p.payload[:2] == b'\x05\x64'
                and p.payload[2] >= 8 and p.payload[10] & 0xc0 == 0xc0 and p.payload[11] & 0xf0 == 0xc0):
            if p.payload[12] == self.c['DNP3_FC_READ']:
                return self.request(t, raw=raw)
            if p.payload[12] == self.c['DNP3_FC_RESPONSE']:
                return self.response(t, raw=raw)
        self.count('parser_subset_bypass')

    # ---- external packets (fresh pass) -----------------------------------------------
    def _owner_pass(self, t, meta, cookie_in):
        act, _ = self.table("tbl_owner_admission", **meta)
        return act, self.run_action(act, t, dict(meta, cookie_in=cookie_in))["owner"]

    def _valid(self, m):
        m["owner_valid"] = 1 if self.table("tbl_owner_valid", **m)[0] == "owner_accept" else 0

    def request(self, t, match=True, raw=None):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_ARM"], role=c["ROLE_ARM"], sess=c["SESS_MASTER"])
        if raw is not None:
            m.update(self._packet_fields(raw, c["ROLE_ARM"]))
        act, prior = self._owner_pass(t, m, 0)
        self.admitted = act == "owner_admit"
        m["owner"] = prior
        self._valid(m)
        self._track(t, m, raw)
        gen = m.get("gen_in", GEN)
        free = (prior & 0x80000000) == 0 and (prior & 0xFFFF) != 0xFFFF        # tracker_write
        self.reg("tag_rmw", t, gen_in=gen, tag_val=gen if free else c["TAG_NO_WRITE"])
        m["tag_diff"] = gen if free else 1                                       # forced after the access
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
            self._push(t + self.adm_delay, "ADMIT", ("ACK", self.cookie))
            self._push(t + self.adm_delay, "ADMIT", ("RESP", self.cookie))
            if self.expiry_enabled:
                self._push(t + self.heartbeat, "PULSE_SCAN", None)
        else:
            self.count(outcome.lower())          # busy / dup: bypassed unchanged
        return outcome

    def pure_ack(self, t, match=True, raw=None):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_ACK"], role=c["ROLE_ACK"], sess=c["SESS_RELAY"],
                 seq_diff=0 if match else 1, ack_diff=0, sport_diff=0)
        if raw is not None:
            m.update(self._packet_fields(raw, c["ROLE_ACK"]))
        _, m["owner"] = self._owner_pass(t, m, 0)
        self._valid(m)
        self._track(t, m, raw)
        m["tag_diff"] = self.reg("tag_rmw", t, gen_in=0, tag_val=c["TAG_NO_WRITE"])
        dec, _ = self.table("tbl_state_decode", **m)
        r = self.run_action(dec, t, dict(m, dl_val=self.candidate("build_cand", t)))
        m.update(verdict=r["verdict"], ack_first=r.get("ack_first", 0))
        rdl, _ = self.table("tbl_resp_deadline", **m)
        self.run_action(rdl, t, dict(m, dl_val_resp=self.candidate(self.table("tbl_build_cand_resp", **m)[0], t)))
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("ACK", t, dec, outcome))
        if outcome in ("OUT_ACK_HOLD", "OUT_ACK_DUP_HOLD"):
            self._hold("ACK", t, raw)
            if self.slot_open["ACK"] is not None:           # queue already ungated: leaves at once
                self._ack_release(t, self.slot_open["ACK"])
        elif outcome == "OUT_ACK_FWD_ARM":
            self._emit("ACK", t, "forwarded", raw); self.count("ack_forwarded_armed")
        else:
            self._emit("ACK", t, "unmatched_forwarded", raw); self.count("ack_unmatched")

    def response(self, t, match=True, raw=None):
        m = self.base(); c = self.c
        m.update(pkt_class=c["CLASS_RESP"], role=c["ROLE_RESP"], sess=c["SESS_RELAY"],
                 seq_diff=0 if match else 1, ack_diff=0, sport_diff=0)
        if raw is not None:
            m.update(self._packet_fields(raw, c["ROLE_RESP"]))
        _, m["owner"] = self._owner_pass(t, m, 0)
        self._valid(m)
        self._track(t, m, raw)
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
            self._hold("RESP", t, raw)
            if self.expiry_enabled and self.slot_open["RESP"] is not None:
                self._release_held(t, "RESP", self.slot_open["RESP"])
        elif outcome == "OUT_RESP_DUP_SUPP":
            self.count("dup_response_dropped")
        else:
            self._emit("RESP", t, "forwarded_unchanged", raw); self.count("resp_" + outcome.lower())

    # ---- tokens -----------------------------------------------------------------------
    def _push(self, t, kind, slot):
        self._n += 1
        heapq.heappush(self.queue, (t, 1, self._n, kind, slot))

    def admit(self, t, slot, cookie=None):
        m = self.base(); c = self.c
        m.update(role=c["ROLE_BLOCK"], is_pktgen=1, pgen_slot=1 if slot == "ACK" else 2,
                 pkt_class=c["CLASS_OTHER"], dequeued=0)
        _, m["owner"] = self._owner_pass(t, m, self.cookie if cookie is None else cookie)
        m["owner_valid"] = 1 if self.table("tbl_owner_valid", **m)[0] == "owner_accept" else 0
        cur = self.reg("tag_read_or_mark", t, tag_val=0)
        m["cur_gen"] = cur
        m["txn_active"] = self.run_action(self.table("tbl_txn_active", **m)[0], t, m)["txn_active"]
        _, outcome = self.table("tbl_decide_fresh", **m)
        self.trace.append(("ADMIT_" + slot, t, "", outcome))
        if outcome in ("OUT_ADMIT_ACK", "OUT_ADMIT_RESP"):
            self.tokens[slot] = dict(seq=self.budget, gen=cur, cookie=self.cookie if cookie is None else cookie)
            self._push(t + self.tau, "PASS", (slot, self.tokens[slot]["cookie"]))
        else:
            self.count("admission_" + outcome.lower())

    def token_pass(self, t, slot, cookie=None):
        tok = self.tokens.get(slot)
        if tok is None or (cookie is not None and tok["cookie"] != cookie):
            return
        c = self.c
        m = self.base()
        m.update(role=c["ROLE_BLOCK"], dequeued=1, pkt_class=c["CLASS_BLOCK_DEQ"], budget_zero=int(tok["seq"] == 0 and not self.expiry_enabled),
                 token_slot=c["SLOT_ACK"] if slot == "ACK" else c["SLOT_RESP"], is_resp_blk=int(slot == "RESP"))
        act, _ = self.table("tbl_owner_admission", **m)
        m["owner"] = self.run_action(act, t, dict(m, cookie_in=tok["cookie"]))["owner"]
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
            self._push(t + self.tau, "PASS", (slot, tok["cookie"]))
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
                self._release_held(t, "RESP", "normal" if outcome == "OUT_RB_DL" else "watchdog")
        else:
            self.count("token_" + outcome.lower())
            if self.expiry_enabled and self.held[slot] is not None:
                self._release_held(t, slot, self.slot_open[slot])

    def lose_token(self, t, slot):
        """Fault injection: the slot's token vanishes (queue ungated, no timeout pass will ever run)."""
        if self.tokens.pop(slot, None) is None:
            return
        self.slot_open[slot] = "tokens_lost"
        self.count("token_lost_" + slot.lower())
        if slot == "ACK" and self.held["ACK"] is not None:
            self._ack_release(t, "tokens_lost")
        elif slot == "RESP" and self.held["RESP"] is not None:
            self._release_held(t, "RESP", "tokens_lost")

    def _release_held(self, t, slot, reason):
        held = self.held_packets[slot]
        self.held_packets[slot] = []
        self.held[slot] = None
        for packet in held:
            if self.expiry_enabled:
                self.held_check(t, slot, packet, reason)
            elif slot == 'RESP':
                self._emit(slot, t, reason, packet['raw'])
        if not self.expiry_enabled and slot == 'RESP' and reason != 'tokens_lost':
            self._resp_release(t)

    def held_check(self, t, slot, packet, reason):
        """Source phase-one eligibility; an ideal queue return consumes one tau.

        The second pass is a separate event, allowing owner retirement/rearming
        between eligibility and commit to exercise the full cookie guard.
        """
        c = self.c
        m = self.base()
        m.update(held_valid=1, dequeued=1, role=c['ROLE_'+slot], pkt_class=c['CLASS_OTHER'])
        _, m['owner'] = self._owner_pass(t, m, packet['cookie'])
        self._valid(m)
        m['cur_gen'] = self.reg('tag_read_or_mark', t, tag_val=0)
        m.update(self.run_action(self.table('tbl_state_decode', **m)[0], t, m))
        m.update(self.run_action(self.table('tbl_resp_deadline', **m)[0], t, m))
        m['ready_age'] = self.reg('ready_expiry_read', t)
        m.update(self.run_action(self.table('tbl_txn_active', **m)[0], t, m))
        action, _ = self.table('tbl_case4_held_release', **m)
        self.trace.append(('HELD_'+slot, t, action, m['owner']))
        if action in ('finish_held_ack_wait', 'finish_held_resp_wait'):
            self._push(t+self.tau, 'HELD_CHECK', (slot, packet, reason))
        elif action in ('finish_held_commit', 'finish_held_resp_commit'):
            # The source RESPONSE phase-one action stamps the phase bit into
            # the carried full cookie; ACK commitment retains its old cookie.
            phased = dict(packet)
            stamp = re.search(r'hdr\.held_owner\.cookie_word\s*=\s*(?:hdr\.held_owner\.cookie_word|meta\.cookie_in)\s*\|\s*32w(0x[0-9a-fA-F]+|[0-9]+)', self.body(action))
            if stamp:
                phased['cookie'] |= int(stamp.group(1), 0)
            self._push(t+self.tau, 'HELD_COMMIT', (slot, phased, reason))
        elif action == 'finish_held_native':
            self._native_held(slot, t, packet)
        else:
            self.count('stale_held_'+slot.lower()+'_dropped')

    def held_commit(self, t, slot, packet, reason):
        if slot == 'ACK':
            self._ack_commit(t, packet, reason, held_valid=2)
        else:
            disposition = self._resp_release(t, packet['cookie'])
            if disposition == 'expiry_native':
                self._native_held(slot, t, packet)
            elif disposition:
                self._emit(slot, t, reason, packet['raw'])

    def _native_held(self, slot, t, packet):
        action = self.body('finish_held_native')
        if 'hdr.held_owner.setInvalid()' not in action or 'D3_TO_FWD()' not in action:
            raise ValueError('source native-held action is outside the supported subset')
        self.run_action('finish_held_native', t, {})
        counter = re.search(r'ctr_outcome\.count\(16w([0-9]+)\)', action)
        if counter is None:
            raise ValueError('source native-held counter is outside the supported subset')
        self.count('source_count_'+counter.group(1))
        self.count('held_expiry_native')
        self._emit(slot, t, 'expiry_native', packet['raw'])

    def _phase2_native(self, m):
        # Bind the pipeline branch to the actual source condition. No inferred
        # cookie subtraction decides whether a phase-two packet is native.
        match = re.search(r'else if \(([^()]+)\)\s*\{\s*finish_held_native\(\);\s*\}', self.src)
        if match is None:
            return False
        terms = match.group(1).split('&&')
        predicates = []
        for term in terms:
            pred = re.fullmatch(r'\s*meta\.(\w+)\s*==\s*\d+w(0x[0-9a-fA-F]+|[0-9]+)\s*', term)
            if pred is None:
                raise ValueError('source phase-two native predicate is outside supported subset')
            predicates.append(m.get(pred.group(1), 0) == int(pred.group(2), 0))
        return all(predicates)

    def _ack_release(self, t, reason):
        if self.expiry_enabled:
            return self._release_held(t, 'ACK', reason)
        held = self.held_packets['ACK'] or [dict(raw=None, cookie=self.cookie)]
        self.held_packets['ACK'] = []
        self.held['ACK'] = None
        for packet in held:
            self._ack_commit(t, packet, reason)

    def _ack_commit(self, t, packet, reason, held_valid=1):
        m = self.base(); c = self.c
        m.update(pkt_class=c['CLASS_ACK_REL'], held_valid=held_valid, role=c['ROLE_ACK'],
                 seq_diff=0, ack_diff=0, sport_diff=0, dequeued=1)
        _, m['owner'] = self._owner_pass(t, m, packet['cookie'])
        self._valid(m)
        if not m['owner_valid']:
            self.count('stale_held_ack_dropped'); return
        if self._phase2_native(m):
            return self._native_held('ACK', t, packet)
        self._emit('ACK', t, reason, packet['raw'])
        rdl, _ = self.table('tbl_resp_deadline', **m)
        self.run_action(rdl, t, dict(m, dl_val_resp=self.candidate(self.table('tbl_build_cand_resp', **m)[0], t)))

    def _resp_release(self, t, cookie=None):
        """A stale held return must neither retire nor clear a new owner."""
        m = self.base(); c = self.c
        m.update(role=c['ROLE_RESP'], held_valid=2 if self.expiry_enabled else 1, dequeued=1, pkt_class=c['CLASS_OTHER'])
        _, m['owner'] = self._owner_pass(t, m, self.cookie if cookie is None else cookie)
        self._valid(m)
        if not m['owner_valid']:
            self.count('stale_held_response_dropped'); return False
        self.reg('tag_rmw', t, gen_in=0, tag_val=c['TAG_INACTIVE'])
        if self._phase2_native(m):
            return 'expiry_native'
        self.slot_open = {'ACK': None, 'RESP': None}
        self.count('completed')
        return True

    def pulse_scan(self, t):
        m = self.base(); c = self.c
        m.update(role=c['ROLE_EXPIRY_SCAN'], pkt_class=c['CLASS_OTHER'], dequeued=0)
        _, m['owner'] = self._owner_pass(t, m, 0)
        m['ready_age'] = self.reg('ready_expiry_read', t)
        m['age_resp'] = self.reg('tresp_read', t)
        action, _ = self.table('tbl_case4_expiry_decide', **m)
        self.trace.append(('PULSE_SCAN', t, action, m['owner']))
        if action == 'finish_expiry_loop':
            self._push(t + self.tau, 'PULSE_RETURN', m['owner'])
        if self.regs['reg_owner'] & 0x80000000:
            self._push(t + self.heartbeat, 'PULSE_SCAN', None)

    def pulse_return(self, t, cookie):
        m = self.base(); c = self.c
        m.update(role=c['ROLE_EXPIRY_RETIRE'], pkt_class=c['CLASS_OTHER'], dequeued=1)
        _, m['owner'] = self._owner_pass(t, m, cookie)
        if m['owner'] == 0:
            self.reg('tag_rmw', t, gen_in=0, tag_val=c['TAG_INACTIVE'])
            self.count('expiry_retired')
        else:
            self.count('stale_expiry_return')
        self.trace.append(('PULSE_RETURN', t, cookie, m['owner']))

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
            elif kind == "PACKET":
                self.packet(t, arg)
            elif kind == "ADMIT":
                self.admit(t, *arg)
            elif kind == "PASS":
                self.token_pass(t, *arg)
            elif kind == "LOSE":
                self.lose_token(t, arg)
            elif kind == "HELD_CHECK":
                self.held_check(t, *arg)
            elif kind == "HELD_COMMIT":
                self.held_commit(t, *arg)
            elif kind == "PULSE_SCAN":
                self.pulse_scan(t)
            elif kind == "PULSE_RETURN":
                self.pulse_return(t, arg)
        return self
