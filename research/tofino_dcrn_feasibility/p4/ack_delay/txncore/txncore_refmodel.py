#!/usr/bin/env python3
"""
Phase-2 generation-safe transaction-core reference model (END_TO_END_IMPLEMENTATION_PLAN.md §6).

A Python mirror of the per-flow transaction state machine in `dcrn_defense1.p4`, PLUS the one thing
Phase 2 adds that the frozen file deferred: **generation freshness**. In the frozen P4 the bridge
header carries a `gen` field but it is hardcoded 0 and `reg_gen` was dropped (dcrn_defense1.p4:365,
581,618) because reading it on the recirc path would need a 3rd MAU stage. This model implements the
intended semantics so the LOGIC can be validated offline (no switch, no relay), which is exactly the
Phase-2 definition of done ("reference-model + replay tests pass … no stale state; fits a variant").

Frozen semantics reproduced verbatim in intent (register names in parentheses):
  ARM (forward READ, dir==0, dst==20000, payload>0, DNP3 app, fc-allowlisted):
      exp_ack = tcp.seq + payload_len                          (meta.exp_ack)
      armed := 1 (reg_armed), exp_ack stored (reg_expected_ack), occupancy cleared (flow_has_held_ack)
  PURE ACK (reverse, dir==1, src==20000, payload==0):
      qualify = armed AND flags_ok((flags&0x17)==0x10) AND ack == exp_ack     -> hold FIRST only (fha TAS)
      a pure FIN/RST clears armed (armed_get_absclr) and is forwarded, never held
  RESPONSE (reverse, dir==1, src==20000, payload>0):
      armed cleared (armed_getclr); if an ACK is held (fha getclr) AND not_abort -> ADMIT (resp_seen)
      else BYPASS (combined mode / abort-with-data)
  HOLD LOOP (recirc): ACK released, then RESPONSE released after guard once the ACK is gone; a
      pass_count >= *_MAX_PASS forces a fail-open release.

Generation freshness (Phase-2 ADD): every ARM bumps the flow generation (mod 256) and each held
frame is stamped with the generation live at hold-enter. On every recirc pass, if the held frame's
stamped generation != the flow's current generation, the frame is a stale straggler (a newer
transaction re-armed the same flow_id — via a rapid second request or a 16-bit hash collision) and
is DISCARDED instead of being released against the wrong transaction. This is the collision- and
reuse-safety the frozen file lacked.

Scope: models classification + per-flow lifecycle + generation. It is byte-preserving by construction
(the shadow/defense never edit DNP3/TCP/IP bytes), so byte/size/order identity is not re-modelled here.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, Tuple

DNP3_PORT = 20000
GEN_MOD = 256           # bridge.gen is bit<8>
MASK32 = 0xFFFFFFFF     # TCP seq/ack are 32-bit modular

# default hold-loop bounds (abstract pass counts; the real P4 uses ACK_MAX_PASS/RESP_MAX_PASS/GUARD_PASSES)
ACK_MAX_PASS = 4096
RESP_MAX_PASS = 4096
GUARD_PASSES = 2


class Ev(Enum):
    ARM = "ARM"
    ARM_BYPASS = "ARM_BYPASS"
    ACK_HELD = "ACK_HELD"
    ACK_DUP_FORWARD = "ACK_DUP_FORWARD"
    ACK_PASSTHRU = "ACK_PASSTHRU"
    RESP_HELD = "RESP_HELD"
    COMBINED_BYPASS = "COMBINED_BYPASS"
    ABORT_FORWARD = "ABORT_FORWARD"
    ACK_RELEASED = "ACK_RELEASED"
    ACK_RELEASED_TIMEOUT = "ACK_RELEASED_TIMEOUT"
    RESP_RELEASED = "RESP_RELEASED"
    RESP_RELEASED_TIMEOUT = "RESP_RELEASED_TIMEOUT"
    STALE_DISCARD = "STALE_DISCARD"
    PASSTHRU = "PASSTHRU"


@dataclass
class Event:
    kind: Ev
    flow_id: int = 0
    detail: str = ""


@dataclass
class Pkt:
    """A minimal L3/L4 view; `dir` is the physical ingress direction (0=dp8 master side, 1=dp9)."""
    dir: int
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int          # TCP flags byte (FIN=0x01, SYN=0x02, RST=0x04, ACK=0x10)
    payload_len: int
    is_dnp3_app: bool
    flow_key: Tuple[int, int, int]
    fc_ok: bool = True


@dataclass
class FlowState:
    gen: int = 0
    armed: int = 0
    exp_ack: int = 0
    resp_seen: int = 0
    ack_gone: int = 0


@dataclass
class HeldFrame:
    role: str            # "ACK" or "RESP"
    gen: int             # generation stamped at hold-enter
    pass_count: int = 0


def _crc16(key: Tuple[int, int, int]) -> int:
    """CRC16 over the canonical flow key {client_ip, server_ip, client_port} (matches the P4 Hash
    domain: same value for request, response, and recirc). Standard CRC-16/CCITT-FALSE."""
    data = b"".join(int(x).to_bytes(4, "big") for x in key)
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def flags_ok(flags: int) -> bool:
    """Pure ACK: (flags & 0x17) == 0x10 — ACK set, SYN/RST/FIN clear."""
    return (flags & 0x17) == 0x10


def not_abort(flags: int) -> bool:
    """No FIN, no RST: (flags & 0x05) == 0."""
    return (flags & 0x05) == 0


class TxnCore:
    def __init__(self, hash_fn: Callable[[Tuple[int, int, int]], int] = _crc16,
                 ack_max_pass: int = ACK_MAX_PASS, resp_max_pass: int = RESP_MAX_PASS,
                 guard_passes: int = GUARD_PASSES, enabled: bool = True):
        self.hash_fn = hash_fn
        self.ack_max_pass = ack_max_pass
        self.resp_max_pass = resp_max_pass
        self.guard_passes = guard_passes
        # runtime enable (mirrors the P4's defense/shadow enable register): when False the core is a
        # transparent bump-in-the-wire — every frame is forwarded unchanged and NO per-flow state is
        # touched, so disabled mode reproduces the Phase-1 passive baseline exactly.
        self.enabled = enabled
        self.flows: Dict[int, FlowState] = {}
        # one in-loop frame per flow_id at a time (the P4 holds one txn/flow); plus a queued RESP that
        # is admitted behind a held ACK and becomes the held frame once the ACK is released.
        self.held: Dict[int, Optional[HeldFrame]] = {}
        self.queued_resp: Dict[int, Optional[HeldFrame]] = {}

    # ---- introspection helpers (tests) ----
    def flow_id(self, key: Tuple[int, int, int]) -> int:
        return self.hash_fn(key)

    def flow_state(self, key: Tuple[int, int, int]) -> FlowState:
        return self.flows.setdefault(self.flow_id(key), FlowState())

    def held_frame(self, key: Tuple[int, int, int]) -> Optional[HeldFrame]:
        return self.held.get(self.flow_id(key))

    def pending(self, key: Tuple[int, int, int]) -> bool:
        fid = self.flow_id(key)
        return bool(self.held.get(fid)) or bool(self.queued_resp.get(fid))

    # ---- main classifier ----
    def process(self, p: Pkt) -> Event:
        fid = self.flow_id(p.flow_key)
        if not self.enabled:
            return Event(Ev.PASSTHRU, fid, "disabled")   # transparent — no state touched
        st = self.flows.setdefault(fid, FlowState())

        is_tcp_dnp3_fwd = (p.dst_port == DNP3_PORT and p.dir == 0)
        is_tcp_dnp3_rev = (p.src_port == DNP3_PORT and p.dir == 1)

        # ARM: forward READ (request), payload-bearing DNP3 app frame on dir 0
        if is_tcp_dnp3_fwd and p.payload_len > 0 and p.is_dnp3_app:
            if not p.fc_ok:
                return Event(Ev.ARM_BYPASS, fid)
            st.gen = (st.gen + 1) % GEN_MOD                    # generation freshness: bump on every arm
            st.armed = 1
            st.exp_ack = (p.seq + p.payload_len) & MASK32       # request end-seq (FIX1)
            st.resp_seen = 0
            st.ack_gone = 0
            # fresh occupancy (FIX4): a re-arm invalidates any in-loop straggler via the generation stamp
            return Event(Ev.ARM, fid)

        # reverse frames from the outstation
        if is_tcp_dnp3_rev:
            if p.payload_len == 0:
                return self._reverse_pure_ack(p, fid, st)
            return self._reverse_response(p, fid, st)

        # everything else: transparent bump-in-the-wire
        return Event(Ev.PASSTHRU, fid)

    def _reverse_pure_ack(self, p: Pkt, fid: int, st: FlowState) -> Event:
        # armed_get_absclr: a pure FIN/RST clears armed and is forwarded (never held)
        if not not_abort(p.flags):
            st.armed = 0
            return Event(Ev.ABORT_FORWARD, fid)
        qualified = (st.armed == 1 and flags_ok(p.flags) and (p.ack & MASK32) == st.exp_ack)
        if not qualified:
            return Event(Ev.ACK_PASSTHRU, fid)
        # one-shot hold (fha test-and-set): only the FIRST qualifying ACK is held
        if self.held.get(fid) is not None:
            return Event(Ev.ACK_DUP_FORWARD, fid)
        self.held[fid] = HeldFrame(role="ACK", gen=st.gen, pass_count=0)
        return Event(Ev.ACK_HELD, fid)

    def _reverse_response(self, p: Pkt, fid: int, st: FlowState) -> Event:
        # armed_getclr: the response commits/aborts the txn -> clear armed (side effect)
        st.armed = 0
        held = self.held.get(fid)
        ack_is_held = held is not None and held.role == "ACK"
        if ack_is_held and not_abort(p.flags):
            st.resp_seen = 1
            # admit the response behind the held ACK (queued until the ACK releases)
            self.queued_resp[fid] = HeldFrame(role="RESP", gen=st.gen, pass_count=0)
            return Event(Ev.RESP_HELD, fid)
        # combined mode / abort-with-data / unmonitored -> bypass
        return Event(Ev.COMBINED_BYPASS, fid)

    # ---- recirc hold loop: one pass over the in-loop frame for a flow ----
    def release_pass(self, key: Tuple[int, int, int]) -> Optional[Event]:
        fid = self.flow_id(key)
        st = self.flows.setdefault(fid, FlowState())
        frame = self.held.get(fid)
        if frame is None:
            # maybe a queued RESP became the head after ACK release
            frame = self.queued_resp.get(fid)
            if frame is None:
                return None
            self.held[fid] = frame
            self.queued_resp[fid] = None

        frame.pass_count += 1

        # generation freshness: a straggler from a superseded transaction is discarded, never released
        if frame.gen != st.gen:
            self.held[fid] = None
            # a queued RESP stamped with the old gen is equally stale
            q = self.queued_resp.get(fid)
            if q is not None and q.gen != st.gen:
                self.queued_resp[fid] = None
            return Event(Ev.STALE_DISCARD, fid)

        if frame.role == "ACK":
            # release the ACK once the response has been admitted (resp_seen) or at max pass (fail-open)
            if frame.pass_count >= self.ack_max_pass:
                self.held[fid] = None
                st.ack_gone = 1
                return Event(Ev.ACK_RELEASED_TIMEOUT, fid)
            if st.resp_seen == 1:
                self.held[fid] = None
                st.ack_gone = 1
                return Event(Ev.ACK_RELEASED, fid)
            return None  # still holding the ACK, waiting for its response

        # frame.role == "RESP": release after the guard once the ACK is gone, or at max pass
        if frame.pass_count >= self.resp_max_pass:
            self.held[fid] = None
            return Event(Ev.RESP_RELEASED_TIMEOUT, fid)
        if st.ack_gone == 1 and frame.pass_count >= self.guard_passes:
            self.held[fid] = None
            st.resp_seen = 0    # txn fully drained -> no stale state
            return Event(Ev.RESP_RELEASED, fid)
        return None


# ---- convenience constructors for tests / replay ----
def _mk(flow_key, dir, src_port, dst_port, seq, ack, flags, plen, dnp3, fc_ok=True) -> Pkt:
    return Pkt(dir=dir, src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, flags=flags,
               payload_len=plen, is_dnp3_app=dnp3, flow_key=flow_key, fc_ok=fc_ok)


def tcp_read(flow_key, seq, plen, fc_ok=True) -> Pkt:
    """Master -> outstation DNP3 READ (arms the flow)."""
    return _mk(flow_key, 0, flow_key[2], DNP3_PORT, seq, 0, 0x18, plen, True, fc_ok)   # PSH|ACK


def tcp_pure_ack(flow_key, ack) -> Pkt:
    """Outstation -> master pure TCP ACK (the CLRT ACK)."""
    return _mk(flow_key, 1, DNP3_PORT, flow_key[2], 5000, ack, 0x10, 0, False)


def tcp_response(flow_key, seq, plen) -> Pkt:
    """Outstation -> master DNP3 response (payload-bearing)."""
    return _mk(flow_key, 1, DNP3_PORT, flow_key[2], seq, 2000, 0x18, plen, True)


def tcp_fin(flow_key, ack) -> Pkt:
    return _mk(flow_key, 1, DNP3_PORT, flow_key[2], 5000, ack, 0x11, 0, False)          # FIN|ACK


def tcp_rst(flow_key) -> Pkt:
    return _mk(flow_key, 1, DNP3_PORT, flow_key[2], 5000, 0, 0x04, 0, False)            # RST


def tcp_syn(flow_key, ack) -> Pkt:
    return _mk(flow_key, 1, DNP3_PORT, flow_key[2], 5000, ack, 0x12, 0, False)          # SYN|ACK
