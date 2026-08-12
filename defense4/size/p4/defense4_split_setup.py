#!/usr/bin/env python3
# ============================================================================
# defense4_split_setup.py — control-plane setup for defense4_split_kernel.p4.
#
# PAD-only response-direction size normalization (SPLIT is not configured here —
# READ and SBO are single packets). Brings up the data ports and installs the
# per-flow PAD policy so the outstation->master response direction is grown to a
# common block-aligned target L.
#
# Modeled on defense4/timing/control/defense4_caseA_setup.py: the frozen Defense 3
# setup module is lazy-loaded for the PROVEN port-bringup (`$PORT`) + gRPC/table/
# register/Checks helpers, WITHOUT modifying it. bfrt_grpc is lazy-imported INSIDE
# functions, so this file imports offline with no SDE present. Every hardware op
# refuses unless DEFENSE4_HW_AUTHORIZED=1.
#
# ►► TARGET-MATH FINDING (verified offline via the split emulator; see `dry-run`).
#    The MVP kernel pads BLOCK-ALIGNED inputs (on-wire 28/46/64 B, ip.total_len
#    68/86/104) up to L=64 B (3 full 18-byte blocks) by appending WHOLE constant
#    filler blocks. The MEASURED SEL-751 responses are NON-block-aligned:
#      READ = 40 B on-wire (total_len 80), SBO = 49 B on-wire (total_len 89).
#    The kernel FAILS THEM OPEN (delta 0) — it does NOT normalize them — and the
#    required deltas (40->64 = +24, 49->64 = +15) are not multiples of 18, so
#    whole-block filler cannot produce them. Normalizing the real frames needs the
#    kernel's non-block-aligned extension (variable last-block parse + a per-flow
#    boundary-block runtime CRC), which is DEFERRED. `configure --mode PAD` REFUSES
#    to install PAD for non-block-aligned declared native sizes unless
#    --force-unaligned is given, because on silicon a non-block-aligned frame can
#    also underflow the egress block parser and drop the response.
# ============================================================================
import argparse
import importlib.util
import json
import os
import socket
import struct
import sys

# ---- resolve the frozen Defense 3 setup module (proven ports + gRPC/table helpers) ----
_HERE = os.path.dirname(os.path.abspath(__file__))
_D3NAME = "case_a_defense3_fixed_ack_delay_setup.py"
_D3CANDS = [os.environ.get("D4_D3SETUP", ""),
            os.path.join(_HERE, _D3NAME),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..", "..", "DNP3",
                                         "defense3", "setup", _D3NAME)),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..", "defense3", "setup", _D3NAME))]
_D3PATH = next((p for p in _D3CANDS if p and os.path.isfile(p)), _D3CANDS[1])
_spec = importlib.util.spec_from_file_location("d3setup", _D3PATH)
d3 = importlib.util.module_from_spec(_spec)
try:
    _spec.loader.exec_module(d3)         # bfrt lazy-imported inside functions -> offline-safe
    _D3_OK = True
except Exception as _e:                  # allow --dry-run / py_compile with no d3 present
    _D3_OK = False
    _D3_ERR = str(_e)

# ---- kernel constants (must match defense4_split_kernel.p4 egress) ----
POL_NONE, POL_PAD, POL_SPLIT = 0, 1, 2
KERNEL_TARGET_L = 64                     # compiled target: 3 full 18-byte blocks (payload 64)
LEGAL_INPUT_ONWIRE = (28, 46, 64)        # on-wire DNP3 frame sizes the parser accepts (1/2/3 blocks)
DNP3_PORT_DEFAULT = 20000
PORT_L = getattr(d3, "PORT_L", 8) if _D3_OK else 8
PORT_VISION = getattr(d3, "PORT_VISION", 9) if _D3_OK else 9
PORT_RELAY = getattr(d3, "PORT_RELAY", 64) if _D3_OK else 64


def _ip2int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _norm_tuple(a):
    """Direction-normalized owner key (nm_ip, nr_ip, nm_pt, nr_pt) for the protected flow,
    matching the kernel's e_fold on the response direction (sport == DNP3 port -> DIR_OUT):
    nm = master (Vision) side, nr = relay (outstation) side."""
    return (_ip2int(a.master_ip), _ip2int(a.relay_ip), int(a.master_port), int(a.dnp3_port))


# ---------------------------------------------------------------------------
# target math via the split emulator (offline; no SDE, no gRPC)
# ---------------------------------------------------------------------------
def pad_delta_math(a, chk, out):
    """For each declared native on-wire size, run the REAL split emulator (the P4
    behavioral model) with PAD and record whether the kernel normalizes it to L and
    the per-direction delta. Also reports the block-aligned sizes that WOULD work."""
    sys.path.insert(0, os.path.join(_HERE, "..", "offline"))
    sys.path.insert(0, os.path.join(_HERE, "..", "readsbo_normalizer"))
    from readsbo_normalizer import build_frame, link_wire_len
    from p4_split_emulator import SplitPadEmulator, Pkt, POL_PAD as EPAD, PORT_DNP3

    owner = (_ip2int(a.master_ip), _ip2int(a.relay_ip), int(a.master_port), int(a.dnp3_port))
    chk.expect("target L is the compiled kernel target", a.target_l, KERNEL_TARGET_L)

    def onwire_to_frame(onwire):
        u = next((n for n in range(1, 200) if link_wire_len(n) == onwire), None)
        if u is None:
            return None
        return build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(u - 1))

    results = {}
    all_normalized = True
    for name, onwire in (("READ", int(a.read_size)), ("SBO", int(a.sbo_size))):
        f = onwire_to_frame(onwire)
        if f is None or f[:2] != b"\x05\x64":
            chk.fail("%s size %dB is a valid DNP3 frame" % (name, onwire), "no user length maps to it")
            all_normalized = False
            continue
        e = SplitPadEmulator(owner, EPAD)
        r = e.process(Pkt(owner[1], owner[0], PORT_DNP3, owner[2], seq=1000, ack=5, payload=f))
        normalized = (r.outcome == "PAD" and len(r.segs[0].payload) == a.target_l)
        block_aligned = onwire in LEGAL_INPUT_ONWIRE
        results[name] = {"native_onwire": onwire, "block_aligned": block_aligned,
                         "kernel_outcome": r.outcome, "delta_wire_bytes": r.delta,
                         "grown_onwire": len(r.segs[0].payload) if r.segs else onwire,
                         "normalized_to_L": normalized,
                         "intended_delta_to_L": a.target_l - onwire}
        if not normalized:
            all_normalized = False
            chk.warn("%s %dB is NOT normalized by the MVP kernel" % (name, onwire),
                     "non-block-aligned -> fail-open (delta 0); needs +%d (not a multiple of 18)"
                     % (a.target_l - onwire))
        else:
            chk.ok("%s %dB -> %dB via PAD" % (name, onwire, a.target_l),
                   "delta +%d wire bytes (whole filler blocks)" % r.delta)

    # what the kernel CAN normalize (block-aligned inputs)
    demo = {}
    for onwire in LEGAL_INPUT_ONWIRE[:-1]:
        f = onwire_to_frame(onwire)
        e = SplitPadEmulator(owner, EPAD)
        r = e.process(Pkt(owner[1], owner[0], PORT_DNP3, owner[2], seq=1, ack=5, payload=f))
        demo[onwire] = {"outcome": r.outcome, "delta": r.delta, "grown": len(r.segs[0].payload)}
    out["pad_target_math"] = {"target_L": a.target_l, "declared": results,
                              "block_aligned_capability": demo}
    out["pad_normalizes_declared_sizes"] = all_normalized
    return all_normalized


# ---------------------------------------------------------------------------
# policy install / removal + readback (hardware; gated)
# ---------------------------------------------------------------------------
def _policy_key(t, gc, norm):
    return t.make_key([gc.KeyTuple("m.nm_ip", norm[0]), gc.KeyTuple("m.nr_ip", norm[1]),
                       gc.KeyTuple("m.nm_pt", norm[2]), gc.KeyTuple("m.nr_pt", norm[3])])


def _set_policy_data(t, gc, pol):
    for act in ("Egress.set_policy", "set_policy"):
        try:
            return t.make_data([gc.DataTuple("pol", pol)], act)
        except Exception:
            continue
    return t.make_data([gc.DataTuple("pol", pol)])


def config_policy(bi, tgt, a, out, chk, pad_on, write=True):
    """Install (pad_on) or remove (OFF) the ONE protected-flow entry in Egress.t_policy.
    OFF removes the entry -> default clr_policy -> owner=0 -> fail-open transparent."""
    import bfrt_grpc.client as gc
    norm = _norm_tuple(a)
    t = d3.get_table(bi, "t_policy", chk)
    if t is None:
        return
    key = _policy_key(t, gc, norm)
    if write:
        if pad_on:
            data = _set_policy_data(t, gc, POL_PAD)
            try:
                t.entry_add(tgt, [key], [data])
            except Exception:
                try:
                    t.entry_mod(tgt, [key], [data])
                except Exception as e:
                    chk.fail("t_policy install", str(e)[:120])
        else:
            try:
                t.entry_del(tgt, [key])
            except Exception:
                pass   # absent entry == already OFF
    # readback
    got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                     ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
    out["t_policy"] = {"owner_norm": norm, "entry": (None if err else got), "err": err}
    if pad_on:
        if err:
            chk.fail("t_policy PAD entry present", err)
        else:
            pol = got.get("pol", got.get("$ACTION_MEMBER_ID"))
            chk.expect("t_policy action is set_policy(POL_PAD)", pol, POL_PAD)
    else:
        chk.ok("t_policy OFF (entry removed -> fail-open)", str(norm))


def clear_epoch(bi, tgt, a, chk):
    """Zero the PAD single-insertion epoch registers so a re-configure starts closed.
    The dataplane flow_idx is a CRC16 hash we don't reproduce here, so clear the whole
    1024-entry arrays (bounded, one-time). --no-clear skips this."""
    n = 0
    for name in ("reg_pdelta", "reg_pb0"):
        for i in range(int(a.clear_indices)):
            ok = d3.reg_write(bi, tgt, name, 0, idx=i, chk=None)
            if not ok:
                chk.warn("clear %s stopped" % name, "at index %d" % i)
                break
            n += 1
    chk.ok("PAD epoch registers cleared", "%d writes (reg_pdelta/reg_pb0 [0..%d))" % (n, a.clear_indices))


def read_policy(bi, tgt, a, out):
    """READ-ONLY evidence: the t_policy owner entry + a sample of the epoch registers."""
    import bfrt_grpc.client as gc  # noqa: F401
    ev = {}
    norm = _norm_tuple(a)
    t = d3.get_table(bi, "t_policy")
    if t is not None:
        got, err = d3.get_entry(t, tgt, [("m.nm_ip", norm[0]), ("m.nr_ip", norm[1]),
                                         ("m.nm_pt", norm[2]), ("m.nr_pt", norm[3])])
        ev["t_policy_owner"] = {"norm": norm, "entry": (None if err else got), "err": err}
    ev["reg_pdelta_sample"] = {i: d3.reg_read(bi, tgt, "reg_pdelta", idx=i) for i in (0, 1, 2, 3)}
    ev["reg_pb0_sample"] = {i: d3.reg_read(bi, tgt, "reg_pb0", idx=i) for i in (0, 1, 2, 3)}
    out["evidence"] = ev
    return ev


def _report(chk, out):
    print(chk.render())
    print("---- readback ----")
    print(json.dumps(out, indent=2, default=str))
    print("RESULT: %s (%d failures)" % ("PASS" if chk.n_fail == 0 else "FAIL", chk.n_fail))


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def run(a):
    chk = d3.Checks() if _D3_OK else _MiniChecks()
    out = {"mode": a.mode, "op": a.op, "program": a.program,
           "ports": {"vision": a.port_vision, "relay": a.port_relay, "loopback": a.port_l}}

    # ---- offline op: validate + target math (no gRPC) ----
    if a.op == "dry-run":
        pad_delta_math(a, chk, out)
        chk.ok("dry-run offline (ports/policy math validated, no hardware touched)", "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    # every remaining op writes/reads hardware
    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        sys.stderr.write("REFUSING: op=%s touches ports/tables/registers (hardware). Set "
                         "DEFENSE4_HW_AUTHORIZED=1 under an authorized session.\n" % a.op)
        return 2
    if not _D3_OK:
        sys.stderr.write("REFUSING: Defense-3 setup module not importable (%s)\n" % _D3_ERR)
        return 2
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(grpc_addr=a.grpc, client_id=0, device_id=0)
    iface.bind_pipeline_config(a.program)
    bi = iface.bfrt_info_get(a.program)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    if a.op == "evidence-dump":
        ev = read_policy(bi, tgt, a, out)
        print("EVIDENCE " + json.dumps(ev, default=str))
        chk.ok("evidence-dump read (read-only)", "")
        _report(chk, out)
        return 0

    if a.op == "configure":
        pad_on = (a.mode == "PAD")
        # SAFETY: refuse PAD for non-block-aligned declared native sizes (kernel fails them
        # open, and a non-block-aligned frame can underflow the egress block parser on silicon).
        if pad_on:
            normalized = pad_delta_math(a, chk, out)
            if not normalized and not a.force_unaligned:
                chk.fail("configure PAD refused",
                         "declared native sizes are not normalized by the MVP kernel "
                         "(non-block-aligned). Re-run with --force-unaligned to install anyway.")
                _report(chk, out)
                return 2
        # (a) ports up (proven D3 path: dp9 Vision 25G, dp64 relay 1G, dp8 loopback)
        d3.config_ports(bi, tgt, a, out, chk, write=True)
        # (b) policy
        config_policy(bi, tgt, a, out, chk, pad_on=pad_on, write=True)
        if pad_on and not a.no_clear:
            clear_epoch(bi, tgt, a, chk)
        chk.ok("configure mode=%s (%s)" % (a.mode, "PAD installed" if pad_on else "transparent/fail-open"), "")
        _report(chk, out)
        return 0 if chk.n_fail == 0 else 2

    chk.fail("unknown op", a.op)
    _report(chk, out)
    return 2


class _MiniChecks(object):
    """Minimal Checks stand-in so --dry-run/py_compile work with no Defense-3 module."""
    def __init__(self):
        self.rows = []
        self.n_fail = 0
    def ok(self, n, d=""):
        self.rows.append(("ok", n, d))
    def warn(self, n, d=""):
        self.rows.append(("WARN", n, d))
    def fail(self, n, d=""):
        self.rows.append(("FAIL", n, d))
        self.n_fail += 1
    def expect(self, n, got, want):
        (self.ok if got == want else self.fail)(n, "got=%r want=%r" % (got, want))
    def render(self):
        return "\n".join("  [%s] %s%s" % (s, n, (" — " + str(d)) if d else "") for s, n, d in self.rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Defense 4 split-kernel PAD-only control-plane setup")
    ap.add_argument("op", choices=["dry-run", "configure", "evidence-dump"])
    ap.add_argument("--mode", choices=["OFF", "PAD"], default="OFF")
    ap.add_argument("--target-l", type=int, default=KERNEL_TARGET_L,
                    help="pad target on-wire size (compile-time-fixed at %d)" % KERNEL_TARGET_L)
    # measured SEL-751 native sizes (coordinator): READ=40 B, SBO=49 B on-wire
    ap.add_argument("--read-size", type=int, default=40)
    ap.add_argument("--sbo-size", type=int, default=49)
    ap.add_argument("--force-unaligned", action="store_true",
                    help="install PAD even when declared native sizes are non-block-aligned (UNSAFE)")
    # protected flow (response direction: outstation->master)
    ap.add_argument("--master-ip", default="10.10.54.19")     # Vision
    ap.add_argument("--relay-ip", default="192.168.10.7")     # SEL-751 outstation
    ap.add_argument("--master-port", type=int, default=40000)
    ap.add_argument("--dnp3-port", type=int, default=DNP3_PORT_DEFAULT)
    # epoch clear
    ap.add_argument("--no-clear", action="store_true")
    ap.add_argument("--clear-indices", type=int, default=1024)
    # ports
    ap.add_argument("--port-vision", type=int, default=PORT_VISION)
    ap.add_argument("--port-relay", type=int, default=PORT_RELAY)
    ap.add_argument("--port-l", type=int, default=PORT_L)
    # gRPC / program
    ap.add_argument("--grpc", default="localhost:50052")
    ap.add_argument("--program", default="defense4_split_kernel")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
