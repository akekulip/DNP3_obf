"""Contract rules model_contention.py judges by, as pure functions (failure analysis of m10_03, 2026-10-17).

The slow model makes host wall time a poor proxy for the dataplane's own order of events. Each rule states what the
contract requires in terms the dataplane itself records, so a point is judged by what the mechanism did, and an
order the evidence cannot establish is never resolved in the point's favour.
"""
MASK32 = 0xffffffff
SIGN = 0x80000000


def readiness_reached_before_release(t0_units, a_commit_units, gap_units, readiness_units):
    """Whether T's readiness fallback is the contract outcome for a committed ACK: the response's normal release
    (a_commit + gap) is not earlier than t0 + readiness. Compared as T compares, on the sign bit of the 32-bit
    difference. Returns None (an invalid read, never a verdict) when a_commit is not after t0 in that arithmetic:
    a register at its initial value, a stale commit, or a read of another lane."""
    if ((int(a_commit_units) - int(t0_units)) & MASK32) & SIGN:
        return None
    due = ((int(a_commit_units) + int(gap_units)) - (int(t0_units) + int(readiness_units))) & MASK32
    return not due & SIGN


def abort_branch_outcome(released_before_send, released_after_send):
    """An outstation RST meant to find the response held. The order is decided only from T's release counters read
    immediately BEFORE the RST is sent:
    - 'released': T had already released the response, so the released-branch expectation is the contract one;
    - 'held': nothing released before the send and nothing after, so the held expectation applies;
    - 'inconclusive': nothing released before the send, but a release after it. That release may have come before
      or after T applied the reset (the N-to-T propagation window), and nothing the driver sees separates the two,
      so the point is never passed."""
    if released_before_send:
        return 'released'
    return 'inconclusive' if released_after_send else 'held'


def request_quiet(kind, watch_later, op_hold_s, default_s=0.2):
    """Quiet after the relayed request. OPERATE keeps op_hold_s (the duplicate-release window) unless the caller
    watches the relay port through the response capture instead (option a, 2026-10-17)."""
    return op_hold_s if kind == 'OPERATE' and not watch_later else default_s


def _tcp_ports(frame):
    """(sport, dport) of an untagged IPv4 TCP frame, or None if the frame cannot be read as one."""
    if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] != 6 or (frame[14] & 0x0f) < 5:
        return None
    tcp = 14 + (frame[14] & 0x0f) * 4
    if len(frame) < tcp + 4:
        return None
    return int.from_bytes(frame[tcp:tcp + 2], 'big'), int.from_bytes(frame[tcp + 2:tcp + 4], 'big')


def outstation_bound(frame, server_port):
    """True only for a frame positively read as IPv4 TCP addressed to the outstation's port. Direction comes from the
    frame: in the model build the relay leg is mapped to the master's device port (port_map relay_port 9), so a
    capture's port tag cannot tell the directions apart (model_contention_m10_03_06). Use it where being
    outstation-bound makes a check PASS (an RST 'relayed')."""
    ports = _tcp_ports(frame)
    return ports is not None and ports[1] == server_port


def master_bound(frame, server_port):
    """True only for a frame positively read as IPv4 TCP sent from the outstation's port (toward the master)."""
    ports = _tcp_ports(frame)
    return ports is not None and ports[0] == server_port


def late_relay_copies(frames, relay_dev_port, server_port):
    """Frames (t, port, frame) on the relay device port after the request capture that are not positively
    master-bound: each is counted as a second copy of the request, an unreadable frame included (fail closed;
    code review). Returns [(t, length)]; empty means none."""
    return [(round(t, 4), len(f)) for t, p, f in frames if p == relay_dev_port and not master_bound(f, server_port)]
