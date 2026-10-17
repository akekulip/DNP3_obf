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
