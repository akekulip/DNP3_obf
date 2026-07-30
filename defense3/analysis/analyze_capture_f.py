#!/usr/bin/env python3
"""Score Gate 4 case F from the MASTER-SIDE CAPTURE.

WHY THIS IS A SEPARATE ANALYZER. Case F fires two synthetic RESPONSES -- N+1's own and a
stale copy -- and NOTHING inside the chip distinguishes them: they share a session, a role,
a class and every counter. The only separable property is the ethertype each leaves with,
which is why the repair candidate gives the stale injector its own (0x88C8). That makes the
question answerable on the wire and nowhere else, so this reads the pcap rather than the
register dump.

THE PROPERTY: a bypassed copy is forwarded immediately, so it must leave the switch BEFORE
the held ACK, which waits for the deadline. A held copy would leave WITH the ACK. So the
sign of (t_alt - t_ack_released) is the whole test.

Usage:  analyze_capture_f.py <capture.pcap> [out.json]
        analyze_capture_f.py --self-test
"""
import json, re, subprocess, sys, statistics as st

E_ACK, E_RESP, E_ALT = "0x88c6", "0x88c7", "0x88c8"
GAP_S = 0.05          # a quiet gap longer than this starts a new transaction


def read_events(pcap):
    out = subprocess.run(["tcpdump", "-r", pcap, "-nn", "-tt"],
                         capture_output=True, text=True).stdout
    ev = []
    for ln in out.splitlines():
        m = re.match(r"^(\d+\.\d+).*ethertype Unknown \((0x88c[678])\)", ln)
        if m:
            ev.append((float(m.group(1)), m.group(2)))
    ev.sort()
    return ev


def group(ev, gap=GAP_S):
    groups, cur = [], []
    for t, k in ev:
        if cur and t - cur[-1][0] > gap:
            groups.append(cur); cur = []
        cur.append((t, k))
    if cur:
        groups.append(cur)
    return groups


def score(ev):
    res = {"frames": len(ev), "transactions_with_alt": 0, "deltas_ms": [], "checks": []}
    for g in group(ev):
        kinds = {k: t for t, k in g}
        if E_ALT not in kinds or E_ACK not in kinds:
            continue
        res["transactions_with_alt"] += 1
        res["deltas_ms"].append((kinds[E_ALT] - kinds[E_ACK]) * 1e3)
    n = res["transactions_with_alt"]
    early = [d for d in res["deltas_ms"] if d < 0]
    ok = n > 0 and len(early) == n
    res["checks"].append({
        "id": "F-10", "result": "PASS" if ok else ("FAIL" if n else "INDETERMINATE"),
        "text": "the STALE copy (0x88C8) left before the held ACK, i.e. it was bypassed",
        "detail": ("no transaction carried a stale frame" if not n else
                   "%d/%d transactions: stale left %.3f ms before the held ACK "
                   "(min %.3f, max %.3f)"
                   % (len(early), n, st.median(res["deltas_ms"]),
                      min(res["deltas_ms"]), max(res["deltas_ms"])))})
    res["verdict"] = res["checks"][0]["result"]
    return res


def self_test():
    """Negative controls: the sign of the delta must decide, and an empty capture must
    not silently pass."""
    bad = []
    held = [(0.0, E_ALT), (0.0000, E_ACK)]          # alt WITH the ack -> held
    bypassed = [(0.0, E_ALT), (0.0015, E_ACK)]      # alt BEFORE the ack -> bypassed
    if score(bypassed)["verdict"] != "PASS":
        bad.append("a stale frame before the ACK must PASS")
    if score(held)["verdict"] != "FAIL":
        bad.append("a stale frame not before the ACK must FAIL")
    if score([])["verdict"] != "INDETERMINATE":
        bad.append("an empty capture must be INDETERMINATE, not PASS")
    if score([(0.0, E_ACK), (0.001, E_RESP)])["verdict"] != "INDETERMINATE":
        bad.append("a capture with no stale frame must be INDETERMINATE")
    if bad:
        print("SELF-TEST FAIL"); [print("  -", b) for b in bad]; return 1
    print("SELF-TEST PASS (4 controls)"); return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    r = score(read_events(sys.argv[1]))
    if len(sys.argv) > 2:
        json.dump(r, open(sys.argv[2], "w"), indent=1)
    c = r["checks"][0]
    print("%-6s %-5s %s" % (c["result"], c["id"], c["text"]))
    print("       %s" % c["detail"])
    sys.exit(0 if r["verdict"] == "PASS" else 1)
