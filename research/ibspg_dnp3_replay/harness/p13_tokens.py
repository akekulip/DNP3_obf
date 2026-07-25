#!/usr/bin/env python3
"""p13_tokens.py — blocker-token frames for the Part 13 real-DNP3 trial.

A blocker token is the internal frame that occupies Q_BLOCK (qid7, strict HIGH) on the dp8
loopback and thereby keeps the held RESPONSE on Q_RESP (qid1, LOW) from being dequeued. Its
wire form is unchanged from Parts 9/11/12:

    Ethernet(dst48, src48, etype=0x88C1) + ibspg(role8, slot8, gen8, seq32)

`ibspg_dnp3.p4` FORCES role = ROLE_BLOCK for any 0x88C1 frame, so the role byte is carried only
for wire compatibility and is never read. `seq` is the pass budget, decremented once per
loopback pass; it is the fail-open watchdog and must be >= 1.

THE GENERATION CONTRACT (this is the whole reason this file exists).
Part 12 injected a synthetic 8-bit generation counter of its own choosing. Part 13 cannot: the
compile note for Gate 13.2 records that `meta.gen_in` is now the DNP3 APPLICATION CONTROL byte
for DNP3 frames and `hdr.ib.gen` for tokens. A real DNP3 READ therefore writes its own
application control byte into `reg_gen`, and a token whose `gen` differs is judged STALE and
self-terminates on its first loopback pass (`ctr_block_term_stale`). So:

    a blocker token MUST carry gen = the application control byte of the READ
    whose transaction it guards.

That byte is lifted from the real captured READ payload at offset 11 (DNP3 link header 10 B +
transport header 1 B), never synthesized. For the SEL-751 corpus it runs 0xC0..0xCF: FIR=1,
FIN=1, CON=0, UNS=0, plus the 4-bit application sequence that increments per poll.

GENERATION UNIQUENESS, HONESTLY STATED. The application sequence is 4 bits, so the generation
repeats every 16 polls: in the 30-transaction corpus txn 0 and txn 16 both carry 0xC0. A token
left over from txn 0 would NOT be detected as stale at txn 16. It is never left over in
practice — a token drains in microseconds and transactions are spaced hundreds of milliseconds
apart — but the guarantee is 16 consecutive polls, not unlimited, exactly as the compile note
says.

Offline. Builds bytes in memory and injects nothing. Python 3.8+, stdlib only.
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPLAY_DIR = os.path.dirname(HERE)

ETYPE_TOKEN = 0x88C1

# Kept for wire compatibility with the Parts 9/11/12 injector. NOT read by ibspg_dnp3.p4 —
# ethertype 0x88C1 is forced to ROLE_BLOCK in the parser.
ROLE_BLOCK = 1

# MAC defaults reproduced from the Part 12 harness (proven on silicon). A token never reaches a
# host port, so its destination is an internal-only address; the source is a private marker that
# no NIC has ever transmitted, so i40e source pruning cannot drop it.
DEFAULT_DST_INTERNAL = "020000000001"
DEFAULT_SRC_TOKEN = "020000000b0c"

# DNP3 application control byte offset inside the TCP payload:
#   link header 10 B (start 2, len 1, ctrl 1, dst 2, src 2, crc 2) + transport header 1 B
APP_CONTROL_OFFSET = 11
APP_FUNC_OFFSET = 12

DNP3_FC_READ = 0x01
DNP3_FC_RESPONSE = 0x81

# The pass budget is a 32-bit field and seq==0 terminates a blocker on its first pass, so a
# budget of 0 means the reservoir never forms at all.
MIN_BUDGET = 1
MAX_BUDGET = 0xFFFFFFFF


def build_token(gen, budget, dst_mac=DEFAULT_DST_INTERNAL, src_mac=DEFAULT_SRC_TOKEN,
                role=ROLE_BLOCK, slot=0, pad_to=60):
    """One blocker-token frame. Layout identical to the Parts 9/11/12 injector's build()."""
    if not (MIN_BUDGET <= budget <= MAX_BUDGET):
        raise ValueError("budget %d out of range [%d, %d]" % (budget, MIN_BUDGET, MAX_BUDGET))
    ib = struct.pack("!BBBI", role & 0xFF, slot & 0xFF, gen & 0xFF, budget & 0xFFFFFFFF)
    frame = bytes.fromhex(dst_mac) + bytes.fromhex(src_mac) + struct.pack("!H", ETYPE_TOKEN) + ib
    if len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return frame


def gen_from_read_payload(payload):
    """The generation a token must carry to guard this READ: the READ's own app control byte.

    Raises rather than guessing — a wrong generation makes every token self-terminate on its
    first pass and the hold silently does not happen, which is the single most expensive way
    for this harness to fail.
    """
    if len(payload) <= APP_FUNC_OFFSET:
        raise ValueError("payload too short (%d B) to contain a DNP3 application header"
                         % len(payload))
    if payload[0:2] != b"\x05\x64":
        raise ValueError("payload does not start with the DNP3 magic 0x0564")
    fc = payload[APP_FUNC_OFFSET]
    if fc != DNP3_FC_READ:
        raise ValueError("function code 0x%02x is not READ (0x01); this is not an ARM frame" % fc)
    return payload[APP_CONTROL_OFFSET]


def check_fir_fin(ctrl):
    """IEEE 1815 single-fragment convention: FIR (0x80) and FIN (0x40) both set, i.e. 0xCn.

    NOTE, and this matters for how the result is read: `ibspg_dnp3.p4` does NOT enforce this.
    Its parser selects on the function code alone and takes whatever the control byte is as the
    generation. This is therefore a HARNESS-side sanity check on the corpus, not a restatement
    of a dataplane guarantee.
    """
    return (ctrl & 0xC0) == 0xC0


def tokens_for_txn(read_payload, k, budget, **kw):
    """K identical blocker tokens stamped with the generation of this transaction's READ."""
    gen = gen_from_read_payload(read_payload)
    frame = build_token(gen, budget, **kw)
    return gen, [frame] * int(k)


def load_spec(path):
    with open(path) as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser(description="blocker tokens carrying the DNP3 generation")
    ap.add_argument("--spec", default=os.path.join(REPLAY_DIR, "replay_spec_sel751.json"))
    ap.add_argument("--k", type=int, default=64,
                    help="reservoir depth (Part 9 measured K>=64 as the working depth)")
    ap.add_argument("--budget", type=int, default=2000000,
                    help="pass budget in the seq field; the fail-open watchdog bound")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--pad-to", type=int, default=60)
    ap.add_argument("--dst-mac", default=DEFAULT_DST_INTERNAL)
    ap.add_argument("--src-mac", default=DEFAULT_SRC_TOKEN)
    ap.add_argument("--ntxn", type=int, default=0, help="limit to the first N transactions (0=all)")
    ap.add_argument("--out", default=None, help="write the per-transaction token table as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.k < 0:
        sys.stderr.write("FATAL: --k must be >= 0\n")
        return 2
    if not (MIN_BUDGET <= a.budget <= MAX_BUDGET):
        sys.stderr.write("FATAL: --budget must be in [%d, %d]; seq==0 terminates a blocker on "
                         "its first pass, so the reservoir would never form.\n"
                         % (MIN_BUDGET, MAX_BUDGET))
        return 2

    spec = load_spec(a.spec)
    txns = spec["transactions"]
    if a.ntxn:
        txns = txns[:a.ntxn]

    table = []
    warn = 0
    for t in txns:
        payload = bytes.fromhex(t["req"]["payload_hex"])
        gen, frames = tokens_for_txn(payload, a.k, a.budget, dst_mac=a.dst_mac,
                                     src_mac=a.src_mac, slot=a.slot, pad_to=a.pad_to)
        if not check_fir_fin(gen):
            warn += 1
            sys.stderr.write("WARN txn %s: app control 0x%02x is not 0xCn (FIR+FIN); the P4 does "
                             "not enforce this, but the corpus is expected to.\n" % (t["txn"], gen))
        table.append({
            "txn": t["txn"],
            "gen": gen,
            "gen_hex": "0x%02x" % gen,
            "app_seq": t["req"].get("app_seq"),
            "k": a.k,
            "budget": a.budget,
            "token_hex": frames[0].hex() if frames else None,
        })

    if a.selftest:
        ok = fail = 0
        for row, t in zip(table, txns):
            payload = bytes.fromhex(t["req"]["payload_hex"])
            checks = [
                ("gen == READ app control byte", row["gen"] == payload[APP_CONTROL_OFFSET]),
                ("gen low nibble == app_seq", (row["gen"] & 0x0F) == t["req"]["app_seq"]),
                ("gen is 0xCn (FIR+FIN)", check_fir_fin(row["gen"])),
            ]
            if a.k > 0:
                f = bytes.fromhex(row["token_hex"])
                checks += [
                    ("token ethertype is 0x88C1",
                     struct.unpack("!H", f[12:14])[0] == ETYPE_TOKEN),
                    ("token gen field == gen", f[16] == row["gen"]),
                    ("token seq field == budget",
                     struct.unpack("!I", f[17:21])[0] == a.budget),
                    ("token slot field == slot", f[15] == a.slot),
                    ("token padded to --pad-to", len(f) == a.pad_to),
                ]
            for name, good in checks:
                if good:
                    ok += 1
                else:
                    fail += 1
                    sys.stderr.write("  FAIL txn=%s %s\n" % (row["txn"], name))
        print("selftest: %d checks passed, %d failed, over %d transactions"
              % (ok, fail, len(table)))
        if fail:
            return 1

    out = {
        "source_spec": os.path.basename(a.spec),
        "k": a.k,
        "budget": a.budget,
        "slot": a.slot,
        "pad_to": a.pad_to,
        "dst_mac": a.dst_mac,
        "src_mac": a.src_mac,
        "generation_contract": "token gen = DNP3 application control byte of the guarded READ "
                               "(payload offset %d)" % APP_CONTROL_OFFSET,
        "transactions": table,
    }
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=1)
        print("wrote %s" % a.out)
    else:
        print(json.dumps(out, indent=1))
    if warn:
        sys.stderr.write("%d transaction(s) had a non-0xCn control byte\n" % warn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
