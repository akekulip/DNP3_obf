"""Defense 4 sustained-connection campaign driver (runs on the master / Vision).

Corrects the bring-up flaws: keeps ONE TCP connection for the whole block, sends N DNP3 READs
that ADVANCE the application-control sequence C0..CF (so generation genuinely rolls over), and
captures the FULL Ethernet on the master-facing interface (no `host` filter) so an escaped
0x88C1 blocker token cannot be hidden. Emits one rich JSON row per poll.

  python3 campaign_driver.py <label> <N> <gap_s> [mode] [d_a_ms] [d_r_ms] [seq_start]

Per-poll record: request index, DNP3 app-seq (C0..CF), TCP 4-tuple, TCP seq/ack, request/ACK/
RESPONSE timestamps, response length + segment count, ACK/RESP ordering (strict, inconclusive
flagged), CLRT, request->ACK and request->RESPONSE latency, retransmissions, duplicate ACK/RESP,
FIN/RST, socket result, and the mode/params in force. Also a block-level token-escape check.
"""
import binascii, json, os, re, socket, subprocess, sys, time

LABEL = sys.argv[1]
N = int(sys.argv[2])
GAP = float(sys.argv[3])
MODE = sys.argv[4] if len(sys.argv) > 4 else "?"
D_A_MS = sys.argv[5] if len(sys.argv) > 5 else "?"
D_R_MS = sys.argv[6] if len(sys.argv) > 6 else "?"
SEQ_START = int(sys.argv[7]) if len(sys.argv) > 7 else 0   # first C-index (0 => C0)

IFACE = os.environ.get("D3_IFACE", "enp59s0f0np0")
RELAY_IP = os.environ.get("D3_RELAY_IP", "192.168.10.7")
MASTER_IP = os.environ.get("D3_MASTER_IP", "192.168.10.1")
DNP3_PORT = int(os.environ.get("D3_DNP3_PORT", "20000"))
TOKEN_ETYPE = "0x88c1"

# 16 DNP3 READ frames, application control C0..CF (the low nibble is the app sequence).
FRAMES = [binascii.unhexlify(h) for h in [
    "05640bc4000001002aecc0c0013c0106ff50", "05640bc4000001002aecc0c1013c0106f973",
    "05640bc4000001002aecc0c2013c0106f316", "05640bc4000001002aecc0c3013c0106f535",
    "05640bc4000001002aecc0c4013c0106e7dc", "05640bc4000001002aecc0c5013c0106e1ff",
    "05640bc4000001002aecc0c6013c0106eb9a", "05640bc4000001002aecc0c7013c0106edb9",
    "05640bc4000001002aecc0c8013c0106b605", "05640bc4000001002aecc0c9013c0106b026",
    "05640bc4000001002aecc0ca013c0106ba43", "05640bc4000001002aecc0cb013c0106bc60",
    "05640bc4000001002aecc0cc013c0106ae89", "05640bc4000001002aecc0cd013c0106a8aa",
    "05640bc4000001002aecc0ce013c0106a2cf", "05640bc4000001002aecc0cf013c0106a4ec"]]
APP_CTRL = [0xC0 + i for i in range(16)]

PC = os.path.expanduser("~/d3phys/blk_%s.pcap" % LABEL)
if os.path.exists(PC):
    os.remove(PC)

res = {"label": LABEL, "mode": MODE, "d_a_ms": D_A_MS, "d_r_ms": D_R_MS,
       "N": N, "gap_s": GAP, "attempted": 0, "sent": 0, "responded": 0,
       "errors": [], "capture_ok": False, "one_connection": True}

# ---- full-Ethernet capture (no host filter) so a 0x88C1 escape is visible -------------
dc = subprocess.Popen(["dumpcap", "-i", IFACE, "-w", PC, "-q"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
for _ in range(30):
    time.sleep(0.1)
    if dc.poll() is not None:
        err = (dc.stderr.read() or b"").decode(errors="replace")[:200] if dc.stderr else ""
        res["errors"].append("dumpcap exited early: %s" % err); break
    if os.path.exists(PC):
        res["capture_ok"] = True; break
if not res["capture_ok"]:
    res["errors"].append("dumpcap did not start on %s" % IFACE)
    print("CAMPAIGN " + json.dumps(res, default=str)); sys.exit(2)
time.sleep(1.0)

# ---- ONE connection, N READs advancing C0..CF ----------------------------------------
sent_app = []
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(8); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
try:
    s.bind((MASTER_IP, 0)); s.connect((RELAY_IP, DNP3_PORT))
    res["local_port"] = s.getsockname()[1]
    time.sleep(0.6)
    for i in range(N):
        res["attempted"] += 1
        idx = (SEQ_START + i) % 16
        try:
            s.sendall(FRAMES[idx]); res["sent"] += 1
            sent_app.append(APP_CTRL[idx])
            s.settimeout(4.0); got = s.recv(4096)
            if got:
                res["responded"] += 1
            else:
                res["errors"].append("poll %d: peer closed" % i); break
        except Exception as e:
            res["errors"].append("poll %d: %r" % (i, e)); break
        time.sleep(GAP)
except Exception as e:
    res["errors"].append("setup: %r" % (e,))
finally:
    try:
        s.close()
    except Exception:
        pass

time.sleep(1.0)
dc.terminate()
try:
    dc.wait(timeout=5)
except Exception:
    dc.kill()

LOCAL_PORT = res.get("local_port")

# ---- parse: -e (ethernet, to see 0x88C1) -tt -S (absolute seq) ------------------------
txt = subprocess.run(["tcpdump", "-r", PC, "-nn", "-e", "-tt", "-S"],
                     capture_output=True, text=True).stdout.splitlines()
# ethernet + IP/TCP line: "<t> <smac> > <dmac>, ethertype IPv4 (0x0800), length L: IP a.b.c.d.p > w.x.y.z.q: Flags [..], seq S:E, ack A, ... length N"
ETH = re.compile(r"^(\d+\.\d+) .*ethertype [^(]*\((0x[0-9a-f]+)\)")
# with -e the addresses follow "length L:" directly, no "IP " prefix; match the dotted quad
IP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]"
                r"(?:, seq (\d+)(?::(\d+))?)?(?:, ack (\d+))?.*?length (\d+)")
token_escapes = 0
ev = []
for ln in txt:
    me = ETH.match(ln)
    etype = me.group(2) if me else None
    if etype == TOKEN_ETYPE:
        token_escapes += 1        # a private blocker token seen on the master-facing wire
    m = IP.search(ln)
    if not m:
        continue
    t = float(ln.split()[0])
    sip, sp, dip, dp, fl, s0, s1, ack, ln_ = m.groups()
    sp, dp, ln_ = int(sp), int(dp), int(ln_)
    from_relay = (sip == RELAY_IP and sp == DNP3_PORT)
    from_master = (sip == MASTER_IP and dp == DNP3_PORT)
    if LOCAL_PORT is not None:
        if from_master and sp != LOCAL_PORT:
            continue
        if from_relay and dp != LOCAL_PORT:
            continue
    if not (from_relay or from_master):
        continue
    ev.append({"t": t, "from_relay": from_relay, "flags": fl, "len": ln_,
               "seq": int(s0) if s0 else None, "ack": int(ack) if ack else None})

res["token_escapes_on_wire"] = token_escapes

# ---- build per-poll rows -------------------------------------------------------------
rows = []
cur = None
seen_relay_seq = {}     # for retransmission / duplicate detection
poll_i = -1
for e in ev:
    if (not e["from_relay"]) and e["len"] == 18:           # a READ from the master
        if cur:
            rows.append(cur)
        poll_i += 1
        cur = {"poll": poll_i,
               "app_seq_sent": ("0x%02X" % sent_app[poll_i]) if poll_i < len(sent_app) else None,
               "t_read": e["t"], "read_seq": e["seq"], "t_ack": None, "t_resp": None,
               "resp_len": None, "resp_segments": 0, "resp_seqs": [],
               "dup_ack": 0, "dup_resp": 0, "retransmit": 0, "fin": False, "rst": False}
    elif cur and e["from_relay"]:
        if "R" in e["flags"]:
            cur["rst"] = True
        if "F" in e["flags"]:
            cur["fin"] = True
        if e["len"] == 0 and e["flags"] in (".", "P."):
            if cur["t_ack"] is None and cur["t_resp"] is None:
                cur["t_ack"] = e["t"]
            elif cur["t_resp"] is None:
                cur["dup_ack"] += 1                        # extra pure ACK before RESP
        elif e["len"] > 0:
            sq = e["seq"]
            if sq is not None and sq in seen_relay_seq:
                cur["retransmit"] += 1                     # same seq re-seen = retransmission
            if sq is not None:
                seen_relay_seq[sq] = True
            if cur["t_resp"] is None:
                cur["t_resp"] = e["t"]; cur["resp_len"] = e["len"]
                cur["resp_segments"] = 1; cur["resp_seqs"] = [sq]
            else:
                # further relay data before the next READ = another RESPONSE segment or a dup
                if sq in cur["resp_seqs"]:
                    cur["dup_resp"] += 1
                else:
                    cur["resp_segments"] += 1; cur["resp_seqs"].append(sq)
if cur:
    rows.append(cur)

for r in rows:
    r["read_to_ack_ms"] = None if r["t_ack"] is None else (r["t_ack"] - r["t_read"]) * 1e3
    r["read_to_resp_ms"] = None if r["t_resp"] is None else (r["t_resp"] - r["t_read"]) * 1e3
    r["clrt_ms"] = (None if (r["t_ack"] is None or r["t_resp"] is None)
                    else (r["t_resp"] - r["t_ack"]) * 1e3)
    if r["t_ack"] is None or r["t_resp"] is None:
        r["ack_before_resp"] = None
        r["order_inconclusive"] = None
    else:
        r["ack_before_resp"] = r["t_ack"] < r["t_resp"]
        r["order_inconclusive"] = (r["t_ack"] == r["t_resp"])
    r.pop("resp_seqs", None)

res["rows"] = rows
res["pcap"] = PC
res["n_rows"] = len(rows)
# app-seq coverage: how many distinct C0..CF codes were actually driven this block
res["distinct_app_seqs"] = sorted(set(r["app_seq_sent"] for r in rows if r["app_seq_sent"]))
print("CAMPAIGN " + json.dumps(res, default=str))
