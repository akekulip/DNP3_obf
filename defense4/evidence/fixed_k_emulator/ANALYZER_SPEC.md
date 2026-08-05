# analyze_fixedk_pcap.py — implementation specification

> Produced by a design-review agent 2026-08-05, verified against
> `smoke_20260805T140802Z/smoke_K4_R2.pcap` (80 packets, 5 TCP connections).
> Supersedes the analyzer design notes in RUN_LOG.md section 2 — see the
> headline corrections at the top.

---

All ground truth verified against the real capture. Here is the implementation specification.

---

# `analyze_fixedk_pcap.py` — implementation specification

Everything below is verified against `smoke_K4_R2.pcap` (80 packets, 5 TCP connections) with a working prototype that recovered all 7 transactions cleanly. Reusable code is cited by file:line.

## 0. Headline corrections to the prior design notes

Three things in `RUN_LOG.md` §2 need amending before you code:

1. **Startup chatter is *interleaved*, not a prefix.** RUN_LOG says chatter "precedes the SBOs". It does not. On the principal stream the real request order is: SELECT(0) OPERATE(1) **WRITE(2)** SELECT(3) OPERATE(4) **DISABLE_UNSOL(5)** SELECT(6) OPERATE(7) **READ(8) CONFIRM×5** SELECT(14) OPERATE(15) **ENABLE_UNSOL(0)** SELECT(1) OPERATE(2) … So chatter must be skipped by *function code wherever it appears*, never by position.
2. **The chatter set is larger than listed.** Observed: func 2 WRITE (g80v1, clear restart IIN), func 21 **DISABLE_UNSOL** (not mentioned in RUN_LOG; `nsbo_master.cpp:257` sets `disableUnsolOnStartup = true`), func 1 READ integrity poll, func 0 **CONFIRM** ×5, func 20 ENABLE_UNSOL at shutdown.
3. **`OPERATE app_seq = (SELECT app_seq + 1) mod 16` is confirmed** on all 7/7 transactions (0→1, 3→4, 6→7, 14→15, 1→2, 3→4, 5→6). Use it as a **validation assertion, not a pairing key** — app_seq repeats within one capture (SELECT seq 3 occurs in transactions 1 and 5; OPERATE seq 4 in transactions 1 and 5).

---

## 1. TCP connection separation and anomaly detection

### 1.1 A real bug you must not inherit

`analyze_multicrob_pcap.py:88-90` builds the connection key from `pkt.src` / `pkt.dst`. On an Ethernet-encapsulated capture those are **MAC addresses**, not IPs. Verified on this file: every packet returns `pkt.src == '00:00:00:00:00:00'`, and `p.layers()` is `['Ether','IP','TCP']`. It happens to work here because the ports still discriminate, but it is wrong. Use `pkt[IP].src`.

### 1.2 Connection identity

```python
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP

def split_connections(pcap_path, port=20000):
    """conn_key -> {'pkts':[...], 'c2s':[seg...], 's2c':[seg...], 'flags':[...]}

    conn_key is the CANONICAL bidirectional key tuple(sorted([(ip,sport),(ip,dport)])),
    so both directions of one TCP connection land in one bucket. Direction is decided
    by which endpoint owns `port`, NOT by the key order.
    """
    conns, order = {}, []
    for i, pkt in enumerate(rdpcap(pcap_path)):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        t, ip = pkt[TCP], pkt[IP]
        a, b = (ip.src, int(t.sport)), (ip.dst, int(t.dport))
        key = tuple(sorted([a, b]))
        if key not in conns:
            conns[key] = {'pkts': [], 'c2s': [], 's2c': [], 'first_pkt': i}
            order.append(key)
        c = conns[key]
        seg = (i, int(t.seq), bytes(t.payload), str(t.flags), float(pkt.time))
        c['pkts'].append(seg)
        (c['c2s'] if int(t.dport) == port else c['s2c']).append(seg)
    return conns, order
```

**Principal-stream selection**: pick the connection with the most total payload bytes (verified: 16 836 B vs 0 B for the four strays). Do *not* pick "first connection" — a stray SYN could precede the real one in a campaign capture.

### 1.3 Additional connections to port 20000

Every non-principal connection where either endpoint's port `== 20000` is an **extra connection**. In this capture there are 4, all `S` → `RA` (client SYN, server RST-ACK = connection refused), at t+101.2 s, +102.2, +104.2, +108.2 — a 1 s / 2 s / 4 s exponential backoff, i.e. an OpenDNP3 `ChannelRetry::Default()` client reconnecting after the outstation exited. Report them as:

```python
{'extra_connections': [{'client': '127.0.0.1:46377', 'first_pkt': 72, 'n_pkts': 2,
                        'flags': ['S','RA'], 'payload_bytes': 0,
                        'after_principal_close': True, 't_first': 1785938988.069769}, ...]}
```

Classify `after_principal_close = first_pkt > principal_last_pkt_index`. Only extras with `after_principal_close == False` or `payload_bytes > 0` should fail the persistence gate; post-close strays are noise and must **not** flip `persistent_single_connection`.

### 1.4 Anomalies — one capture-order pass

`analyze_multicrob_pcap.py:96-111` sorts by seq (line 101). That recovers bytes correctly but **destroys reordering evidence** and silently zero-fills gaps (lines 105-107), which will corrupt CRCs with no trace. Replace with a single capture-order pass that reassembles *and* records:

```python
def reassemble(segs):
    """segs in CAPTURE ORDER. Returns (buf, stamps, anomalies).
    stamps: [(start_off, end_off, pkt_idx, ts)] -- byte-range -> supplying packet.
    """
    data = [s for s in segs if s[2]]
    if not data:
        return b'', [], []
    base = min(s[1] for s in data)          # this connection's own ISN+1
    buf, stamps, anomalies = bytearray(), [], []
    for (i, seq, pl, fl, ts) in data:
        off = seq - base
        if off < 0 or off - len(buf) > MAX_GAP:      # reuse MAX_GAP = 1<<20 (line 63)
            anomalies.append({'kind': 'out_of_window', 'pkt': i, 'off': off}); continue
        end = off + len(pl)
        if end <= len(buf) and bytes(buf[off:end]) == pl:
            anomalies.append({'kind': 'retransmission', 'pkt': i, 'off': off, 'len': len(pl)})
            continue
        if end <= len(buf):
            anomalies.append({'kind': 'overlap_conflict', 'pkt': i, 'off': off, 'len': len(pl)})
        elif off < len(buf):
            anomalies.append({'kind': 'overlap_partial', 'pkt': i, 'off': off, 'len': len(pl)})
        elif off > len(buf):
            anomalies.append({'kind': 'gap', 'pkt': i, 'off': off, 'bytes': off - len(buf)})
            buf.extend(b'\x00' * (off - len(buf)))   # placeholder; frames touching it are tainted
        if end > len(buf):
            buf.extend(b'\x00' * (end - len(buf)))
        buf[off:end] = pl
        stamps.append((off, end, i, ts))
    return bytes(buf), stamps, anomalies
```

Also record the **zero-filled byte ranges** so any link frame overlapping one is flagged `tainted_by_gap: true` rather than merely `crc_ok: false`.

Verified on the smoke capture: `anomalies == []` for both directions, 1263 request bytes / 15 573 response bytes.

### 1.5 RST / FIN / premature FIN / post-analysis packets

```python
flags = str(t.flags)   # scapy: 'S','SA','A','PA','FA','RA','R'
has_rst  = 'R' in flags
has_fin  = 'F' in flags
has_syn  = 'S' in flags
```

- **Principal-stream RST**: any `'R' in flags` on the principal connection ⇒ `rst_seen = True`, hard fail.
- **FIN**: expect exactly 2 on the principal stream (pkt #69 client `FA`, #70 server `FA`, then #71 `A`).
- **Premature FIN** — define positionally, not by time: let `last_scored_pkt` be the packet index of the OPERATE-response's *last* byte for the final expected transaction. A FIN is premature iff `fin_pkt_index < last_scored_pkt`, or equivalently if `n_transactions_closed_at_fin < expected_transactions`. Both are cheap; compute both and report `premature_fin: bool` plus `transactions_closed_at_first_fin: int`.
- **Post-analysis packets**: every packet with index `> principal_last_pkt` (71 here). Count them, and count how many belong to fresh connections. Report `post_analysis_packets: 8, post_analysis_connections: 4`.

**⚠ Committed-evidence discrepancy you must know about:** `SMOKE_VERDICTS.txt` reports `SYN(client): 1`, `RST: 0`. The committed pcap actually contains **5 client SYNs and 4 RST-ACKs**. The verdict file (mtime 10:08) predates the pcap's final flush (mtime 10:09) — `tshark` was run before `dumpcap` wrote the trailing strays. **Do not write a regression test asserting the SMOKE_VERDICTS numbers over the whole file.** The correct principal-stream-scoped numbers are SYN=1, FIN=2, RST=0, SELECT=7, OPERATE=7.

---

## 2. TCP payload reassembly across segment boundaries

Both directions of coalescing/splitting occur in this capture and must be handled:

- **One app fragment split across TCP segments**: pkt #22 carries 292 B (link frame 1 of a transport sequence), then 40 ms later pkt #24 carries 2119 B containing the remaining 8 frames of the *same* application fragment.
- **Multiple link frames coalesced into one segment**: pkt #24 = 2119 B = 7 × 292 + 75 → 8 complete link frames in one TCP payload.
- **Max link frame is 292 B** (verified: 48 frames of exactly 292; max LENGTH observed = 255).

The correct algorithm is therefore: **reassemble the whole per-direction byte stream first, then parse frames out of the stream — never parse per-packet.** The existing analyzer already gets this right in spirit (`read_streams` → `parse_link_frames`); what it lacks is per-connection scoping (it *concatenates* all connections at lines 113-121, which is wrong for the fixed-K experiment) and byte→packet attribution.

**Framing must be strictly sequential, not `find`-based.** `analyze_multicrob_pcap.py:135` re-scans for `0x0564` on every frame, which risks a false sync on payload data. Parse at the current offset; only scan forward when the current offset does not hold a valid frame:

```python
LINK_START = b'\x05\x64'

def parse_link_frames(buf):
    i, out = 0, []
    while i < len(buf):
        if buf[i:i+2] != LINK_START:                 # resync ONLY on error
            j = buf.find(LINK_START, i + 1)
            if j < 0: break
            out.append({'kind': 'resync_skip', 'from': i, 'to': j})
            i = j; continue
        if i + 10 > len(buf): break                  # truncated header
        length = buf[i+2]
        user_len = length - 5
        if user_len < 0: i += 2; continue
        nblocks = (user_len + 15) // 16
        wire = 10 + user_len + 2 * nblocks
        if i + wire > len(buf): break                # incomplete tail frame
        ...
        i += wire                                    # advance by the EXACT frame size
    return out
```

---

## 3. DNP3 link layer — exact byte offsets

For a frame starting at stream offset `j`:

| offset | field | notes |
|---|---|---|
| `j+0 .. j+1` | START | `0x05 0x64` |
| `j+2` | **LENGTH** | see below |
| `j+3` | CONTROL | `0xC4` master→outstation, `0x44` outstation→master (both = unconfirmed user data) in every frame of this capture |
| `j+4 .. j+5` | DESTINATION | uint16 **little-endian** (10 = outstation, 1 = master) |
| `j+6 .. j+7` | SOURCE | uint16 little-endian |
| `j+8 .. j+9` | header CRC | little-endian, computed over **`buf[j:j+8]` — the 8 bytes *including* START** |
| `j+10 …` | data blocks | 16 data bytes + 2 CRC bytes, repeating; final block ≤ 16 data bytes + 2 CRC |

**LENGTH semantics** (this is the field everyone gets wrong): LENGTH counts **CONTROL + DESTINATION(2) + SOURCE(2) + user data**, i.e. `LENGTH = 5 + user_len`, so `user_len = LENGTH - 5` (matches `analyze_multicrob_pcap.py:143-144`). LENGTH **excludes** START(2), the LENGTH octet itself, the header CRC(2), and **every data-block CRC**. Range: 5 (link-only frame, zero user data) … 255 (250 user bytes).

**Wire size arithmetic** — the load-bearing formula:

```python
n_blocks  = (user_len + 15) // 16
wire_size = 10 + user_len + 2 * n_blocks          # header(8)+hdrCRC(2) + data + block CRCs
```
`user_len = 250` → `10 + 250 + 32 = 292` = the maximum DNP3 link frame. Verified.

**CRC**: reuse `dnp3_crc.verify_crc` (`dnp3_crc.py:64-78`; CRC-16/DNP, reflected poly `0xA6BC` at `dnp3_crc.py:25`, final complement, transmitted low byte first). The block loop at `analyze_multicrob_pcap.py:147-162` is correct — reuse it verbatim, but keep the `blocks_ok` flag *and* record **which** block failed.

### Reassembled application size vs observed TCP size

Report both, per message. Given `K` CROBs in a single-fragment message:

```
app_len(request)   = 2 (app ctrl + func)          + 5 (obj hdr + count) + 13*K  =  7 + 13K
app_len(response)  = 2 (app ctrl + func) + 2 (IIN)+ 5                  + 13*K  =  9 + 13K
user_len           = app_len + 1                  # + transport header, single fragment
wire_size          = 10 + user_len + 2*((user_len + 15)//16)
```

Verified byte-exact against the capture, K=4: request `app_len = 59`, `user_len = 60`, 4 blocks, `wire = 78` (pkt #3 tcp_plen = 78 ✓). Response `app_len = 61`, `user_len = 62`, 4 blocks, `wire = 80` (pkt #5 tcp_plen = 80 ✓).

For the campaign K values: K=8 → req 111/112/8blk/**138**, resp 113/114/8blk/**140**; K=16 → req 215/216/14blk/**254**, resp 217/218/14blk/**256**. **A CROB message needs 2 link frames only at K ≥ 19** (`user_len > 249`). Do not hard-code single-frame assumptions anyway.

Emit three size layers per message so the size-constancy claim is auditable at every layer:
`app_bytes` (reassembled application fragment), `link_wire_bytes` (Σ frame wire sizes), `tcp_payload_bytes` (Σ TCP payload of contributing segments — equals `link_wire_bytes` only when no coalescing occurred; on pkt #24 it does not).

---

## 4. Transport-fragment reassembly

Transport header = **first byte of link-frame user data**:

| bit | mask | meaning |
|---|---|---|
| 7 | `0x80` | **FIN** |
| 6 | `0x40` | **FIR** |
| 5..0 | `0x3F` | SEQ, **mod 64** |

Application payload contributed by one link frame = `user_data[1:]`, ≤ 249 bytes.

`analyze_multicrob_pcap.py:186-187` has this right (`fir = th & 0x40`, `fin = th & 0x80`). **Do not copy the app-layer mask by mistake — the app control octet reverses FIR and FIN** (see §5). Verified live at pkt #22: transport `TH = 0x48` → FIN=0, FIR=1, SEQ=8, while app control `0xA8` → FIR=1, FIN=0, CON=1, SEQ=8.

Reuse the accumulator at `analyze_multicrob_pcap.py:171-205`, extended to carry stream offsets and per-frame accounting:

```python
def reassemble_app_fragments(frames):
    out, cur = [], None
    for f in frames:
        tp = f['transport_payload']
        if not tp:                       # LENGTH==5 link-only frame (LINK_STATUS/keep-alive)
            continue
        th  = tp[0]
        fir, fin = bool(th & 0x40), bool(th & 0x80)
        if fir:
            if cur is not None:
                out_warn('transport FIR while a fragment was open — dropping partial')
            cur = {'app': bytearray(tp[1:]), 'link_frames': 1,
                   'crc_ok': f['header_crc_ok'] and f['blocks_crc_ok'],
                   'start': f['start'], 'end': f['end'], 'wire': f['wire'],
                   'tseq_first': th & 0x3F}
        elif cur is not None:
            if (th & 0x3F) != (cur['tseq_last'] + 1) % 64:
                cur['tseq_discontinuity'] = True
            cur['app'].extend(tp[1:]); cur['link_frames'] += 1
            cur['crc_ok'] &= f['header_crc_ok'] and f['blocks_crc_ok']
            cur['end'] = f['end']; cur['wire'] += f['wire']
        else:
            continue                      # continuation with no FIR start
        cur['tseq_last'] = th & 0x3F
        if fin:
            cur['app'] = bytes(cur['app']); out.append(cur); cur = None
    return out
```

**Critical distinction, verified at pkt #27:** transport `TH = 0x51` → FIR=**1**, FIN=0 while the app control is `0x29` → app FIR=**0**, FIN=0, CON=1. Each *application fragment* is its own *transport sequence*. So transport FIR/FIN delimit an application fragment; app FIR/FIN delimit a multi-fragment application *response*. Never use one to drive the other. (Only the outstation's integrity-poll response is multi-*fragment* here — CROB messages are always app-FIR+FIN.)

---

## 5. Application layer

### App control octet (`app[0]`) — bits reversed vs transport

| bit | mask | meaning |
|---|---|---|
| 7 | `0x80` | FIR |
| 6 | `0x40` | FIN |
| 5 | `0x20` | CON (confirm requested) |
| 4 | `0x10` | UNS (unsolicited) |
| 3..0 | `0x0F` | **SEQ, mod 16** |

`analyze_multicrob_pcap.py:217` reads only `app_ctrl & 0x0F`; extend it to expose all five fields — the CON bit is what tells you a response will draw a CONFIRM (chatter) rather than close a transaction.

### Layout

```python
FUNC_CONFIRM, FUNC_READ, FUNC_WRITE = 0, 1, 2
FUNC_SELECT, FUNC_OPERATE = 3, 4
FUNC_ENABLE_UNSOL, FUNC_DISABLE_UNSOL = 20, 21
FUNC_RESPONSE, FUNC_UNSOL_RESPONSE = 129, 130

def parse_app_header(app):
    if len(app) < 2:
        return None
    ac, fc = app[0], app[1]
    off = 2
    iin = None
    if fc in (FUNC_RESPONSE, FUNC_UNSOL_RESPONSE):
        if len(app) < 4: return None
        iin = (app[2], app[3]); off = 4          # 2-octet IIN
    return {'app_ctrl': ac, 'func': fc, 'app_seq': ac & 0x0F,
            'fir': bool(ac & 0x80), 'fin': bool(ac & 0x40),
            'con': bool(ac & 0x20), 'uns': bool(ac & 0x10),
            'iin': iin, 'objects_offset': off}
```
Matches `analyze_multicrob_pcap.py:211-221`. IIN observed: `0x82 0x00` on the first response (device restart + class-2 events), `0x02 0x00` after the WRITE clears it, `0x02 0x01` on the DISABLE_UNSOL response (IIN2 bit 0 = *function not implemented* — the emulator rejects func 21; harmless, but a response with **zero objects** that your object parser must survive).

### G12V1 CROB parsing — exact offsets

Object header at `off`, then `count` × **13-byte** records:

```
[off+0]  = 0x0C   group 12
[off+1]  = 0x01   variation 1
[off+2]  = 0x28   qualifier: 2-octet index prefix, 2-octet count
[off+3:off+5]     count, uint16 LE
then, repeating `count` times, pos starting at off+5:
  [pos+0:pos+2]   index prefix, uint16 LE
  [pos+2]         control code   (0x03 LATCH_ON, 0x04 LATCH_OFF)
  [pos+3]         count field    (0x01)
  [pos+4:pos+8]   on-time  ms, uint32 LE   (100 here)
  [pos+8:pos+12]  off-time ms, uint32 LE   (100 here)
  [pos+12]        CommandStatus (0x00 SUCCESS)
  pos += 13
```

Raw evidence, SELECT request pkt #3 app bytes:
`c0 03 | 0c 01 28 04 00 | 0000 03 01 64000000 64000000 00 | 0100 03 01 … | 1000 … | 1100 …` → indexes `[0, 1, 16, 17]`, control code `0x03`, status `0x00`. The response (pkt #5) is byte-identical in its object block, prefixed by `c0 81 82 00`.

**The request and the response use the identical 13-byte record layout**, so one parser serves both — this is exactly what `parse_g12v1` at `analyze_multicrob_pcap.py:224-254` does (status = `b[pos+10]`, the 11th byte of the CROB body). Reuse it; add a `status` field only meaningfully for responses (requests carry `0x00` filler), and add a trailing-bytes check (`pos == len(app)`) to catch a second object block. Also keep `STATUS_NAMES` / `status_name()` (`analyze_multicrob_pcap.py:50-57`) — do not invent new status mappings.

Ordered index list: `[i for (i, _c, _s) in crob['items']]`, in **transmitted order** (the seeded balancing plan in RUN_LOG §3 randomizes object position, so order is a feature — never sort it).

---

## 6. Startup-chatter exclusion

**Rule: a transaction is opened by, and only by, a request-direction application fragment with `func == 3`.** Everything else in the request direction is chatter and is recorded but never opens or closes a transaction.

Observed chatter in the smoke capture (all skipped correctly by the prototype):

| pkt | func | app_seq | identification |
|---|---|---|---|
| #9 | 2 WRITE | 2 | obj `50 01 00 07 07` = g80v1, qual 0x00, index 7..7 — clear the IIN device-restart bit |
| #15 | 21 DISABLE_UNSOL | 5 | obj `3c 02 06 3c 03 06 3c 04 06` = g60v2/v3/v4, qual 0x06 (all objects) |
| #21 | 1 READ | 8 | obj `3c 02 06 3c 03 06 3c 04 06 3c 01 06` = integrity poll (classes 1,2,3,0) |
| #26,31,36,41,46 | 0 CONFIRM | 8–12 | 15-byte frames, no objects; app control echoes the fragment being confirmed |
| #55 | 20 ENABLE_UNSOL | 0 | same object headers as #15; emitted at shutdown |

```python
TXN_OPENING_FUNCS = {FUNC_SELECT}
TXN_CLOSING_FUNCS = {FUNC_OPERATE}
CHATTER_FUNCS = {FUNC_CONFIRM, FUNC_READ, FUNC_WRITE,
                 FUNC_ENABLE_UNSOL, FUNC_DISABLE_UNSOL, 13, 23}  # 13 cold restart, 23 delay meas
```
Do not whitelist — treat any request func ∉ {3, 4} as chatter, count it by func code into `chatter_by_func`, and warn on any func you did not expect (e.g. func 5 DIRECT_OPERATE would mean the master is bypassing SBO entirely and must fail the run).

**Response-side chatter** is the harder half, because chatter responses are also `func == 129`. Two guards, both verified sufficient:
1. Only consider a response while a transaction is open.
2. Require the response to carry a **G12V1 object block** before it may close a transaction.

The integrity poll's 6-fragment response (app_seq 8–13, carrying g1/g30 objects, `CON=1`) arrives while no transaction is open and carries no G12V1 — it is excluded twice over.

---

## 7. Pairing state machine

**Design principle: pairing is by capture order on the principal connection. app_seq is used only to bind a response to its request *within an already-open transaction*, and to validate the +1 rule. There is no global app_seq map** — that is what makes it wrap-safe for >16 transactions.

```python
def pair_transactions(msgs, warmup=1):
    """msgs: ALL application fragments (both directions) from the principal connection,
    sorted by (t_last, stream_offset). Returns (transactions, chatter, warnings)."""
    txns, chatter, warnings = [], [], []
    cur = None
    for m in msgs:
        if m['dir'] == 'req' and m['func'] == FUNC_SELECT:
            if cur is not None:
                warnings.append({'kind': 'select_while_open',
                                 'abandoned_sel_seq': cur['select']['app_seq'],
                                 'pkt': m['pkt_first']})
                txns.append(_close_incomplete(cur))
            cur = {'select': m, 'operate': None,
                   'select_resp': None, 'operate_resp': None}

        elif m['dir'] == 'req' and m['func'] == FUNC_OPERATE:
            if cur is None:
                warnings.append({'kind': 'orphan_operate', 'pkt': m['pkt_first']}); continue
            if cur['operate'] is not None:
                warnings.append({'kind': 'duplicate_operate', 'pkt': m['pkt_first']}); continue
            cur['operate'] = m
            expected = (cur['select']['app_seq'] + 1) % 16          # <-- the +1 rule
            cur['app_seq_rule_ok'] = (m['app_seq'] == expected)
            if not cur['app_seq_rule_ok']:
                warnings.append({'kind': 'app_seq_rule_violation',
                                 'select_seq': cur['select']['app_seq'],
                                 'operate_seq': m['app_seq'], 'expected': expected})

        elif m['dir'] == 'req':
            chatter.append({'func': m['func'], 'app_seq': m['app_seq'],
                            'pkt': m['pkt_first'], 'inside_txn': cur is not None})

        elif m['dir'] == 'resp' and m['func'] == FUNC_RESPONSE:
            if cur is None or not (m['crob'] and m['crob']['items']):
                chatter.append({'func': m['func'], 'app_seq': m['app_seq'],
                                'pkt': m['pkt_first'], 'response_chatter': True})
                continue
            # OPERATE response checked FIRST: it can only exist once `operate` is set,
            # and the OPERATE request always follows the SELECT response on the wire.
            if cur['operate'] is not None and cur['operate_resp'] is None \
                    and m['app_seq'] == cur['operate']['app_seq']:
                cur['operate_resp'] = m
                txns.append(cur); cur = None                        # OPERATE-response CLOSES
            elif cur['select_resp'] is None and m['app_seq'] == cur['select']['app_seq']:
                cur['select_resp'] = m
            else:
                warnings.append({'kind': 'unmatched_response',
                                 'app_seq': m['app_seq'], 'pkt': m['pkt_first']})
    if cur is not None:
        warnings.append({'kind': 'unterminated_transaction_at_eof'})
        txns.append(_close_incomplete(cur))
    for n, t in enumerate(txns):
        t['ordinal'] = n
        t['role'] = 'warmup' if n < warmup else 'scored'
    return txns, chatter, warnings
```

**Wrap safety proof by construction:** the only app_seq comparisons are between messages inside one open transaction, where at most two distinct sequence values exist (`s` and `(s+1) % 16`) — always distinct. Transaction *identity* is the list position, which is unbounded. Verified: this capture already contains a duplicated SELECT seq (3) and a wrap boundary (transaction 3 uses seq 14/15; the next request, ENABLE_UNSOL, takes seq 0).

**Prototype output on the real capture** (all 7 recovered, all assertions held):

```
ord  sel_seq opr_seq selW oprW sel_ms  gap_ms  opr_ms  tot_ms  indexes
0    0       1       78   78   1.631   0.283   1.642   3.556   [0,1,16,17]
1    3       4       78   78   1.208   0.098   1.230   2.536   [0,1,16,17]
2    6       7       78   78   1.063   0.086   1.100   2.249   [0,1,16,17]
3    14      15      78   78   1.811   0.182   1.599   3.593   [0,1,16,17]
4    1       2       78   78   1.447   0.164   1.543   3.155   [0,1,16,17]
5    3       4       78   78   1.265   0.136   1.143   2.544   [0,1,16,17]
6    5       6       78   78   1.065   0.129   1.089   2.283   [0,1,16,17]
```

### Timestamp attribution

Latency features need a defensible timestamp per *message*, not per packet, because a message can span segments. Use the `stamps` table from §1.4:

```python
def ts_at(stamps, offset):
    for (s, e, pkt, ts) in stamps:
        if s <= offset < e:
            return pkt, ts
    return None, None

t_first = ts_at(stamps, frag['start'])[1]       # segment carrying the FIRST byte
t_last  = ts_at(stamps, frag['end'] - 1)[1]     # segment carrying the LAST byte
```

Define the four preregistered features off `t_last` (the moment the message was fully on the wire):

```
sel_lat_ms   = (select_resp.t_last  - select.t_last)      * 1000
int_gap_ms   = (operate.t_last      - select_resp.t_last) * 1000
opr_lat_ms   = (operate_resp.t_last - operate.t_last)     * 1000
sbo_total_ms = (operate_resp.t_last - select.t_last)      * 1000
```

**ACK-gap features must be dropped for this testbed.** The 95 %-availability admission rule in RUN_LOG §2 fails hard: only **1 of 14** SBO requests (7 %) is followed by a bare ACK from the outstation (pkt #4); loopback piggybacks the ACK onto the response segment. Emit `ack_gap_available: false` and the measured availability so the stats driver can apply the rule mechanically rather than assuming.

---

## 8. Output schemas

### JSON, one per capture

```jsonc
{
  "schema_version": "fixedk-analyzer-1",
  "pcap": "smoke_K4_R2.pcap",
  "pcap_sha256": "…",
  "analyzed_utc": "2026-08-05T14:10:00Z",
  "params": {"port": 20000, "expected_k": 4, "expected_r": 2,
             "expected_transactions": 7, "warmup": 1, "block_id": "smoke_K4_R2"},

  "pass": true,
  "failures": [],          // hard gate violations, strings
  "warnings": [],          // state-machine warnings (see §7)

  "tcp": {
    "principal": {"client": "127.0.0.1:48097", "server": "127.0.0.1:20000",
                  "first_pkt": 0, "last_pkt": 71, "packets": 72,
                  "req_bytes": 1263, "resp_bytes": 15573,
                  "client_syn": 1, "fin": 2, "rst": 0,
                  "retransmissions": 0, "gaps": 0, "overlaps": 0, "out_of_order": 0,
                  "zero_filled_bytes": 0, "premature_fin": false,
                  "transactions_closed_at_first_fin": 7},
    "extra_connections": [ {"client":"127.0.0.1:46377","first_pkt":72,"n_pkts":2,
                            "flags":["S","RA"],"payload_bytes":0,
                            "after_principal_close":true} ],
    "post_analysis_packets": 8,
    "persistent_single_connection": true      // 1 payload-bearing conn, 1 SYN, 0 RST, FIN only at end
  },

  "dnp3": {
    "link_frames": {"req": 23, "resp": 71},
    "app_fragments": {"req": 23, "resp": 23},
    "crc": {"header_failures": 0, "block_failures": 0, "all_valid": true},
    "resync_events": 0,
    "link_addrs": {"master": 1, "outstation": 10}
  },

  "chatter": {"by_func": {"0": 5, "1": 1, "2": 1, "20": 1, "21": 1},
              "interleaved_with_transactions": true,
              "response_fragments_excluded": 11},

  "transactions": {
    "count": 7, "warmup": 1, "scored": 6,
    "complete": 7, "incomplete": 0,
    "app_seq_rule_violations": 0,
    "select_operate_lists_identical": 7,
    "all_statuses_success": true,
    "distinct_index_sets": 1
  },

  // the size-constancy one-liner the claim depends on
  "sizes": {
    "select_request":  {"min":78,"max":78,"unique":1,"n":7,"app_min":59,"app_max":59,"app_unique":1,"link_frames":[1],"size_constant":true},
    "operate_request": {"min":78,"max":78,"unique":1,"n":7,"app_min":59,"app_max":59,"app_unique":1,"link_frames":[1],"size_constant":true},
    "select_response": {"min":80,"max":80,"unique":1,"n":7,"app_min":61,"app_max":61,"app_unique":1,"link_frames":[1],"size_constant":true},
    "operate_response":{"min":80,"max":80,"unique":1,"n":7,"app_min":61,"app_max":61,"app_unique":1,"link_frames":[1],"size_constant":true},
    "size_constant_all": true,
    "predicted": {"select_request_wire": 78, "select_response_wire": 80}   // from §3 formula, K=4
  },

  "timing": {"ack_gap_available": false, "ack_gap_availability": 0.071,
             "sel_lat_ms": {"n":6,"min":1.063,"median":1.265,"max":1.811}}
}
```

Note `sizes.predicted` — compute the expected wire size from the §3 formula and `expected_k`, and fail if observed ≠ predicted. That turns the size claim into a closed-form check rather than a self-consistency check.

### CSV, one row per transaction

```
pcap,block_id,run_id,K,R,code_mode,conn_id,txn_ordinal,role,
select_app_seq,operate_app_seq,app_seq_rule_ok,
select_pkt_first,select_pkt_last,operate_pkt_first,operate_pkt_last,
t_select,t_select_resp,t_operate,t_operate_resp,
sel_lat_ms,int_gap_ms,opr_lat_ms,sbo_total_ms,
sel_req_wire,sel_req_app,sel_req_frames,
sel_resp_wire,sel_resp_app,sel_resp_frames,
opr_req_wire,opr_req_app,opr_req_frames,
opr_resp_wire,opr_resp_app,opr_resp_frames,
n_crobs,indexes,control_codes,
select_statuses,operate_statuses,all_success,
select_operate_identical,crc_ok,complete,
tcp_retransmits_before,tcp_gaps_before,chatter_before
```

`indexes` / `control_codes` / `*_statuses` as `|`-joined (e.g. `0|1|16|17`) to stay CSV-safe. `role ∈ {warmup, scored}`. `conn_id` is present so the stats driver can use the **connection as the independent cluster** for GroupKFold, per the RUN_LOG §2 power correction. Crucially, the classifier feature set must exclude `indexes`, `txn_ordinal`, and raw timestamps — keep them in the CSV for auditing but name them in a `LEAKY_COLUMNS` constant in the module so the stats driver can drop them programmatically instead of by hand.

### CLI

Mirror `analyze_multicrob_pcap.py:559-598`: `--pcap`, `--expected-k`, `--expected-r`, `--expected-transactions`, `--warmup 1`, `--port` (default `cfg.DNP3_PORT`), `--json PATH`, `--csv PATH`, `--strict`. Keep the `except Exception` → `{'pass': false, 'failures': ['analyzer error: %r']}` wrapper (lines 589-591) and `sys.exit(0 if pass else 1)`.

---

## 9. Pitfalls to write tests for

**Verified-real in this capture (regression tests against `smoke_K4_R2.pcap`):**

1. `pkt.src` returns a MAC (`00:00:00:00:00:00`), not an IP. Test that connection splitting uses `pkt[IP].src`.
2. **app_seq is not unique** — SELECT seq 3 appears in transactions 1 and 5. Test that both are recovered as distinct transactions.
3. **Transport SEQ ≠ app SEQ.** pkt #55: transport SEQ = 16 (mod 64), app SEQ = 0 (mod 16). Test they are read from different octets with different masks.
4. **Transport FIR = `0x40` / FIN = `0x80`; app FIR = `0x80` / FIN = `0x40`.** Assert both directly.
5. **Transport-FIR restart mid-multi-fragment-response.** pkt #27 has transport FIR=1 while app FIR=0. Test that fragment reassembly is driven by transport bits alone.
6. **Chatter interleaved between transactions**, including a func-21 DISABLE_UNSOL absent from the prior spec. Test that exactly 7 transactions and 9 chatter requests are found.
7. **One app fragment split across TCP segments** (pkt #22 + pkt #24, 40 ms apart).
8. **8 link frames coalesced in one TCP segment** (pkt #24, 2119 B).
9. **Response with zero objects** (pkt #10, #16 — 4-byte app fragment). `parse_g12v1` must return `None` without an IndexError.
10. **IIN2 bit 0 set** on the DISABLE_UNSOL response (`0x02 0x01`) — must not be misread as a failure of the experiment.
11. **Stray post-run connections** (4 SYN/RST-ACK pairs at +101 s) must not set `rst_seen` on the principal stream.
12. **`SMOKE_VERDICTS.txt` is stale relative to the pcap** (says SYN=1/RST=0; file has 5/4). Assert the *principal-scoped* numbers, never the whole-file counts.
13. **ACK-gap availability is 7 %**, below the 95 % admission threshold — assert the feature is marked unavailable rather than silently emitted as NaN.

**Synthetic tests (build these pcaps with scapy `wrpcap`):**

14. **>16-transaction wrap.** The committed capture never wraps *inside* a transaction. Synthesize ≥20 transactions so a SELECT lands on app_seq 15 and its OPERATE on 0; assert `(15 + 1) % 16 == 0` passes and that all 20 are recovered.
15. **K ≥ 19 → 2 link frames.** `user_len = 8 + 13*19 = 255 > 249`. Assert `link_frames == 2` and that `app_bytes` is still `7 + 13K`.
16. **Zero-filled gap must taint, not silently pass.** `analyze_multicrob_pcap.py:105-107` injects `0x00`; a frame overlapping that range must come back `crc_ok: false` **and** `tainted_by_gap: true`, and the transaction must be marked incomplete rather than "CRC failure".
17. **Retransmission vs overlap-conflict.** Duplicate a segment byte-identically (→ `retransmission`, no data change) and with different bytes (→ `overlap_conflict`, hard fail).
18. **Out-of-order delivery.** Emit segments 2,1,3; assert bytes reassemble correctly *and* an `out_of_order` anomaly is recorded (the existing sort at line 101 would hide it).
19. **Premature FIN.** Truncate after transaction 3 of 7; assert `premature_fin: true`, `transactions_closed_at_first_fin: 3`, `pass: false`.
20. **Mid-run RST** on the principal stream ⇒ hard fail.
21. **Orphan OPERATE / SELECT-while-open** ⇒ named warnings, no crash, no silent transaction loss.
22. **False `0x0564` sync.** Craft a payload containing `05 64` inside a CROB on-time field; assert strictly-sequential framing does not resync on it.
23. **`LENGTH == 5`** link-only frame (empty transport payload) is skipped without disturbing an open fragment.
24. **Truncated final frame** (capture cut mid-frame) ⇒ frame dropped, `incomplete_tail: true`, no exception.
25. **Two connections both carrying SBOs** (a reconnect mid-campaign) ⇒ the analyzer must *not* concatenate their streams the way `analyze_multicrob_pcap.py:113-121` does; assert `persistent_single_connection: false` and per-connection transaction lists.

**Cross-check oracle.** `master.json` and `outstation_objects.jsonl` are independent ground truth for the smoke capture: 7 transactions, indexes `[0,1,16,17]`, alternating LATCH_ON/LATCH_OFF, all SUCCESS, and 56 JSONL rows = 7 × 4 × 2. Write one test that reconciles the analyzer's CSV against both — it catches whole classes of parsing error that self-consistency checks cannot.