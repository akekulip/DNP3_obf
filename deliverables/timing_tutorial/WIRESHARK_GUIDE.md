# Wireshark / TShark Guide: Inspecting the DNP3 Timing-Obfuscation Demo Captures

This guide teaches someone who did **not** build the mechanism how to open the two
example packet captures shipped with this tutorial, confirm what they contain, and
verify with their own eyes the single claim the mechanism makes: that the
**Cross-Layer Response Time** of a real relay is converted from a variable,
device-revealing quantity into a fixed constant, with the response frames left
byte-for-byte unchanged.

Everything shown below was produced on the machine that ships this tutorial, using
**TShark (Wireshark) version 4.4.9**, run directly against the two `.pcap` files in
`example_pcaps/`. Every command is reproducible; every output block is real captured
output, not an illustration.

---

## 0. Terms used in this guide

- **DNP3** — Distributed Network Protocol, version 3.0. The application-layer SCADA
  (Supervisory Control And Data Acquisition) protocol spoken between the *master*
  (the control-room client) and the *outstation* (the field device, here a physical
  SEL-751 protective relay). DNP3 in this deployment runs over TCP port **20000**.
- **Master** — the DNP3 client that issues requests. In these captures it is the host
  at IP address **192.168.10.1**.
- **Outstation** — the DNP3 server (the SEL-751 relay) that answers. In these captures
  it is the host at IP address **192.168.10.7**, and its Ethernet address
  `00:30:a7:02:4c:a2` is registered to Schweitzer Engineering, confirming a real relay.
- **TCP** — Transmission Control Protocol. **ACK** — a TCP acknowledgment; a *pure* ACK
  is a TCP segment that acknowledges received data but carries no payload of its own.
- **READ** — a DNP3 request from master to outstation, application function code **1**.
- **RESPONSE** — a DNP3 reply from outstation to master, application function code **129**.
- **CLRT (Cross-Layer Response Time)** — named by Formby et al.: the interval between the
  outstation's *transport-layer* pure TCP ACK of a request and its *application-layer*
  DNP3 RESPONSE to that request. The ACK is emitted by the TCP stack the instant the
  request segment arrives; the RESPONSE is emitted later, after the device firmware has
  read its I/O and assembled the DNP3 objects. That gap measures the device's internal
  processing latency and is stable per device and distinct across devices, which is why
  it is a fingerprint. **The CLRT-magnitude channel is exactly what this mechanism
  closes, and the only thing this guide asks you to verify.**

### Claim discipline (read before drawing conclusions)

What you can confirm from these captures is that the ACK-to-RESPONSE interval, which
varies widely in the native capture, becomes a single constant (the guard interval
G = 25 ms) in the protected capture, while the RESPONSE frames are unchanged. That is a
**within-channel timing-normalization result**. It is **not** a demonstration of device
anonymity, and it does **not** conceal:

- **ACK mode** — whether the device sends a separate pure ACK before its RESPONSE
  (the SEL-751 does; some devices piggyback). This structural signature is untouched.
- **TCP-stack signature** — the initial TTL, MSS, and window advertised at connection
  setup differ per device and are untouched.
- **Response size** — size normalization is a separate, out-of-scope line; this
  mechanism neither pads nor splits.

Do not read a size-obfuscation or anonymity claim into anything below.

---

## 1. The two example captures at a glance

| file | packets | direction captured | master | outstation | what it shows |
|---|---:|---|---|---|---|
| `example_pcaps/native_demo.pcap` | 486 | both directions (full session) | 192.168.10.1 | 192.168.10.7 | the relay's **native** CLRT — variable, revealing |
| `example_pcaps/protected_demo.pcap` | 200 | outstation → master only | 192.168.10.1 | 192.168.10.7 | the **protected** CLRT — normalized to G = 25 ms |

The two files were captured differently on purpose, and Section 3 explains how to see
that for yourself. The DNP3 TCP port is 20000 in both.

---

## 2. Opening a capture

### 2.1 In the Wireshark graphical interface

1. Launch Wireshark.
2. **File -> Open**, then choose `example_pcaps/native_demo.pcap` (or
   `protected_demo.pcap`).
3. The packet list appears. To narrow it to the DNP3 session immediately, type the
   display filter `tcp.port == 20000` into the filter bar and press Enter (Section 4).

### 2.2 On the command line with TShark

TShark is the terminal build of Wireshark and is what every block in this guide uses.
The most basic view — one line per packet — is:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "tcp.port==20000" -c 5
```

Observed output (the opening of a single DNP3 transaction):

```
    1   0.000000 192.168.10.1 → 192.168.10.7 TCP 74 33175 → 20000 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2163830540 TSecr=0 WS=128
    2   0.001072 192.168.10.1 → 192.168.10.7 TCP 66 33175 → 20000 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=2163830541 TSecr=143136090
    3   0.001231 192.168.10.1 → 192.168.10.7 DNP 3.0 88 Read, Analog Input
    4   0.002805 192.168.10.7 → 192.168.10.1 TCP 66 20000 → 33175 [ACK] Seq=1 Ack=23 Win=8666 Len=0 TSval=143136090 TSecr=2163830541
    5   0.116314 192.168.10.7 → 192.168.10.1 DNP 3.0 120 Response
```

This five-packet window already contains a complete CLRT measurement: packet 4 is the
outstation's pure ACK of the request, packet 5 is its DNP3 RESPONSE, and the interval
between them (0.116314 − 0.002805 = **113.5 ms** for this first, cold-start transaction)
is the CLRT. Section 13 measures it properly.

> **Gotcha — the `-c` flag limits packets *read*, not packets *matched*.**
> `-c 5` above stops TShark after reading five packets from the file, then shows those
> matching the filter. If you combine `-c` with a restrictive filter (for example
> `ip.src==192.168.10.7`), TShark may read past none of the matching packets and print
> nothing. When you want the first N *matches* of a narrow filter, drop `-c` and pipe to
> `head` instead: `tshark -r file.pcap -Y "<filter>" | head -3`.

---

## 3. Confirming the correct interface / direction was captured

Before trusting timing, confirm the capture actually contains both endpoints you expect,
and understand which direction was recorded. The endpoint summary answers both:

```bash
tshark -r example_pcaps/native_demo.pcap -q -z endpoints,ip
```

Observed (native — a full bidirectional capture, roughly symmetric byte counts):

```
IPv4 Endpoints
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.168.10.1                 486         41204        244           18752         242           22452
192.168.10.7                 486         41204        242           22452         244           18752
```

```bash
tshark -r example_pcaps/protected_demo.pcap -q -z endpoints,ip
```

Observed (protected — **one-directional**: every packet was transmitted by the
outstation 192.168.10.7 and received at the master; the master's own requests are not in
this file):

```
IPv4 Endpoints
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.168.10.7                 200         18600        200           18600           0               0
192.168.10.1                 200         18600          0               0         200           18600
```

This one-way shape is expected and correct for the protected capture: it was taken at the
master's inbound side, where the two things that define CLRT — the outstation's pure ACK
and its RESPONSE — are both visible. The READ that triggers them travels the other way and
is not needed to measure the ACK-to-RESPONSE interval. The analyzer in Section 14 is
written to handle exactly this inbound-only case.

If you were verifying a *live* capture you took yourself, this same command is how you
confirm you captured on the right interface: if one endpoint is missing, or byte counts
are zero in the direction you care about, you captured on the wrong link or the wrong
side of the switch.

---

## 4. The basic display filter

Restrict the view to the DNP3 session on TCP port 20000:

```
tcp.port == 20000
```

In the Wireshark GUI, type it into the filter bar. On the command line it is the argument
to `-Y`. In `native_demo.pcap` all 486 packets belong to this session; in
`protected_demo.pcap` all 200 do. Use this as the base filter, then add the more specific
filters below with `&&`.

---

## 5. Identifying the three frame types that matter

CLRT is defined over three roles: the **READ** that opens a transaction, the outstation's
**pure ACK**, and the outstation's **RESPONSE**. Each has a precise, verifiable filter.

### 5.1 A valid READ — `dnp3.al.func == 1`

`dnp3.al.func` is the DNP3 application-layer function code; value **1** is READ. Requests
flow master (192.168.10.1) to outstation (192.168.10.7):

```bash
tshark -r example_pcaps/native_demo.pcap -Y "dnp3.al.func==1" \
  -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
  -e tcp.seq -e tcp.ack -e tcp.len -e ip.len -e dnp3.al.func -e dnp3.al.ctl | head -3
```

Observed:

```
3   0.001231000  192.168.10.1  192.168.10.7  1   1    22  74  1  0xc0
7   0.416758000  192.168.10.1  192.168.10.7  23  55   22  74  1  0xc1
11  0.718860000  192.168.10.1  192.168.10.7  45  109  22  74  1  0xc2
```

The one-line summary form confirms the object being read:

```
3   0.001231 192.168.10.1 → 192.168.10.7 DNP 3.0 88 Read, Analog Input
```

`dnp3.al.ctl` is the application control byte; its low nibble is the DNP3 application
sequence number (here 0, 1, 2 …), which increments per request and is the closest thing
DNP3 offers to a per-transaction identifier (Section 10).

### 5.2 A pure TCP ACK — `tcp.len == 0 && tcp.flags.ack == 1`

A pure ACK carries zero TCP payload and has the ACK flag set. This is the *start* of a
CLRT interval. Restricting to the outstation's own ACKs (`ip.src==192.168.10.7`):

```bash
tshark -r example_pcaps/native_demo.pcap \
  -Y "tcp.len==0 && tcp.flags.ack==1 && ip.src==192.168.10.7" | head -3
```

Observed:

```
    4   0.002805 192.168.10.7 → 192.168.10.1 TCP 66 20000 → 33175 [ACK] Seq=1 Ack=23 Win=8666 Len=0 TSval=143136090 TSecr=2163830541
    8   0.417363 192.168.10.7 → 192.168.10.1 TCP 66 20000 → 33175 [ACK] Seq=55 Ack=45 Win=8644 Len=0 TSval=143136510 TSecr=2163830957
   12   0.720038 192.168.10.7 → 192.168.10.1 TCP 66 20000 → 33175 [ACK] Seq=109 Ack=67 Win=8622 Len=0 TSval=143136810 TSecr=2163831259
```

`Len=0` and `[ACK]` with no other data flag confirm these are pure ACKs. The native
capture holds 245 pure ACKs (both directions); the protected capture holds 100 (all from
the outstation).

### 5.3 A RESPONSE — `dnp3.al.func == 129`

Function code **129** (0x81) is the DNP3 RESPONSE, the *end* of a CLRT interval, flowing
outstation to master. To see one fully decoded:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "frame.number==5" -O dnp3
```

Observed (abridged to the structural lines):

```
Frame 5: 120 bytes on wire (960 bits), 120 bytes captured (960 bits)
Ethernet II, Src: SchweitzerEn_02:4c:a2 (00:30:a7:02:4c:a2), Dst: Dell_55:0c:46 (2c:ea:7f:55:0c:46)
Internet Protocol Version 4, Src: 192.168.10.7, Dst: 192.168.10.1
Transmission Control Protocol, Src Port: 20000, Dst Port: 33175, Seq: 1, Ack: 23, Len: 54
Distributed Network Protocol 3.0
    Data Link Layer, Len: 43, From: 0, To: 1, PRM, Unconfirmed User Data
        Start Bytes: 0x0564
        Length: 43
        Control: 0x44 (PRM, Unconfirmed User Data)
            .... 0100 = Control Function Code: Unconfirmed User Data (4)
        Destination: 1
        Source: 0
        Data Link Header checksum: 0x157a [correct]
    Transport Control: 0xe9, Final, First(FIR, FIN, Sequence 41)
    Data Chunks
        Data Chunk: 0
            Data Chunk: e9c08180001e03000107060000000300
            Data Chunk checksum: 0xe057 [correct]
```

Note the data-link addresses **as observed in this capture**: the RESPONSE carries
`dnp3.src = 0` and `dnp3.dst = 1`, and the matching READ (frame 3) carries `dnp3.src = 1`,
`dnp3.dst = 0`. Read them from the capture (`-e dnp3.src -e dnp3.dst`) rather than
assuming a fixed pair. Also note the checksums are marked **[correct]** — the mechanism
holds the *original* frame in a switch queue and never rebuilds it, so the DNP3 CRCs are
untouched, which is what you would expect from a byte-preserving hold.

---

## 6. Version-correct DNP3 field names

Wireshark's DNP3 field names have changed across releases, so never guess them. Enumerate
the ones this installed version actually knows:

```bash
tshark -G fields | grep -i dnp3 | head -40
```

The fields relevant to this guide, confirmed present on TShark 4.4.9, are:

| purpose | field | example value seen |
|---|---|---|
| application function code (1 = READ, 129 = RESPONSE) | `dnp3.al.func` | `1`, `129` |
| application control byte (FIR/FIN/CON/UNS + app sequence) | `dnp3.al.ctl` | `0xc0`, `0xc1` |
| internal indications (device status flags in a RESPONSE) | `dnp3.al.iin` | — |
| data-link primary function code | `dnp3.ctl.prifunc` | `4` (Unconfirmed User Data) |
| data-link direction / primary bits | `dnp3.ctl.dir`, `dnp3.ctl.prm` | — |
| transport control byte (FIR/FIN + transport sequence) | `dnp3.tr.ctl` | `0xe9` |
| DNP3 source / destination link address | `dnp3.src`, `dnp3.dst` | `0` / `1` |

These are the only DNP3 field names used anywhere in this tutorial. If a future Wireshark
version renames one, re-run the `tshark -G fields` command above and update accordingly.

---

## 7. Inspecting the fields that define the transaction

The following per-packet fields are what you read to reason about timing and byte
preservation:

- `frame.time_relative` — seconds since the first packet in the file; the timeline you
  subtract to get CLRT.
- `frame.time_delta` — seconds since the previous *displayed* packet; a quick eyeball of
  gaps.
- `tcp.seq` / `tcp.ack` — TCP sequence and acknowledgment numbers; identical seq/len
  reappearing later is how you spot a replayed or retransmitted segment (Section 11).
- `tcp.len` — TCP payload length; `0` marks a pure ACK, non-zero marks a data frame.
- `ip.len` — total IP datagram length; a proxy for on-wire frame size (the size channel,
  which this mechanism does **not** alter).
- **TCP options** — MSS, window scale, SACK-permitted, timestamps, seen at connection
  setup (Section 9); part of the TCP-stack fingerprint this mechanism does **not** touch.
- **DNP3 function information** — `dnp3.al.func` and friends from Section 6.

One command lays them side by side over the opening of the native session:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "tcp.port==20000" \
  -T fields -e frame.number -e frame.time_relative -e frame.time_delta \
  -e tcp.seq -e tcp.ack -e tcp.len -e ip.len -e dnp3.al.func | head -6
```

Observed (columns: frame, time_relative, time_delta, tcp.seq, tcp.ack, tcp.len, ip.len,
dnp3.al.func):

```
1   0.000000000  0.000000000  0   0    0   60   
2   0.001072000  0.001072000  1   1    0   52   
3   0.001231000  0.000159000  1   1    22  74   1
4   0.002805000  0.001574000  1   23   0   52   
5   0.116314000  0.113509000  1   23   54  106  129
6   0.116346000  0.000032000  23  55   0   52   
```

Reading this: packet 3 is the READ (`tcp.len=22`, `dnp3.al.func=1`); packet 4 is the
outstation's pure ACK (`tcp.len=0`); packet 5 is the RESPONSE (`tcp.len=54`,
`dnp3.al.func=129`) arriving 113.5 ms after the ACK — a large native CLRT for this
cold-start transaction; packet 6 is the master's pure ACK of the RESPONSE.

---

## 8. TCP options (the setup handshake)

TCP options are advertised on the SYN and reveal the sending stack. They are part of the
TCP-stack fingerprint that this mechanism leaves **unchanged** — inspect them so you can
see, concretely, a channel the timing defense does not close:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "tcp.flags.syn==1" \
  -T fields -e frame.number -e tcp.options.mss_val \
  -e tcp.options.wscale.shift -e tcp.options.sack_perm | head
```

Observed (frame, MSS value, window-scale shift, SACK-permitted):

```
1   1460  7  0402
```

The MSS of 1460, window-scale shift of 7, and SACK-permitted option are stack
characteristics that persist regardless of any timing normalization.

---

## 9. Adding useful columns

To make the packet list readable for CLRT work, add columns for the fields above. In the
Wireshark GUI: **Edit -> Preferences -> Appearance -> Columns -> +**, then add each with
the given type/field:

| column title | type | field name |
|---|---|---|
| Time relative | Custom | `frame.time_relative` |
| Source | (built-in Source) | — |
| Destination | (built-in Destination) | — |
| TCP seq | Custom | `tcp.seq` |
| TCP ack | Custom | `tcp.ack` |
| TCP len | Custom | `tcp.len` |
| DNP3 function | Custom | `dnp3.al.func` |
| Transaction id (see note) | Custom | `dnp3.al.ctl` |

**On the transaction identifier:** DNP3 has no explicit per-transaction ID field. The
practical stand-in is the application sequence number carried in the low nibble of
`dnp3.al.ctl` (it steps 0, 1, 2, … per request/response and wraps), which you already saw
as `0xc0`, `0xc1`, `0xc2` on the READs in Section 5.1. Use it to associate a READ with its
RESPONSE when the timeline alone is ambiguous.

The command-line equivalent of a column layout is simply the `-T fields -e …` list used
throughout this guide; the same field names populate GUI columns and `-e` selectors
identically.

---

## 10. Retransmission check (capture cleanliness)

A clean CLRT measurement needs a clean capture: genuine TCP retransmissions or resets
would distort timing. The filter is:

```
tcp.analysis.retransmission || tcp.analysis.fast_retransmission
```

**Native capture — genuinely clean (zero retransmissions):**

```bash
tshark -r example_pcaps/native_demo.pcap \
  -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission" | wc -l
# -> 0
```

Zero flags, zero SYN-retries, zero resets: `native_demo.pcap` is one continuous session
and is the clean reference. This is the state a live capture of the mechanism should be in
(the project's success bar is a run with 0 retransmits and 0 resets).

**Protected capture — 70 flags, but they are a capture artifact, not real
retransmissions.** Be honest about what TShark reports here:

```bash
tshark -r example_pcaps/protected_demo.pcap \
  -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission" | wc -l
# -> 70
```

These 70 are **not** genuine on-wire retransmissions. `protected_demo.pcap` was assembled
by concatenating several replay passes over the *same* TCP four-tuple
(port 39167 <-> 20000). At frame 61 the sequence number restarts at 1 — a value TShark
already saw earlier in the file — so its duplicate-sequence heuristic flags every frame of
the later passes. Two independent checks confirm the artifact interpretation:

```bash
# no connection setup and no resets exist in the file at all:
tshark -r example_pcaps/protected_demo.pcap -Y "tcp.flags.syn==1"   | wc -l   # -> 0
tshark -r example_pcaps/protected_demo.pcap -Y "tcp.flags.reset==1" | wc -l   # -> 0

# the "retransmitted" frames carry sequence numbers identical to earlier frames:
tshark -r example_pcaps/protected_demo.pcap \
  -Y "tcp.analysis.retransmission" -T fields -e frame.number -e tcp.seq -e tcp.len | head -4
# 62  1    54
# 64  55   54
# 66  109  54     (seq 1, 55, 109 … all reappear from the file's first pass)
```

A real retransmission storm would show duplicate ACKs, resets, or SYN retries; none exist
here. The CLRT structure (a pure ACK followed 25 ms later by a RESPONSE) is intact in
every pass, which is why the analyzer in Section 14 — which parses payloads directly and
does not defer to TShark's retransmission heuristic — recovers all 100 protected
transactions cleanly. When you take your *own* live capture, expect 0 flags as in the
native file; treat any non-zero count as something to explain, exactly as done here.

---

## 11. Blocker-token check (the internal-only invariant)

To hold a response, the mechanism keeps a reservoir of tiny internal "blocker" packets
churning inside the switch on a high-priority queue. These blocker tokens use a private
EtherType **0x88c1** and are supposed to *never* leave the switch onto the LAN. Verify
that no blocker frame is visible on the external interface:

```bash
tshark -r example_pcaps/protected_demo.pcap -Y "eth.type==0x88c1"
```

Observed: **no output** (zero frames). The same query on the native capture also returns
nothing:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "eth.type==0x88c1" | wc -l   # -> 0
tshark -r example_pcaps/protected_demo.pcap -Y "eth.type==0x88c1" | wc -l # -> 0
```

An empty result is the desired result: the holding mechanism adds **no chaff** to the wire.
An observer on the LAN sees ordinary DNP3-over-TCP and zero blocker frames.

---

## 12. Measuring CLRT manually

The definition is mechanical: **select the outstation's pure ACK, find the matching
RESPONSE, subtract the two timestamps.**

### 12.1 Native — variable CLRT

List the outstation's frames with their relative time, payload length, and DNP3 function,
so ACK/RESPONSE pairs line up:

```bash
tshark -r example_pcaps/native_demo.pcap -Y "tcp.port==20000 && ip.src==192.168.10.7" \
  -T fields -e frame.number -e frame.time_relative -e tcp.len -e dnp3.al.func | head
```

Observed (frame, time_relative, tcp.len, dnp3.al.func):

```
4   0.002805000  0     (pure ACK)
5   0.116314000  54  129   (RESPONSE)
8   0.417363000  0     (pure ACK)
9   0.418426000  54  129   (RESPONSE)
12  0.720038000  0     (pure ACK)
13  0.725195000  54  129   (RESPONSE)
```

Subtract each ACK time from its following RESPONSE time:

- Transaction 1: 0.116314 − 0.002805 = **113.509 ms** (a cold-start outlier).
- Transaction 2: 0.418426 − 0.417363 = **1.063 ms**.
- Transaction 3: 0.725195 − 0.720038 = **5.157 ms**.

The spread from ~1 ms to ~113 ms across transactions is the native leak: the CLRT is not
constant, and its distribution is characteristic of this relay.

### 12.2 Protected — constant CLRT

Repeat on the protected capture. Because it is inbound-only, the outstation's ACK and
RESPONSE are simply consecutive frames:

```bash
tshark -r example_pcaps/protected_demo.pcap -Y "tcp.port==20000" \
  -T fields -e frame.number -e frame.time_relative -e tcp.len -e dnp3.al.func | head -4
```

Observed:

```
1  0.000000000  0     (pure ACK)
2  0.024995000  54  129   (RESPONSE)
3  1.599120000  0     (pure ACK)
4  1.624119000  54  129   (RESPONSE)
```

Subtracting:

- Transaction 1: 0.024995 − 0.000000 = **24.995 ms**.
- Transaction 2: 1.624119 − 1.599120 = **24.999 ms**.

Every protected transaction lands on the same value: the guard interval **G = 25 ms**. The
variability of the native capture has collapsed to a constant.

---

## 13. The same measurement, automatically

Doing this by hand for 100+ transactions is error-prone. The analysis script performs the
identical calculation — pure ACK to matching RESPONSE, per transaction — over the whole
file, rejects ambiguous pairings instead of guessing, and cross-checks its own CLRT median
against an independent TShark extraction. The packaged copy is `scripts/analyze_clrt.py`
in this tutorial; the canonical implementation used to produce the numbers below is
`research/timing_final/scripts/analyze_clrt.py`. It uses only the Python standard library.

**Native:**

```bash
python3 research/timing_final/scripts/analyze_clrt.py \
  --pcap example_pcaps/native_demo.pcap --label native --tshark-crosscheck
```

Observed:

```
native: 121 txns (120 clean, 1 ambiguous)
  CLRT ms: n=120 median=2.038002 sd=10.291459 p99=11.423111 range=112.456799 distinct=108
  leakage @1ms=2.3286 bits, @50us=4.4499 bits
  tshark cross-check median=2.038002 ms (agrees within 0.0 us)
```

**Protected (declaring the configured guard interval G = 25 ms):**

```bash
python3 research/timing_final/scripts/analyze_clrt.py \
  --pcap example_pcaps/protected_demo.pcap --label protected --g-ms 25 --tshark-crosscheck
```

Observed:

```
protected: 100 txns (100 clean, 0 ambiguous)
  CLRT ms: n=100 median=24.998903 sd=0.010117 p99=25.024176 range=0.082016 distinct=39
  leakage @1ms=-0.0 bits, @50us=0.3664 bits
  tshark cross-check median=24.998188 ms (agrees within 0.715 us)
```

Two things to take from this:

1. **The Python median and the independent TShark median agree** — to 0.0 µs (native) and
   0.715 µs (protected) — so the automated result is not an artifact of the parser; you can
   reproduce it with the manual TShark method of Section 12.
2. **The leakage numbers quantify what your eye saw.** Observer entropy at 1 ms resolution
   drops from **2.33 bits** (native) to **0.00 bits** (protected): the CLRT-magnitude
   channel is closed. (The frozen campaign, over a larger native sample, reports 2.73 bits
   at 1 ms; the demo capture's 2.33 bits is the same effect on a smaller sample.) A faint
   residual appears only below 100 µs (0.37 bits at 50 µs), from the fixed ~1.7 µs
   hardware release tail — a constant that is the same for any device and therefore carries
   no fingerprint.

The analyzer also writes `<pcap>.transactions.csv` (one row per transaction),
`<pcap>.summary.json` (statistics plus the per-resolution leakage table and the separate
ACK-mode / size channels), and `<pcap>.validation.json` (per-transaction validity flags).

---

## 14. Native versus protected, side by side

| quantity (this demo capture) | native | protected (G = 25 ms) |
|---|---:|---:|
| clean transactions measured | 120 | 100 |
| CLRT median | 2.038 ms | 24.999 ms |
| CLRT standard deviation | 10.29 ms | 0.010 ms |
| CLRT range (max − min) | 112.46 ms | 0.082 ms |
| distinct CLRT values | 108 | 39 |
| observer entropy @ 1 ms | 2.33 bits | 0.00 bits |
| genuine TCP retransmissions | 0 | 0 (the 70 flags are a concatenation artifact, Section 10) |
| blocker frames (EtherType 0x88c1) on the wire | 0 | 0 |

For a visual version, the tutorial ships pre-rendered figures in `assets/`:
`native_vs_protected_histogram.png` and `native_vs_protected_ecdf.png` (the CLRT
distributions), `clrt_trace.png` (per-transaction CLRT over time), and `release_tail.png`
(the fixed sub-microsecond release tail). These are generated from the same captures.

---

## 15. What you have and have not shown

**Shown, and verifiable in these captures:** the outstation's ACK-to-RESPONSE interval,
which spans ~1 ms to ~113 ms natively and carries 2.33 bits of observer entropy at 1 ms
resolution, is normalized to a single 25 ms constant with 0.00 bits of entropy, while the
RESPONSE frames — including their DNP3 CRCs — are left unchanged, and no blocker traffic
appears on the wire.

**Not shown, and not claimed:** device anonymity, response-size obfuscation, or the
closure of the ACK-mode and TCP-stack channels. The SEL-751 still emits a separate pure
ACK before its RESPONSE (visible in Section 5.2) and still advertises its own TCP options
(Section 8); both remain independent fingerprints untouched by this mechanism. This guide
demonstrates a working timing-normalization *mechanism* on one real relay, which is a
within-channel result — not an end-to-end anonymity result.

---

## Appendix: every filter and command in one place

All verified on TShark (Wireshark) 4.4.9 against the two files in `example_pcaps/`.

```bash
# open / basic view
tshark -r example_pcaps/native_demo.pcap -Y "tcp.port==20000" -c 5

# confirm interface / direction captured
tshark -r example_pcaps/native_demo.pcap    -q -z endpoints,ip
tshark -r example_pcaps/protected_demo.pcap -q -z endpoints,ip

# frame-type filters
#   valid READ:
tshark -r example_pcaps/native_demo.pcap -Y "dnp3.al.func==1"
#   pure TCP ACK (from the outstation):
tshark -r example_pcaps/native_demo.pcap -Y "tcp.len==0 && tcp.flags.ack==1 && ip.src==192.168.10.7"
#   RESPONSE:
tshark -r example_pcaps/native_demo.pcap -Y "dnp3.al.func==129"

# enumerate version-correct DNP3 field names
tshark -G fields | grep -i dnp3 | head -40

# per-packet field inspection
tshark -r example_pcaps/native_demo.pcap -Y "tcp.port==20000" \
  -T fields -e frame.number -e frame.time_relative -e frame.time_delta \
  -e tcp.seq -e tcp.ack -e tcp.len -e ip.len -e dnp3.al.func

# TCP options on the SYN
tshark -r example_pcaps/native_demo.pcap -Y "tcp.flags.syn==1" \
  -T fields -e tcp.options.mss_val -e tcp.options.wscale.shift -e tcp.options.sack_perm

# retransmission check (expect 0 on a clean live capture)
tshark -r example_pcaps/native_demo.pcap \
  -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission" | wc -l

# blocker-token check (expect 0 — no chaff on the wire)
tshark -r example_pcaps/protected_demo.pcap -Y "eth.type==0x88c1" | wc -l

# automated CLRT (with independent tshark cross-check)
python3 research/timing_final/scripts/analyze_clrt.py \
  --pcap example_pcaps/native_demo.pcap    --label native              --tshark-crosscheck
python3 research/timing_final/scripts/analyze_clrt.py \
  --pcap example_pcaps/protected_demo.pcap --label protected --g-ms 25 --tshark-crosscheck
```
