# Timeout and retransmission audit

Dr. Lin's question was whether holding an acknowledgment for 20 ms puts the transaction at risk
of a timeout or a retransmission. It had not been answered anywhere in this repository. This
document answers it from the code that ran and from the captures, and marks the parts that
remain unknown.

Five timers can end a DNP3-over-TCP transaction. They are kept separate throughout, because
they start at different instants, are owned by different layers, and have different consequences.

| # | timer | owner | starts at | consequence |
|---|---|---|---|---|
| 1 | TCP retransmission timeout (RTO) | either kernel | when unacknowledged bytes are first sent | the segment is sent again |
| 2 | application receive timeout | the master program | when the program enters a blocking receive | the program gives up on this response |
| 3 | application retry policy | the master program | after timer 2 fires | a fresh request, or none |
| 4 | select validity | the outstation | when the outstation accepts a SELECT | a later OPERATE is refused with `NO_SELECT` |
| 5 | DNP3 link and application confirmation | either endpoint | on a confirmed frame | retransmission at the DNP3 layer |

---

## 1. What the master actually is

Not OpenDNP3. The master is a Python program using a plain blocking TCP socket. Generic
OpenDNP3 defaults do not apply and are not used anywhere below.

### The driver that produced `campaign_v1`

`evidence/campaign_v1/s01/tools/campaign_run.py`,
sha256 `3994aca143b07b067417f4fcca5c3e57a8c1c06f3e4c6f617ad0ae97bb83ca48`, invoked by
`campaign_block.sh` line 25 as

```
python3 campaign_run.py --session <s> --block <b> --condition <native|obfuscated> \
        --mode <OFF|D4> --j-ms '<codebook>' --n-read 400 --n-sbo 40 \
        --min-gap 6 --gap-ms 20 --seed <seed> --out <block>.jsonl
```

Timer facts, read from the source:

* **There is no transaction deadline at all.** `recv(s, timeout=3.0)` sets `s.settimeout(3.0)`
  and then loops on `s.recv(4096)` until a complete link frame is assembled (lines 30 to 42).
  The value is a **per-receive** socket timeout, re-armed on each call, so it bounds one read
  and nothing bounds the transaction. A response arriving as a slow trickle of partial reads
  could run arbitrarily long, and the program would still be waiting.
* This matters for how the numbers below may be read. **3.0 s is not a transaction budget and
  is not treated as one.** The only thing it bounds is a single silent gap in the stream. What
  is measured against it is therefore the longest silent gap, not the longest transaction; the
  transaction durations are reported separately in §3 and come from the wire and from the
  driver's own log, not from this timer.
* **Timer 3 does not exist.** On timeout `recv` returns whatever it has; the caller records the
  row and moves on. There is no retry of the same request anywhere in the program.
* **No monotonic deadline.** `t_send` and `t_recv` are `time.time()`, wall clock. The published
  timing does not depend on them (it comes from the capture), but the application log's
  `rtt_ms` does.
* **Timer 5 is not in play.** Requests are built with link control `0xC4`, unconfirmed user
  data, and the application control byte sets no confirmation. No DNP3-layer confirmation timer
  runs.
* **Nagle is left enabled.** Unlike the other drivers in this tree, `campaign_run.py` does not
  set `TCP_NODELAY`. It never mattered in this campaign, because the master never had
  unacknowledged bytes outstanding when it sent (§3), but it is an unforced risk and the
  corrected driver sets the option.

### The frozen harnesses, and whether they produced anything

The two files the task specification names were checked against commit `8a6896e` and are
**byte-identical** to their versions there, at both paths that commit carries:

| file | sha256 (first 16) | path at `8a6896e` |
|---|---|---|
| `relay_read_g10_23.py` | `feeb6c5cac66900a` | `defense4/size/native_parity/hw/` |
| `relay_sbo_operate_guarded.py` | `2ecdf066dbd20856` | `defense4/defense4_release/code/harness/` and `defense4/size/native_parity/h3_harness/` |
| `relay_operate_guarded.py` | `39642db9049f65bd` | `defense4/defense4_release/code/harness/` |
| `dnp3_wire.py` | `1b3488b2bb2b5e0e` | `defense4/defense4_release/code/harness/` |

Both specification claims about them are **confirmed**:

* `relay_read_g10_23.poll()` calls `s.sendall(...)` then `s.settimeout(2.0)`, loops on `recv`,
  catches `socket.timeout` and advances. There is no retry of the same request (lines 46 to 55).
* `relay_sbo_operate_guarded.py` defaults `_recv_frame(sock, timeout=2.0)` (line 29), and in the
  full SBO path builds and sends the OPERATE at lines 134 to 137 while `sel_ok` is not computed
  until line 140. **The OPERATE is sent before the SELECT response is validated.**

**But neither drove a capture.** `campaign_run.py` imports `build_select` and `build_operate`
from `relay_operate_guarded` and `read_frame` from `relay_read_g10_23`: the **frame builders
only**. Its own `recv`, `parse` and control flow replace `poll()`, `_recv_frame()` and
`_status()`. So the frozen 2.0 s timeouts are the provenance of the frame bytes, not of any
measured interval. The operative application timeout for every number in this study is 3.0 s.

Two further defects in the frozen SBO driver, found while establishing this and recorded so they
are not rediscovered:

1. **A DNP3 response carries a two-octet IIN, and `_status()` does not skip it.** It takes
   `obj = userdata[3:]` and tests `obj[2] == 0x17` for the qualifier, but with the IIN present
   `obj[2]` is the object group `0x0C`. The reference response embedded in `dnp3_wire.py`
   (`...e0 c0 81 84 00 0c 01 17 02...`) shows the layout: transport, application control,
   function `0x81`, IIN `84 00`, then group `0x0C`. The test can never succeed, so `st` is always
   `None`, `sel_ok` and `op_ok` are always false, and the driver always exits non-zero. Its
   status reporting was inoperative. `campaign_run.py` uses `obj = u[5:]` and is correct; so is
   `relay_read_g10_23.analyze()`.
2. **It reuses one application sequence number for the SELECT and the OPERATE**
   (`seq = i & 0x0F`, then both builders take `seq`). The campaign manifest records the
   consequence directly: *"frozen driver reused seq => NO_SELECT; fixed here => SUCCESS"*
   (`evidence/campaign_v1/s01/provenance/MANIFEST.json`, `driver.sbo_fix`).

Point 2 matters beyond the harness: it means the rig **demonstrably produces** a `NO_SELECT`
status when the select is invalid, which is what makes the absence of that status in §4 evidence
rather than an untested path.

## 2. Timer 1: TCP retransmission

### What the standard requires

RFC 6298 sets the initial RTO to 1 s before any round-trip sample, and thereafter
`RTO = SRTT + max(G, 4 * RTTVAR)`, with a lower bound of 1 s recommended in §2.4 and a 60 s
upper bound. Mainstream kernels clamp the lower bound far below that recommendation; Linux's
`TCP_RTO_MIN` is 200 ms.

**How the 200 ms figure is used here, and its standing.** It is a **reference value from the
Linux source's documented constant, not a measurement of this host and not a recorded campaign
setting.** It is retained as a comparison because the host is known to be Linux — the
preservation record sets `net.ipv4.tcp_timestamps`, a Linux sysctl — but the kernel version and
`net.ipv4.tcp_rto_min` were never read, so the realized floor on this host is **unknown** and
could differ. Every margin computed against 200 ms below inherits that assumption. The
assumption is not load-bearing for the conclusion: the conclusion rests on the measured
retransmission count, which is zero, and that holds whatever the RTO was.

### What is not known

The evidence records the master host, its interface and its Python version. On TCP state it
records **exactly one sysctl, and only for the earlier campaign**:
`E0_testbed_preservation.md` (session 2026-08-13) gives
`net.ipv4.tcp_timestamps=0 (0=off for defended timing measurement; original=1)`.

Three things follow. The host is Linux, since that is a Linux sysctl. That setting belongs to
`final_read_sbo`, **not** to `campaign_v1`, and the wire shows it had been restored by then: the
independent TCP pass finds the timestamp option negotiated in both directions on all 132
`campaign_v1` captures, which is only possible with `tcp_timestamps=1`. And no
retransmission-related sysctl and no kernel version was recorded for **either** campaign.

The realized RTO is therefore **UNKNOWN** and is reported as unknown. A 2.0 s or 3.0 s socket
timeout in a driver is a socket option; it is not evidence of a 2 s or 3 s TCP RTO, and it is
not treated as such anywhere in this repository.

### What was measured

`audit_current/tools/timeout_and_tcp_audit.py`, an independent TCP parser, over all 132 captures:

| arm | requests | standalone acknowledgments | piggybacked | request retx | response retx | RST | SACK blocks | sent with bytes outstanding |
|---|---|---|---|---|---|---|---|---|
| Timing OFF | 31,680 | 31,680 | 0 | **0** | **0** | 0 | 0 | 0 |
| Obfuscated | 31,680 | 31,680 | 0 | **0** | **0** | 0 | 0 | 0 |

One TCP connection per capture (132 SYN frames per arm across 66 captures each). Options
negotiated in both directions: MSS, window scale, SACK permitted and **timestamps**.

**Zero retransmissions in 63,360 exchanges, on the master-facing link.** Scope and detector
limits, stated so the result is not over-read:

* **Vantage.** The only tap is the master host's own interface. The finding is a statement about
  what reached or left the master, and about nothing else.
* **Detector.** A retransmission is counted when a `(direction, TCP sequence, payload length)`
  triple is seen more than once. That catches an ordinary retransmission of the same bytes. It
  would **not** distinguish a repacketized retransmission, which changes the length, and it does
  not use the TCP timestamp option to resolve ambiguity even though the option was negotiated.
  Both are minor here because the payload is a single fixed-size segment, but neither was tested.
* **Capture completeness.** Every capture matches its expected frame count of 1,448 and byte
  count of 130,708 exactly, and the reproduction fails a capture that does not, so a dropped
  frame would have failed the gate rather than passed silently. No `tcpdump` kernel-drop counter
  was archived, however, so completeness is established from the invariant rather than from the
  capture tool's own accounting.
* **What it does not cover.** Relay-facing traffic is not observed at all, and a response
  retransmission by the outstation would be dropped inside the switch before reaching the tap
  (§2, last subsection). This finding says nothing about it.

### Why, quantitatively

The relevant wait is how long the master's request bytes stayed unacknowledged, `L_A = m_a - m_0`:

| arm | class | median | p99.9 | max |
|---|---|---|---|---|
| Timing OFF | READ | 0.555 ms | 4.750 ms | 5.903 ms |
| Obfuscated | READ | 21.336 ms | 25.645 ms | 25.769 ms |
| Obfuscated | SELECT | 21.239 ms | 25.508 ms | 25.576 ms |
| Obfuscated | OPERATE | 20.650 ms | 26.050 ms | 29.150 ms |

The worst acknowledgment wait anywhere in the campaign is **29.150 ms**, against a floor of at
least 200 ms for any plausible RTO: a margin of about 6.9x, and about 34x against RFC 6298's
recommended 1 s. The configured hold `D_A` = 20 ms is an order of magnitude below the smallest
RTO any mainstream kernel will use. Even at the far end of the measured sweep, `D_A` = 36 ms with
a request-to-response latency of 40.6 ms, the margin is about 4.9x.

### The asymmetry that limits this result

Two things the master-facing capture cannot rule out:

* **The relay's own retransmissions.** The switch holds the relay's response for `D_R` after
  releasing the acknowledgment, so from the relay's side its response sits unacknowledged for
  roughly `D_R` plus the master's acknowledgment latency. The relay may have retransmitted it.
  The program contains `CF_RESP_DUP_SUPP`, which suppresses a TCP-position-matched response
  retransmission, so such a retransmission would be **absorbed inside the switch and invisible**
  in a master-facing capture. `response retx = 0` above means no duplicate reached the master; it
  does **not** mean the relay never retransmitted. Settling this needs a relay-facing tap, or a
  readback of the suppression counter, and it is listed in the rerun plan.
* **The relay's RTO.** Also unknown, and also not recorded.

Neither weakens the answer for the master side, and neither is glossed over.

## 3. Timer 2 and 3: the application

Every request received a **standalone** acknowledgment before its response: 31,680 of 31,680 in
each arm, with zero piggybacked. The mechanism therefore always had a separate acknowledgment
segment to hold, and the response never had to carry the request's acknowledgment. Also zero
requests were sent while earlier bytes were still unacknowledged, which is why leaving Nagle
enabled did no harm.

**What the per-receive timeout can and cannot be compared against.** A TCP acknowledgment is not
delivered to an application, so the master's first blocking `recv` does not return when the
acknowledgment arrives; it returns when response *data* arrives. Measured from the captures,
every outstation-to-master data frame carries a payload of exactly 49 bytes and there is one per
exchange, so each response crossed the wire as a **single TCP segment containing a complete DNP3
frame**.

That is a fact about the wire, and it is **not sufficient** to establish how many `recv` calls
the application made. TCP is a byte stream: it does not preserve segment boundaries as
application read boundaries, and a receiving application may take one segment in several reads or
several segments in one. Establishing the number of reads per transaction would need
application-level receive tracing, which was not collected. An earlier version of this section
claimed the per-receive timeout and the transaction duration coincide "because every response
arrived as a single TCP segment"; that inference does not follow and is withdrawn.

What stands is narrower and still sufficient for the conclusion. The measured completion times
below are what the master actually experienced, from the wire. The 3.0 s value is the driver's
configured per-receive timeout. **No application timeout occurred**, which is a measured outcome
from the driver's own log and does not depend on knowing the read count. The ratios in the last
column are offered as scale against that configured value, not as a claim that a single read
spanned the whole transaction.

| arm | class | median `L_R` | p99.9 | max | max as a ratio of the 3.0 s per-receive timeout |
|---|---|---|---|---|---|
| Timing OFF | READ | 2.680 ms | 24.880 ms | 83.862 ms | 36x |
| Obfuscated | READ | 25.337 ms | 29.659 ms | 77.713 ms | 39x |
| Obfuscated | SELECT | 25.239 ms | 29.502 ms | 29.577 ms | 101x |
| Obfuscated | OPERATE | 24.650 ms | 30.032 ms | 33.151 ms | 90x |

The largest request-to-response latency observed under the mechanism is **77.713 ms**.

Confirmed from the application log independently: of 63,360 rows across the 22 grouped runs,
every row has `valid = true` and `resp_func = 129`; all 5,280 SELECT and OPERATE rows carry
`status = SUCCESS`; **zero timeouts, zero malformed responses, zero invalid rows**. The manifest
states the log is unfiltered: *"Any future failures/timeouts/malformed responses are preserved
verbatim in the JSONL, not filtered."* The driver's own wall-clock `rtt_ms` agrees in magnitude,
with a maximum of 84.110 ms across all rows.

Timer 3 never ran because no timeout occurred and no retry exists. Under the mechanism the worst
case is a 39x margin, so this is not a close call. It is, however, a margin that holds for
*this* setting: at a much larger `D_A`, or with a master whose timeout is tens of milliseconds
rather than seconds, the analysis would have to be redone. The corrected driver makes the
deadline explicit and monotonic so that it can be set deliberately rather than inherited.

## 4. Timer 4: select validity at the outstation

The risk is specific: holding the SELECT's acknowledgment and response delays the master's
OPERATE, and if the delay exceeds the outstation's select-validity window the OPERATE is refused.

The master itself adds almost nothing. From the application log, the interval between receiving
the SELECT response and sending the OPERATE is 0.190 ms at the median in **both** arms (max
0.581 ms). The delay is entirely the mechanism's.

Master-side, over 5,280 matched SBO pairs:

| quantity | Timing OFF median | Obfuscated median | Obfuscated max |
|---|---|---|---|
| SELECT sent to OPERATE sent | 2.990 ms | 25.602 ms | 29.968 ms |
| SELECT sent to OPERATE response received | 6.665 ms | 50.425 ms | 58.934 ms |

Relay-facing, the gap is larger still, because the OPERATE is additionally held inside the
switch until `t_0 + J`. Adding the configured codebook, the OPERATE reaches the relay
approximately 27 to 37 ms after the SELECT did, against roughly 3 ms unprotected. This is an
estimate assembled from a master-facing measurement and a configured offset, not a measurement:
the relay-facing link was not captured.

**The outstation's select-validity window is not recorded in this evidence.** The SEL-751A
setting was never read back, so its value is **UNKNOWN**.

What is measured is the outcome, and it is unambiguous: of 2,640 obfuscated OPERATE exchanges,
**2,640 returned CROB status 0, SUCCESS, and none returned status 2, `NO_SELECT`**. Because the
frozen driver's sequence-reuse bug shows this rig does return `NO_SELECT` when the select is
invalid (§1), that absence is a real negative and not an untested path. The select remained
valid in every obfuscated transaction at this setting.

## 5. Timer 5: DNP3 confirmation

Not in play. Requests use link control `0xC4`, unconfirmed user data, and no application
confirmation is requested. No DNP3-layer timer runs, so none can expire.

## 6. Verdict

| question | answer | status |
|---|---|---|
| Did any TCP retransmission occur? | No, 0 in 63,360 exchanges, both arms, **on the master-facing link** | **VERIFIED** for that vantage, with the detector limits in §2 |
| Could the 20 ms acknowledgment hold expire an RTO? | Not at the observed waits: worst 29.150 ms against a floor of at least 200 ms **if this host uses the Linux default** | **VERIFIED** that no retransmission occurred; the margin itself rests on a reference RTO value, not a measured one |
| What is the actual TCP RTO on this path? | Not recorded | **UNRESOLVED**: no kernel version, no `tcp_rto_min` |
| Which TCP sysctls were recorded at all? | One, and only for the earlier campaign: `tcp_timestamps=0` in `E0_testbed_preservation.md`. The wire shows it restored to 1 by `campaign_v1` | **PARTIAL** |
| Did the relay retransmit a held response? | No duplicate reached the master, but the switch drops a position-matched duplicate before the tap | **UNRESOLVED**, needs a relay-facing tap or the decide table's direct counter |
| Did any application timeout occur? | No, from the driver's own log; worst request-to-response 77.713 ms, against a configured 3.0 s per-receive timeout | **VERIFIED**. The absence of a timeout is a measured outcome; the ratio to 3.0 s is scale, not a claim that one read spanned the transaction (§3) |
| Is 3.0 s a transaction deadline? | No. It is a per-receive socket timeout, re-armed on each read; nothing bounded the transaction | **VERIFIED** from the source |
| Is there a retry policy? | None exists in any driver | **VERIFIED** from the source |
| Was select validity ever violated? | No; 2,640 of 2,640 obfuscated OPERATE exchanges SUCCESS, zero `NO_SELECT` | **VERIFIED** from the application log |
| What is the outstation's select-validity window? | Not recorded | **UNRESOLVED**, needs a relay configuration readback |
| Does any DNP3 confirmation timer run? | No, unconfirmed user data throughout | **VERIFIED** from the frame builders |

The headline, stated with its scope: **no retransmission and no timeout occurred**, which is a
measurement. The **margins** around those measurements are partly reference-based, because the
host's retransmission timeout and the relay's select window were never recorded, and the rerun
plan archives both. And the application timer was never a transaction deadline in the first
place, and how many reads each transaction actually took is not recoverable from the wire. What
is measured is that no application timeout occurred at all.

## 7. Corrections applied to the active drivers

The frozen files are untouched. `active_harness/` carries corrected drivers, listed in
`active_harness/README.md`, whose behaviour differs from the frozen ones in exactly these ways:
an explicit monotonic transaction deadline with the remaining budget passed to every blocking
receive; complete DNP3 message reassembly across TCP reads with excess buffered bytes preserved;
per-block CRC validation; validation of function, IIN placement, object group, variation,
qualifier, count and CROB status offsets; sequence association between request and response; a
matching successful SELECT response required before any OPERATE is built; stale and unrelated
responses rejected rather than accepted as completion; missing acknowledgment logged separately
from missing application data; explicit timeout and cancellation outcomes; no automatic OPERATE
retry; and the `{1, 3}` index allowlist and every construction-time guard preserved unchanged.

## 8. Provenance

Regenerated 2026-09-07 by `audit_current/tools/timeout_and_tcp_audit.py` over
`evidence/campaign_v1/s[0-9][0-9]/raw_pcaps/*.pcap`; full output in
`audit_current/outputs/timeout_and_tcp_audit.json`. Application-layer counts are from
`evidence/campaign_v1/s[0-9][0-9]/app_jsonl/*.jsonl`. Source claims are quoted with file and
line from the files named above, all present in this checkout. The independent reproduction
`evidence/campaign_v1/repro/reproduce.sh` completed on the same day with 0 validation problems,
131 passing tests and 0 publication-gate problems; its per-capture gate requires
`retransmissions == 0`, which is a second, independent confirmation of the retransmission result.
