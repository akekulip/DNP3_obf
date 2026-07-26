# Cold / warm / idle characterization — results (directive §5, §16)

Read-only Class-0 READs only (DNP3 function 1, asserted before every send). Physical SEL-751 at
192.168.10.7 through the inline Tofino-1. Native only: no blocker tokens were injected in any cell,
so these are the relay's own timings. Analyzed with the exact-pairing analyzer
(`scripts/analyze_live_clrt.py`), which passes 10 adversarial pairing tests.

**Every cell: 100 % of transactions paired, 0 ambiguous, 0 validation failures.**

## Headline: the "outliers" were a second relay state, and it is one poll deep

The 22.660 ms and 37.215 ms values that v1 treated as outliers to warm away are ordinary draws from
a distinct **connection-cold** state. Its median is 25.25 ms and its maximum is 87.7 ms.

The state is exactly **one poll deep**. C2 polled ordinals 1 to 5 on each of 20 fresh connections:

| poll ordinal | n | median | mean | max | sd |
|--:|--:|--:|--:|--:|--:|
| **1** | 20 | **23.600** | 28.996 | **102.805** | 26.570 |
| 2 | 20 | 2.128 | 2.786 | 8.159 | 1.845 |
| 3 | 20 | 2.083 | 2.232 | 6.035 | 1.182 |
| 4 | 20 | 2.052 | 3.038 | 11.761 | 2.728 |
| 5 | 20 | 2.167 | 2.550 | 5.651 | 1.527 |

Ordinal 1 is an order of magnitude slower and fifteen times more variable than ordinal 2. Ordinals
2 through 5 are indistinguishable from each other. There is no gradual warm-up; the relay is slow
once and then fast.

## Per-cell distributions (CLRT, ms)

| cell | n | median | p95 | p99 | max | > 25 ms | > 40 ms |
|:--|--:|--:|--:|--:|--:|--:|--:|
| **C1** connection-cold, first poll on 30 NEW connections | 30 | **25.252** | 77.692 | 87.735 | **87.735** | **15/30 (50 %)** | 11/30 (37 %) |
| **C2** ordinals 1-5 pooled, 20 connections | 100 | 2.309 | 37.986 | 102.805 | **102.805** | 6/100 (6 %) | 4/100 |
| **C3** steady state, 100 polls on one connection | 100 | **1.401** | 7.452 | 21.695 | **21.695** | **0/100 (0 %)** | 0/100 |

**C4 answers the follow-up: idleness does NOT re-create the cold state.** After 1, 5, 15 and 30 s of
silence on an established connection the relay still answers like steady state.

| idle | n | median | p95 | max | sd | > 25 ms |
|--:|--:|--:|--:|--:|--:|--:|
| 1 s | 23 | 2.156 | 6.139 | 6.990 | 1.715 | 0/23 |
| 5 s | 23 | 4.249 | 5.794 | 9.207 | 1.569 | 0/23 |
| 15 s | 23 | 2.038 | 4.370 | 5.294 | 1.348 | 0/23 |
| 30 s | 23 | 1.662 | 5.786 | 14.675 | 2.958 | 0/23 |

Pooled C4: n=92, median 2.723, max 14.675. **0 of 92 exceed the C3 steady maximum of 21.695 ms.**
So the slow state belongs to TCP connection establishment, not to inactivity. That is what makes
"protect the steady state, first poll out of scope" a safe policy rather than a hopeful one.

**Do not pool these cells.** C1 and C3 differ by 18x in median and their supports barely overlap.

## ★ The relay sends TCP keepalives every ~10 s, and they are a hazard for ACK matching

C4 at 15 s and 30 s idle produced `ambiguity: multiple qualifying pure ACKs before the next READ`
on 20 of 23 transactions in each cell (0 of 23 at 1 s and 5 s idle). The cause is visible on the
wire:

```
f14  t=0.8188  src=192.168.10.7  len=54  seq=109  ack=67    <- the DNP3 RESPONSE
f16  t=10.832  src=192.168.10.7  len=0   seq=162  ack=67    <- keepalive
f18  t=20.854  src=192.168.10.7  len=0   seq=162  ack=67    <- keepalive
f20  t=30.874  src=192.168.10.7  len=0   seq=162  ack=67    <- keepalive
```

The relay's next sequence number is 163, and these carry `seq = 162 = SND.NXT - 1`, which is the
textbook TCP keepalive probe, at a ~10.02 s interval.

Two consequences.

**For measurement:** a keepalive is a pure ACK from the outstation carrying exactly the
`expected_ack` of the last READ, so it *qualifies* under the ACK rule. The analyzer took the first
qualifying ACK (read frame 12 -> ack frame 13 -> response frame 14, CLRT 3.906 ms, correct) and
flagged the rest rather than choosing silently. The CLRT values stand.

**For the implementation, and this is the important one:** the keepalive is a naturally occurring
instance of directive §20 T6, "correct ACK after transaction completion". It arrives seconds after
the transaction finished, from the right flow, with the right ack number. If the P4 does not clear
transaction state on normal release (§11), a keepalive can re-arm a deadline on a completed
transaction. This is no longer a synthetic adversarial case to construct — the device generates it
every 10 seconds whenever the master is idle, and any deployment with a poll interval above ~10 s
will meet it constantly.

## What this means for G

This is the measurement that G selection was blocked on, and it changes the answer.

- **Steady state is comfortably protectable.** C3's maximum over 100 consecutive polls is
  21.695 ms, so G = 25 ms covers every observed steady-state transaction and G = 40 ms covers it
  with real margin.
- **A single G cannot cover the cold state.** Covering C2's observed cold maximum would need
  G > 102.8 ms. At the G = 25 ms actually used in campaigns A and B, **half of connection-cold
  transactions would have passed through unprotected**.
- The v1 report's "only 2.3 ms of headroom" understated the problem. The true gap at G = 25 ms is
  not 2.3 ms, it is 62.7 ms against the observed cold maximum.

Two defensible policies follow, and this is a decision for §8 step 2 rather than something to
assume:

1. **Protect the steady state, and say so.** Choose G from C3 (for example 25 or 40 ms), and state
   that the first poll after connection establishment is out of scope. Honest, and matches how a
   SCADA master polling a long-lived connection actually behaves.
2. **Protect both with one G.** Requires G > ~103 ms, which is still far below the Linux 200 ms RTO
   floor and far below the 400 ms poll period, but it inflates every steady-state response by
   ~100 ms and makes the constant very conspicuous.

A third option, per-state G, is not available: the switch cannot know a transaction is the
connection's first until after it has answered.

## Method notes

- Polls fire on an **absolute monotonic schedule** (`t0 + k*period`), never sleeping relative to the
  response. That was the confound in campaign A, whose arms ran at 300.4 ms native versus 400.5 ms
  protected.
- Capture filter `(host 192.168.10.7 and tcp port 20000) or ether proto 0x88c1`, snap length 0, so
  blocker frames are admitted and the token-isolation check is not vacuous.
- Cells C1 and C2 open many short connections. That is the treatment, not a defect.
- Per-poll labels (connection id, source port, ordinal, idle interval, app sequence) are in
  `cwi/cwi_C*.labels.json` and join to transactions by DNP3 application sequence.

## Artifacts

    cwi/pcaps/cwi_C1.pcap   sha256 262da5ed27fcdaf8…   30 transactions
    cwi/pcaps/cwi_C2.pcap   sha256 656841aa7dfbba91…  100 transactions
    cwi/pcaps/cwi_C3.pcap   sha256 3686744fd43c5b11…  100 transactions
    cwi/out_C1|C2|C3/native_transactions.csv + native_summary.json
