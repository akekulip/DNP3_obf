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

C4 (idle recovery at 1, 5, 15 and 30 s) is still running; it decides whether idleness on an
established connection re-creates the cold state or whether the state is purely
connection-establishment.

**Do not pool these cells.** C1 and C3 differ by 18x in median and their supports barely overlap.

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
