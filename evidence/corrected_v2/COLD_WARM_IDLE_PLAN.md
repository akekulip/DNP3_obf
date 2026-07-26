# Cold / warm / idle characterization — plan and commands (directive §5)

Runs BEFORE the final Phase A native campaign. Read-only Class-0 READs only. No SELECT, OPERATE,
DIRECT_OPERATE, WRITE, restart or configuration. No relay IP change.

## Why this runs first

The whole published compression ratio is driven by one transaction. Campaign A's first poll
measured 22.660 ms and campaign B's measured 37.215 ms; excluding them the native standard
deviation falls from 6.261 to 1.008 ms and from 9.514 to 2.320 ms respectively. That first
transaction is also the **only** observation that has ever exceeded G. It is data, not noise, and
until we know which state produces it we cannot choose G or state what is being protected.

Open question this matrix answers: is the large first value a **TCP connection-cold** effect, a
**relay application cold-start** effect, an **idle-recovery** effect, or a distinct relay state?

## Design

| cell | condition | repetitions | what it isolates |
|:--|:--|--:|:--|
| **C1** | new TCP connection, first READ, then close | ≥ 30 connections | connection-cold cost, cleanly separated from poll ordinal |
| **C2** | one connection, polls 1 through 5 | ≥ 20 connections | how fast the cold effect decays with poll ordinal |
| **C3** | one connection, absolute-cadence steady state | ≥ 100 polls | the steady-state distribution and its tail |
| **C4** | one connection, idle 1 s / 5 s / 15 s / 30 s then poll | ≥ 20 per interval | whether idleness re-creates the cold state |

Every trial is labelled with: connection id, poll ordinal, idle duration before the poll,
native/protected state, CLRT, relay response TCP payload length, TCP options (data offset),
retransmission status.

**Do not pool cells until a distribution test justifies pooling.** Report each cell separately with
n, median, sd, p95, p99, min, max and a bootstrap 95 % CI. C1 and C3 are compared explicitly; if
they differ, the relay has at least two timing states and G must be chosen against the one being
protected.

## Controls that apply to every cell

- Absolute monotonic schedule. Poll k fires at `t0 + k * period`, never `sleep(period)` after the
  response, because sleeping after the response makes the protected arm slower than the native arm
  and that is exactly the confound in campaign A (300.436 ms native vs 400.451 ms protected).
- Period strictly greater than the largest G under test.
- Identical Class-0 READ bytes in every cell.
- One capture interface, one capture configuration, snap length 0.
- Capture filter must admit blocker frames so the isolation check is not vacuous:
  `(host 192.168.10.7 and tcp port 20000) or ether proto 0x88c1`
- All four cells run NATIVE first. Protected repeats come later, interleaved, in the final campaign.

## Commands

Run from `~/dnp3_live` on Vision (reach Vision at `10.10.54.166`).

```bash
# preflight — refuses to proceed unless the inline path is live
./status.sh || exit 1

# C1  new connection, first READ only, 30 connections
./cwi.sh --cell C1 --connections 30 --out cwi_C1.pcap

# C2  poll ordinal 1..5, 20 connections
./cwi.sh --cell C2 --connections 20 --polls 5 --out cwi_C2.pcap

# C3  steady state, one connection, 100 polls on an absolute 400 ms schedule
./cwi.sh --cell C3 --polls 100 --period-ms 400 --out cwi_C3.pcap

# C4  idle recovery, 20 trials at each interval
for s in 1 5 15 30; do
  ./cwi.sh --cell C4 --idle-s $s --trials 20 --out cwi_C4_idle${s}s.pcap
done

# analysis — exact pairing, both pipelines, must agree transaction by transaction
for f in cwi_*.pcap; do
  python3 analyze_live_clrt.py --pcap "$f" --label native --outdir out_$(basename $f .pcap)
done
python3 crosscheck_pipelines.py --glob 'out_cwi_*' --report cold_warm_idle_summary.json
```

`cwi.sh` and the `--cell` support in the poller are **not yet written**. They are the first build
task of the next gate, together with the absolute-schedule fix.

## Outputs

    COLD_WARM_IDLE_CHARACTERIZATION.md
    cold_warm_idle_transactions.csv
    cold_warm_idle_summary.json

## Decision this feeds

1. Which relay state is being protected (cold, steady, or both under separate policies).
2. Whether one G covers all states or cold and steady need different targets.
3. The value of G, chosen from the measured state-conditioned distribution, not from convenience.
4. The low-G control points, which must then be observed under **matched relay state** — the
   current low-G miss is a prediction from source, never an observation, because no protected
   transaction anywhere has exceeded 25.0826 ms.

## Analyzer status

The exact-pairing analyzer is in place and passes 10 adversarial tests
(`scripts/test_analyzer_pairing.py`): duplicate ACK, wrong-ack-number, FIN/ACK, ACK-before-READ,
stale RESPONSE, wrong application sequence, wrong link address, and multi-stream.

**Known limitation, asserted rather than hidden:** when two TCP streams have transactions in flight
simultaneously, the analyzer pairs one and rejects the other with an explicit `validation_failure`.
It never mispairs. Sequential multi-stream captures pair correctly. The campaign is single-stream,
so this does not affect it.
