# Phase 04 — netem Smoke Test (control-point validation)

**Human-authorized 2026-07-16** ("authorize the netem smoke test"). This is the coarse pre-check
that precedes the eBPF mechanism; it does **not** build the eBPF mechanism, and it does not
manipulate any real device — it runs entirely inside an isolated user network namespace on
loopback. The eBPF prototype remains **not authorized**.

## Question

Can a `tc`/netem egress control point hold an **existing** pure TCP ACK *independently* of the DNP3
response — byte-preservingly, forging nothing, without breaking the connection? (This is the
capability the application demonstrably lacks: Phase 03 showed the app can delay the response but
cannot hold an already-emitted ACK.)

## Method (non-sudo, isolated)

- Runs inside `unshare -rn` (user + network namespace): full `CAP_NET_ADMIN` **without sudo**,
  no impact outside the namespace. Verified `tc`/netem, the `flower` pure-ACK filter, and `dumpcap`
  all work there; netem delays loopback traffic (ping RTT 0.03 ms → 60.7 ms under 30 ms delay).
- Traffic: the replay server in the **separate-ACK regime** (`--timing-mode fixed
  --target-delay-ms 50 --server-quickack`, `--delivery full`) driven by the replay client, 10
  sessions × 5 requests = 50 transactions per scenario.
- Two scenarios captured on `lo`:
  - **native** — no netem.
  - **ack30_netem** — classful `prio` + `netem delay 30ms` on band `1:1`, with a `flower` filter
    steering **only the server's pure ACKs** (`ip_proto tcp src_port 20000 tcp_flags 0x10/0x1f`)
    into the delayed band; the payload response is unmatched and stays fast.
- netem only **delays existing packets** — no ACK is forged, no byte is altered.

Tooling: `phase04_netem_smoke.py`. Run dir (git-ignored): `runs/20260716T173701Z_phase04_netem_smoke`;
committed evidence in this directory (`native.pcap`, `ack30_netem.pcap`, `netem_smoke_summary.json`).

## Result (non-first SEPARATE transactions, medians)

| metric | native | ack30_netem |
|---|---|---|
| request → pure ACK | 0.011 ms | **30.02 ms** (ACK held independently) |
| pure ACK → response (visible gap) | 50.45 ms | **20.31 ms** (gap shrank) |
| request → response | 50.46 ms | 50.34 ms (response unchanged) |
| separate / non-first | 40 / 40 | 40 / 40 |
| retransmissions / dup-ACKs / resets | 0 / 0 / 0 | 0 / 0 / 0 |
| byte-identical | 50 / 50 | 50 / 50 |

Per-transaction: all 40 separate transactions held the ordering invariant `ack_release <
response_release` (0 violations); request→ACK clustered tightly at 30.011–30.034 ms and the gap at
20.196–20.513 ms.

## Mapping to the plan's required tests (ACK-delay direction)

- **ACK delay shrinks the visible gap** — YES (50.45 → 20.31 ms), by holding the ACK 30 ms while
  the response stayed at 50 ms.
- **No packet reordering / no ACK after response** — YES (invariant held, 0/40 violations).
- **No connection reset / no unsafe retransmission** — YES (0 resets, 0 retransmissions; the 30 ms
  hold is well under the ~211 ms RTO, consistent with the safety envelope).
- **Application response byte-identical** — YES (100/100 across both scenarios).
- **DNP3 completes** — the replay client received every expected response in full (50/50 per
  scenario). (Note: driver is the replay client, not an OpenDNP3 master — the stronger DNP3-task
  claim belongs to a later rig/pydnp3 run.)

## Finding on classifier fragility (concrete evidence for the eBPF decision)

The first run used a `tcp_flags 0x10/0x17` mask, which **omits the PSH bit**, so PSH+ACK responses
(`0x18`) also matched the "pure ACK" filter and were delayed too (request→response wrongly moved
50 → 80 ms). Correcting the mask to `0x10/0x1f` (PSH included) fixed it. This is a concrete instance
of the feasibility report's Q4 conclusion: **flag-based pure-ACK classification is fragile; the
robust discriminator is TCP payload length, which needs eBPF** (exact `payload_len == 0`) rather
than `tc` flag matching. The smoke test succeeded with a corrected flag mask, but the fragility is
real and motivates the eBPF classifier.

## Conclusion

**The egress control point is validated.** `tc`/netem can hold a real pure TCP ACK independently of
the DNP3 response, byte-preservingly and without breaking the connection — closing exactly the gap
the application cannot. This confirms the eBPF mechanism (precise per-flow classification + EDT
release) is worth building.

**Not done / still gated:** per-flow request-correlated scheduling, robust payload-length
classification, the response-delay and gap-normalization directions, and any run in front of a real
outstation — all belong to the eBPF prototype, which is **not authorized**. `next_phase_allowed =
false`.

```
STOP: netem smoke test complete and positive; awaiting authorization for the eBPF prototype.
```
