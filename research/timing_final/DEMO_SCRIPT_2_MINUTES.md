# DEMO_SCRIPT_2_MINUTES.md (directive §9)

A two-minute live/replay demonstration script for the meeting. Spoken lines in plain text; actions in
`[brackets]`. Assumes the lab interface (`make demo`) or the pre-captured PCAPs are ready. Timings are
guidance, not a stopwatch.

---

**[0:00 — the problem]**

"An attacker who just *watches* the SCADA network — never touching any device — can often tell which
relay model is answering, from timing alone. The tell is the gap between the TCP ACK and the DNP3
response: the device's own processing latency. On our SEL-751 that gap carries almost three bits of
identifying information."

**[0:20 — show native]**

`[open Fig 3, or run: make demo-native]`

"Here's the native relay: the ACK-to-response interval is all over the place — median 2 ms, but a long
tail out past 11, even a 100-ms outlier. That spread *is* the fingerprint."

**[0:45 — the idea]**

"Our switch doesn't rewrite anything. When the real response arrives it parks the *original packet* in
a low-priority hardware queue and holds it there — using tiny internal 'blocker' tokens that never
leave the switch — until a fixed deadline: the ACK time plus a policy constant G. Then it lets the
untouched packet go."

**[1:05 — show protected]**

`[open Fig 3 overlay / run: make demo — protected run]`

"Same relay, mechanism on, G = 25 ms. Every response now leaves at exactly 25 ms. The whole
distribution collapses to a single spike. Standard deviation goes from 10 ms to ten *microseconds*."

**[1:30 — the honest part]**

`[open Fig 6]`

"Measured as leakage: 2.73 bits down to zero at millisecond resolution. And the response is
byte-for-byte identical — we don't touch a single DNP3 field. What this does *not* hide: the ACK mode
and the TCP stack are separate fingerprints, still visible. This closes the timing channel — one axis,
proven on real Tofino silicon, on the real relay's traffic."

**[1:55 — close]**

"No endpoint changes, no controller in the loop, no extra packets on the wire. That's the timing
normalizer."

---

## One-command version

```bash
cd research/timing_final
make demo          # runs native + protected, prints the before/after CLRT and byte-identity check
```

Fallback if hardware is offline: the same numbers are reproducible from the committed PCAPs without
touching the switch —

```bash
# entropy table (before/after):
python3 scripts/fingerprint_eval.py --native-live evidence/native/native120.pcap \
    --protected evidence/protected/final100_g25.pcap --out /tmp/fp.json
# the 10 publication figures:
~/.venvs/research/bin/python scripts/make_pub_figures.py --figdir evidence/figures
# CLRT stats for any single pcap:
make analyze PCAP=evidence/protected/final100_g25.pcap G_MS=25
```
