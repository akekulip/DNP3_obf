# Final experiment campaign plan (directive §5) — ready for go/no-go

Runs **only after** the §4 review passes and the reference compiles clean (both already true for compile;
review in progress). All relay contact is **read-only** (Class-0 READ, Request-Link-Status, telnet
status). No DNP3 write/control, no re-cabling. Switch restored to `queue_microbench_abs.conf` after.

## Program under test

`dnp3_timing_normalizer.p4` (sha `d6fcd530`, 10/12 ingress, verified on 9.13.1 + on-switch 9.13.2).
Loaded via a gated `bf_switchd` swap (displaces `queue_microbench`, reversible with `launch_mb.sh`).

## Evidence levels (kept distinct, per direcr2 §19)

- **native** = the physical SEL-751's own frames, captured live read-only (the true fingerprint).
- **protected** = those real relay frames (real `data_offset=8`, byte-for-byte) replayed through the
  loaded normalizer, two-sided (READ from Vision/dp9, ACK+RESPONSE from Hulk/dp11).
The relay is **not** placed physically inline (gated re-cabling); this is labelled replay-of-real-frames,
never "live inline relay."

## Stage A — native timing characterization

- ≥ 100 read-only Class-0 polls of the physical relay (`multipoll.py`, source `192.168.10.1`, link
  addr 0), captured on Vision → `native.pcap` (full frames, `-s 0`).
- Analyze with `scripts/analyze_clrt.py --tshark-crosscheck`: record the native CLRT distribution
  (count/min/mean/median/sd/p5/p25/p75/p95/p99/range/distinct), confirm separate-ACK, confirm
  `data_offset=8`. **Pick the final G > measured native p99.**

## Stage B — protected timing, G sweep

Load the normalizer. For each **G ∈ {5, 10, 17, 20, 25, 40} ms**: configure G (`p13_guard.py`,
verified readback), run ≥ 30 protected trials, capture on Vision, read switch counters.

Then the **final G** (the one exceeding native p99, expected 25 ms): **100 repetitions**.

### Per-trial verification (all must hold; from §5)

READ arm = 1 · ACK arm = 1 · ACK bypass = 0 (valid ACK) · RESP enqueue = 1 · RESP release = 1 ·
deadline arithmetic correct (`reg_deadline == t_ack+G`) · release reason correct ·
**protection-applied flag correct · low-G warning correct** (G-guard) · no blocker escape
(`ctr_bypass[1]=0`, zero `0x88C1` in the Vision capture) · no timeout in normal protected trials ·
byte identity (released response == injected) · no missing / duplicate / reorder · state returns to idle.

Preserve the **campaign exit code and per-trial return codes**. Any failed trial → preserve it, root-cause,
restart the final campaign from trial 1 (do not average over a failed trial).

### G-guard demonstration (the point of §3)

G = 5 and 10 ms are **below** the native interval on this fast LAN, so they should show the
**low-G warning fire** (`ctr_response_zero_hold`/`ctr_response_at_or_after_deadline` > 0, protection not
applied) — a deliberate positive demonstration that the guard detects an ineffective G, not a failure.
G = 17/20/25/40 ms should show protection applied and the interval normalized to G.

## Stage C — evidence + analysis (§6/§7/§8)

Single pipeline from raw PCAP + switch evidence: full stats native vs protected; leakage entropy at
10/50/100/500 µs/1 ms; MI(interval;device) and MI(interval;operation) where labels exist; balanced
accuracy + confusion + bootstrap CIs; separate CLRT-magnitude / ACK-mode / TCP-stack / size channels.
All into `evidence/timing_final/` with the required subtree; 10 figures reproducible from committed
scripts+CSV.

## Safety / restoration

Snapshot before load (bf_switchd PID, binding, ports, queues, git). After: stop generators/tcpdump,
verify no token/transaction residue, collect final counters, **restore `queue_microbench_abs.conf`**,
verify exactly one `bf_switchd` bound to `queue_microbench`, hosts reachable, Vision retains
`192.168.10.1`. Write `evidence/timing_final/final_state/restoration_report.txt`.

## Go/no-go

Gated on: §4 review clean (or findings fixed and re-frozen). Loading the normalizer is a gated
`bf_switchd` swap — pre-authorized by this directive's autonomy clause (bounded synthetic/read-only
silicon experiments), reversible, non-SEL-inline. I will run Stage A→C autonomously once the review
clears, and report the results.
