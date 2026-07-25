# LAB RUNBOOK — DNP3 In-Network CLRT Timing Normalizer (Intel Tofino-1)

Operator-grade laboratory procedure for the DNP3 timing-obfuscation demonstration.
This is the detailed runbook: it walks one person, end to end, through preparing the
testbed, running the demonstration safely, collecting evidence, and returning the
switch to its resting state. For a one-screen fast path use `QUICKSTART.md`; this
document is deliberately more thorough and exists so that nothing depends on
undocumented shell history.

**Terminology defined on first use.**

- **DNP3 (Distributed Network Protocol 3):** the SCADA application protocol spoken
  between a *master* (control center) and an *outstation* (a field device such as a
  protective relay). It runs here over TCP port 20000.
- **CLRT (Cross-Layer Response Time):** the interval between a device's
  transport-layer TCP acknowledgement (ACK) of a request and its application-layer
  DNP3 response to that same request. Formby et al. showed CLRT is stable per device
  and distinct across devices, so a passive observer can use it to *fingerprint*
  which outstation model is answering. This mechanism normalizes that one interval to
  a constant.
- **G (guard interval):** the single policy value every protected CLRT is normalized
  to. The demonstration default is `G = 25 ms`.
- **Tofino-1:** the Intel programmable switch ASIC hosting the P4 data-plane program
  `dnp3_timing_normalizer.p4`.

## What this demonstration claims, and what it does not

**Claimed.** A data-plane-scheduled, chaff-free, byte-preserving *timing-normalization
mechanism* on Tofino-1 that converts the ACK-to-RESPONSE interval of a real relay into
the constant G, substantially reducing the CLRT-magnitude fingerprint (measured on the
physical SEL-751: 2.73 bits down to 0.00 bits of observer entropy at millisecond
resolution). The original response is held byte-for-byte in a Traffic-Manager queue and
released on a data-plane deadline; no controller sits in the fast path and no blocker
traffic ever leaves the switch.

**Not claimed.** This is the *timing axis only*. It does **not** conceal response
size, does **not** conceal the ACK mode (whether a device sends a separate ACK or
piggybacks it) or the TCP-stack signature, and does **not** deliver device anonymity —
on the three-device corpus those untouched channels still identify the SEL-751 at
accuracy 1.000. It is **not** production ready, and the meeting demonstration is a
*replay* of the relay's real frames, not a live inline session held in real time. Do
not overstate any result beyond the CLRT-magnitude channel.

---

## 0. Prerequisites and where things live

All work is driven from the dev box (this host) over SSH. You run `make` targets from
one directory:

```bash
cd /home/philip/Projects/DNP3/research/timing_final
```

- **Configuration:** `config/lab.env` (falls back to the committed
  `config/lab.env.example` if you have not copied it). Every script and the Makefile
  read this one file through `scripts/lib/common.sh`.
- **Credentials:** SSH password lives only in `~/.lab_env` (exports `SSHPASS`, read by
  `sshpass -e`). It is never stored in the repository.
- **Scripts:** the numbered lab scripts `scripts/00_preflight.sh` … `scripts/12_restore.sh`.
- **Evidence output:** `research/timing_final/evidence/timing_final/` (PCAPs, manifests,
  counters, verify/analysis JSON, figures, restoration report).
- **Logs:** `research/timing_final/logs/` (one timestamped log per script run).

### The lab topology (three machines plus the relay)

```
  Vision / master          10.10.54.19 (mgmt)   192.168.10.1 (relay-facing NIC)
        |                    data NIC -> switch dev-port dp9 (direction 0)
   Tofino-1 switch          10.10.54.81   (ssh decps@10.10.54.81, SDE 9.13.2)
        |                    Q_BLOCK qid7 (strict HIGH)  >  Q_RESP qid1 (strict LOW)
        |                    internal loopback dp8 (blocker-token recirculation)
  Hulk / outstation         10.10.54.158    data NIC -> switch dev-port dp11 (direction 1)

  physical SEL-751 relay    192.168.10.7:20000  (MODE B live only; Tofino NOT inline)
```

The relay-facing Vision interface is **auto-detected** at run time as the interface
holding `192.168.10.1`; you never hard-code it. The data-plane NIC toward dp9 carries
no distinguishing IP and is set explicitly in `lab.env` (`VIS_DATA_IFACE`).

### Dry-run first

Every target accepts `DRYRUN=1`, which prints every remote command and touches
nothing. Review the whole flow before you touch hardware:

```bash
make demo MODE=replay TRIALS=10 G_MS=25 DRYRUN=1
```

### Make targets used in this runbook (all present in the Makefile)

`help`, `preflight`, `build`, `load`, `configure-tm`, `capture`, `run-native`,
`run-protected`, `demo-native`, `demo-protected`, `analyze`, `figures`, `status`,
`restore`, `demo`, `clean-logs`.

Two evidence steps have **no** dedicated make target and are run as scripts directly:
per-run **verification** (`scripts/08_verify.py`) and **evidence collection**
(`scripts/11_collect_evidence.sh`). Both are covered below.

---

## 1. Pre-flight and safety baseline (before loading anything)

The switch is shared hardware. Before changing the program you record the current
state so you can prove afterwards that you restored it, and so you can recover if a
step fails midway.

### 1.1 Automated pre-flight check

```bash
make preflight
```

`scripts/00_preflight.sh` is strictly read-only (only ping and SSH reads). It verifies
and prints a `PASS`/`FAIL` summary for:

- **Reachability:** switch `10.10.54.81`, Vision `10.10.54.19`, Hulk `10.10.54.158`.
- **Vision relay address + interface auto-detect:** confirms Vision holds
  `192.168.10.1` and auto-detects the relay-facing interface (fails loudly if the
  address is missing or if more than one interface matches).
- **Switch program binding:** confirms **exactly one** `bf_switchd` process is running
  and reports which P4 program is currently bound. At rest this should be
  `queue_microbench`; after load it will be `dnp3_timing_normalizer`.
- **Local toolchain:** local `bf-p4c`, `sshpass`, `tshark` (needed for the independent
  CLRT cross-check), and the replay spec/frames and injector are present.
- **Topology print:** the full map above with the program-under-test SHA.

Do not proceed if any line reads `[FAIL]`. A `FAIL` here is exactly the state
Section 5 (Restoration) exists to recover; resolve it first.

### 1.2 Baseline snapshot (captured automatically at load)

You do not have to snapshot by hand. The load step (`scripts/02_load.sh`, step 1)
records the *before* state into `evidence/timing_final/pre_load/` for you:

- current `bf_switchd` PID(s) and command line;
- the currently bound P4 program;
- port and queue state;
- host reachability (from pre-flight);
- **git state** — `git rev-parse HEAD` plus `git status --short` of the repository.

If you want the git baseline independently, run from the repository root before
loading:

```bash
git rev-parse HEAD && git status --short
```

Confirm the pre-flight `PASS` and note the resting bound program (`queue_microbench`)
before continuing.

---

## 2. The two execution modes

The demonstration supports two clearly separated modes. **Never blur the four evidence
levels** they produce (Section 2.3) — a result from replayed frames is not the same as
a result from the physical relay, and neither is a live inline session.

### 2.1 MODE A — Safe replay demo (default; use this for the meeting)

MODE A replays previously validated real SEL-751 READ, pure-ACK, and RESPONSE frames
through the loaded normalizer. It is the default and the mode you run in front of an
audience because it has these properties:

- **no physical relay modification** — the SEL-751 is not contacted at all;
- **no DNP3 write or control operation** of any kind;
- **no physical recabling;**
- **deterministic transaction count** (`TRIALS`);
- **produces both a native and a protected PCAP** for side-by-side comparison;
- **repeatable in a few minutes.**

Native replay runs with the blocker reservoir **off** (bypass), so the captured
ACK-to-RESPONSE interval *is* the device's native fingerprint. Protected replay runs
with the reservoir **on**, so each response is held queue-resident until `t_ack + G`
and the captured interval becomes G.

One-command guarded form:

```bash
make demo MODE=replay TRIALS=10 G_MS=25
```

### 2.2 MODE B — Live read-only relay mode (optional; requires explicit authorization)

MODE B polls the physical SEL-751 at `192.168.10.7:20000`. It is opt-in and must not
be run without explicit authorization. It is invoked as
`make run-native MODE=live` (or `MODE=live scripts/05_run_native.sh`). The injector
(`multipoll.py`) asserts the DNP3 function byte is READ on every frame and can issue
nothing else.

- **Allowed:** Class-0 READ; Request-Link-Status; the existing approved connection
  parameters only.
- **Prohibited (never issue any of these):** `DIRECT_OPERATE`, `OPERATE`, `SELECT`,
  `WRITE`, restart, any configuration change, password guessing, and any change to the
  relay's IP address.

The Tofino is **not** inline to the relay in MODE B; the capture is taken on the
auto-detected relay-facing interface, and the result must be labelled as a
physical-relay-generated capture.

### 2.3 The four evidence levels (label every result with exactly one)

1. **Synthetic markers** — internal blocker tokens and on-chip counters/registers.
   Not DNP3 traffic. Used to prove the *mechanism* (queue held, deadline armed,
   response released, zero blocker frames escape).
2. **Real replayed DNP3** — MODE A replay of validated SEL-751 frames through the
   switch. This is what the meeting demonstration produces.
3. **Physical-relay-generated captures** — MODE B live read-only polling of the SEL-751,
   and the native CLRT characterization taken from the physical relay.
4. **Live inline relay session** — a session held in real time with the switch inline.
   **This has not been done and is not claimed.** Do not present any result as this
   level.

---

## 3. Full manual procedure (step by step)

Run these in order from `research/timing_final`. After each step, check the stated
condition before moving on. Any script that fails exits nonzero and prints `FATAL:` at
the top of its output; stop and read the log under `logs/` rather than pushing through.

### Step 1 — Pre-flight

```bash
make preflight
```

**Check:** final line reads `PREFLIGHT: PASS`; the topology print shows the resting
program `queue_microbench`.

### Step 2 — Build the P4 artifact (local, offline)

```bash
make build
```

`scripts/01_build.sh` compiles `p4/dnp3_timing_normalizer.p4` with the local bf-p4c
(9.13.1), *after* gating on the frozen source SHA-256 (it refuses to build anything
that is not the reference program).

**Check:** `[PASS] source is the frozen reference`, `[PASS] 0 errors`, ingress stage
count reported as `10/12`, and `BUILD: PASS`.

### Step 3 — Load the program onto the switch (the one guarded, switch-changing step)

```bash
make load
```

`scripts/02_load.sh` snapshots the current switch state (Section 1.2), then **asks for
explicit confirmation** — you must type `load` — before it displaces
`queue_microbench`, stages the compiled artifact, and relaunches `bf_switchd` on
`dnp3_timing_normalizer`.

**Check:** `[PASS] one bf_switchd bound to dnp3_timing_normalizer` and
`LOAD: PASS — next: make configure-tm`. This is the only step that changes the switch;
`make restore` reverses it.

### Step 4 — Configure Traffic Manager and the guard interval

```bash
make configure-tm G_MS=25
```

`scripts/03_configure_tm.py` sets the two-level strict priority (Q_BLOCK qid7 HIGH
outranks Q_RESP qid1 LOW), explicitly clears and verifies that **no max-rate shaper**
remains on Q_BLOCK (a stale shaper would make Q_BLOCK ineligible and let the response
leak), and sets the guard interval G (tick-aligned to 256 ns granularity and read back
from the chip).

**Check:** the printed `CONFIGURE_TM` JSON shows every gate true —
`strict_priority_verified`, `qblock_shaper_cleared`, `guard_g_readback_verified` — and
the final line reads `configure-tm: PASS`.

### Step 5 — Start a capture (for the meeting / Wireshark)

In a separate terminal, start a foreground passive capture you control:

```bash
make capture OUTPUT=protected_demo.pcap
```

`scripts/04_start_capture.sh` captures on the correct interface (the dp9-facing data
NIC in MODE A). The documented capture pattern is:

```bash
tcpdump -i <detected-interface> -s 0 -nn -U -w <output-file> 'tcp port 20000'
```

`-s 0` = full frames (no truncation); `-U` = unbuffered write; `-nn` = no name
resolution. The wrapper additionally filters `or (ether proto 0x88c1)` so the
blocker-token isolation check is a real observation (you expect to see **zero** such
frames on this external interface). It records epoch timestamps and, on Ctrl+C, stops
cleanly and writes the JSON manifest (Section 4).

**Check:** the terminal prints `CAPTURING in the foreground` and the interface it
chose. Leave it running; you stop it with Ctrl+C after the trials.

### Step 6 — Run the native (un-normalized) trial

```bash
make run-native TRIALS=10
```

`scripts/05_run_native.sh` (MODE A) replays validated frames through the switch in
bypass — reservoir off — and captures its own native evidence PCAP plus manifest. The
captured ACK-to-RESPONSE interval is the device's native CLRT.

**Check:** `RUN_NATIVE (replay): done — RUNID=…`. Note the printed `RUNID`.

### Step 7 — Run the protected (normalized) trial

```bash
make run-protected TRIALS=10 G_MS=25
```

`scripts/06_run_protected.sh` (MODE A) sets and verifies G on chip, then replays with
the blocker reservoir on (K ≥ 64). Each response is held queue-resident until
`t_ack + G`, so the captured interval becomes G. It captures its own protected evidence
PCAP plus manifest.

**Check:** `RUN_PROTECTED: done — RUNID=…`. Note the printed `RUNID` and the follow-up
`08_verify.py` / `09_analyze_clrt.py` hint it prints.

### Step 8 — Stop the meeting capture

Return to the Step-5 terminal and press **Ctrl+C**. The capture stops cleanly, the
PCAP is fetched back, its readability and packet count are checked, and the manifest is
written. (The per-trial captures in Steps 6-7 are already stopped and manifested
automatically.)

**Check:** `STOP_CAPTURE: PASS` with the packet count and SHA-256 prefix.

### Step 9 — Verify packet identity and timing

There is no make target for verification; run the script, with the lab environment
loaded, using the protected `RUNID` from Step 7:

```bash
set -a; . config/lab.env 2>/dev/null || . config/lab.env.example; set +a
python3 scripts/08_verify.py --runid <PROTECTED_RUNID> --g-ms 25
```

`scripts/08_verify.py` confirms the held response is byte-for-byte identical to what
the device sent (no CRC recompute, no field edits) and that the timing landed at G. It
writes `<runid>.verify.json`.

**Check:** verification reports the byte-identity and G-timing gates PASS.

### Step 10 — Analyze CLRT from a PCAP

```bash
make analyze PCAP=protected_demo.pcap G_MS=25
```

`scripts/09_analyze_clrt.py` computes per-transaction CLRT and, when `tshark` is
available, cross-checks the headline median against an independent tshark extraction so
the numbers do not depend on a single parser. It writes `transactions.csv`,
`summary.json`, and `validation.json`. Run it once for the native PCAP and once for the
protected PCAP to compare.

**Check:** the summary shows the protected median at ~G (25 ms) with a tiny standard
deviation, versus the native median near 2 ms with large spread; the tshark
cross-check agrees within tolerance.

### Step 11 — Generate figures

```bash
make figures G_MS=25 NATIVE_PREFIX=<native_prefix> PROTECTED_PREFIX=<protected_prefix>
```

`scripts/10_generate_figures.py` renders the CLRT figures (native vs protected). The
prefixes are the PCAP paths without the `.pcap` suffix, printed by the trial steps.

**Check:** figures are written under `evidence/timing_final/figures/`.

### Step 12 — Collect the evidence chain

Bundle the run's PCAPs, manifests, counters, verify/analysis JSON, and figures into one
directory with a `SHA256SUMS` file (no make target; run the script directly):

```bash
scripts/11_collect_evidence.sh --native-runid <NATIVE_RUNID> --protected-runid <PROTECTED_RUNID>
```

**Check:** `COLLECT_EVIDENCE: done -> …/collected/<timestamp>/` and that directory
contains a `SHA256SUMS`.

### Step 13 — Restore the switch

```bash
make restore
```

Covered in full in Section 5. Always run this before you leave the lab.

**Check:** `RESTORATION: PASS`.

---

## 4. PCAP manifest (what is recorded beside every capture)

Every capture writes a JSON manifest next to the `.pcap`
(`<pcap>.manifest.json`), produced by `scripts/07_stop_capture.sh`. It records:

- `host` — which machine captured (vision / hulk);
- `interface` — the capture interface (auto-detected relay iface, or the dp9-facing
  data NIC in MODE A);
- `start_epoch` / `end_epoch` — capture start and end times (epoch seconds);
- `filter` — the exact capture filter (`(tcp port 20000) or (ether proto 0x88c1)`);
- `packet_count` — packets in the file (verified readable with `tcpdump -r`);
- `sha256` — SHA-256 of the PCAP file;
- `source_commit` — the repository commit the run was produced from;
- `g_ms` — the guard interval G in effect;
- `transaction_count` — the number of transactions;
- `program` — the loaded P4 program.

If the capture cannot be fetched back, `07_stop_capture.sh` **aborts** rather than
accept a missing or empty PCAP — a trial with no verifiable capture must not be
trusted.

---

## 5. Safety and restoration (always return the lab)

The runnable package must always preserve the lab. The restore step is **idempotent**:
running it again when the lab is already clean is a no-op that simply re-verifies, so
you can (and should) run it more than once if a session was interrupted.

### 5.1 What restore does

```bash
make restore
```

`scripts/12_restore.sh` performs, in order:

1. **Stop generators and captures** — signals any `p13_inject.py` injector and any
   `tcpdump` left running on Vision and Hulk (no error if none are running).
2. **Stop temporary BFRT clients** — any staged control-plane client on the switch.
3. **Read final on-chip state** — collects the final counters and checks that
   `reg_deadline` is **not armed** (no transaction still held) and that no live blocker
   reservoir remains; warns if a transaction still appears armed.
4. **Verify no blocker tokens remain** externally — the capture filter admits the
   `0x88c1` token EtherType precisely so this is a real (non-vacuous) observation; you
   expect zero such frames outside the switch.
5. **Restore `queue_microbench`** — rebinds (idempotent) or, if needed, swaps
   `bf_switchd` back to `queue_microbench` via its launch script. The restore target is
   `queue_microbench` / `queue_microbench_abs.conf`.
6. **Verify exactly one `bf_switchd`** is running.
7. **Verify the BFRT binding** is `queue_microbench`.
8. **Verify switch reachability** (`10.10.54.81`).
9. **Verify Vision retains `192.168.10.1`** on its relay-facing interface.
10. **Verify Hulk reachability** (`10.10.54.158`).
11. **Write the restoration report** to
    `research/timing_final/evidence/timing_final/final_state/restoration_report.txt`.

**Check:** the final line of the report and the console read `RESTORATION: PASS`. If it
reads `FAIL`, resolve the flagged item (see the Troubleshooting guide) and run
`make restore` again — it is safe to repeat.

### 5.2 End-of-session checklist

- [ ] Meeting capture stopped (Ctrl+C in the Step-5 terminal).
- [ ] `make restore` ran and printed `RESTORATION: PASS`.
- [ ] Restoration report present under `evidence/timing_final/final_state/`.
- [ ] Switch bound to `queue_microbench`, exactly one `bf_switchd`.
- [ ] Vision still holds `192.168.10.1`; switch and Hulk reachable.
- [ ] No blocker tokens observed externally; no transaction left armed.

---

## 6. The three-terminal meeting workflow

For a live demonstration, use three terminals, all `cd`'d into
`research/timing_final`, after you have already completed pre-flight, build, load, and
`configure-tm` (Steps 1-4 above). This is the compact experience described in the
directive.

**Terminal 1 — switch status (leave visible):**

```bash
make status
```

`scripts/demo_status.py` shows only meeting-relevant state: the loaded P4 program, the
Q_BLOCK > Q_RESP strict priorities (and that no shaper sits on Q_BLOCK), whether a
transaction is currently held (`deadline_armed`), and the blocker/release counters.
Re-run it before and after the traffic to show the counters move.

**Terminal 2 — capture:**

```bash
make capture OUTPUT=protected_demo.pcap
```

Leave it capturing in the foreground; Ctrl+C after Terminal 3 finishes.

**Terminal 3 — traffic:**

```bash
make run-protected TRIALS=10 G_MS=25
```

Then analyze the capture and render the figures:

```bash
make analyze PCAP=protected_demo.pcap G_MS=25
make figures G_MS=25
```

### Compact result block

`make analyze` prints a compact result of this shape (numbers filled from the run):

```
Transactions:              10
Valid READs:               10
Qualified ACKs:            10
Responses held:            10
Responses released:        10
Mean ACK->RESPONSE:        ...
CLRT standard deviation:   ...
Low-G warnings:             0
Missing/duplicate frames:   0
External blocker frames:    0
Verification:             PASS
```

Read it as follows. `Valid READs`, `Qualified ACKs`, `Responses held`, and
`Responses released` should all equal `Transactions` — every transaction was
classified, its deadline armed, its response held, and then released. `Mean
ACK->RESPONSE` should sit at G (25 ms) plus the fixed ~1.7 µs implementation release
tail, with a very small `CLRT standard deviation`. `Low-G warnings` must be `0` (a
nonzero value means G was set below the device's native CLRT and no real holding
occurred — the mechanism degenerated to pass-through). `Missing/duplicate frames` must
be `0`. `External blocker frames` must be `0` — the internal `0x88c1` tokens never left
the switch. `Verification: PASS` confirms byte-identity and G-timing.

To show the contrast, capture and analyze a native run the same way
(`make run-native`, then `make analyze` on the native PCAP): the native mean sits near
2 ms with a large standard deviation, versus the protected run pinned at G.

---

## 7. If something goes wrong

- Any script prints `FATAL:` at the top of its output on failure and exits nonzero;
  read the matching timestamped log under `research/timing_final/logs/`.
- The single switch-changing action is `make load`; **`make restore` reverses it** and
  is safe to run repeatedly.
- If a session was interrupted at any point, the correct first move is `make restore`,
  then re-run `make preflight` to confirm the lab is healthy before trying again.
- For symptom-by-symptom recovery (wrong program bound, more than one `bf_switchd`,
  empty PCAP, response never released, low-G warning, blocker token visible externally,
  etc.), use the Troubleshooting guide in this tutorial package.

---

*Claim discipline reminder: every result from this runbook is about the CLRT-magnitude
timing channel on a separate-ACK device. It is not a size result, not an anonymity
result, and not a production deployment. Label each figure and number with its evidence
level (Section 2.3).*
