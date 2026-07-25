# QUICKSTART — 10-Minute Path to the DNP3 Timing-Normalizer Demo

This is the fastest safe route from a cold checkout to a before/after CLRT result
and back to a clean switch. It is a ten-step path; each step lists its purpose, the
exact command, the expected output, the common failure, and the recovery command.

**Terms.** DNP3 is the Distributed Network Protocol version 3, the SCADA protocol
the SEL-751 relay speaks. CLRT is the interval between the device's link-layer
acknowledgment (ACK) and its DNP3 application response — the timing channel this
defense normalizes to a fixed guard value G (default 25 ms).

**Scope and safety.** This demo covers the **timing/CLRT channel only** — not size
obfuscation, not device anonymity, not production readiness. The default `MODE=replay`
is a **safe replay** of the relay's previously captured frames: it does not modify
the physical relay and issues no DNP3 control or write commands.

**Before you start.** Run every command from the directory that holds the Makefile:

    cd /home/philip/Projects/DNP3/research/timing_final

Tip: append `DRYRUN=1` to any `make` target to print the remote commands without
touching hardware — a good rehearsal before the real run.

The three machines: Vision (master side, 10.10.54.19 / 192.168.10.1), the Tofino-1
switch (10.10.54.81), and Hulk (outstation side, 10.10.54.158).

---

## Step 1 — Source the environment

- **Purpose:** make the lab configuration and SSH credentials available. The
  Makefile auto-reads `config/lab.env` (falling back to `config/lab.env.example`);
  SSH credentials come from `~/.lab_env`, which is never stored in the repository.
- **Command:**

      cp -n config/lab.env.example config/lab.env
      test -f ~/.lab_env && echo "credentials present" || echo "MISSING ~/.lab_env"

- **Expected output:** `credentials present`. (The `cp -n` copies the config only on
  the first run and never overwrites your edited copy.)
- **Common failure:** `MISSING ~/.lab_env` — SSH to the three machines will fail with
  an authentication error on the next step.
- **Recovery command:** create the credentials file (it must contain `SSHPASS=...`)
  and re-run the test:

      printf 'SSHPASS=<lab-password>\n' > ~/.lab_env && chmod 600 ~/.lab_env

---

## Step 2 — Preflight

- **Purpose:** confirm the lab is in a known-good state before changing anything —
  all three machines reachable, Vision holds the relay-facing address, and exactly
  one `bf_switchd` is running.
- **Command:**

      make preflight

- **Expected output:** each machine reported reachable, Vision's relay interface
  detected on `192.168.10.1`, one `bf_switchd` process, and a printed topology
  ending with no error.
- **Common failure:** a machine is unreachable, Vision is missing `192.168.10.1`, or
  more than one `bf_switchd` is reported.
- **Recovery command:** look the exact symptom up in `TROUBLESHOOTING.md`, fix it,
  then re-run `make preflight`. Do not proceed until preflight is clean.

---

## Step 3 — Build

- **Purpose:** compile `dnp3_timing_normalizer.p4` locally and verify the source
  SHA-256, zero compile errors, and the expected MAU-stage fit before loading it.
- **Command:**

      make build

- **Expected output:** `0 errors`, the source SHA matching the value pinned in
  `config/lab.env.example`, and the reported ingress-stage count within budget.
- **Common failure:** compiler not found (wrong `LOCAL_BFP4C_BIN` path) or a SHA
  mismatch (edited or stale P4 source).
- **Recovery command:** confirm the local bf-p4c path, then rebuild:

      make build DRYRUN=1   # inspect the exact compile command, then rerun: make build

---

## Step 4 — Load

- **Purpose:** perform the guarded `bf_switchd` swap that loads the timing
  normalizer onto the Tofino-1 switch. This step changes the switch and asks you to
  confirm.
- **Command:**

      make load

- **Expected output:** a confirmation prompt, then the switch launching with the
  `dnp3_timing_normalizer` program bound (BFRT binding reported OK).
- **Common failure:** BFRT binding failure, or the wrong P4 program ends up loaded.
- **Recovery command:** restore the baseline and retry from a clean state:

      make restore && make preflight && make load

---

## Step 5 — Configure queues

- **Purpose:** program the Traffic-Manager so the held response is scheduled
  correctly — strict priority between the block and hold queues, a cleared Q_BLOCK
  shaper, and the guard interval G set to the demo value.
- **Command:**

      make configure-tm G_MS=25

- **Expected output:** strict priority and shaper settings applied and **read back
  verified**, with G reported as 25 ms.
- **Common failure:** queue-priority readback does not match what was written.
- **Recovery command:** re-apply and re-verify; if it still mismatches, reload:

      make configure-tm G_MS=25 DRYRUN=1   # review, then: make configure-tm G_MS=25

---

## Step 6 — Start capture

- **Purpose:** begin a passive full-frame packet capture so the before/after
  intervals are recorded to a PCAP for analysis.
- **Command:** run this in its own terminal (it captures until you stop it):

      make capture OUTPUT=evidence/timing_final/quickstart.pcap

- **Expected output:** a message that capture has started, writing to the named
  file; it keeps running in the foreground until you press Ctrl+C.
- **Common failure:** capturing on the wrong interface, or no write permission for
  the output path, so the PCAP stays empty.
- **Recovery command:** stop with Ctrl+C, pick a writable path under
  `evidence/timing_final/`, and restart the capture:

      make capture OUTPUT=evidence/timing_final/quickstart.pcap

---

## Step 7 — Run native

- **Purpose:** inject a native (bypass) replay trial — the relay's real timing with
  no normalization — to record the baseline CLRT the observer would normally see.
- **Command:**

      make run-native TRIALS=10

  (`make demo-native` is an alias for the same target.)
- **Expected output:** ten transactions injected and captured, with a variable,
  short native ACK-to-response interval (roughly a couple of milliseconds, high
  variance).
- **Common failure:** no frames captured because the capture in Step 6 is not
  running, or the injector cannot reach the data-plane interface.
- **Recovery command:** confirm the Step 6 capture is live, then re-run:

      make run-native TRIALS=10

---

## Step 8 — Run protected

- **Purpose:** inject a protected (hold-response) replay trial so the switch holds
  each response until the deadline, normalizing the CLRT to the guard value G.
- **Command:**

      make run-protected TRIALS=10 G_MS=25

  (`make demo-protected` is an alias for the same target.)
- **Expected output:** ten transactions captured with the ACK-to-response interval
  pinned at approximately 25 ms and near-zero variance, and the held responses
  byte-identical to the native ones.
- **Common failure:** the interval does not track G — usually because Step 5 did not
  apply, or G is not above the relay's native interval.
- **Recovery command:** re-apply the queue config, then re-run the protected trial:

      make configure-tm G_MS=25 && make run-protected TRIALS=10 G_MS=25

---

## Step 9 — Analyze

- **Purpose:** compute the CLRT statistics (median, spread, and the before/after
  comparison) from the captured PCAP.
- **Command:** stop the Step 6 capture with Ctrl+C first, then:

      make analyze PCAP=evidence/timing_final/quickstart.pcap G_MS=25

- **Expected output:** CLRT median and standard deviation per phase — a variable
  native interval versus a protected interval sitting at G with a very small spread,
  and a PASS verification line.
- **Common failure:** `tshark` not installed/available (analysis is tshark-gated),
  or the PCAP path is wrong or empty.
- **Recovery command:** point at a valid, non-empty PCAP (a shipped example works
  for a dry check) and re-run:

      make analyze PCAP=deliverables/timing_tutorial/example_pcaps/protected_demo.pcap G_MS=25

---

## Step 10 — Restore

- **Purpose:** return the switch to its safe baseline. This is mandatory before you
  leave the testbed.
- **Command:**

      make restore

- **Expected output:** the switch reloaded with the `queue_microbench` program and a
  final lab-health check reported clean. The command is idempotent.
- **Common failure:** restore reports the switch did not return to `queue_microbench`
  (for example, a launch-script path problem).
- **Recovery command:** re-run restore, then confirm the lab is back to baseline:

      make restore && make preflight

---

## The one-command alternative

Steps 6 through 9 are wrapped in a single guarded target. From the Makefile
directory:

    make demo MODE=replay TRIALS=10 G_MS=25

It runs the native capture, the protected capture, and the analysis in sequence and
asks before changing the switch. Add `DRYRUN=1` to rehearse it without touching
hardware. Always finish with `make restore` (Step 10).
