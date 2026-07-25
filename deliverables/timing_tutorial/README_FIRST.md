# README FIRST — DNP3 Timing-Normalizer Demo

Read this page before touching anything. It answers the eight questions people ask
at the start. For deeper help see `TROUBLESHOOTING.md` (symptom-based fixes) and
`WIRESHARK_GUIDE.md` (how to read the captures).

All commands below run from the directory that holds the Makefile:

    cd /home/philip/Projects/DNP3/research/timing_final

**1. What does this project demonstrate?**
An in-network timing-obfuscation defense running on an Intel Tofino-1 switch. It
takes DNP3 (Distributed Network Protocol version 3, the SCADA protocol the relay
speaks) and normalizes the CLRT — the interval between the device's link-layer
acknowledgment (ACK) and its DNP3 application response — to a fixed guard value G.
The switch holds the *original* response byte-for-byte in a queue until the
deadline, so a passive observer sees a constant interval instead of the relay's
native timing. Scope is the **timing/CLRT channel only**: this is not size
obfuscation, not device anonymity, and not a production-ready system. The default
demo is a **safe replay** of the real relay's captured frames — it does not modify
the physical relay and issues no DNP3 control or write commands.

**2. Which three machines are involved?**
- Vision — master side, 10.10.54.19 (management), 192.168.10.1 (relay-facing).
- Tofino-1 switch — 10.10.54.81, runs the normalizer P4 program.
- Hulk — outstation-side host, 10.10.54.158.
The physical device is an SEL-751 relay at 192.168.10.7:20000 (touched only in the
optional live read-only mode, never in the default demo).

**3. Which command checks the lab?**  `make preflight`
(reachability of all three machines, Vision's relay interface, exactly one
bf_switchd; prints the topology.) A one-line health view is `make status`.

**4. Which command runs the demo?**  `make demo MODE=replay TRIALS=10 G_MS=25`
The single guarded end-to-end demo (native capture, protected capture, analysis).
It asks before changing the switch. Add `DRYRUN=1` to print every remote command
and touch no hardware.

**5. Where are the PCAPs stored?**
Fresh captures land under `research/timing_final/evidence/timing_final/`. Ready-made
example captures ship with this tutorial in
`deliverables/timing_tutorial/example_pcaps/` (`native_demo.pcap`,
`protected_demo.pcap`).

**6. How do I open them in Wireshark?**
    wireshark deliverables/timing_tutorial/example_pcaps/protected_demo.pcap
Apply the display filter `dnp3` to see the transactions. Full walkthrough (columns,
CLRT time-delta, what to point at in a meeting) is in `WIRESHARK_GUIDE.md`.

**7. Which command restores the switch?**  `make restore`
Returns the switch to the `queue_microbench` program and verifies lab health. It is
idempotent — safe to run more than once.

**8. What should I do if the demo fails?**
1. Run `make status` to see what the switch is doing.
2. Look up the symptom in `TROUBLESHOOTING.md`.
3. Run `make restore` to put the switch back in its safe baseline.
4. Re-check the lab with `make preflight`, then retry.
