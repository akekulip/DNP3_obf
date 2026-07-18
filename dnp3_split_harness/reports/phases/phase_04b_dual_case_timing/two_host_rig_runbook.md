# Phase 04B — Two-host rig runbook (Vision master ↔ Hulk outstation)

**Status: NOT YET EXECUTED — blocked on the rig `decps` sudo password.**
Passwordless SSH to `decps@Hulk` / `decps@Vision` works, but `decps` sudo requires a
password that is *not* the gambit local password and is *not* stored anywhere in this repo
or project memory (per the `lab-hosts-dnp3` memo: "sudo needs a password — ask the user").
Loading DCRN on Hulk (`tc`/eBPF → CAP_NET_ADMIN + CAP_BPF) and capturing on Vision
(`tcpdump`) both require rig root. Once the rig sudo password is supplied to the driver
transiently (env var, never written to disk), the run below is one command.

## Topology (from `lab_config.py` / `lab-hosts-dnp3`)

- **Vision** = DNP3 **master / client + authoritative observer.** mgmt `10.10.54.19` (eno1, 1G).
- **Hulk** = DNP3 **outstation / replay server + DCRN load point.** mgmt `10.10.54.158` (eno1, 1G).
- DNP3 over TCP/20000 on the **1G management net** (the proven baseline path; does not
  traverse the Tofino). DCRN attaches on **Hulk `eno1`** (egress = the outstation's
  responses/ACKs). Capture on **Vision `eno1`** = external observer of post-DCRN timing (§6).

## Why this vantage

DCRN normalizes *when the outstation's bytes leave the wire*. The observer that a passive
fingerprinter would occupy is downstream of that egress — Vision's `eno1` sees exactly the
inter-arrival timing DCRN produced. Capturing on Hulk itself (before its own egress qdisc)
would not show the enforced EDT; capturing on Vision does.

## Preconditions to verify on the rig before the campaign

1. **RTO re-measure on Vision.** `Dhigh = 151 ms` and the 32.39 ms target were calibrated
   from a gambit RTO probe. Re-run `rto_probe.py` against the live path Vision→Hulk and
   confirm `effective_rto_ms` still comfortably exceeds the target window. If the rig RTO
   differs materially, re-run `phase04b_calibrate.py` before loading DCRN.
2. **Toolchain on Hulk.** `clang`, `tc` (iproute2 with `bpf`), a writable bpffs
   (`mount -t bpf`), `kernel.unprivileged_bpf_disabled` — the load is done under sudo so
   `=2` is fine. Rig kernel is 6.8.0-134 (newer than gambit's 5.15; the `.o` should load,
   but re-verify with the capability probe below — do **not** assume).
3. **Capability probe (Gate A on the rig).**
   `sudo IFACE=eno1 bash scripts/phase04b_capability_probe.sh` on Hulk — confirms the DCRN
   object loads + verifier-accepts on both `tc` hooks on the rig kernel, then auto-detaches.
4. **Deploy.** rsync `dnp3_split_harness/` (harness + `bpf/*.o` + scripts + spec) to
   `decps@Hulk` and `decps@Vision` (no sudo). Build the spec once with
   `phase04b_dcrn_harness.py build`.

## Campaign (per condition: NATIVE / DCRN_FIXED / DCRN_COMMON_BOUNDED)

For each condition, on the SAME source transactions/order/seed:

1. **Hulk** — if a DCRN condition: `sudo IFACE=eno1 BPF_OBJ=<obj> RUN_DIR=<dir> bash
   scripts/phase04b_prepare.sh` (saves offloads, sets `fq` root, attaches DCRN ingress+egress).
   For NATIVE: ensure detached (`scripts/phase04b_cleanup.sh`).
2. **Hulk** — start the replay server: `phase05_rig_replay.py --role server --spec spec.json
   --iface eno1` (background, `ssh -f`).
3. **Vision** — start the authoritative capture: `sudo tcpdump -i eno1 -w <cond>.pcap "tcp
   port 20000"` (background).
4. **Vision** — run the replay client: `phase05_rig_replay.py --role client --spec spec.json
   --hulk-ip 10.10.54.158` (repeat for RUNS iterations × the spec session set).
5. **Teardown** — stop client, capture, server; on Hulk run `phase04b_cleanup.sh` (detach
   DCRN, restore offloads). Pull `<cond>.pcap` from Vision to the analysis host.

## Analysis (unprivileged, on any host with the pcaps)

```
python3 phase04b_dcrn_analyze.py       --run-dir <rig_run_dir>   # per-condition timing + transport
python3 phase04b_dcrn_attacker_eval.py --run-dir <rig_run_dir>   # timing leakage vs mode/size
```

## Expected result (to confirm, not assume)

Mirror of the local Gate C campaign: NATIVE req→resp device-dependent (~16 ms class on the
1G path, absolute value will differ from loopback); DCRN_FIXED pinned to the (re-measured)
fixed target, structure-independent, separate-case gap → guard delta; DCRN_COMMON_BOUNDED
inside the bounded window. Transport clean (0 retrans/reset/dup-ACK). Attacker timing
balanced-accuracy falls toward 0.333; mode_only + size unchanged. **Any deviation
(retransmissions on the real path, RTO drift, ACK-mode change) is reported, not smoothed
over — a rig PASS requires the measured PCAPs, not this expectation.**

## Driver

`scripts/phase04b_rig_campaign.sh` automates the above from gambit over SSH. It reads the
rig sudo password from `$RIG_PW` (used only transiently for `sudo -S`, never echoed or
written), defaults to `DRYRUN=1`, and must be run with `DRYRUN=0 RIG_PW=… ` to execute.
It has **not** been wire-verified on the rig (that verification is the run itself).
