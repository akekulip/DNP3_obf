# Candidate on the Tofino — first hardware load and the Timing OFF smoke, 2026-10-06

Authorised by Philip in this session ("yes, write the bring-up and run the smoke"). **Scope run:** load the response-ready candidate, bring it up with the release
block disabled, run 30 READs from Vision to the SEL-751 through it, restore the pre-test program. **Not run:** any holding arm (admission), SELECT, OPERATE.

## What happened (UTC)

| time | event | outcome |
|---|---|---|
| 16:45:00 | first swap attempt: my stop step matched no launcher process, the old daemon kept running, and the script launched the candidate anyway | the second daemon aborted on a thrift bind conflict and never touched the chip; before/after snapshots show **no configuration difference**; this was my sequencing error, replaced by `swap_daemon.sh` (`set -eu`, exactly one daemon, aborts if the old one does not stop) |
| 16:46:07 | candidate `df599101…` loaded after the first build | **`bf_device_add failed(9) … Not enough space adding static entry 4 … Ingress.tbl_owner_valid`**: the device did not instantiate; the switch was effectively down |
| 16:46:38 | restore (rehearsed procedure) | configuration identical to the pre-candidate snapshot, SEL reachable |
| — | root cause | `tbl_owner_valid` had 5 const entries and `size = 4`; `tbl_tracker_admission` 3 and 2. bf-p4c accepts this and every offline model passed. Sizes fixed (8, 4), `test_table_capacity.py` added with a mutation check, rebuilt on SDE 9.13.1 and **9.13.2** (7 ingress / 0 egress, 88 tables) |
| 16:54:47 | candidate (fixed source `df5991016285…`) loaded | device instantiated; only platform message was a transceiver checksum note for port 33, also present in the known-good launches; a read-only client bound to `defense4_timing` and read 310 tables |
| 16:55 | `candidate_bringup.py --case off`: `PASS (n_fail=0 n_warn=0)` | ports, MAC-near loopbacks dp8 and dp10, both strict-priority ladders, packet generator, mirror, two sessions, **codebook empty**, the three parameter tables written and read back, pktgen enabled last |
| 16:55:58–16:56:12 | `run_block.py cand_off_30 --reads 30 --sbo 0` on Vision (harness byte-identical to the repository's) | see below |
| 16:56:56 | restore | configuration identical to the pre-candidate snapshot; SEL 5/5, 0.37–1.9 ms |

## Smoke result (Timing OFF, candidate loaded)

- Harness: output-state check before 0, READ 0, output-state check after 0, capture exit 0. 30 of 30 READ `OK`, no stale frames, no problems.
- Independent re-analysis of the raw capture (`results/hw_smoke_20261006/cand_off_30/traffic.pcapng`): 30 responses of 49 B plus the single 58-byte output-state read;
  every SEL→master frame has valid IP and TCP checksums (68 of 68). The 68 flagged frames are Vision's own master→SEL transmissions captured before NIC checksum offload.
- Master-facing timing, native: **CLRT_original median 2.240 ms** (IQR 3.109, sd 3.926, min 1.104, max 22.387 ms; n = 31 of 31 attempted including the pre-check READ), request-to-ACK median 0.513 ms.
  The 2026-09-25 Timing OFF READ median was 2.231 ms. The 22 ms maximum is the known cold-poll tail.
- Loaded identity (`loaded_identity_candidate_20261006.json`): one daemon; `bfrt.json`, `context.json`, `tofino.bin` equal the compiler manifest; source `df5991016285…`.

## What this establishes, and what it does not

- **Established:** the candidate loads on the hardware (after the fix), brings up with strict readback, and is transparent in the OFF arm. First rows with status
  *loaded, configured, hardware-measured (OFF arm, n = 30)*.
- **Not established:** any holding behaviour on hardware (D_A, gap, fallback, split). The release block was disabled, so this says nothing about the response-ready mechanism itself.
- **Holding arms are blocked on admission, correctly.** The profile gate requires transport timers measured on this connection **and build**. The master's timer was measured on 2026-09-16 on the frozen build; re-measuring it
  on the candidate means dropping inbound traffic on Vision with `iptables` for one 4-tuple (`audit_current/master_rto_20260916/master_rto.py`), which was not authorised in this session.
  The outstation's timer needs its own measurement. The worst-case hold is the watchdog horizon, about 30.8 ms.
- The model-load attempt (offline test of the same load path) got as far as the driver and then failed on DMA buffer setup in the namespace; inconclusive, not a pass. The hardware found the capacity defect instead.

## Lesson recorded as a test

A fault only the driver sees must have an offline stand-in: `response_ready/tests/test_table_capacity.py` fails whenever const entries outnumber a table's declared size.
