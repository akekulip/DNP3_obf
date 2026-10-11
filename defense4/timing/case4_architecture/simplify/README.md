# Simplification track (2026-10-11)

Offline work toward a smaller, working size+timing target. **Nothing here has run on the Tofino model
or been loaded on the switch.** The P4 was compiled with the open-source Tofino compiler (bf-p4c
9.13.4, p4lang/p4c `ff507048`, built from source in the cloud session); see "Compile results". That is
not the switch's SDE 9.13.2, so the 9.13.2 build under "Next steps" is still required before loading.

## What is here

| Path | What it is | Verified by |
|---|---|---|
| `tools/syn_option_audit.py` | Reads captures (read-only) and reports the TCP options on every SYN and SYN-ACK, per host, and whether the response-path mapper would arm | Run over 200 retained captures; result in `evidence/syn_options_relay_rig.json` |
| `single_pipe/make_single_pipe.py` | Composes ONE pipeline: the seven-stage timing ingress (`stage_reduction/src/defense4_timing.p4`, `U_BOR`) + role E egress (`make_e.py`, from the hardware-run `protocol/case4_response_path.p4`), with edits S1 (reverse pass on the relay port) and S2 (SYN option scrub) | `single_pipe/tests` (17 tests); compiled, see "Compile results" |
| `single_pipe/single_pipe.p4` | Generated output; a test pins it to the generator | same |
| `single_pipe/cp_single_pipe.py` | Egress control-plane rows: forward rows at the master port (9), reverse rows at the relay port (64) | same |

Changes made elsewhere for this track:

| Path | Change | Default behavior |
|---|---|---|
| `integration/core/response_only/make_n.py`, `compose.py` | Edit 9, opt-in (`--no-response-tail-crc`, `--no-n-response-tail-crc`): N drops the response tail and second-block CRC checks that E repeats. Measured: no stage saved; 6 tables, 3 hash units and 8 PHV containers fewer in pipe 0 | Unchanged: default N output is byte-identical to `n_response_only.p4`, and the default composite hashes to `90eab15b…`, the source of the last compiled build (`shared_port_01`) |
| `integration/controller/t_register_reset.py` | Reset plan for T's registers, derived from the P4 declarations; restores the five `0xffffffff` registers instead of clearing them | New module, new tests |
| `stage_reduction/control/reservoir_sizing.py` | Blocker-reservoir sizing from port speed and measured loop latency | New module, new tests |
| `stage_reduction/control/defense4_timing_setup.py` | `--bor-loopback-speed {25G,10G}` for dp10 | Unchanged: default 25G; `dry-run` output identical |
| Seven Case 4 documents | Dated two-pipe correction banner; the history below each banner is untouched | n/a |
| `audit_current/verification_20260929/README.md` | Finding B1 (TCP timestamps on the relay rig) | n/a |

## Compile results (open-source bf-p4c 9.13.4)

Evidence: `evidence/opensource_9134_01/` (compile logs, final table and PHV summaries, `manifest.json`
with compiler binary hashes; no SDK binaries). The compiler was first checked against three builds
whose results are already recorded on 9.13.1 / 9.13.2:

| Build | Recorded (SDE 9.13.1 / 9.13.2) | Open-source 9.13.4 |
|---|---|---|
| Seven-stage timing (`-DU_BOR`) | 7 / 0 | 7 / 0, critical path 7 |
| Response path (`case4_response_path.p4`) | 1 / 12, critical path 11 | 1 / 12, critical path 11 |
| Two-pipe composite (default) | p0 12 / 11, p1 11 / 0; PHV 193; 26 hash units | identical |

Results for this track:

| Build | Ingress / egress | Critical path | Other |
|---|---|---|---|
| **Single-pipe candidate** | **10 / 12** | 11 | Exit 0, `tofino.bin` assembled. Fifth egress checksum unit (SYN scrub) accepted. PHV 158 / 224 containers (32-bit 57 / 64), final attempt. Warning kinds are the same as the two separate programs. |
| Composite with `make_n` edit 9 | p0 12 / 11, p1 11 / 0 | 11 / 9 | No stage saved. Tables 115 -> 109, hash-distribution units 26 -> 23, PHV 193 -> 185. |

The single-pipe ingress rises from 7 to 10 stages beside a full egress: a stage's table IDs, crossbar
and hash units are shared by both gresses. Two ingress stages remain spare.

## Findings that drove it

1. **The real rig negotiates TCP timestamps, SACK and window scaling.** On 198 of 198 handshakes the
   master (192.168.10.1) offers them and the SEL-751 (192.168.10.7) accepts all three. Two
   consequences:
   - The response-path mapper arms only on an MSS-only SYN-ACK, so against the relay it would never
     pad.
   - The timing setup itself states its guarantee only for no-timestamp flows (finding B1).

   The OpenDNP3 hardware runs worked only because timestamps were switched off inside the endpoint
   namespaces. Edit S2 rewrites the master's SYN options after MSS to NOP at the switch. The relay
   echoes only offered options, so it should answer MSS-only. That relay behavior is inferred from
   the captures, not tested.
2. **Three blockers I listed in the earlier review were already closed in the repository:**
   - N's `bypass_egress` (`make_n.py` edit 1);
   - the pipe-1 generator port (`3c6138aa`; 196 is pipe 1's local 68);
   - T's fixed relay port (`compose.py --relay-port`).
3. **The padder must run once per frame.** The timing ingress already sends every loopback hold with
   `bypass_egress = 1` and every final departure with `0`, and it uses no multicast. The tests pin
   all three properties. The egress parser parses only on ports 9 and 64, so mirror copies on dp68
   are not touched.

## Edit S2 in detail (SYN option scrub)

- **Parser:** select `(offset, flags)`. Offset 10 with SYN set and ACK clear extracts a 20-byte
  `sopt` header after the checksum residual deposit, so the parser subtracts those bytes too.
- **Table `syn_scrub_t`:** one const row, `(dir 2, SH_SYN, sopt valid, first option 0x0204)`. It
  keeps MSS and writes the remaining 16 bytes as NOP.
- **Deparser:** a fifth TCP checksum case, `m.scrub == 1`, single-term. It sums only fields valid on
  that SYN: seq, window, the options and the residual. It is exclusive with `m.changed` and both
  padding cases, because only dir 1, or dir 2 with `SH_ACK`, set those.
- **Arithmetic:** `SynScrubArithmetic` applies the parser-residual / deparser-update formula to a
  real master SYN from `campaign_v2/s01`. The result equals a full recomputation. That capture was
  taken on the master before transmit offload, so the test first restores the on-wire checksum.
- **Fit:** the 9.13.4 build accepted the fifth checksum unit and placed `syn_scrub_t`; 9.13.2 must
  confirm. If 9.13.2 refuses the unit, the fallback is to scrub in the timing ingress, which has spare
  stages and its own deparser.

## Not implemented, and why

| Item from the review | Status |
|---|---|
| Move stateless N checks to pipe 1's unused egress | Not done. It changes where N decides READ admission and needs compile iterations to show a stage is freed. The single-pipe target removes N entirely, which is the larger saving. |
| Merge `confirm_activation_t` / `claim_once_t` (m23) into one table | Not done. Role M is retired; there is no target to apply it to. |
| `quarantine_reg` reset comment in `read_queue_timing.p4` | Not done in the P4: any byte change would detach T from its compile and model evidence. The rule is now enforced by `controller/t_register_reset.py` and its tests. |
| Early `hold_ok` read in the seven-stage source | Not fixed. `tbl_select_deadlines` (`@stage(3)`) and `tbl_state_decode` (`@stage(4)`) read `meta.hold_ok` before `tbl_hold_ok` writes it. A fix reorders stateful tables. It needs a compiler, and a decision on which OPERATE deadline that early read was meant to select. The September 29 ledger notes the randomized source does not have this dependency, so that source is the model for a fix. |
| Spent OPERATE generation drops a retransmission | Not changed: a delivery-semantics decision. See the released-domain candidate in `audit_current/verification_20260929/p4_candidate/`. |
| Bind the loaded `tofino.bin` to a repository build | Needs the switch: hash the loaded binary and record it beside `response_path_9132_01`. |

## Next steps (in order; hardware steps need Philip's recorded authorization)

1. Compile `single_pipe/single_pipe.p4` with the switch's SDE 9.13.2 (compile-only, through
   `installed_sdk_build.py`) and locally with 9.13.1:
   `python3 build.py simplify/single_pipe/single_pipe.p4 simplify/evidence/single_pipe_01`.
   `U_BOR` is defined in the file. Compare with the 9.13.4 result (10 / 12, PHV 158).
2. Run the local Tofino model with the existing drivers: the padding drivers for E, the timing
   driver for ingress, then both together on one READ and one SELECT/OPERATE.
3. On the switch: compare a master SYN before and after the scrub, and confirm the SEL-751's
   SYN-ACK becomes MSS-only.
4. Measure the reservoir loop latency, then choose K with
   `stage_reduction/control/reservoir_sizing.py`, and dp10's speed if 10G is supported in that quad.
