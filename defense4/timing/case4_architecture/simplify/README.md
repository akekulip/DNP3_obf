# Simplification track (2026-10-11)

Work toward a smaller, working size+timing target. **The single-pipe program has run on the Tofino model
(functional), not on the switch.** It was compiled with the open-source Tofino compiler (bf-p4c 9.13.4,
p4lang/p4c `ff507048`) and run on the open-source tofino-model and bf_switchd (open-p4studio), all built in
the cloud session; see "Compile results" and "Model results". That is not the switch's SDE 9.13.2, so the
9.13.2 build under "Next steps" is still required before loading.

## Lessons from main (merged 2026-10-11)

While this track worked offline, the two-pipe composite ran on silicon (`integration/evidence/milestone_sbo_01`,
`combined_silicon_01/02`). Three statements made during this track's review were wrong and are corrected here:

- **"Pipe 0 is full; any addition to N or E will fail to compile."** Wrong. Main's `make_n.py` edit 9 added the
  real timestamped TCP profile to N's parser (+6 PHV containers) and still fits at p0 12 / 11 on 9.13.1 and 9.13.2.
- **"Timing and padding have never run together on the switch."** No longer true. On 2026-10-11 the composite
  did READ + SELECT/OPERATE on the physical Tofino-1 with timing on: OUT_ACK_COMMIT 10, OUT_RESP_RELEASE 10,
  OUT_OP_RELEASE 1, zero fallback, every eligible response 58 B with valid CRCs (software OpenDNP3 endpoints,
  clean TCP profile, 5 ms response fixture).
- **The real TCP profile.** Main admits the timestamped profile in N by parsing it (exact IP length, data offset,
  flags and `01 01 08 0a` option prefix; option bytes enter the checksum residual) instead of rewriting the SYN.
  E's mapper still arms only on an MSS-only SYN-ACK, so padding a real relay connection still needs E to accept
  that profile or the SYN scrub (S2); the silicon milestone used the clean profile.

What silicon taught that the model could not (main's commits, worth carrying into this track):
- A frame that crosses a front-panel MAC loopback needs a valid ethertype at bytes 12-13; the MAC drops it
  otherwise. Main fixed the OPERATE blocker (`421d78ac`) and seeded the generator buffer with 0x0800
  (`f4272787`). The single-pipe candidate's loopback ports carry blockers too: audit them the same way before
  hardware. The model run here emulated the loopback in software and could not see this.
- The real outstation answers SELECT/OPERATE with IIN1 0x90 (NEED_TIME + DEVICE_RESTART); exact-match keys on
  IIN refused it (defect A, `8efae400`).
- The readiness deadline must exceed the outstation's response time, or every READ falls back (defect D).
- Main's remaining issue: OUT_HELD_REWAIT 71,310 for 10 READs + 1 SBO, the residency overhead.
  `stage_reduction/control/reservoir_sizing.py` is meant for that sizing once the loop latency is measured.

## What is here

| Path | What it is | Verified by |
|---|---|---|
| `tools/syn_option_audit.py` | Reads captures (read-only) and reports the TCP options on every SYN and SYN-ACK, per host, and whether the response-path mapper would arm | Run over 200 retained captures; result in `evidence/syn_options_relay_rig.json` |
| `single_pipe/make_single_pipe.py` | Composes ONE pipeline: the seven-stage timing ingress (`stage_reduction/src/defense4_timing.p4`, `U_BOR`) + role E egress (`make_e.py`, from the hardware-run `protocol/case4_response_path.p4`), with edits S1 (reverse pass on the relay port), S2 (SYN option scrub), S3 (reverse window fold), S4 (grouped CRC tables) and S5 (`hold_ok` defined) | `single_pipe/tests` (27 tests); compiled and run on the model |
| `single_pipe/single_pipe.p4` | Generated output; a test pins it to the generator | same |
| `single_pipe/cp_single_pipe.py` | Egress control-plane rows: forward rows at the master port (9), reverse rows at the relay port (64) | same |
| `single_pipe/model_drive_single_pipe.py`, `model_drive_single_pipe_timing.py` | Tofino-model drivers, phase P (padding through the timing ingress) and phase T (timing D4 configured + padding) | `evidence/model_single_pipe_01/` |
| `single_pipe/HARDWARE_RUNBOOK.md` | Attended runbook for the relay rig (draft, not executed) | n/a |
| `tools/tsval_exposure.py` | What the outstation's TCP timestamps reveal about response delay (finding B1) | `evidence/tsval_exposure_campaign_v2.json` |

Changes made elsewhere for this track:

| Path | Change | Default behavior |
|---|---|---|
| `integration/core/response_only/make_n.py`, `compose.py` | **Retired at the merge with main (2026-10-11).** An opt-in edit dropping N's response tail CRC checks: measured, it saved no stage (6 tables, 3 hash units, 8 PHV containers). Main's own edit 9 (timestamped TCP profile) took that number; main's generator and composer are kept unchanged | n/a |
| `integration/controller/t_register_reset.py` | Reset plan for T's registers, derived from the P4 declarations; restores the five `0xffffffff` registers instead of clearing them | New module, new tests |
| `stage_reduction/control/reservoir_sizing.py` | Blocker-reservoir sizing from port speed and measured loop latency | New module, new tests |
| `stage_reduction/control/defense4_timing_setup.py` | `--bor-loopback-speed {25G,10G}` for dp10 | Unchanged: default 25G; `dry-run` output identical |
| Seven Case 4 documents | Dated two-pipe correction banner; the history below each banner is untouched | n/a |
| `audit_current/verification_20260929/README.md` | Finding B1 (TCP timestamps on the relay rig) | n/a |
| `stage_reduction/tests/test_build_evidence.py` | The retained evidence is the 16050715 build; the test now checks that the working source has the same code (comments and whitespace removed) instead of the same bytes | Was failing since the comment-only cleanup; passes, and fails on a one-line code change |

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
| Single-pipe candidate, S1+S2 (`opensource_9134_01`) | 10 / 12 | 11 | Exit 0, `tofino.bin` assembled. Fifth egress checksum unit (SYN scrub) accepted. PHV 158 / 224 containers (32-bit 57 / 64), final attempt. Warning kinds are the same as the two separate programs. |
| **Single-pipe candidate, S1-S4 (`opensource_9134_02`)** | **10 / 11** | 10 | Egress stage cut (see "Stage cuts"). Tables 117 -> 113; PHV unchanged at 158 (32-bit 57 / 64). |
| Composite with the retired N CRC option | p0 12 / 11, p1 11 / 0 | 11 / 9 | No stage saved. Tables 115 -> 109, hash-distribution units 26 -> 23, PHV 193 -> 185. Option retired. |

The single-pipe ingress rises from 7 to 10 stages beside the egress: a stage's 16 logical table IDs, 4
stateful ALUs, crossbar and hash units are shared by both gresses, and the compiler gives the early slots
to the egress tables, whose dependency chain is longer. Two ingress stages remain spare.

## Model results (open-source tofino-model, functional only)

Evidence: `evidence/model_single_pipe_01/` (cases, setup readback, build logs, `manifest.json` with program,
model and switchd hashes). Program: the committed `single_pipe.p4` (S1-S5), 10 / 11 stages.

| Phase | What ran | Result |
|---|---|---|
| P | Padding through the timing ingress (timing unconfigured): the rig master's SYN options, MSS-only SYN-ACK, handshake ACK, READ request, outstation ACK, READ response, master ACK of the image | **16 / 16.** SYN leaves 64 as MSS + 16 NOPs with a valid checksum; ARM_MAP +1; READ response leaves 9 as the 58-byte image (commit); master ACKs reverse-translated (959 -> 950); every frame byte-exact against the independent oracles (vectors / pad58b / ResponseMapper) |
| T | Timing configured with the repository's own `defense4_timing_setup.hw_configure_all` (mode D4: ports, dp8/dp10 queue ladders, pktgen apps, mirror, session, params, codebook), then the same handshake and one READ | **11 / 11.** The outstation's ACK is not forwarded at once (held), then released; the response is released after it and leaves 9 padded to 58 bytes with the mapper's translation; nothing leaks toward the relay; 387 frames circulated through the dp8 loop |

How the model was made to run the hardware path, each recorded in the manifest:
- dp8 / dp10 MAC-near loopback is emulated by the driver (`LoopbackCable`: every frame the model emits on
  those ports is written back into them); tofino-model does not loop a port by itself.
- The setup's BF Runtime handle is wrapped to translate names only (`Ingress.` -> `d_Ingress.`, the merged
  program's prefix); values and checks are the setup's own.
- `tbl_params read_len` reads back 0 under 9.13.4: it is a dead parameter (the source keeps it only for the
  frozen readback). The driver enables the packet generator, the setup's own last step, only when that is
  the sole failing check.
- The model's default 10G `$PORT` entries are removed first: the setup expects a cold switch and asserts
  dp8 at 25G.

The model clock is not wall time; hold durations are not timing evidence.

## Stage cuts (edits S3, S4)

- **S3, reverse window fold: egress 12 -> 11.** The reverse-ACK path ended `img_wend_t` (stage 8, after the
  forward classifier) -> `rev_prep_t` -> `classify_rev` -> `window_t` -> `count_t`. Of the window edge
  `(r + window) + (q - p)`, only `r` comes from the `img_wend` register, so `q - p + window` is computed
  earlier (`rev_qp_t`, plus one add inside `img_wend_t`'s reverse action) and `classify_rev` picks the exact
  or clamped window in its own actions: `window_t` is gone. `classify_rev` counts its own outcome code in the
  same `outcome` counter (same indices), and `count_t` moves into the else branch so the two counter users
  share a stage. `m.changed` is set in `rev_qp_t`: every reverse outcome rewrites the segment except
  `rev_drop`, which drops it. `tests/test_stage_cuts.py` runs the original and S3 reverse logic on 200,000
  biased random inputs and an edge grid, outcome, ACK and window identical; a deliberately broken variant
  fails it on 14,441 of 20,000 inputs.
- **S4, grouped CRC tables: 8 tables -> 4, no stage change.** The same hash actions, two per table (bf-p4c
  allows 32 hash-output bits per table), under the same header validity.
- **Tried and not kept:** reusing `m.y` / `m.t` for the new reverse values (egress back to 12: write-after-
  write ordering with the forward path); `@stage` hints on `mode_t` or on the timing decision chain (no
  change: the final placement round re-allocates PHV and ignores them). The ingress stays at 10.

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
| Early `hold_ok` read | **Defined (edit S5), behaviour kept.** `tbl_select_deadlines`, `tbl_state_decode` and `tbl_resp_deadline` read `meta.hold_ok` at level 3, before `tbl_hold_ok` writes it in the same pass, and the parser never initialized it. On hardware the OPERATE lane used the read lane's offsets (2026-09-18 tail sweep, `CLAIMS_AND_LIMITATIONS.md`), which is what `hold_ok == 0` selects; S5 zeroes it in the parser so that is now defined. Stages unchanged (10 / 11). Selecting the OPERATE A/R deadlines instead would change claimed behaviour: Philip's decision. The September 29 ledger says the randomized source's admission and deadline arming use the current `tbl_hold_ok` readback, which is true; its deadline *selection* has the same early read (`latency_search/randomized/defense4_timing_randomized.p4`: `tbl_select_deadlines` at line 3251 before `tbl_hold_ok` at 3301, no parser initialization). |
| Spent OPERATE generation drops a retransmission | Not changed: a delivery-semantics decision. The option on file is the released-domain candidate in `audit_current/verification_20260929/p4_candidate/` (fixes the immediate retry; a late retry after the next PREPARE can still be held again). |
| Bind the loaded `tofino.bin` to a repository build | Needs the switch; step 0 of `single_pipe/HARDWARE_RUNBOOK.md`. |
| TCP timestamps (finding B1) | Measured, not decided: see "Finding B1 measured". |

## Finding B1 measured

`tools/tsval_exposure.py` over all 159 campaign_v2 captures (read-only): the SEL-751's TSval clock runs at
1,000 ticks/s but advances in steps of 30 ticks (30 ms). Pairing each outstation ACK with the response to the
same request:

| Arm | Exchanges | Observed ACK -> response gap, median | TSval(response) - TSval(ACK) = 0 |
|---|---:|---:|---:|
| Timing OFF | 32,040 | 2.13 ms | 88.5 % |
| Obfuscated | 31,680 | 8.00 ms | 88.7 % |

The added delay does not appear in the TSval: it tracks the relay's own send times, at 30 ms resolution. For
gaps of a few ms that carries little per exchange, but it is a channel the claims do not cover. Whether it
matters for the campaign's claims is for Philip and Dr. Lin. The SYN scrub removes timestamps from future
connections on the rig. Evidence: `evidence/tsval_exposure_campaign_v2.json`.

## Next steps (in order; hardware steps need Philip's recorded authorization)

1. Compile `single_pipe/single_pipe.p4` with the switch's SDE 9.13.2 (compile-only, through
   `installed_sdk_build.py`) and locally with 9.13.1:
   `python3 build.py simplify/single_pipe/single_pipe.p4 simplify/evidence/single_pipe_01`.
   `U_BOR` is defined in the file. Compare with the 9.13.4 result (10 / 11, PHV 158).
2. Done on the open-source model for READ (phases P and T). Still to run on the model: SELECT/OPERATE
   (BOR hold on dp10) and the negative cases (corrupt CRC, unconfigured tuple, retransmission).
3. On the switch, per `single_pipe/HARDWARE_RUNBOOK.md`: compare a master SYN before and after the scrub, and confirm the SEL-751's
   SYN-ACK becomes MSS-only.
4. Measure the reservoir loop latency, then choose K with
   `stage_reduction/control/reservoir_sizing.py`, and dp10's speed if 10G is supported in that quad.
