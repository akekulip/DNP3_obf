# Pipe-0 headroom probes on m12p_c26 (2026-10-23)

Objective (Claude_C26_Headroom_Hardware_Directive.md): N and E both at highest occupied stage index <= 10 in one
integrated build (a usable last stage of pipe 0), T <= 11, pipe-1 egress <= 4. NOT REACHED. All builds bf-p4c 9.13.1,
hand-edits of c26's P4 (sources/*.p4.xz; generator for the h* series: hx/mk.py with hx/*.edits.json); per-build
status (exit code), metrics.txt and compile.log under builds/. Compiler output (out/) is not retained.

Columns: occupied stages / highest index (pipe 0 depth 12).

| build | edit (Philip's three experiments first) | rc | N | E | note |
|---|---|---|---|---|---|
| c26 | baseline | 0 | 12/11 | 12/11 | E dependency chain 10 stages |
| h1 | 1: CRC verdicts + tails into the pad branch | 2 | - | 13 | verdicts (badh/cbad0/cbadt) are INPUTS to the pad decision (acct_t, classify_fwd keys): cannot move |
| h1c | 1 (feasible form): only the control CRC-tail work under the control-pad gate | 0 | 12/11 | 12/11 | lifecycle_access and in_dl_t move to stage 1 |
| h2 | 2: CRC metadata isolated from lifecycle fields (pins on the instantiated egress parser) | 0 | 12/11 | 12/11 | crc_ctl_tail2_t->lifecycle_access edge gone; stage-1 crossbar shared with N still blocks |
| h3 | 3: unreachable READ declarations removed | 0 | 12/11 | 12/11 | compiler already dropped read_b0 + its tables; headers still held 12 containers (saves 12 PHV containers/232 bits, no stage) |
| h1c2 | 1c + 2 | 0 | 12/11 | **11/11** | best E: stage 2 of E empty, but the freed stage is internal, index 11 still occupied |
| h1c23 | 1c + 2 + 3 | 0 | 12/11 | 11/11 | as h1c2 with less PHV |
| h12, h13, h123, h1b* | combinations with literal experiment 1 / nested variant | 2 | - | 13 | do not fit |
| hx4 | h1c2 + plain move in prep_t (exploratory) | 0 | 12/11 | 12/11 | E front compresses; img_wend (SALU) waits for stage 9 |
| h1c2n / h1c2n2 | h1c2 + N pins removing N's PHV edges (owner_command->read_app, sequence_guard->reset_boundary) | 0 | 12/11 | 11/11 | pins took effect (phv.json), edges gone, no stage freed |

What holds pipe 0 at 12: N's own saturation -- stateful ALUs 4/4 in stages 7 and 8 (13 of N's 17 SALUs cannot start
before stage 7) and 15-16/16 logical tables in stage 10 -- not dependency depth (N needs 9 stages by dependencies).
E reaches index 10 only if its img_wend SALU table fits in stage 7 or 8, which N fills. Next step (not attempted): move
one of N's stateful operations out of stages 7-8 (register layout of the base timing machinery), then rebuild h1c2.

Finding: c26's egress PHV pins (the @pa_* block before r_IgParser) attach to a parser no Pipeline instantiates; bf-p4c
drops them silently, so they have never applied. Any checksum-safety argument relying on those pins is not in force.

## Round 2 (Philip: targeted register-layout change) — E reaches index 10, N does not

N's 17 SALUs (c26): retry_epoch 0; counter 4; work 5; epoch 6; client, server, application, pair_native_end_server_start
7; links, tcp_dst, object, off pairs 8; owner, read_app 9; count_busy, count_term 10; count_first 11. Everything from 7
keys on epoch_diff (epoch at 6, which keys on work_phase from guard at 4); guard's predecessors are held at 3 by
stage-2 resources shared with E (a @stage(2) pin was demoted), not by dependencies.

| build | edit | rc | N | E | T | p1 egress |
|---|---|---|---|---|---|---|
| nA / nA2 / nA3 | merge application into the redundant native_start lane of pair_native_end_server_start (three SALU output forms) | 3 | - | - | - | - |
| h1c2P1 | application_t @stage(9) | 0 | 12/11 | 11/11 | 11/10 | 4/3 |
| all_P1R9 / h1c2_P1R9 | + read_app_t @stage(9) on c26 / h1c2 | 0 | 12/11 | 12/11 / 11/11 | 11/10 | 4/3 |
| **hx4_P1R9** | h1c2 + X4 (identity hash -> copy in prep_t) + P1 + R9 | 0 | 12/11 | **11/10** | 11/10 | 4/3 |
| hx4_P1R9G2 | + @stage(2) on retry_valid_t, rd_request_two_crc_t | 0 | 12/11 | 11/10 | 11/10 | 4/3 |

Register merges fail on Tofino-1 pair-SALU output limits (a pair SALU returns a stored lane or a predicate, not a
difference or an OR; an exact OPERATE check plus the off check needs three comparisons, two condition units exist).
Every N register carries state across packets (no metadata replacement). N reaching index 10 needs first_event at 10,
which needs ~10 N SALUs + E's img_wend in stages 7-8 (8 slots) and ~24 logical tables in stage 10 (16): i.e. the
front of the chain compressed (guard at 3), a stage-2 resource question shared with E, not register layout.
Not adopted (pins are placement-only and fragile; target not met). Generator for this round: nx/mkn.py.
