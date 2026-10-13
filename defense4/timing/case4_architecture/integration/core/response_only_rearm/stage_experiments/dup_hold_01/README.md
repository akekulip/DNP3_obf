# dup_hold_01: hold an identical OPERATE copy in T while its original is held

## What and why

On rearm_56r plus read_reencode_01, an identical retransmitted OPERATE (N `packet_kind` 7,
`sequence_valid` 3, owner phase 0xc) sent while T still held the original matched first_event's
`forward_original` row. That row produces event 0x0108, which is N kind 8. read_terminal_t has no
kind-8 row, so terminal_ack or terminal_strip put the copy on the wire. It reached the outstation
about 0.1 s after it was sent, before the held original's release at about 0.90 s
(`read_reencode_01/evidence/dup_model_01`, `dup_model_02`). Forwarding a copy after the release is
correct, because it is how a loss downstream of the switch is recovered, and this build keeps that.

`generate.py` edits N and T of `read_reencode_01/evidence/full_01/response_only.p4` (sha256
3bab2181…f43b). The script checks the input hash, requires every anchor to match exactly once,
asserts that E is byte-identical to the input's E, and writes `.inputs.json` metadata. full_02 is
not used, because on the model it drops SYN-ACKs. N and T are identical in full_01 and full_02.

## Kinds chosen

The new values below were grepped against N, E and T, and none of them was already in use.

- **N kind 24** (`m.kind`), with events 0x0118, 0x0218 and 0x0318 for laps 1 to 3. Each lap
  carries the t0 header, as kind 7's laps do.
- **T kind 15** (`t_KIND_OPERATE_DUP`). It travels N `commit_before_t(8w15)` → E lap 0xe50f
  (E keys only on the high byte, so it needs no edit) → N `committed_t` 0xe60f → tev 0x0f00 on
  T_IN.
- **Outcomes index 16** (`t_OUT_OP_DUP_DROP`). Index 16 was in the unused range 16–22.

## Rows and tables changed

| table / site | change | size, then entry count |
|---|---|---|
| N parser `envelope_event` | +0x0118, 0x0218, 0x0318 → `read_t0` | n/a |
| N `committed_t` | +`0xe60f → committed_to_t(0x0f00)` | 2→3 / 3 |
| N `network` | +kind 24 with TCP flags 16 and 24 | 32 / 29 |
| N `first_event` | new action `first_operate_dup` (event 0x0118 plus t0, like `first_operate`). The row `(8w7,3w3,_,0xc…)` now uses it instead of `forward_original` | 163 / 156 (unchanged) |
| N `guard` | +`(_,8w7,8w24,…same CRC qualification as the 8w8 row…):go_ret_work` | 48 / 42 |
| N stage-1/2 owner check | `m.kind==8w24` added beside `8w8` (owner check kept) | n/a |
| N `read_terminal_t` | +`(8w24,0,0,_):commit_before_t(8w15)` | 10 / 10 |
| T parser `parse_tev` | +`(15,0)` → `opaque_ethernet` | n/a |
| T `t_T_IN` branch | `read_op_done()` under a gateway on kind 15 with `e_bad==0` and `enabled!=0`. It is placed first in the branch (see Stages) | n/a |
| T `tin_verdict` | +`(15,0,0,…)` passthrough (enabled 0), +`(15,_,0,done 0)` passthrough, +`(15,_,0,_)` `drop_operate_dup`. `e_bad≠0` falls to the default `drop_old_epoch` | 19→22 / 22 |
| T `outcome_count` | +`16 : bump(16)` | 25 / 19 |

T leaves the duplicate through `passthrough_operate_dup`, which is `passthrough_tev_relay` plus
`hdr.tev.kind = 12`. A plain `passthrough_tev_relay` would arrive at E with provenance kind 15, and
E's `lifecycle_access` rejects any kind it does not list. With the rewrite the frame leaves exactly
as an OPERATE passthrough does. The duplicate never bumps `op_gen` (it takes the default
`peek_operate_generation`), never arms `op_t0`, never calls `op_done_try`, is never cloned or held,
and touches no padding accounting.

Three tables already declared more space than they had entries before this change: `network`
(32 / 27), `guard` (48 / 41) and `first_event` (163 / 156). Their sizes were left alone. Every
table has its entry count at or below its size, and `scan_static_entries.py` passes on the compiled
build.

## Stages

| build | p0 ingress | p0 egress | p1 ingress |
|---|---|---|---|
| input full_01 | 12 | 12 | 11 |
| evidence/full_01 (this build) | 12 | 12 | 11 |
| evidence/on_full02_build_01 (first revision, on full_02) | 11 | 12 | **12** |

In the first revision, the `read_op_done` gateway came after `read_resp_done`'s gateway, which sits
in stage 8. bf-p4c places a gateway with the first table it guards, so `op_done_reg` was pulled to
stage 9 and `tin_verdict` to stage 10, which made T 12 stages. Moving the gateway to the start of
the `t_T_IN` branch puts `op_done_reg` back in stage 7 and `tin_verdict` in stage 9. The
on_full02_build_01 build was compiled only and never run on the model.

## Results (model; evidence/)

All three runs used `read_reencode_01/model_drive_oracle.py`, so the READ steps check the
re-encoded image. Pass counts are quoted from each result JSON's `summary`:

- **`dup_model_01/dup_results.json`:** 43/44. The one failure is `C_read_dup_no_early_READ_copy`,
  the READ case that is out of scope. A10 left one copy at 0.9041 s (duplicate sent at 0.1037 s),
  and A50 one copy at 0.9106 s (duplicate sent at 0.504 s). Both show outcomes[5] +1 and
  outcomes[16] +1. B left two copies, at 0.9075 s and 3.296 s (duplicate sent at 3.2109 s), with
  outcomes[16] +0.
- **`model_diag_01/rearm_results.json`:** 519/519.
- **`model_retx_01/rearm_results.json`:** 37/37.

`model_drive_dup.py` is a copy of read_reencode_01's probe with these added checks:

- **A10 and A50:** exactly one OPERATE copy at least 0.2 s after the duplicate was sent, with
  outcomes[5] +1 and outcomes[16] +1.
- **B:** two copies, the second one after the duplicate was sent, with outcomes[16] +0.
- **C:** the READ-request duplicate is out of scope and the case is unchanged. It still fails, as
  it did before this change.

### Follow-up runs: dup_model_02 and dup_model_03

The driver gained four cases:

- **D:** the duplicate is sent with T off (`enabled` 0).
- **E:** the duplicate carries an old epoch. A transaction completes, a qualified RST closes the
  connection and a new handshake opens one, so the epoch advances (62 to 73). Then two copies are
  sent:
  - **E1:** the old OPERATE's exact wire frame, sent from the master. N drops it, so it never
    reaches T.
  - **E2:** a T input event of kind 15 that carries the old epoch, which is what N would hand to T.
- **F:** two duplicates are sent after the release.
- **A10 and A50** now check the single copy without using the observed release. It must arrive at
  least 0.8 × op_j after the original was sent and after the duplicate was sent. The driver
  records the copy's time divided by op_j as the model-clock ratio, measured at 0.90–0.93.

Results:

- **`dup_model_03`:** 84/88 passed. A10, A50, B, D, E1, E2 and F all pass. E2 increments
  outcomes[14] by 1, nothing leaves the switch, and the registers do not change.
- **The four failures** are case C's setup (SYN, SYN-ACK, ACK and setup). After case E, C cannot
  open the same 4-tuple, even though E now ends with an RST that is forwarded. This comes from the
  order of the cases, not from this change. C's own READ-duplicate observation is the one in
  `dup_model_01`.
- **`dup_model_02`:** the same run without E's closing RST, giving 83/87 with the same C setup
  failures.

## Limitations

- **(a) Content is not checked.** After the release, a copy with the same sequence number but
  different CROB bytes is forwarded and padded as a replay. The outstation's own comparison of the
  SELECT and OPERATE octets is the only guard.
- **(b) Every post-release copy is forwarded, not only the first.** Case F shows three copies
  reaching the outstation.
- **(c) Switching the policy off during a hold opens a gap.** A duplicate sent after that is
  forwarded through the `enabled == 0` row and can reach the relay before the original's off-flush.
- **(d) Stale flush and exhaustion fail closed.** After a stale flush, or once `op_gen` reaches
  0xffff, op_done is never written for that generation. Every later duplicate is then dropped and
  counted at outcomes[16].
- **(e) The reply is not timed.** When the outstation answers a forwarded post-release duplicate,
  the reply leaves through `passthrough_tev_forward` with no timing applied.
- **(f) READ-request duplicates (kind 9) are unchanged.** The model shows READ requests are not
  held: the original is forwarded about 0.1 s after it is sent (`dup_model_01`, case C). The
  early-delivery premise therefore does not apply to them.
- **(g) One guard row is now unreachable.** The row `(_,8w7,8w8,...)` can no longer be reached,
  because kind 7 no longer produces kind 8. It is left in place.


## Case ordering fixed; hardware candidate rearm_57s (2026-10-13)

- **Case C fixture.** C's setup failures after E came from the fixture, not from this change. C reused
  the 4-tuple with client ISN 9000, behind E's last client frontier (16000), and the rearm rule
  correctly refuses a reconnect that does not advance the frontier. C now uses ISNs 23000/26000.
  `dup_model_04` gives 88/89. Its only failure is C's early-copy premise: the original READ request
  is forwarded at 0.093 s, so it is not held, as limitation (f) states.
- **Control-policy offsets.** `model_drive_dup.py` now derives the master's control-response frontier
  from `CASE4_STRICT_CONTROLS` (58 or 37 octets). Before this change, `dup_model_05_strict` failed from
  A10's OPERATE onward because those offsets were hardcoded for 58.
- **`--strict` input.** `generate.py --strict` takes `read_reencode_01/evidence/full_04` (strict
  policy) as input in place of `full_01`. N and T come out identical to `full_01`'s output; E differs
  in the single `ctl_profile` entry.
- **Build `rearm_57s` = `evidence/full_02_strict`.**
  - Local 9.13.1 and installed 9.13.2 (`compile_switch_9132`) both give N12/E12/T11. The mirror guard
    passes (`mirror_guard.txt`), and `epoch_t`'s action bus is a single 32-bit slot in both `.bfa` files.
  - Model (9.13.1, native-control oracle): diag 519/519 (`model_diag_02_strict`) and retx 37/37
    (`model_retx_02_strict`), both with the strict-frontier drivers.
  - Pinned in `hw/sealed_profile.py`; campaign configs `rearm_01/config/candidate57s_*.json`
    (`make_candidate57s.py`).
- **Duplicate suite with policy-derived offsets.** `dup_model_06_strict` (rearm_57s, native-control
  oracle) and `dup_model_07` (all-58 `full_01`) both give 88/89. A10, A50, B, D, E and F pass on both;
  the single failure is C's inapplicable early-copy premise.
