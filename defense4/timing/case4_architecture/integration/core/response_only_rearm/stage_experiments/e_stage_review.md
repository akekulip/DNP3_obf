# E-stage reduction review: incremental_55 p0 egress 12 -> 11

Scope: read-only review of the immutable 55 source and the existing local SDK/BFA evidence. No source transform, compile, SSH, or hardware action was run for this slice.

## Evidence anchors

Source inspected:

- `evidence/incremental_55/response_only.p4`

Compiled artifact inspected:

- `evidence/incremental_55/compile_local/out/p0/response_only.bfa`
- `evidence/incremental_55/compile_local/out/p0/response_only.prim.json`
- `evidence/incremental_55/compile_local/out/p0/context.json`

The existing p0 egress allocation is 12 stages. The relevant tail is:

| Stage | Egress work on the critical mapper/checksum tail |
| --- | --- |
| 6 | `img_end_t`, `img_start_t` |
| 7 | `fwd_prep_t` |
| 8 | `classify_fwd`, `reverse_gap_t` |
| 9 | `img_wend_t`, `read_pad_t`, `ctl_pad_t`, `reverse_window_base_t` |
| 10 | `classify_rev` |
| 11 | `window_t`, `egress_reset_invalidated_checksum_fields_{1,0}`, `count_t`, `egresshdr.ip.checksum_encode_update_condition_2_egress`, `egresshdr.tcp.checksum_encode_update_condition_3_egress` |

The source confirms the last explicit dependency is the reverse ACK/window path:

- `reverse_gap_t`: `m.s_end = m.q - m.p`
- `reverse_window_base_t`: `m.s_end = m.s_end + widen_win.get({hdr.tcp.window})`
- `classify_rev`: either translates ACK, withholds with zero window, withholds and sets `m.wide = 1`, or drops stale reverse packets
- `window_t`: if `m.wide == 1`, writes either the exact low 16 bits of `m.s_end` or clamps the TCP window to `0xffff`

The source also marks `count_t` as observability only, but not `settle_t`:

> `count_t` is observability only. `settle_t` is NOT: it drops untranslatable shapes on mapped connections and gives `m.result` its value on paths no classifier writes.

## Practical conclusion

A simple `count_t` deletion is not enough for E12 -> E11. Stage 11 is not only the outcome counter; it also contains `window_t` and compiler-inserted checksum helper tables. A successful E-stage cut must eliminate or move every stage-11 allocation, or the BFA will still contain `stage 11 egress:`.

The smallest plausible source-level work is therefore the reverse-window tail. Lifecycle-at-stage-3 movement is lower value for this specific goal because the pipeline is tail-limited by stage 11. Even if `lifecycle_access` moved earlier, E would remain 12 while `window_t`/checksum helpers/count remain in stage 11.

## Candidate 1: remove final-stage observability after the semantic tail is gone

Remove `count_t.apply()`, `outcome`, and the `count()` action from the experiment source only, or compile an experiment flag that omits them. This should be treated as a cleanup/pressure reduction, not as the primary E12 -> E11 transform.

Why it is safe semantically:

- The immutable source comments label `count_t` observability-only.
- `m.result` is produced earlier by `settle_t`, `classify_fwd`, `classify_rev`, and native/drop paths. The counter does not feed packet edits, lifecycle, ACK accounting, FIRST/native CRC verdicts, or window clamp.

Why it is probably insufficient alone:

- The existing BFA places `window_t` and hidden checksum reset/encode tables in the same final stage.
- Removing `count_t` may reduce counter/SRAM pressure, but it does not break the `classify_rev -> window_t -> checksum` ordering.

Proof obligations before accepting it:

1. Compile the experiment and bind actual BFA stage counts, not manifest guesses.
2. Prove `count_t`, `outcome`, and `count_t_0$stats` are absent from the transformed BFA.
3. Confirm packet-level composite parity for all non-observability behavior: lifecycle rejects, FIRST/open handling, native CRC verdicts, ACK accounting, padding, reverse ACK/window outcomes, and old-token/new-connection isolation.
4. If stage 11 remains, record the remaining table names. That is expected unless the reverse-window/checksum tail also moves.

Realistic resource risk: low. It removes one counter table and one metadata consumer. The risk is operational, not dataplane semantic: any scripts or lab dashboards reading `r_Egress.outcome` must tolerate its absence for the experiment.

## Candidate 2: fold `window_t` into the reverse classifier and delete `m.wide`/`window_t`

Target the true source-visible final dependency by replacing:

```p4
classify_rev(stage 10) -> m.wide/m.s_end -> window_t(stage 11)
```

with reverse classifier actions that write the final TCP window directly on `rev_withhold_*` outcomes.

Intended semantics to preserve:

- `rev_translate`: `hdr.tcp.ack = m.q + m.r`, `m.changed = 1`, no reverse window rewrite.
- `rev_withhold_zero`: `hdr.tcp.ack = m.p`, `hdr.tcp.window = 0`.
- `rev_withhold_open`: `hdr.tcp.ack = m.p`, `hdr.tcp.window = min(m.s_end + m.r, 0xffff)` under the same range envelope now enforced by `classify_rev` plus `window_t`.
- `rev_drop`: stale reverse packets still drop.

The direct version must preserve the existing clamp rule exactly: when the 32-bit final window value has high bits clear, write the low 16 bits; otherwise write `0xffff`.

Two implementation shapes are plausible:

1. Add precomputed metadata before `classify_rev`, for example `m.rev_win = m.s_end + m.r`, then split classifier actions into exact/clamp variants that write either `m.rev_win[15:0]` or `0xffff`.
2. If Tofino action constraints allow it, make `rev_withhold_open` write the exact/clamped window directly. The existing source comment says a 16-bit operand in a 32-bit add previously produced an invalid-container ALU error, so this is a high-risk compile fit unless the operands are already widened and container-aligned.

Why this is the best candidate for an actual stage cut:

- It removes the only explicit source table that is allocated in stage 11 before the hidden checksum helpers.
- It shortens the reverse path by one table after `classify_rev`.
- It can preserve lifecycle, FIRST/native CRC, ACK accounting, padding, and forward path behavior if constrained to the reverse window rewrite.

Why it may still fail to achieve E11:

- Stage 11 also contains hidden invalidated-checksum reset tables and IP/TCP checksum encode condition tables. Those may remain after deleting `window_t` if the compiler still schedules checksum helper work after the final packet-field write.
- `classify_rev` is already a 118-entry ternary/range table in stage 10. Splitting exact/clamp actions or adding precomputed window metadata may increase action complexity, action-data pressure, PHV liveness, or range-entry pressure enough to push `classify_rev` later or fail placement.
- The existing use of `widen_win`/`narrow_win` identity hashes is there to satisfy Tofino ALU/container constraints, so a direct arithmetic rewrite is not mechanically safe without a compile.

Proof obligations before accepting it:

1. Algebraic proof over the existing reverse-entry envelope that direct window writes equal the current `classify_rev + window_t` output for all covered `m.r`, `hdr.tcp.window`, `m.q`, and `m.p` cases.
2. Regression vectors for:
   - reverse translate leaves window unchanged;
   - reverse withhold zero writes ACK `m.p` and window `0`;
   - reverse withhold open exact writes low 16 bits when the 32-bit value is in range;
   - reverse withhold open clamp writes `0xffff` when the 32-bit value exceeds 16 bits;
   - stale reverse packets still drop;
   - native/FIRST/CRC/ACK accounting and padding paths remain byte-identical.
3. Compile with the actual local SDK and bind BFA evidence that `r_Egress.window_t` is absent and that no `stage 11 egress:` remains, or else record the remaining hidden checksum tables as the blocker.
4. PHV/liveness diff: `m.wide` should disappear; any new `m.rev_win` or equivalent must not extend another 32-bit value into the deparser/checksum tail.

Realistic SALU/PHV risk: medium to high. The transform does not add stateful ALUs, but it adds action arithmetic and/or metadata near an already dense range classifier. The main risk is not SALU count; it is action/container legality and the hidden checksum helpers staying in a final stage even after `window_t` is removed.

## Options I would not prioritize

- Moving `lifecycle_access` earlier. The source already calls it early, but BFA places it at stage 3 because of surrounding parser/profile/CRC/SALU/resource pressure. More importantly, the current E length is tail-limited; moving lifetime earlier does not remove `window_t` or checksum helper work from stage 11.
- Weakening the clamp by always advertising `0xffff` or always using low 16 bits. Either changes the reverse-window contract. It would violate the requirement to keep the window clamp intact.
- Dropping or simplifying checksum updates. The checksum helpers in stage 11 are real generated tables, and the deparser recomputes IP/TCP checksums for padding and changed TCP fields. Removing that would disturb packet correctness rather than reduce a dependency safely.

## Recommended next experiment boundary

If root wants one bounded E experiment, make it a two-part final-stage removal experiment in a new directory, with source edits limited to E:

1. Remove observability-only `count_t`.
2. Fold `window_t` into `classify_rev` while preserving exact/clamp semantics.

The stop condition should be strict: compile once, inspect actual BFA. If hidden checksum helpers still force `stage 11 egress`, report `compiled_no_stage_reduction` with the exact remaining table names rather than expanding scope into checksum/deparser redesign.
