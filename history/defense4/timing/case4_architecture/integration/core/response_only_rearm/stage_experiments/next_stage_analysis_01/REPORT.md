# next_stage_analysis_01

Read-only offline analysis for next N/E stage-cut candidates. No source, generated, canonical, HW, SSH, or hardware state was modified.

## Evidence read

- Candidate56/local baseline: `evidence/incremental_55/compile_local/out`.
- Split-counter T10 local compile: `stage_experiments/t_split_outcomes_01/evidence/full_01/compile_local/out`.
- Failed E window-fold evidence: `stage_experiments/e_window_fold_classify/{README.md,evidence/full_01,result_summary.json,evidence/full_02,result_summary.json,evidence/full_02/algebra_review.json,evidence/full_03/result_summary.json}`.
- Extracted placements/edges: `evidence/placement_extract.json`.

## Baseline versus split-counter placement

Candidate56 `incremental_55` still has the T late sink:

- p1 table summary reports 12 ingress stages and critical path length 12.
- BFA places `t_Ingress.outcome_count` in stage 11 after `tin_verdict`/`held_verdict` stage 10 and `hb_verdict` stage 9.

The split-counter compile removes that T sink:

- p1 table summary reports 10 ingress stages and critical path length 10.
- BFA places `outcomes_token` with `token_verdict` at stage 4, `outcomes_hb` with `hb_verdict` at stage 8, and `outcomes_tin`/`outcomes_held` with `tin_verdict`/`held_verdict` at stage 9.

N/E remain the next pressure points in p0. In the split-counter compile:

- N late path: `reset_boundary`, `abort_t`, `carry_t`, and `read_terminal_t` are in BFA stage 8; `object_match`, `snapshot_t`, `close_phase_t`, `busy_t`, and `next_stage_t` are in stage 9; `first_event` and its `count_first` SALU are in stage 10.
- E late path: `reverse_window_base_t`, `img_wend_t`, `read_pad_t`, and `ctl_pad_t` are in egress stage 9; `classify_rev` is in stage 10; `window_t`, `count_t`, and the `outcome` counter are in stage 11.

## N: late-stage cause

The last N table is `n_Ingress.first_event`. It is not late just because it is large. The program graph shows true dependencies into it:

- `n_Ingress.snapshot_t -> n_Ingress.first_event` via output/action-read edges.
- `n_Ingress.close_phase_t -> n_Ingress.first_event` via action-read edges.
- `n_Ingress.object_match -> n_Ingress.first_event` for the match result used in the first-event decision.

Source shape confirms the dependency: in the stage-0 work-phase-4 branch, the apply order is `close_phase_t.apply(); snapshot_t.apply(); first_event.apply();`. `snapshot_t` writes the envelope/work/event/origin headers and `first_event` then changes the event-specific fields. That forces `first_event` after `snapshot_t`. `first_event` also owns `count_first` for refused/resent/replay observability, so the counter must remain with whatever final first-event decision table remains.

### N bounded experiment

Try a metadata-only snapshot precompute, then merge header materialization into `first_event`:

1. Replace `snapshot_t`'s header-writing action with a small earlier table that only computes a metadata value such as `m.snapshot_epoch` from the existing `m.lap`/`m.epoch` decision: normal epoch, lap-normalized epoch, or `0xffffffff` for zero epoch.
2. Move the common header writes currently done by `snapshot()` into the `first_*` event actions, using `m.snapshot_epoch` for `hdr.envelope.epoch`.
3. Keep `first_event` rows, refused/resent/replay counters, owner/epoch/sequence guards, object matching, and stale-generation protections unchanged.

This is semantically safe to test because it preserves the same snapshot epoch selection and event-row priority, but removes the header-output dependency `snapshot_t -> first_event`. If bf-p4c can place the small metadata precompute before stage 9, `first_event` has a credible chance to move out of the final N stage. The bounded compile proof should compare row priority and run the existing N/source invariants before any integration decision.

## E: late-stage cause

The E tail is the reverse-window chain:

- `r_Egress.img_wend_t -> r_Egress.classify_rev` and `r_Egress.reverse_window_base_t -> r_Egress.classify_rev`.
- `r_Egress.classify_rev -> r_Egress.window_t`.
- `r_Egress.window_t -> r_Egress.count_t` appears as an ordering edge in the split compile; `count_t` is observability only and `window_t` does not modify `m.result`.

The failed `e_window_fold_classify` evidence rules out the tempting shortcut:

- full_01 failed because precomputing the post-r endpoint in `reverse_window_base` required a multi-stage action.
- full_02 proved the simpler algebra `wire_ack - img_start + tcp_window` is wrong when `img_end != img_wend`.
- full_03 kept the algebra but failed PHV/action-source constraints when trying to fold final window behavior into `classify_rev`.

So the next E experiment should not fold endpoint algebra into `classify_rev`, should not drop `img_end - img_wend`, and should not enlarge `rev_translate`/`classify_rev` action sources.

### E bounded experiment

Try branch-local outcome counting before `window_t`, leaving reverse-window algebra untouched:

1. Keep `reverse_gap_t`, `reverse_window_base_t`, `img_wend_t`, `classify_rev`, `rev_withhold_open`, and `window_t` semantics unchanged.
2. Move reverse-path outcome counting to immediately after `classify_rev` and before `if (m.wide == 1) window_t.apply();`, because `m.result` is final after `classify_rev` and `window_t` only writes `hdr.tcp.window`.
3. Preserve all outcome counter values by either using a branch-local counter bank with a CP sum or by proving bf-p4c accepts the existing counter with a single legal call-site placement. If branch-local banks are used, keep all original outcome indices and document the CP sum exactly, as in the T split-counter experiment.
4. Keep non-reverse/lifetime/drop outcome counting in branch-local post-result locations so each packet is counted once.

This experiment targets the artificial `window_t -> count_t` tail dependency without changing the failed reverse-window arithmetic. It may not by itself remove the checksum stage after `window_t`, but it is the lowest-risk E cut candidate because it preserves `classify_rev`/`window_t` packet behavior and all counters. If the compile still leaves E at the same stage count, the remaining critical edge is the real `classify_rev -> window_t -> TCP checksum` chain, and further reduction would require a new reverse-window representation rather than another fold of the already-failed kind.

## Stop condition

This task was analysis-only. No compile or source experiment was run. The next concrete work items are one bounded N compile experiment for snapshot-metadata precompute and one bounded E compile experiment for branch-local outcome counting before `window_t`.
