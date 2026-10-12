# Inflated READ triggers and OUT_TOKEN_STALE under shaping: cause, model reproduction, proposed fix (2026-10-12)

Analysis plus model and compile evidence. **No production P4 is changed by this record.** The fix was prototyped on
scratch copies (`prototype/type1_fix.diff`), compiled on both SDKs, and model-run.

## Cause (in the compiled program, every production build, both SDKs)

The Tofino-1 ingress deparser selects a mirror entry by `ig_intr_md_for_dprsr.mirror_type` on **every** packet.
T's deparser (read_queue_timing.p4:932-938) clones only `if (mirror_type == MIRROR_TYPE_CLONE)`. Only
`admit_request` (:472) and `hold_operate` (:528) set `mirror_type`. For the `mirror_type == 0` entry, bf-p4c emits a
session id taken from a compiler temporary, `$tmp4`. No action writes `$tmp4`; it is meant to stay 0, which is no
session.

In every production build that temporary shares container H2 with **`md.cur_gen`**, the live READ generation.
`gen_access` runs on every pass and its default `peek_gen` (:272) writes `cur_gen` (`bfa_mirror_excerpts.txt`,
`check_mirror_select.txt`):

```
mirror:
  select: B0(0..2)        # mirror_type
  0:  - H2(0..9)          # $tmp4   (H2 also holds md.cur_gen, live stages 3-9)
  1:  - H1(0..9)          # md.clone_ses, then md.clone_tag
```

So every T pass that does not clone is mirrored to session `cur_gen[9:0]`. On the switch only session 7 is
configured, with `$ucast_egress_port` = PKTGEN_RETURN (196). So **while the live READ generation is 7 (mod 1024)**,
from the admission of READ 7 until the admission of READ 8, every T pass is copied to 196:

- **The READ-7 clone copies itself.** Its pass at 196 (`drop_clone`) is mirrored again. The copy still starts
  `0xE1000007`, so it matches the READ generator pattern (`0xE1000000/0xFFFF0000`) on every trip and fires a
  trigger.
- **Copies of generated tokens are accepted as tokens.** A copy keeps the generator header (pipe 1, app 0), so T's
  token path accepts it and seeds another blocker. These packets are not in `pkt_counter`.
- **Copies of held frames, blockers and T_IN events** also arrive at 196 and are dropped there (`drop_foreign`),
  after having been copied again.

When READ 8 is admitted the session becomes 8, which is not configured, and the copying stops. All generation-7
tokens and blockers still queued then end as `OUT_TOKEN_STALE`.

**Ruled out:** repeated `admit_request` passes. The model ran exactly **10** `admit_request`s for 10 READs, and
your registers show `gen_alloc_reg` 11 and commits 10. **Also not the cause:** the overlays of `mirror_type`,
`clone_ses` and `clone_tag` themselves. Pinning those three removed their overlays, but the storm remained
(`falsified_pin_mirror_fields`). Pinning `md.cur_gen` only moved `$tmp4` next to `md.new_gen`
(`falsified_pin_cur_gen`).

## Reconciliation with the silicon data (trigger_probe_01, p2_production_01)

| observation | explanation |
|---|---|
| 1 READ -> 1 trigger, 5 READs -> 5, stale 0 | generations 1-5 present sessions 1-5, which are not configured |
| onset between 5 and 10 READs | the storm starts exactly at READ 7 (generation 7 = session 7) |
| idle 10 s: 0 | no T passes, nothing mirrored |
| triggers are not admissions (`gen_alloc_reg` 11, commits 10) | the triggers are recirculating mirror copies of the READ-7 clone |
| stale (27k) > generated packets (14k) | mirrored token copies are accepted as tokens and seed blockers outside `pkt_counter` |
| stale saturates ~22-27k regardless of 10 or 50 READs or rate | one storm per run (one generation 7); when READ 8 arrives everything queued for generation 7 drains as stale, bounded by the two blocker queues (both-shaped watermarks 13.4k + 13.4k cells; q3723 stale 27,007, q14892 26,805) |
| small excess in unshaped, hold-only and blocker-only runs (10 READs -> 23-34; 50 READs -> 64) | the same storm, but a short one: READ 7 completes quickly, so generation 7 is live only briefly |
| runaway only when hold AND blocker queues are shaped | *inference, not measured:* with both ladders shaped, READ 7's held frames lap slowly behind blocker queues the storm has filled, so generation 7 stays live much longer. A READ-by-READ trigger snapshot measures this window directly (probe 2) |

Off-silicon this is limited to session 7 because only session 7 is configured; any configured session `s` gets
the same storm while `cur_gen ≡ s (mod 1024)`. The next storm with session 7 would be READ 1031.

## Model reproduction (only session 7 configured, as on the switch)

`count_pktgen_return.py` on the model log. 10 READs, real timestamped profile, T on, default ports:

| | production build (close_reset_fix_01) | prototype fix |
|---|---|---|
| READ clones on 196 | gens 1-6, 8-10: 1 each; **gen 7: 269** | every generation **once** |
| other frames copied to 196 | **848** (T_IN events 426, held READ laps 214 + 208) | **0** |
| admit_request / drop_clone | 10 / **278** | 10 / **10** |
| `model_reads10_default` checks | 83/84 (one outdated close assertion, fixed in the driver) | 84/84 |

Mirror-sink probe (`MIRROR_SINK=2`: sessions 1-6 to a sink port, composite, hardware map): the production build
sent **129** clones from passes that never asked for one (held laps, T_IN events, and the READ clones
`e1000001..3`), and E's outcome counters moved, because the copies crossed pipe-0 egress. The prototype sent
**0** and passes 62/62. Composite default 70/70 on the prototype.

## Proposed fix (smallest; not applied)

`read/read_queue_timing.p4` (`prototype/type1_fix.diff`):

- At the top of `apply`, write `ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE; md.clone_ses = 0;`. Mirror entry 0,
  the one with the unwritten temporary, can then never be selected. Every non-cloning pass selects entry 1 with
  session 0, which is not a valid session (the SDE refuses to configure it), so nothing is copied.
  `admit_request` and `hold_operate` still set session 7.
- Add `@pa_no_overlay` on `ig_intr_md_for_dprsr.mirror_type` and `md.clone_ses`. bf-p4c drops the `= 0` as
  redundant, so the zero must come from a container of its own. Pipe 1 honors these pins (it uses about 52 of 224
  containers), unlike pipe 0's E.

Prototype builds (hardware map) exit 0 on 9.13.1 and 9.13.2:
- Stages: p0 12/11 (critical path 11), p1 11/0 (critical path 9), unchanged.
- PHV: p1 ingress 52 containers / 1,542 bits (was 50 / 1,542); p0 unchanged (127/2,832, 118/2,535).
- 9.13.2 prototype hashes, NOT for loading until approved: bfrt.json `4e24bc8a…`, p0 `2290c420…`, p1 `e0ad62df…`.

**Red -> green.**
- `core/response_only/check_mirror_select.py <build>` is a static check of the compiled deparser mirror table. It
  fails when a non-clone mirror entry can be selected with a session id that another field writes. It is FAIL on
  the production builds (both SDKs) and on both falsified prototypes, and PASS on the type-1 prototype (local and
  9.13.2).
- Model checks:
  - `no_clone_from_a_pass_that_never_requested_one` (`MIRROR_SINK`): 129 -> 0.
  - `count_pktgen_return.py` on 10 READs: generation 7 seen 269 times -> 1 time.

## Decisive switch-side probes (your choice; no recompile for 1-3)

1. **READ-count edge**, both ladders shaped: 6 READs should give exactly 6 READ triggers / 0 stale; 7 READs a
   storm. Since READ 8 never comes, the storm lasts until teardown.
2. **READ-by-READ snapshots** of READ `trigger_counter` and `OUT_TOKEN_STALE` after each READ: flat up to READ 6,
   a jump only between READ 7's admission and READ 8's. The jump is the window length.
3. **Move the storm with the control plane.** Add `$mirror.cfg` session 3 with `$ucast_egress_port` = a free
   front-panel port in MAC loopback (e.g. 16; N's `ports` default denies what loops back). Predicted: frames
   transmitted on that port only while generation 3 is live (between READ 3 and READ 4), roughly the number of T
   passes in that window; zero on the fixed build. This measures the unwanted mirroring without touching 196.
4. **On the fixed build:** 10 and 50 READs with both ladders shaped should give READ triggers = READs and stale 0
   (or only genuine stale).

## Not verifiable off-silicon

- That a mirror request with session 0 is a no-op on the switch. This is supported by the switch already: sessions
  0-6 were presented on every pass before READ 7 with no effect. Still, read any TM mirror drop counter during
  probe 4.
- The exact duration of the storm window under each shaping configuration (probe 2 measures it).
- N and E have no `Mirror` extern, so their deparsers have no mirror table. This is from source, not measured.
