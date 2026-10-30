# c75_diag_mirror: the c75 diagnostic relay-leg mirror build

**Diagnostic build; its blocks never qualify.** It is c75 (the source selected for testing) plus the same two relay-leg
mirror sessions that c72_diag_mirror and c74_diag_mirror carried, and nothing else. It replaces c74_diag_mirror for the
c75 connection-start blocks. c74_diag_mirror is historical: its canonical base is no longer `p4/response_only.p4`, so
it is no longer admitted, but its retained evidence stays readable.

- Source SHA-256: `be52635641fde1cc436d96293bf0a220b4a962cedc9cb2d4519de39e2fead4c5`
- Canonical base: `results/builds/c75` (`5ca9168d366a1faf662ecaa53db224b6a814357f5bc37df88ec513cdb6edde49`)
- Made by `python3 scripts/build_diag_mirror.py results/builds/c75_diag_mirror --compile` (SDK 9.13.2, the canonical
  command), with the generator unchanged since c74_diag_mirror (SHA-256 `ca40dc83…`). `diag_mirror.json` records the
  identity; `diag_mirror.diff` is the full insertion diff: 13 insertion fragments, 31 inserted lines, 0 deleted or
  replaced. After the base name is normalised, it is identical to c74_diag_mirror's diff.
- Sessions: 101 (ingress copy of every frame arriving on dev64) and 102 (egress copy of every frame leaving on dev64
  and not dropped), both to copy port 10, untruncated. T's clone session 7 is untouched. No port-9 session.

## Static checks and resources

- `diag_mirror_checks.json` (`scripts/diag_mirror_checks.py`, baseline c75): passed. Both pipe-0 deparser mirror
  guards pass, the unchanged pipe-1 guard passes on both builds, and pipe 1 is equivalent to c75's after
  generated-name mapping except one hash seed line.
- `resource_comparison.json` (`scripts/analysis/resource_compare.py`, baseline c75): stages unchanged (p0 10/10,
  p1 8/4). Every delta against c75 equals c74_diag_mirror's delta against c74: +3 PHV containers, +23 bits, +4 logical
  tables, +2 gateways and +2 VLIW instructions, with the same per-stage moves.

## Model evidence (results/models/c75_diag_mirror/)

SDK tofino-model functional output; not hardware and not timing.

- `diag_mirror_fidelity_01.json`: passed. With sessions on, all 13 relay-leg frames of the smoke exchange set were
  copied byte-exact to dev10; off and absent produced no copies.
- `gate_vs_c75_01.json` (`scripts/model/diag_gate_compare.py`): the 17 gate drivers ran on this build with the sessions
  absent, through `run_model.py` (2026-10-30 18:20–19:00), and were compared against c75's own runs. Every attempt
  exited 0 at its first try, and every case name and verdict is identical. The observed differences:
  - 48 T `ack_commit_at_reg` timestamps (23 in control_timing, 23 in response_ready, 2 in rearm);
  - T outcome counts: in 17 control_timing cases one count moves from `HELD_REWAIT` (cell 1) to `OLD_EPOCH_DROP`
    (cell 14); in 17 response_ready cases `HELD_REWAIT` is one higher.
  c75's and c74's own runs differ from c72's by the same classes in the same cases (`results/models/c75/gate_vs_c72.json`,
  kinds `t_rewait` and `t_old_epoch`), and c74_diag_mirror differed from c74 by the same re-wait class. These are
  run-to-run variation, not a mirror effect.
- The runs used an overlay copy of `scripts/`, `tests/fixtures` and `p4/` (`scratchpad/c75/diag_overlay`) whose
  `action_observations.json` names this build's source; the recorded action bodies are unchanged.
  `gate_vs_c75_01.json` lists every overlay file that differs from the base commit.
- Not run for this build: the companion runs (`run_diag_mirror.py --companion`), as for c74_diag_mirror.

## Not established

- dev10's cabling to Vision `enp59s0f1np1` is carried over from c72_diag_mirror and still an inference.
- Mirror timing and copy loss under load are uncharacterized; mirror evidence is for packet presence, content and
  copy order only.
