# c74_diag_mirror: the c74 diagnostic relay-leg mirror build

**Diagnostic build; its blocks never qualify.** It is c74 (the canonical candidate) plus the same two relay-leg mirror
sessions that c72_diag_mirror carried, and nothing else. It has not run on hardware. It replaces c72_diag_mirror for
diagnostic blocks; c72_diag_mirror is historical and is no longer admitted, because its canonical base is no longer
`p4/response_only.p4`. Its retained evidence stays readable and still passes its own evidence check.

- Source SHA-256: `e46391d81e569a19a527604d3f2d3d454589f4261149ce697c79af952cbca7f4`
- Canonical base: `results/builds/c74` (`c7e37eff347f09c30af3a46f566cf41069df2d9c099e0227a102c16733116efd`)
- Made by `python3 scripts/build_diag_mirror.py results/builds/c74_diag_mirror --compile` (SDK 9.13.2, the canonical
  command). `diag_mirror.json` records the identity (`base_build`, canonical and generator SHA-256); `diag_mirror.diff`
  is the full insertion diff: 13 insertion fragments, 31 inserted lines, 0 deleted or replaced.
- Sessions: 101 (ingress copy of every frame arriving on dev64) and 102 (egress copy of every frame leaving on dev64
  and not dropped), both to copy port 10, untruncated. T's clone session 7 is untouched. No port-9 session.

## Static checks and resources

- `diag_mirror_checks.json` (`scripts/diag_mirror_checks.py`, baseline c74): passed. Both pipe-0 deparser mirror
  guards pass; the unchanged pipe-1 guard passes on both builds; pipe 1's `.bfa` equals c74's after generated-name
  mapping except one exact-match hash seed line.
- `resource_comparison.json` (baseline c74): stages unchanged (p0 10/10, p1 8/4). The deltas (+3 PHV containers, +23
  bits, +4 logical tables, +2 gateways, +2 VLIW, +2/+3 exact/ternary xbar bytes) are exactly c72_diag_mirror's deltas
  against c72.

## Model evidence (results/models/c74_diag_mirror/)

SDK tofino-model functional output; not hardware and not timing.

- `diag_mirror_fidelity_01.json`: passed. With sessions on, all 13 relay-leg frames of the smoke exchange set were
  copied byte-exact to dev10 (the same 13 as c72_diag_mirror); off and absent produced no copies; dev9/dev64 outputs,
  ingress passes, recirculations and reflections are identical across the three states; an LLDP frame entering dev10
  goes nowhere.
- `gate_vs_c74_01.json` (`scripts/model/diag_gate_compare.py`): the 17 gate drivers on this build with the sessions
  absent, through `run_model.py`, against c74's own runs. All latest attempts exit 0 and every case name and verdict
  is identical. The observed differences are 23 T `ack_commit_at_reg` timestamps in control_timing, 23 timestamps and
  17 T re-wait counts in response_ready, and 2 timestamps in rearm: the run-to-run classes c72_diag_mirror and c73
  showed.
- `fin_busy` failed on attempt 01 and passed 193/193 on attempt 02. In attempt 01 the model stalled for about 4 s
  between the SELECT response's N laps (06:52:36.25) and its T ingress on port 180 (06:52:40.18); the 60-octet image
  left on dev9 at 06:52:40.19, after the driver's 3 s window, and the next connections' SYNs then failed. A test suite
  was running on the same host at that time, the likely cause of the stall. c74's own fin_busy run passed 193/193.
- The runs used an overlay copy of the worktree's `scripts/` (and `tests/fixtures`, `p4/`) whose
  `action_observations.json` names this build's source; the 61 recorded action bodies are unchanged.
  `gate_vs_c74_01.json` lists every overlay file that differs from commit `e4a876dfa` (the integration edits and the
  observation binding).
- Not run for this build: the companion runs (`run_diag_mirror.py --companion`) that c72_diag_mirror also had.

## Freeze admission

`freeze_gate.py write` and `check` on a prepared `diag_e2_combined_c74` config: admitted as diagnostic
(`diagnostic_model_evidence`, both evidence files hashed), check OK with 0 changed and 0 missing, `qualifies` false.

## Not established

- dev10's cabling to Vision `enp59s0f1np1` is carried over from c72_diag_mirror and still an inference.
- Mirror timing and copy loss under load are uncharacterized; mirror evidence is for packet presence and content only.
