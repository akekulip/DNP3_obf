# read_complete_01 — status (newest first)

Plan: ~/.claude/plans/pasted-content-id-463c-execute-this-quiet-pascal.md (approved 2026-10-20).
Production implementation stays m12_fullsize/make_m12.py + its consumers; this directory holds evidence,
policy, reproduction and the completion record only.

## 2026-10-21T02:50:33Z M0 started
- Handoff: /home/philip/Projects/DNP3/Claude_READ_Complete_Handoff_20261020.zip
  sha256 7638cb2ad45369937e6c09619f64c369e6ae888632f924fbd3387edd4ca8dfba, extracted to handoff/.
  SHA256SUMS verified: top 98/98, read_coverage 38/38, target_selection 49/49.
- AUTONOMOUS_OVERNIGHT.md: NOT present in this verified archive, nor in any nested historical zip, nor
  elsewhere on gambit. Working from START_HERE.md + Philip's written corrections in the session.
- HEAD afbea5a52; uncommitted C1/C2/C3 in make_m12.py, model_fullread.py, run_model.py.
- Testbed ownership.json: unsafe_restoration=true (dev_m11_09_20261019_01); no dnp3-eval unit active.
- afbea5a52 review findings 1..6 -> current status: 1 fixed (C1, uncommitted); 2 fixed (C2 honest
  waiver + corruption 36/36, uncommitted); 3 partial (269 classify fixed; SBO-61 boundary + transitions
  open); 4 open (C4); 5 open (C5); 6 partial (C6 inputs.json).
- CORRECTION: Philip supplied the directive separately at /home/philip/Projects/DNP3/AUTONOMOUS_OVERNIGHT.md
  (sha256 bb12f57517dc0bf1cd667610a5e9f1db01d2bd9da7a300c0530afd5158959baf, 10,322 B). It was absent from the
  verified zip; it is the governing directive. Its precedence over START_HERE's stopping language is applied.
  Restore lock: Philip explicitly authorized a reviewed reconcile command in-session (lock + fresh unchanged
  restore_verify + immutable record + atomic ownership update); that is the "existing process" used.
- M1: handoff pytest 51/51 passed (Python 3.12.13, ~/.venvs/research) -> evidence/m1_pytest_01/pytest.log.
- M1 DONE (live software endpoints, pinned stack): full_read_gate built by full_read_01/endpoint/run_full_read.py
  build from git archive of OpenDNP3 4648fcb898456d1cb70b5baecc38cc256c859c2e (archive a4a9a8a8...),
  binary ea7347206072885e8ef4faa753748cd6a2afb1554fddfff800a68eb21f783405, libopendnp3.so c14c7628...,
  at ~/dnp3_endpoint_builds/read_complete_01_m1 (manifest + build.log copied to evidence/m1_software_pinned_01).
  reproduce_software.sh on that binary: pytest 51/51; live fallback full 247->269 16/16 + segmented 377->399
  16/16 (+ native comparison), target-163 range 16/16 + analog 16/16, IIN 0x9000, errors [] in all 8 runs.
  Tier: live software endpoints over loopback TCP, two independent connections via proxy; NOT switch/timing.
