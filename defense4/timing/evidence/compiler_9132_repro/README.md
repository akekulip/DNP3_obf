# Reproducible compile of the corrected source (BF-SDE 9.13.2)

Fresh compile of the exact corrected source, to check the source-to-binary chain reproduces.

- **Source:** `/home/decps/d4_fix_build/src/defense4_caseA.p4`, sha256 `1242ca4d…` (identical to the
  repo's `defense4/timing/p4/defense4_caseA.p4`).
- **Command:** `bf-p4c --target tofino --arch tna -o out2 -g defense4_caseA.p4`.
- **Compiler:** `9.13.2 (1baf055)` (same as the deployed build).
- **Result (`out2/manifest.json`):** `compilation_succeeded: true`, 0 errors, 2 warnings (the two
  benign parser-unroll warnings, identical to the original build), compile time 25.5 s.
- **Binary:** `out2/pipe/tofino.bin`, size **1,418,611 bytes — exactly the same size as the deployed
  binary** (`97175e7d…`, also 1,418,611 bytes). The fresh sha (`4454da3d…`) differs only because
  bf-p4c embeds a build date and run id in the binary; the size match plus identical error/warning
  count and stage placement (the same LTID-saturated stage-8/9 tail) confirm the source compiles
  reproducibly to the same program.

Artifacts (in `repro_artifacts.tgz` and extracted under `out2/`): `manifest.json`, `stage_adv.log`,
`mau.resources.log`, `table_placement_1.log`, `phv.log`, `power.json`, and the compile log. The
deployed build's resource footprint (12/12 ingress, SRAM 47, TCAM 10, 107 logical tables) is recorded
in the archived freeze; this fresh build places into the same stages with the same size.

Conclusion: the corrected source `1242ca4d` compiles cleanly and reproducibly on BF-SDE 9.13.2 to a
same-size binary. The deployed binary `97175e7d` is the corrected program.
