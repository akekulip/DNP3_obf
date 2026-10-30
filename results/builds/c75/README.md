# c75: c72 plus the request retries only

**c75 is MODEL-QUALIFIED ONLY.** It has not run on the switch, Vision or the SEL-751. It is not canonical:
`p4/response_only.p4` is still c74 in this tree. Integration and hardware are plan Step 6.

- c75 source SHA-256: `5ca9168d366a1faf662ecaa53db224b6a814357f5bc37df88ec513cdb6edde49`
- c72 source SHA-256 (base): `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`
- c74 source SHA-256 (H1 + H2): `c7e37eff347f09c30af3a46f566cf41069df2d9c099e0227a102c16733116efd`

## The change

c75 is c74's H1 (the request retries) without c74's H2 (the four late-handshake-ACK `first_event` rows).
`derive_c75.py` is `derive_c74.py` without the H2 edit and without the `first_event` size change. It produces c75 from
`results/builds/c72/response_only.p4` byte for byte, and each edit asserts its exact match count:

    python3 results/builds/c75/derive_c75.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json

- Against c72, two lines change: 519 (`busy_t`, 22 to 28 rows) and 529 (`guard`, 54 to 57 rows). The rows are
  c74's exactly; `c72_to_c75_rows.json` lists them with their positions and equals c74's record for these two tables.
- Against c74, two lines differ: 404 and 405 (`first_event` size and entries), which are c72's. So c75 equals c74 with
  lines 404-405 taken from c72. The `busy_t` trailing comment keeps c74's text (`/* c74: READ/SELECT/OPERATE retry
  ... */`) so that line 519 is byte-identical to c74's.
- No action body, key, register, header, metadata field or control-flow line changes. Line numbers, and the bf-p4c
  table names derived from them, equal c72's.
- What H1 does, why SYN keeps `busy_drop`, and why the guard rows do not depend on the `first_event` rows:
  `results/builds/c74/README.md` ("H1"). A retried request is re-admitted by the same stage-0 rows as on first arrival;
  a late handshake ACK takes c72's path (default `NoAction`, event code 255, abort).

`tests/p4/test_c75_derivation.py` (7 tests, written first and seen failing with the c75 files absent) checks the
byte-exact derivation, the changed lines against c72 ([519, 529]) and against c74 ([404, 405], equal to c72's), the
absence of the four `forward_original` rows, the retry tables against c74's, that nothing outside const entries
changes, and the row record. Mutation runs on scratch copies (an H2 row added, the comment edited, a guard row removed,
a `first_event` size edit in the derivation, a row dropped from the record) each fail at least one test.

## Compile and pinned artifacts

Packaged and compiled once: `python3 scripts/profile.py results/builds/c75 --source <derived c75> --compile`, which
runs `scripts/build.py`'s compile with c72's command (`bf-p4c --target tofino --arch tna -g -o OUT SOURCE`, no
defines; p4c 9.13.2, SHA 1baf055; compiler SHA-256 `787631a6...`), then pins the artifacts. Exit 0, 93 s.

- Pinned artifact manifest: `supported_profile.json` (`candidate.artifact_sha256.compile_local`, the same block in
  `response_only.inputs.json`): `bfrt.json`, `manifest.json`, p0/p1 `context.json`, `response_only.bfa`,
  `tofino.bin`, `response_only.conf`, `response_only.p4pp`.
- `compile_local/manifest.json` and `compile_local/compiler_evidence.json` hash every compiler output and log;
  `compiler_evidence.tar.xz` retains the exact bytes. Every later model run uses these artifacts; nothing recompiles.

| artifact | SHA-256 |
|---|---|
| p0/tofino.bin | `3e11043af08a3e7de7e89956ec20d2b86d50199afdebc3d71a6d79c2adcb45b3` |
| p1/tofino.bin | `f52aaedd35c0c737de1b90f6914f3825dd19f87e4738e6fe09d9c8c1c7a12b99` |
| p0/context.json | `03221ae2b4790c567a9ad75743b417c910129886fc696b1e81dae499aa1d10db` |
| p1/context.json | `8a74333d702e107cb95fc568dbf4d460ae26ea74853c7ccb633488bdaa61f3da` |
| bfrt.json | `dcf9853796834df7c73b9071dae30f87bc0942868562d53e814107db99fad8b9` |

## Resources

`resource_comparison.json` (baseline c72): every delta is 0, and the stage target is met.

| | c72 | c75 |
|---|---|---|
| p0 ingress / egress stages | 10 / 10 | 10 / 10 |
| p1 ingress / egress stages | 8 / 4 | 8 / 4 |
| p0 SRAM / TCAM blocks | 158 / 96 | 158 / 96 |
| p0 VLIW instructions / Meter ALUs / gateways | 119 / 19 / 57 | 119 / 19 / 57 |
| p0 exact / ternary xbar bytes, hash bits, hash dist units | 436 / 363, 1,017, 22 | 436 / 363, 1,017, 22 |
| p0 PHV containers / bits used | 174 / 3,381 | 174 / 3,381 |
| p1 SRAM / TCAM / VLIW / hash bits | 36 / 36 / 44 / 142 | 36 / 36 / 44 / 142 |
| per-stage table IDs, SRAM, TCAM, gateways, VLIW, Meter ALUs | | identical |

- `phv_allocation_0.log` and both pipes' `table_summary.log` are byte-identical to c72's.
- p0 `response_only.bfa` differs from c72's only in the two table sizes, their const-entry listings and the run_id.
  p1 equals c74's apart from the run_id (and c74's p1 equals c72's apart from the run_id).
- `resource_review.json` (baseline c69) has the same deltas as c72's and c74's reviews.
