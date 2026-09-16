# Why the build hashes cannot settle attribution, and what can

Run on the switch (`ufispace`, 10.10.54.81) on 2026-09-16 with its own SDE 9.13.2,
`p4c 9.13.2 (SHA: 1baf055)`. **Compile only.** No program was loaded, no traffic was sent, the
relay was never contacted, and no configuration was changed. The switch was running an unrelated
program throughout (`mcp_fabric_ledger_abs.conf`) and still is; nothing about it was touched. The
scratch directory was removed afterwards and its absence checked.

This supersedes the recommendation in `ATTRIBUTION_AND_DECODE_20260916.md` §1 and in
`CORRECTION_REPORT_20260916.md` that a recompile of the v2 source could be compared against the
recorded binary hash. It cannot, and the reason generalises.

---

## 1. `bf-p4c` does not produce a reproducible binary

Compiling the **same source twice**, with the same flags, on the same machine:

```
bf-p4c --target tofino --arch tna -g -DU_BOR -o out_base  defense4_rrc_bor_unified12.p4
bf-p4c --target tofino --arch tna -g -DU_BOR -o out_base2 defense4_rrc_bor_unified12.p4
```

| compile | sha256 of `pipe/tofino.bin` |
|---|---|
| first | `f9dade81656d304767855177585e8677f962a12362918fd418460bfd6fb6b2db` |
| second | `1690e914792cee2a2a1ab01f9f5b33b0ee53bbf6678337d17a8d0beeb8cfc991` |

Both are 1,477,327 bytes and differ in **13 bytes**, at offsets 130 to 144. Those bytes are the
value of an embedded `run_id` field:

```
... run_id \x00\x11\x00\x00\x00 29e5b75dae754104 \x00 program_name ...
... run_id \x00\x11\x00\x00\x00 2bc1aa1f757f447f \x00 program_name ...
```

The compiler stamps a fresh random 16-hex-character identifier into every binary it produces.

**Consequently a raw `tofino.bin` hash identifies a compile event, not a program.** It cannot be
re-derived by anyone, including by the person who produced it, from the same source on the same
machine minutes later. The recorded `1d5470a678c6df4e…` for the candidate and
`33fa3a77c732f4cf…` for the frozen build are therefore not evidence about which source was
compiled, and no recompilation can make them so. Compiling the frozen source here gave
`f9dade81…`, which agrees with `33fa3a77…` no better than any other pair of compiles would.

That also explains a note in `REPRODUCTION_REPORT_20260826.md` that the loaded-binary hash "cannot
be re-derived". The reason is not that no binary was kept. It is that the value is not a function
of the input.

## 2. Zeroing that field restores exact reproducibility

Replacing the 16-byte `run_id` value with zeros before hashing:

| source | sha256 of `tofino.bin` with `run_id` zeroed |
|---|---|
| frozen base `7ce30494…`, compile 1 | `f52b4a71bd3ee4fc93268bc50a1facef689c70e7e60413df4f65045eb5416084` |
| frozen base `7ce30494…`, compile 2 | `f52b4a71bd3ee4fc93268bc50a1facef689c70e7e60413df4f65045eb5416084` |
| v2 candidate `7d175222…`, compile 1 | `b57801960b82627392381038c21bf610777449977a399183c2bfa7c82e8f14bc` |
| v2 candidate `7d175222…`, compile 2 | `b57801960b82627392381038c21bf610777449977a399183c2bfa7c82e8f14bc` |

Each source reproduces its own normalised hash exactly, and the two sources give different ones.
**This is the identity the repository should record for any future build**, alongside the source
hash. It is a function of the input, so it can be checked.

## 3. What this does and does not resolve

**Resolved.** The v2 candidate source in this directory, `7d175222…`, compiles cleanly for Tofino
with the recorded flags on the recorded SDE, and has a stable build identity of
`b5780196…`. The question of whether the instrumentation fits is settled independently of the v1
records.

**Still unresolved, and now known to be unresolvable retrospectively.** Which source produced the
binary that was loaded when `epsilon_v2.jsonl` was captured. The only recorded identifier for that
load is a raw binary hash, which §1 shows carries no information about the source. No offline work
and no recompilation can recover it. The v2 measurement therefore remains a diagnostic with
incomplete build attribution, and the manuscript continues to scope it that way.

**Resolved going forward.** Recording the normalised hash at load time closes this for future
runs, at the cost of one line in the build record.

## 4. The resource counts, from the compiler itself

Both builds, same invocation, read from each compile's own `table_summary.log`, which are
preserved beside this file in `compile_20260916/`:

| | frozen base | v2 candidate |
|---|---|---|
| stages in table allocation | 12 | 12 |
| ingress table allocation | **12** stages | **12** stages |
| egress table allocation | **6** stages | **6** stages |
| tables allocated | **112** | **114** |

This settles the disagreement recorded in `ATTRIBUTION_AND_DECODE_20260916.md` §5 with direct
evidence rather than with a reading of two undefined counts.

* **The manuscript is right.** Twelve ingress stages, six egress stages and 112 tables for the
  evaluated build, now confirmed by a fresh compile as well as by the archived summary in
  `evidence/final_read_sbo/readbacks/tofino_resource_table_summary.log`.
* **`COMPILE_RESULT_20260915.md` is wrong on the compiler's own definitions.** Its "13 ingress
  stages" is not what the allocator reports for either build, and its table count rising from 176
  to 182 is not the allocated-table count. The v2 instrumentation adds **two** tables, 112 to 114,
  which is exactly what its design predicts: two registers, and a Tofino table may access only
  one register each.
* The candidate fits in the same twelve ingress stages as the frozen build, so the concern that a
  program already filling the pipeline would have no room did not materialise. That conclusion
  survives; only the numbers behind it were wrong.
