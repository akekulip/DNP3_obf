# Core-vs-telemetry parity — artifact level (open-work #13)

**Final 9.13.2 assemblies, `artifacts/final/final_core_sde9132.bfa` vs
`final_telemetry_sde9132.bfa`.** All physical timing was collected on the instrumented
(telemetry) build; this establishes that the 10-stage core's shared logic is identical.

- **17 shared SALU actions; 16 byte-identical.** The only actions present in telemetry and
  absent from core are the two **write-only** timestamp registers `ts_last_block_w_0` and
  `ts_last_term_w_0` — the instrumentation itself.
- The single flagged shared action `ack_rel_rmw_0` differs **only** in a table-graph label
  (`next_table_miss: cond-66` → `cond-68`), a renumbering forced by the two extra telemetry
  tables. Its SALU instructions are bit-identical:
  `sub hi, phv_lo, lo ; neq lo, phv_hi, -1 ; alu_a cmplo, lo, phv_hi ; output alu_hi`.

**Conclusion:** core and telemetry differ only by write-only instrumentation and a cosmetic
label renumber; no shared match-action logic differs. The physical timing measured on the
telemetry build is representative of the core build. A full physical campaign on the core
build (Vision master + live relay) remains the gold-standard confirmation and is left as the
larger open item; this artifact-level parity is the achievable-now check.
