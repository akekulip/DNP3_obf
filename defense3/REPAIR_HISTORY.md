# Defense 3 — repair history (why `case_a_defense3_repair_candidate.p4` is named that)

This file holds the historical build-and-provenance notes that used to sit in the header of
`p4/case_a_defense3_repair_candidate.p4`, moved here on 2026-07-30 once the three repairs
were loaded and validated on silicon and the header's "candidate / not loaded" framing
became false. The P4 file is now the **final repaired R1+R2+R3 build**; this is its history.

## Why a separate file, not `#ifdef`s in the frozen source

The repairs were authored in a **copy** of `p4/case_a_defense3_fixed_ack_delay.p4` rather than
edited into it, because the archived resource logs and assembly name tables by **source line
number** (e.g. `tbl_case_a_defense3_fixed_ack_delay1871`). Editing the original would break
the correspondence between the source, the archived assembly in `artifacts/`, and the binaries
that were run. The frozen `case_a_defense3_fixed_ack_delay.p4` is the original (unrepaired)
Defense 3 program and remains the switch's restore baseline; it is **not** modified by the
repair work. The repaired program kept the `..._repair_candidate.p4` filename after validation
because the harness (`harness/inject_probe.py`, the setup module), the swap `.conf` files, and
the archived evidence all reference it by that exact name; renaming would orphan that evidence.

## The candidate phase (now superseded)

Originally the file was **authored and locally compiled only** — nothing loaded, the switch
untouched, and the (then) loaded program was the frozen baseline. That phase is over:

- **R1** (authorise a RESPONSE's marker before writing it, `D3_REPAIR_R1`) — validated on
  silicon in the synthetic build (Gate 2/3/4) and run against the physical relay for 960
  transactions (REPORT §7.6, §10.5).
- **R2** (generation-qualify the fail-open via a second register `reg_failopen`,
  `D3_REPAIR_R2`) — validated on silicon at two budgets; fail-open terminations went from the
  defective 1 TMO / K−1 STALE to the correct K TMO / 0 STALE with `reg_tag` preserved
  (REPORT §7.7). The three refuted merge attempts (single arm → input-crossbar error; fifth
  RegisterAction → too-many-RegisterActions error; packed 16-bit pair → "requires more than 2
  PHV inputs") are recorded in `p4/probe_failopen_qualification.p4` and REPORT §7.6.
- **R3** (drop a fresh, non-generator `0x88C1` frame instead of enqueuing it, `D3_REPAIR_R3`)
  — demonstrated on silicon with the in-switch injector; the dropped frame increments the
  distinct `BLOCK_REJECT` counter and never reaches the loopback (REPORT §7.8).

## The fail-open clobber: what the injector did and did not show

The `D3_INJECT` in-switch injector faithfully reproduces the **admission** state R3 must
reject (a fresh `0x88C1` token on a host-facing port). It is **not** a faithful stand-in for a
native token's budget-zero *termination*: a frame forged through the legacy `is_pktgen = 0`
path with `seq = 0` from the start does not traverse the same write as a native token that was
admitted, stamped, and looped its budget to zero. The injected token therefore left `reg_tag`
unchanged, which briefly looked like evidence the destructive write never fires — an
**injection-harness artifact**. The fail-open **K-sweep** on the *native* reservoir settled it:
a single native budget-zero token clears `reg_tag` at K = 1 (1 TMO / 0 STALE / `reg_tag → 0`),
so the write the audit predicted is real and single-token. The cross-transaction *reach* of
that write (a retired transaction's token clearing a different live one) still needs the
generation-wrap coincidence and stays model-checked, not reproduced (REPORT §7.8, limit 10).

## Resource footprint across the two generations

See REPORT §9.9 for the two-generation table. In short: the original campaign build was 9/12
(core) at critical path 8; the final R1+R2+R3 build is 10/12 (core) / 11/12 (telemetry and
synthetic/injector) at critical path 10, the extra table and dependency level being R1's cost.
R2 and R3 add zero on top of R1.
