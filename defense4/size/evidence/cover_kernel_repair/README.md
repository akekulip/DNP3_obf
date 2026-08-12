# Cover-kernel REPAIR — compile evidence record

Repaired / downgraded `defense4/size/p4/defense4_cover_kernel.p4` (Tofino-1 / TNA).
This records the FINAL repaired source only. Build artifacts (`tofino.bin`,
`context.json`, `.bfa`) were produced in a clean `/tmp` dir and are **not** committed;
only sanitized text logs live here.

## Build facts (see `manifest.json` for the machine-readable copy)

| item | value |
|---|---|
| exact command | `bf-p4c --target tofino --arch tna --std p4-16 -g -o build_cover defense4_cover_kernel.p4` |
| compiler | `p4c 9.13.1 (SHA: e558d01)` — local SDE `bf-sde-9.13.1` |
| source sha256 | `8074374074c3d46019d214711111d039ee6b5b891e171ffa863c187f1b499699` |
| exit status | **0** |
| errors / warnings | **0 errors, 3 warnings** |
| `tofino.bin` | 1,523,726 bytes (in /tmp, not committed) |

### Warnings (verbatim, all inherited from the frozen timing ingress)
```
defense4_cover_kernel.p4(362): [--Wwarn=unused] warning: tag_clear: unused instance
warning: Parser state min_parse_depth_accept_loop will be unrolled up to 3 times ... (x2)
```
The new egress size layer contributes **zero** warnings. `tag_clear` is an unused
RegisterAction in the timing core; the `min_parse_depth` unrolls come from the ingress
`@pragma max_loop_depth`. Both also appear in `defense4_joint_canon` builds.

## Resource fit
- **Fits Tofino-1.** The compiler's final table allocation reports **ingress 12 / egress 12**
  stages and the whole-program **max physical stage = 11 (12 of 12)**; `tofino.bin` was
  produced (the compiler hard-errors when a gress needs > 12 physical stages — the
  pre-optimisation attempt did exactly that at 14, see below).
- **Egress size state: two registers** — `reg_delta @ stage 3`, `reg_b0 @ stage 5` (down from
  the pre-repair three; `reg_optseen` was folded into `reg_delta` as a poison sentinel and
  the separate flow-index cut table was inlined, which is what brought egress from 14 → 12).
- MAU logical tables 103, SRAM 46, TCAM 7 (`metrics.json`).
- Full per-stage placement: `table_summary.log`, `mau.resources.log`. PHV:
  `phv_allocation_summary_0.log` (ingress-owned) / `_3.log` (egress-owned).

## Ingress bit-identity (Case-A verbatim)
Every source edit is egress-side or comment-only (verified by `git diff`; the ingress
parser/control/deparser bytes are unchanged). The ingress table placement matches the
pre-repair cover-kernel build except for a single gateway (`tbl_predecessor`) that landed
in an additional physical stage under competition from the different egress — a
placement-only, semantics-preserving shift (documented previously as inert).

## What a clean compile proves / does NOT prove
- PROVES: the cover-frame parser/deparser, the bounded single-insertion transport state
  (`reg_delta`, `reg_b0`), the exact 5-tuple `t_owner` table, the fragment/option/MTU
  fail-closed gates, and the residual-preserving IPv4+TCP checksum recompute all **co-fit**
  with the frozen Case-A timing ingress on one Tofino-1 pipe.
- DOES NOT prove: any silicon behavior. Nothing was loaded or run. Cover CRC-validity was
  verified offline (`offline/cover_frame_golden.py`); the transport translation + fail-closed
  eligibility were verified offline against the P4 behavioral emulator and the depth-1 oracle
  (`offline/test_cover_conformance.py`). A compile is not a run.
