# Diagnostic switch-clock anchors on c52: fit record (2026-10-25)

**Result: does not fit. The branch is stopped under the agreed contract.** No limit was relaxed, no check was
removed, and c52 was not touched. The generator emits c52 byte for byte without `--diag-anchors`
(`m12_fullsize/tests/test_diag_anchor.py`).

## Goal

Add per-transaction, write-once records to T (pipe-1 ingress), on the switch clock (Philip, 2026-10-25):
- P1 t0 admission;
- P2 genuine ACK commit, the anchor of D;
- P3 ACK release, commit or fallback;
- P4 response release, release or fallback;
- P5 OPERATE anchor (op_t0);
- P6 OPERATE release.

Each record is a 256-slot ring indexed by generation[7:0]. A slot holds lo = `md.now` and hi = tag (epoch[13:0],
generation[15:0], and a flag). It has sticky collision and duplicate marks, and it must add no forwarding,
timer or traversal change. The generator layer is `m12_fullsize/m12gen/diag_anchor.py`, behind the
`make_m12.py --diag-anchors` flag.

## Attempts (SDK 9.13.2, `case4_architecture/build.py`, local compiler sha256 787631a6…)

| identity | source sha256 | compile log sha256 (xz kept) | exit | first error |
|---|---|---|---|---|
| `m12p_c52d_sdk9132` | 89ac8c0da76f85ac… | 09fbc1a3ff1c5585… | 3 | `t_Ingress.d_p1 requires more than 2 PHV inputs` (two RegisterActions per register with different tag fields); then `d_rec_p2` could not fit the input crossbar |
| `m12p_c52d2_sdk9132` | c76ffc764a389b3f… | 8fb968e9cd048411… | 2 | `PHV allocation was not successful`: 19 field slices unallocated |
| `m12p_c52d3_sdk9132` | ba646a7777a4c746… | 2373551281bddba5… | 2 | the same 19 slices unallocated |

**Changes between attempts:**
- **Attempt 2:** one RegisterAction per register, with two PHV inputs (tag and `md.now`). The fallback bit is ORed
  into the tag after the verdict by a constant action.
- **Attempt 3:** a single 32-bit tag field shared by both lanes, so `d_tag_o`, `d_idx_o` and `d_role` were
  removed. P2 is recorded in the held branch while the ladder header is still valid.

The 19 unallocated pipe-1 slices in attempts 2 and 3:
- the clock: `md.now` and `global_tstamp[39:8]`;
- the deadline chain: `now_m_da`, `da`, `now_m_readiness`, `readiness`, `now_m_gap`, `gap`, `now_m_pb`,
  `pb_bound`, `now_m_opj` and `op_j`;
- the deltas and anchors: `da_delta`, `t0_v`, `readiness_delta`, `pb_delta`, `op_delta`, `op_t0_masked` and
  `op_t0_v`.

## What the measurement shows

- Shrinking the recorder's own fields, from 3 tags plus 2 indices plus a role byte down to 1 tag plus 1 index,
  did not change the unallocated set.
- The constraint is therefore T's clock and deadline chain. Recording a release instant after T's verdict keeps
  `md.now` live to the last stage, and pipe-1 PHV can no longer allocate the chain that c52 overlays.
- c52 itself compiles, with 39/64 32-bit containers on pipe 1.
- Inference, not measured: any recorder that timestamps P3, P4 or P6 (the release points, and therefore D and
  OPERATE J) hits the same constraint.

## Not done, and why

Each of the following is outside the agreed contract, so none was attempted:
- Moving the recording to a later traversal or to another pipe: that adds a traversal.
- Relaxing stage or PHV limits.
- Restructuring T's deadline chain to free PHV: that changes T's behavior, so it would be a new candidate, not
  instrumentation.
- Keeping only the early points (P1, P5, and possibly P2): this cannot observe release, D or OPERATE J, so it
  does not meet the stated purpose.

These are listed as options for Philip in the diagnosis report. The independent observation path is now the
physical relay-leg tap (plan Step 3).
