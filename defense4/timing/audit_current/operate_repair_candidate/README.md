# A lost OPERATE can be repaired: the correction, compiled, loaded and measured — 2026-09-17

The frozen program keeps a released OPERATE's application generation as a spent marker and drops
any later OPERATE carrying it. A command lost on the relay-facing link is retransmitted by the
master's transport with that same generation, so the switch discards the packet that would have
repaired the loss. That is the defect recorded in `OPERATE_RETRANSMISSION_RISK_20260916.md`.

This directory holds the correction. **The frozen tree is read, never written.** The candidate was
compiled, loaded on the switch, configured, and measured against the frozen program on the same
testbed within minutes of it.

## What it changes

A held generation is `0xC0..0xCF`, because the parser admits only `(app_control & 0xF0) == 0xC0`.
Bit 4 is free, so a **released** generation becomes `0xD0..0xDF` and the verdict can tell the two
apart:

| stored in `reg_bor_gen` | arriving OPERATE | verdict | outcome |
|---|---|---|---|
| `0x00` | any | `V_OP_FRESH` | hold it |
| `0xCs` | `0xCs` | `V_OP_DUP` | **drop**: a duplicate of a command still held |
| `0xDs` | `0xCs` | `V_OP_REPAIR` | **relay it**: the transport repairing a loss after release |
| anything else | `0xCs` | `V_OP_BUSY` | fail open |

`gen_release` moves the generation on the `BPC_RELEASE` pass, where the frozen program deliberately
left it alone. `meta.gen_rel = gen_in | 0x10` is precomputed on its own keyless table at level 1,
so the verdict stays a single-field comparison. `OUT_OP_REPAIR` commits through `cmt_op_relay`,
the same action the original release uses, so a repair reaches the relay byte-identically and is
not held.

**Two encodings that do not work**, both of which an earlier draft of the risk note proposed:
reusing bit 7 as a released flag is impossible because every admitted generation already has it
set, and masking to the low nibble collides application sequence zero with `GEN_INACTIVE`.

## What it does not claim

**It is not exactly-once.** If the original did reach the relay and the copy is a spurious
retransmission, forwarding it delivers the same bytes twice to the relay's TCP, which discards
them as an already-received sequence range. That is TCP's job. The switch cannot see what the
relay received, and this correction stops it pretending otherwise: it no longer treats its own
earlier forward as proof of delivery.

## Verification

**The encoding, exhaustively.** All 16 application sequences against every register state, 528
cases, every verdict correct, and the three stored domains disjoint: inactive `{0x00}`, held
`0xC0..0xCF`, released `0xD0..0xDF`.

**It compiles and fits.** `bf-p4c --target tofino --arch tna -g -DU_BOR`, 0 errors:

| | frozen | corrected |
|---|---|---|
| ingress stages | 12 | **12** |
| egress stages | 6 | 6 |
| tables | 112 | 116 |

Four more tables, **no additional stage**, which was the question that mattered: the correction
fits inside the existing budget.

**It loads and configures.** `RESULT: PASS (n_fail=0 n_warn=0)` with the control-plane patch
below. Without that patch it fails exactly one check, `tbl_commit const map matches COMMIT_MAP`,
because the data-plane correction introduces a 44th outcome and the frozen map asserts totality
over 1..43. That failure is the two halves disagreeing, and it is why they ship together.

**It does not change the timing.** Sixty READ polls through each build, same relay, same
configuration, captured on the master-facing link and extracted with the repository's own reader:

```
frozen     n=60  CLRT median 3.9995 ms  min 3.9300  max 4.0650  sd 0.0190  60/60 within 0.10 ms of 4.000
corrected  n=60  CLRT median 4.0000 ms  min 3.9400  max 4.0240  sd 0.0116  60/60 within 0.10 ms of 4.000
```

Zero malformed frames, zero CRC errors and zero retransmissions in both. The captures are in
`../hardware_20260917/`.

**What is still untested.** The repair path itself. Exercising it needs a controlled loss injected
on the relay-facing link after release, and that link is not instrumented on this testbed. Every
result above is the normal path continuing to work and the correction fitting; none of it shows a
repair being forwarded, because no loss was induced. The acceptance cases in
`../OPERATE_RETRANSMISSION_RISK_20260916.md` still stand, in particular a repair arriving during a
later transaction, where the shared sequence and acknowledgment trackers run before the verdict.

**Nothing in the manuscript comes from this.** The campaign's numbers are the frozen program's and
stay that way. The paper reports the defect as a limitation of the evaluated build, which is
still true of the build that was evaluated.

## Files

```
operate_repair.patch                  over the frozen P4; reproduces the candidate exactly
control_plane_corrections.patch       over the frozen setup; three fixes, below
compile_20260917/corrected.compile.log      bf-p4c, 0 errors
compile_20260917/corrected_table_summary.log 12 ingress stages, 116 tables
compile_20260917/configure_corrected2.log    RESULT: PASS (n_fail=0 n_warn=0)
compile_20260917/switchd_corrected.log       the load
```

### The control-plane patch carries three fixes

1. **`OUT_OP_REPAIR` = 44** in `COMMIT_MAP`, mapped to `cmt_op_relay`, with the totality and
   single-valued assertions widened to 1..44. Required by the data-plane correction.
2. **`verify` passed the wrong target.** `hw_verify_tbl_commit` reads the `const` table
   `tbl_commit`, whose entries are reported at the device target, not per pipe. `configure-all`
   passed `tdev`; `verify` passed `tgt` (pipe 0) and read an empty table, so it could never pass
   its own check. Measured on the loaded program: 43 entries at the device target, 0 at pipe 0.
3. Not patched, recorded instead: **`read_len` cannot round-trip.** It is assigned twice in the P4
   and never read, so the compiler drops its storage while bfrt still declares the parameter.
   Writing 18 and reading 0 is reproducible in two API calls. Any configure needs `--read-len 0`.
   Fixing it properly means deleting a vestigial field from the data plane, which is a change to
   the frozen program for no functional gain, so it is left alone and documented.
