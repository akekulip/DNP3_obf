# Isolated T sealed-lifetime experiment

This experiment derives the full composite from immutable checkpoint 55,
SHA-256 `628af1c66da5b61a7b4062dfae40b3e14320bc5d370d20219d893fef3862b261`.
Only its T source changes. N, E, physical ports, current candidate generators,
control plane, and hardware harness remain outside this experiment.

The current lifetime register uses bit 31 for a seal and bits 30:0 for its
bounded epoch. The first matching CLOSE returns status 0 from the prior live
state, seals it, and advances both generation allocators. A duplicate returns
status 2 and does not advance either allocator. Old or invalid events return
status 1. An increasing valid OPEN unseals the register and advances the
preserved allocators. The accepted epoch domain remains `1..0x7ffffffe`;
generation exhaustion retains the fail-closed `0xffff` sentinel.

The separate quarantine register and access table are removed. This removes
the lifetime → quarantine → generation dependency, while full held-packet
epochs and the existing nonaliasing generation policy continue to fence old
originals and raw generator tokens. Current-owner OFF flush remains intact.

The initial version (`evidence/full_01`) passes 19 actual-source tests and
places N/E/T in 12/12/11 stages, but **does not produce a usable full binary**.
Local SDK 9.13.1 assembly fails at `p1/response_only.bfa:918` with
`Syntax error, expecting register slice`. The offending SALU instruction is
`grt.u lo, phv_lo, (-lo & -2147483647)`, generated from a masked register-value
comparison. Its source, inputs, generator, tests, build manifest, compiler log,
and BFA are retained in that directory. PHV placement and the compiled-BFA
mirror guard pass; these do not override the assembly failure.

The bounded repair (`evidence/full_02`) prepares `1w1 ++ epoch[30:0]` in the
parser using the existing `epoch_delta` metadata. OPEN uses two full-width
comparisons: unsigned `current < new` for a live current epoch, or signed
`current < encoded_new` for a sealed epoch. For valid positive `new`, the other
comparison is false in each case. Invalid zero, maximum, and high-bit OPEN
epochs are rejected by the same lifetime table before the register action.
Both actions use the existing `packet_epoch` and `epoch_delta` PHV operands;
there is no added MAU preparation dependency.

The repaired source passes 20 tests, including frozen N/E with experimental T
through the full source pipeline. Coverage includes both epoch encodings and
OPEN bounds, first/duplicate CLOSE, graceful and RST retirement, old RESET,
raw app-0/app-1 tokens on port 196 before and after OPEN, all six old ladder
roles under OFF, current-owner OFF flush, generation exhaustion, handshake
retries, READ/SBO behavior, and cross-role authority isolation. The source
harness executes parser, control, register actions, and headers with its
documented queue assumptions; these results are not compiled-model or
hardware results.

The repaired full composite **compiles and assembles successfully** with local
SDK 9.13.1 in 83.164 seconds. Both pipe binaries and contexts are present and
hash-checked. BFA stages are N/E/T **12/12/11**, with empty pipe-1 egress.
T's lifetime table is stage 0 and generation table is stage 1, compared with
checkpoint 55's lifetime/quarantine/generation stages 0/1/2. The generated
SALU uses full-width `lss.u` and `lss.s` comparisons. PHV allocation completes;
pipe 1 uses 52 normal PHV containers and 1,108 occupied normal bits. The
compiled mirror guard passes with solitary clone select/session containers.
`evidence/full_02/full_composite_qualification.json` binds the source, binary,
BFA, BFRT schema, compiler manifest, resource reports, and source-test result.

SDK 9.13.2, compiled-model behavior, and hardware behavior remain unverified
for this experiment. The raw T epoch diagnostic gains the high seal bit, and
the quarantine bank disappears; any future integration must deliberately
update diagnostic/model assumptions. Checkpoint 55 remains unchanged.

Run the source tests with:

```sh
python -m unittest discover -s defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/t_sealed_lifetime/tests
```

Generate a new immutable experiment directory and compile it with the
repository's `case4_architecture/build.py`. Never regenerate an existing
evidence directory. This experiment is not integrated into checkpoint 55.
