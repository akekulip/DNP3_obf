# Combined N/T stage experiment

This isolated experiment combines only the N role from the immutable CRC
residue experiment and the T role from the repaired sealed-lifetime experiment.
E and all surrounding composition source remain byte-identical to checkpoint
55. Input SHA-256 values are pinned in `generate.py` and recorded in the frozen
`response_only.inputs.json`. The generator rejects an input hash mismatch,
unexpected edits outside either role, or any role-identity mismatch before
creating output.

The combined source is retained in `evidence/full_01/response_only.p4`,
SHA-256 `cad16b85f79d0609ad07e547a9551def720fdfa668c14000b7503a570cae7357`.
It preserves N's full-width CRC-residue guard qualifications, E's checkpoint
55 behavior, and T's sealed low-31-bit epoch with preserved generation
allocators. No current candidate generator, control plane, installer, hardware
harness, or independent experiment is changed.

The actual-source suite passes 41 tests. It reuses the retained full-composite
source pipeline, complete protected-lifecycle regressions, and independent
N-residue and T-lifetime regressions. Coverage includes bilateral FIN/ACK in
both orders, simultaneous FIN/ACK, qualified established and pending RST,
genuine Work-free retirement, exact handshake retries, fresh mapping, READ/SBO
timing and padding, malformed CRC and READ link IDs, conservative ISN reuse,
exhaustion, old external packets, private Work returns, old RESET, all six old
ladder roles under OFF, raw tokens on physical return port 196, and
current-owner OFF flush. Only identifier and test-port adapters are used for
the source harness; full generated P4 retains the checkpoint's physical map.

Run the source suite with:

```sh
python -m unittest discover -s defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/combined_nt_01/tests
```

`evidence/full_01/source_test_result.json` pins the source and reused test/helper
inputs. Source-harness results include its documented queue assumptions and
are separate from compiled-model or hardware results. The experiment remains
outside checkpoint 55; a future integration must update diagnostics for T's
seal bit and removed quarantine bank.

The full composite compiles and assembles with local SDK 9.13.1 in 81.773
seconds. BFA placement is **N/E/T 11/12/11**, with empty pipe-1 egress. Both
pipe binaries and contexts are present and hash-checked; the compiled mirror
guard passes. `evidence/full_01/full_composite_qualification.json` pins the
binaries, BFA, BFRT schema, compiler manifest, PHV/parser/table reports, and
source-test inputs. Its register-authority comparison confirms that the sole
removed authority is T's quarantine register and all retained sizes match
checkpoint 55. SDK 9.13.2, compiled-model behavior, and hardware behavior
remain outside this offline qualification.
