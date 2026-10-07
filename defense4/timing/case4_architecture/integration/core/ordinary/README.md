# Ordinary control candidate

Execution follows [PLAN.md](../../../PLAN.md), with current evidence in
[HANDOVER.md](../../../HANDOVER.md). This separate candidate preserves the original
N/T sources and their prerequisite evidence.

The N checkpoint `n_local_abort_02` compiles with SDE9.13.1 at12 ingress/0 egress
stages, critical path11. N SHA `dfac97f8…4cbbe`, helper `273c405b…f0649` match
[the source/artifact verification](evidence/n_local_abort_verification_01/verification.json).
Its15 focused source tests pass: actual handshake→SELECT→M196, full identity,
immutable captured decoy, zero/wrap, duplicate/format refusal and pre-M cancellation.
There is no stage saving versus the original N12-stage baseline.

SELECT reaches M with a16-byte identity envelope and12-byte captured decoy extension.
For the89-byte input frame, each private transfer carries117 bytes, excluding link
framing. This N path has four ingress visits and four private transfers: three
returns to N68 and one handoff to M196. A pre-M cancellation uses an additional
N visit for its actual abort terminal. Complete M/E pass and bandwidth accounting
is still pending; these are source-path counts, not measured model/hardware costs.

Work3→pending5 uniquely hands off SELECT. Helper5→7 records readiness receipt;
it alone cannot authorize release. Release requires a genuine ready event and
current epoch/owner/cancellation qualification at the owner transition. Actual
downstream completion must precede free9. Normal handshake still uses free4.
The ready/commit/emission join remains unfinished.

The implemented local-abort opcode applies only before M receives this producer.
N3 must win Work and qualify the current epoch before stamping the abort return.
The full epoch/stamp and generation/phase checks precede free; no bank access
follows. Epoch writes require a phase1 Work grant, excluded while this pin lasts.
Lost returns preserve the pin. This opcode cannot drain M/E producers.

Run the completed N prerequisite tests from `case4_architecture`:

```sh
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_work.py -q
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_n_handoff.py -q
```

M PREPARE `m_prepare_02` matches source `23239836…ce16d` and compiles12/0,
critical8. Its three source tests consume the actual N handoff, construct the
independent codec's exact55 bytes and execute the actual source checksum/deparser
statements. It emits privately to N68 through E, with a40-byte prefix containing
separate current and cached producer identities. Duplicate/invalid preparation
does not mutate M banks. [Verification](evidence/m_prepare_verification_01/verification.json)
is source/compiler evidence; target-model wire and endpoint emission remain open.

```sh
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_m_prepare.py -v
```

New E/join tests may still expose unfinished implementation. External55-byte output,
subsequent ACK mapping, full SBO, timing, fragments/lifecycle and final9.13.2
qualification are open. This checkpoint has no target-model or hardware result.
