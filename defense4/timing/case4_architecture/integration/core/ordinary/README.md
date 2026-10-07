# Ordinary control candidate

Execution follows [PLAN.md](../../../PLAN.md), with current evidence in
[HANDOVER.md](../../../HANDOVER.md). This separate candidate preserves the original
N/T sources and their prerequisite evidence.

M prepare/activation now compiles at10 ingress/0 egress stages, critical9,
with two spare ingress stages: `m_activate_06`, SHA `cf1eaaa4…46575`.
[Scoped verification](evidence/m_activate_verification_01/verification.json)
records ten passing source methods and exact tested dependencies; the independent
review accepts M05 and M06's sole route change to68. Actual reservation and full
producer context qualify a once-only activation. Geometry and position complete
before ledger publication; a genuine stamped return frees M, with N still pinned
and no later M bank access. Endpoint delivery and completion need the composed
model. This replaces M PREPARE03's12-stage fit, not the failed15-stage old canary.

Current N checkpoint `n_ready_03` compiles with SDE9.13.1 at12 ingress/0 egress
stages, critical path11. N SHA `1be0eb09…33b8b`, helper `273c405b…f0649` match
[the source/artifact verification](evidence/n_ready_verification_01/verification.json).
The completed preparation suites have25 source methods: actual handshake→SELECT→M196,
full identity, immutable decoy, zero/wrap, duplicate/format refusal, pre-M cancellation,
M/E preparation and genuine N ready/commit. N02's capacity27/entries28 failed
load validation despite compilation; N03 has capacity28 and a clean scan.
There is no stage saving versus the original N12-stage baseline.

SELECT reaches M with a16-byte identity envelope and12-byte captured decoy extension.
For the89-byte input frame, each private transfer carries117 bytes, excluding link
framing. This N path has four ingress visits and four private transfers: three
returns to N68 and one handoff to M196. A pre-M cancellation uses an additional
N visit for its actual abort terminal. Complete M/E pass and bandwidth accounting
is still pending; these are source-path counts, not measured model/hardware costs.
Through the actual M activation handoff, [source-path accounting](evidence/n_ready_verification_01/source_path_accounting.json)
now counts6 N ingress visits,1 M ingress and1 E egress. Seven private transfers
carry867 bytes: four117-byte N transfers and three133-byte prepare/ready/commit
transfers. This stops before M activation, E emission and terminal cleanup and
excludes handshake, link padding/framing and TM/fabric overhead.

Work3→pending5 uniquely hands off SELECT. Helper5→7 records readiness receipt;
it alone cannot authorize release. Release requires a genuine ready event and
current epoch/owner/cancellation qualification at the owner transition. Actual
downstream completion must precede free9. Normal handshake still uses free4.
Actual E0514 first qualifies active-generation/epoch/owner without Work mutation;
genuine0614 then wins Work5→7 and full owner9→17 before emitting0714 to M.
The ready qualification adds a32-bit authoritative active-generation bank,
written only by actual successful Work claims. Full matching wrong generations
in both references are rejected. FIN before owner CAS retains the pin and
prevents activation; post-M abort/drain and endpoint emission remain unfinished.

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

Retained M PREPARE `m_prepare_03` matches source `2475f93b…ec9f3` and compiles12/0,
critical8. Its three source tests consume the actual N handoff, construct the
independent codec's exact55 bytes and execute the actual source checksum/deparser
statements. It emits privately to N68 through E, with a24-byte format2 prefix containing
separate current and cached producer identities. Duplicate/invalid preparation
does not mutate M banks. E PREPARE `e_prepare_03`, source `55c2bae9…06589`,
compiles1 diagnostic ingress/9 egress, critical6. Actual all14 stores occupy
stages3–6, full owner/tag publication7 and private ready8, consuming every real
store completion. The133-byte private frame uses exactly160 egress-parser bytes
including SDK metadata. [Verification](evidence/me_prepare_verification_01/verification.json)
includes all six M/E source methods and compiler ordering. The M06 activation
checkpoint above supersedes this source; target-model endpoint emission remains open.

```sh
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_m_prepare.py -v
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_e_prepare.py -v
python3 -B -m unittest discover -s integration/core/ordinary/tests -p test_n_ready.py -v
```

New E/join tests may still expose unfinished implementation. External55-byte output,
subsequent ACK mapping, full SBO, timing, fragments/lifecycle and final9.13.2
qualification are open. This checkpoint has no target-model or hardware result.
