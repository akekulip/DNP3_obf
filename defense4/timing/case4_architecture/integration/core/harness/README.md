# Whole-program source-level harness for `native_binding.p4`

Runs the repository source `integration/connection/binding/native_binding.p4`
(sha256 `35bf9aa3...`, with `work_record.p4` inlined at its `#include`) packet by packet:
parser, `Ingress`, deparser, and recirculation on `RETURN_PORT` (68), up to 8 passes.

**This is a source-level interpreter. It is not the Tofino compiler, the ASIC, the traffic
manager or the packet generator. Nothing here is target-verified, compiled-binary evidence, or
hardware evidence.** It shows what the P4 text says, under the semantics assumed below.

## Files

- `p4syntax.py`: tokenizer and recursive-descent parser for the P4 subset used (AST of tuples).
- `interp_ext.py`: `ExtSource`, a subclass of the existing
  `protocol/egress/source_packets.Source` (-> `tests/source_control.Source` ->
  `protocol/source_eval.Source`). It inherits the header/meta width tables, the field-order
  renderer and `block()`, and overrides `expr`, `run`, `table`, `action`, `register`,
  `packet_parser`, `apply_control` and `deparse`. The frozen regex/substitution evaluators
  were not edited and cannot express these constructs (`ig.*` reads, range keys, typed widths,
  slice assignment, register pairs, sub-control call), so the override is a parsed-AST evaluator,
  not a patch of them.
- `driver.py`: `Config`, `Pipeline(source_text, config, include_dir=...)` / `Pipeline.from_path`,
  `.preset(owner, client, server, epoch, work)`, `.state()`, `.inject(port, frame)`.
- `vectors.py`: frame builders (the retained step-1 `frame()` and an independent TCP/IPv4/DNP3
  builder) and the test topology.
- `tests/`: 34 tests (`python3 -m unittest discover -s integration/core/harness/tests -p 'test_*.py'`
  from `case4_architecture`).

## What is executed

- Parser: every state, `extract`, `select` (exact, tuple, range `a..b`, `default`), `m.*`
  assignments, `Checksum` `add/subtract/verify/get`, truncated-extract detection.
- Ingress: every `if/else`, assignment (including `x[7:0]=...`), concatenation `a++b`, slices,
  fixed-width wraparound, `(int<32>)` signed compare, `setValid/setInvalid`, action calls.
- Tables: const entries (exact, ternary mask, range, `_`, bool) in declaration order, then
  runtime entries, then the default action. `ports`, `connection`, `data_connection` are
  filled by `Config` (port routes, the 10.0.0.1:30001 <-> 10.0.0.2:20000 forward/reverse flows
  with output ports, one `configure`).
- Registers: `Register`/`RegisterAction` for scalars and struct pairs; the
  `ExpectedWorkRecord` sub-control (`work.apply(...)`) with its own register state.
- CRC: `Hash` with `CRCPolynomial` (0x3D65, reflected, xor 0xFFFF), checked against
  `framework/size/rrc.dnp3_crc`.
- Deparser: `pkt.emit(hdr)` in `headers_t` order for valid headers, followed by the unparsed
  remainder of the frame. Outcome: egress port, `drop_ctl` (deny), recirculation, trace per pass.

## What is NOT executed or modeled

- Compiler, stage/PHV/SALU fit (the retained compile of this lineage fails 19 of 12 stages),
  table sizes, register-action restrictions, one-register-per-table rules.
- Parser error behaviour of the target: a truncated extract is reported as a drop by default
  (`on_parser_error='drop'`); `'continue'` runs the control on the partial parse. Which one the
  ASIC does is unverified.
- `Checksum.subtract` is modeled as additive accumulation. The program's `0xffeb` constant is
  the folded sum with `ip.len` in the pseudo-header; whether the target negates is unverified.
- Metadata and invalid-header reads are zero (the trace lists reads of invalid headers).
- Traffic manager, queues, egress pipeline (`Egress` is empty), bypass semantics, recirculation
  port bandwidth, ingress port metadata bytes, Ethernet padding/FCS, multicast, timing.
- Controller-installed state beyond the three runtime tables; table `size` limits.
- `reset_registers` is initial state `{0,0}`/`{0,4}`; tests preset registers directly, which the
  real system reaches only through the handshake.

## Findings from the first run (2026-10-06)

1. The four retained step-1 witnesses are still denied on the repository source. Pass 1
   forwards correctly and recirculates event `0x0108`; pass 2 misses `network` (no row for
   kind 8) and `else if(m.stage!=8w0){deny();}` fires. Adding the single row
   `(8w1,8w8,_,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();` in an in-memory copy makes
   all four forward byte-identical in 4 passes with the owner unchanged (hypothetical, not the
   repo). `tests/test_witnesses.py` pins both facts and keeps the acceptance test as
   `expectedFailure`, which flips to a failure (unexpected success) once the source is repaired.
2. With the `epoch` register at 0 a forwarded original recirculates until the pass limit
   (parser accepts at the envelope, `m.parsed` stays 0, nothing denies).
3. Stage-0 frames rejected by the network, connection or data guards are not dropped; they pass
   through byte-identical via `ports.route`.
