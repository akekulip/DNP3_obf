# opendnp3 replay of the retained c72 transport-wrap READ responses (audit 2026-10-28, follow-up to 4.2)

`scripts/analysis/opendnp3_wrap_check.py` feeds the exact retained response bytes of padded c72 connections to a
second DNP3 reassembly implementation: the opendnp3 master inside pydnp3. The build is opendnp3 2.x (asiodnp3 API),
statically linked in the ChargePoint pydnp3 0.1.0 fork; the binary does not record the exact opendnp3 release. The
run is offline, over localhost, with no hardware contact.

Method:
- A replay outstation answers each READ from the master with the next retained READ response, in recorded order. It
  answers nothing else and synthesises nothing.
- The master uses the recorded link addresses (master 1, outstation 0), so every retained link header arrives
  unmodified. Each READ carries the recorded object headers. All 520 live requests matched the recorded request
  bytes after the application control byte.
- opendnp3 drops a response whose application sequence differs from its request. The live master numbers its READs
  0, 1, 2, ..., while the recorded custom master also spent sequence numbers on SELECT and OPERATE. For 448 of 520
  responses the tool therefore rewrote the low nibble of the application control byte (wire offset 11) and the two
  CRC octets of the data block that holds it: 3 bytes per response, all recorded in `opendnp3_wrap.json`. No
  transport header was rewritten in the test run. 72 responses, including 2 of the 8 wrap responses, went through
  byte-identical.
- Pass, per response: task SUCCESS; the SOEHandler values (group, variation, qualifier, index, value) equal the
  repository codec's decode of the same bytes; no WARN or ERR log entry. Per run: opendnp3's transport and link
  error counters stay at 0, and no unexpected request reaches the outstation.

| Arm | D (ms) | READ replayed | READ wraps | Delivered OK | Errors | Control OK / errors |
|---|---:|---:|---:|---:|---:|---|
| combined | 5 | 65 | 1 | 65 | 0 | 65 / 0 |
| size_only | 5 | 65 | 1 | 65 | 0 | 65 / 0 |
| combined | 10 | 65 | 1 | 65 | 0 | 65 / 0 |
| size_only | 10 | 65 | 1 | 65 | 0 | 65 / 0 |
| combined | 15 | 65 | 1 | 65 | 0 | 65 / 0 |
| size_only | 15 | 65 | 1 | 65 | 0 | 65 / 0 |
| combined | 20 | 65 | 1 | 65 | 0 | 65 / 0 |
| size_only | 20 | 65 | 1 | 65 | 0 | 65 / 0 |
| **Total** | | **520** | **8** | **520** | **0** | **520 / 0** |

**Result.** opendnp3 reassembled every READ wrap response. Its transport log shows `FIR: 1 FIN: 0 SEQ: 63` followed
by `FIR: 0 FIN: 1 SEQ: 0`, and it delivered the values the codec decodes (50 points for mixed, 73 for integrity).
- **Control:** the same replay with the wrap responses renumbered to 0, 1 by `independent_decode.renumber` also gave
  520/520.
- **Negative control:** the e01 wrap response with its second segment numbered 5 instead of 0 was rejected. opendnp3
  logged "Ignoring bad sequence, got 5, expected 0", raised `numTransportIgnore` and `numTransportErrorRx` to 1, and
  timed out. So opendnp3 does check transport sequences, and after 63 it expects 0.
- **All 128 padded evaluation connections:** the same script over every padded connection delivered 8,320/8,320 READ
  responses, all 128 READ wrap responses included, with 0 errors in both the test and the control run. Per-response
  detail of that run (14 MB) is not retained. `opendnp3_wrap_all128_compact.json` keeps per-connection totals and
  the SHA-256 of the full output.

**Coverage limit.** Every padded response is two-segment, SELECT and OPERATE included. The 3 wraps in each padded
connection are always one READ, one SELECT and one OPERATE (64 exchanges apart; 64 mod 3 = 1). This check replays
READ only, so it covers 1 of the 3 wraps per connection. The 256 SELECT/OPERATE wrap responses in the evaluation
were not replayed through opendnp3 in this pass.

**Scope.** One master implementation, fed master-NIC captures. This does not show what the relay emitted before the
switch, and it does not test the SEL-751 master path or any other vendor's master.

Files: `opendnp3_wrap.json` (method, totals, per-response byte changes, sequences, opendnp3 transport lines,
negative control), `opendnp3_wrap_all128_compact.json`, `run.log`. Tests: `tests/analysis/test_opendnp3_wrap_check.py`
(RED `tdd_red.log`, GREEN `tdd_green.log`; 9 passed).
