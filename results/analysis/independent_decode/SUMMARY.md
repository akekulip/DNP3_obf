# Independent decode of the retained c72 responses (audit 2026-10-28, section 4.2)

`scripts/analysis/independent_decode.py` decodes every retained response twice and compares the results. The first
decoder is the repository codec (`dnp3_codec.py`), which the custom master and the checker share. The second is the
Wireshark DNP3 dissector (TShark 4.4.9). Both decode the same bytes captured at the master NIC.

Compared fields:
- function code, IIN and application sequence;
- object group, variation and qualifier, in order;
- point indices;
- binary-input and binary-output point values;
- analog values;
- CROB indices and statuses.

| Campaign | Connections | Responses | Matched | Field differences | tshark expert warnings | Wrap responses |
|---|---:|---:|---:|---:|---:|---:|
| Evaluation `rc01_hw_c72_eval_20261027_01` | 256 | 49,408 | 49,408 | 0 | 0 | 384 |
| Qualification `rc01_hw_c72_20261027_02` | 34 | 2,440 | 2,440 | 0 | 0 | 22 |

**Transport-sequence wrap.**
- **The pattern:** a padded response is carried in two DNP3 transport segments, the prefix and the native frame.
  When the first segment carries transport sequence 63, the second carries 0. Modulo-64 numbering makes that valid.
  It occurs 3 times in each of the 128 padded evaluation connections, which is 384 responses. No-obfuscation and
  timing-only responses are single-segment and never span the wrap.
- **tshark's failure:** tshark 4.4.9 does not reassemble such a fragment, even when the frame is decoded on its own.
  The failed reassembly also corrupts its decode of later responses in the same capture; separate TCP conversations
  do not isolate it.
- **The control:** the decoder therefore reads a control copy in which only those wrap responses have their
  transport sequence numbers renumbered, with link CRCs recomputed. The tests check that the copy changes nothing
  else and that its CRCs verify. Every other response is byte-identical to the retained capture.
- **Compatibility risk (not established):** a DNP3 master whose transport reassembly behaves like tshark's would
  reject about 1 in 64 padded responses. This needs a check against an independent master implementation before
  any compatibility claim. It is a risk the two-segment padding introduces; the captures do not show it occurring.

**Scope.** This is a second parser over master-NIC captures. It is not a test of a deployed master. It says nothing
about whether the delivered bytes equal what the relay emitted before the switch; that needs a relay-side capture
(plan Phase D/E1).

Files: `evaluation.json`, `qualification.json` (totals and any connection with a difference, an unmatched response,
a codec problem or an expert warning). Tests: `tests/analysis/test_independent_decode.py` (RED `tdd_red.log`,
GREEN `tdd_green.log`).
