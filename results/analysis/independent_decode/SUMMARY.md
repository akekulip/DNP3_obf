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

Three results are kept apart:
- TShark's reassembly of the transport segments as captured;
- the 63→0 wrap cases where that reassembly fails;
- agreement between the repository codec and TShark on the decoded content.

| Campaign | Responses | Wrap responses (63→0 inside the fragment) | TShark reassembled from unchanged bytes | TShark reassembly failed | Decoded content agrees (codec vs TShark) |
|---|---:|---:|---:|---:|---:|
| Evaluation `rc01_hw_c72_eval_20261027_01` (256 connections) | 49,408 | 384 | 49,024 | 384, all at 63→0 | 49,408 (384 of them via the renumbered control) |
| Qualification `rc01_hw_c72_20261027_02` (34 connections) | 2,440 | 22 | 2,418 | 22, all at 63→0 | 2,440 (22 of them via the renumbered control) |

There were 0 field differences and 0 TShark expert warnings. The compared fields are function code, IIN,
application sequence, object group, variation and qualifier, point indices, binary and analog values, and CROB
indices and statuses.

**Reassembly at the transport-sequence wrap.**
- **The pattern:** a padded response is carried in two DNP3 transport segments, the prefix and the native SEL-751 frame.
  When the first segment carries transport sequence 63, the second carries 0, which modulo-64 numbering allows. It
  happens in 3 responses of each of the 128 padded evaluation connections. No-obfuscation and Timing responses
  are single-segment and never span the wrap.
- **TShark's failure:** TShark 4.4.9 fails to reassemble every one of these fragments, even when the frame is
  decoded alone. The failure also corrupts its decode of later responses in the same capture, so a direct decode
  of the unmodified capture is not available after the first wrap.
- **The renumbered control:** the counts in the table therefore come from a copy of each capture in which only the
  wrap responses have their transport sequence numbers renumbered (0, 1), with link CRCs recomputed. The tests check
  that nothing else changes. The other 49,024 and 2,418 responses are byte-identical to the retained captures.
- **What this does and does not show:** the content agreement for the 384 and 22 wrap responses is a statement about
  the renumbered copies. That TShark cannot reassemble the originals is a dissector limitation. It does not show
  that a real master, such as an opendnp3 or SEL master, rejects them.
- **Independent reassembly (opendnp3):** the exact retained READ wrap responses were replayed to the opendnp3
  master in pydnp3 (`results/analysis/opendnp3_wrap/`). It reassembled all 128 READ wrap responses of the padded
  evaluation connections, from unrenumbered transport bytes, and delivered the codec's values. A second segment
  renumbered to 5 was rejected. The 256 SELECT/OPERATE wrap responses were not replayed through opendnp3 in this
  pass. A compatible live-master check against the physical SEL-751 remains open.

**Scope.** This is a second parser over master-NIC captures. It is not a test of a deployed master. It says nothing
about whether the delivered bytes equal what the relay emitted before the switch; that needs a relay-side capture
(plan Phase D/E1).

Files: `evaluation.json`, `qualification.json` (totals and any connection with a difference, an unmatched response,
a codec problem or an expert warning). Tests: `tests/analysis/test_independent_decode.py` (RED `tdd_red.log`,
GREEN `tdd_green.log`).
