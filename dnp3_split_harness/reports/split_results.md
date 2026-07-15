# Split Replay Results

Live results from the Vision↔Hulk rig. Phase 7: replay the **same** captured
response bytes split across **multiple TCP writes** and confirm the OpenDNP3
master's parse is unaffected by the TCP-write boundaries.

This tests TCP-stream robustness only — it is **not** DNP3 semantic splitting.

## Setup
- **Split replay server:** Hulk `10.10.54.158:20000`
  (`replay_tools/dnp3_split_replay_server.py`).
- **Response:** `payloads/replay/replay_response.bin` — same 902-byte / 6-frame file
  used in the exact-replay test (`replay_results.md`).
- **Split mode:** `byte` — the most extreme case: **902 separate 1-byte `sendall()`
  calls**, no byte modification. The server asserts `b''.join(chunks) == original`
  before sending (reconstruction verified).
- **Master:** Vision `10.10.54.19` (`experiment_master.py --action scan-class0`).

## Observations
| | Exact replay (Phase 6) | Byte-split replay (Phase 7) |
|---|---|---|
| TCP writes for the response | 1 (verbatim) | **902 (1 byte each)** |
| Bytes reconstruct to original | yes | yes (asserted) |
| Master link/transport reassembly | full | **identical — 6 frames** |
| `OnReceiveIIN` count | 4 | **4 (identical)** |
| App responses parsed (SEQ : IIN) | 0:[0x82,01] 1:[02,00] 2:[02,01] 3:[02,00] | **same exact sequence/IIN** |
| Master exit | clean | clean |

The master's application-level view is **byte-for-byte identical** whether the 902-byte
response arrives in one TCP write or in 902 single-byte writes.

## Conclusion
- **TCP-stream robustness proven.** OpenDNP3 reassembles its own DNP3 frames from the TCP
  byte stream regardless of how that stream is chopped across TCP segments — even 1 byte at a
  time yields an identical parse. TCP write boundaries are irrelevant to DNP3 framing (each
  frame self-delimits with `0x0564` + length + CRCs).
- This is the prerequisite the spec required before any DNP3-aware work: **the same bytes can
  be split across multiple TCP `send()` calls without breaking the master.** ✔
- As in Phase 6, no measurement values are delivered to the SOE handler — same cause
  (application sequence / solicited-task gating), and orthogonal to TCP splitting. Phase 7's
  claim is specifically about TCP-boundary independence, which holds.
- **Greenlight:** exact replay (Phase 6) and split replay (Phase 7) both behave as required,
  so later phases may proceed toward DNP3-aware splitting — which must operate on the **DNP3
  frame** unit (rewrite app-control/sequence, recompute per-block CRCs), not on TCP boundaries.
