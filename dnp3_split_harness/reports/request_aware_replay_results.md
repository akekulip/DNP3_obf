# Request-Aware Split Replay — Rig Results

_Run: 2026-06-15 17:15 (gambit-driven over SSH). Mode: `request-aware` (default)._

## What was tested
The request-aware replay outstation (folded inline into
`replay_tools/dnp3_split_replay_server.py`, driven by `split_server.py` with
`DEFAULT_REPLAY_MODE="request-aware"`) replaced the real outstation on Hulk
`10.10.54.158:20000`. The live master on Vision `10.10.54.19` ran `run_master.py`
unchanged. This validates the spec that diagnosed `split_reader.pcap`'s blind
byte-dumper bug: the server now parses each request's DNP3 function code + app
sequence and replies with only the matching captured response, splitting solely the
READ response on CRC boundaries.

## Server behavior (logs/replay/request_aware_stdout.log)
Each master request was parsed and matched semantically (function code + app_seq):

| # | Master request           | Matched response                | Chunks | Byte-preserve |
|---|--------------------------|---------------------------------|--------|---------------|
| 1 | ENABLE_UNSOLICITED seq0  | resp_0001 (17 B)                | 1      | PASS |
| 2 | WRITE seq1               | resp_0002 (17 B)                | 1      | PASS |
| 3 | ENABLE_UNSOLICITED seq2  | resp_0003 (17 B)                | 1      | PASS |
| 4 | **READ seq3**            | resp_0004+5+6 (**2407 B**)      | **141**| PASS |
| 5 | **CONFIRM seq3**         | resp_0007+8+9 (1657 B)          | 1      | PASS |

The master sent the **DNP3 CONFIRM** after the 141-chunk split READ response — the
key sign of application-level acceptance the blind dumper never produced.

## Success criteria (Guide §18) — all met
- **§18.1 TCP delivery** — pcap `captures/replay/request_aware_rig.pcap`: 0
  retransmissions, 0 resets.
- **§18.2 Parser acceptance** — master completed full startup + READ + CONFIRM and
  shut down cleanly; no CRC/transport/timeout errors.
- **§18.3 CONFIRM appears** — pcap frame 296: master→outstation `dnp3.al.func=0`
  (CONFIRM, app_seq=3). ✓
- **§18.4 SOE matches baseline** — `logs/master/soe.csv` gained **800 measurements**
  for this run (2026-06-15T17:15); values are **byte-identical** to the ordered
  milestone run (2026-06-12, 800 rows) — `diff` empty.
- **§18.5 Wireshark reassembly** — pcap frame 294: outstation RESPONSE
  **reassembled from fragments 46,80,…,294** into one valid DNP3 application message.

## Safety property (Guide §2.1 / §12)
Local loopback test confirmed an unmatched request (DIRECT_OPERATE 0x05, not in the
captured map) returns **0 bytes** — the large READ response is never fired at a
non-matching request. The blind byte-dumper bug is fixed by construction.

## Artifacts
- `captures/replay/request_aware_rig.pcap` (301 pkts, clean) — pulled to gambit.
- `logs/replay/request_aware_stdout.log` — server match/split/CONFIRM trace.
- `logs/master/soe.csv` (on Vision) — rows tagged `2026-06-15T17:15` = this run.

## Relationship to the ordered milestone
This is a second, independent, rig-proven path to the same result as the `ordered`
mode (`dnp3_ordered_replay_server.py`, `captures/replay/ordered_rig.pcap`). The
request-aware path adds explicit semantic matching + refusal safety; the ordered
path matches by capture position. Both deliver the identical 800 measurements and a
master CONFIRM, byte-preserving (no CRC recompute, no field/length change).

---

## Two-sided manual capture (2026-06-15 17:57)

A second, manually run pass captured the same exchange **at both ends simultaneously**
to document the splitting (outstation egress) and the receipt + reassembly (master
ingress) independently. Same `request-aware` server, same payload set.

- Split side  (Hulk egress)  → `captures/manual/split_side.pcap`
- Master side (Vision ingress) → `captures/manual/master_side.pcap`
- Server log: `logs/replay/manual_split_server.log`
  (`split_replay_server_1781545848.log` on Hulk)
- Master log: `logs/master/experiment_master_1781546243.log` (on Vision)

Both captures are 301 packets, one TCP connection
(`10.10.54.19:42691 ↔ 10.10.54.158:20000`), **0 retransmissions, 0 resets**.

### Splitting (split_side.pcap — what the outstation sent)
The split server emitted 145 outbound data segments. The READ response (2407 B) was
cut into **141 segments on existing DNP3 CRC-block boundaries**:

| Segment size | Count | Meaning |
|--------------|-------|---------|
| 17 B   | 3   | startup responses (ENABLE_UNSOL, WRITE, ENABLE_UNSOL), one segment each |
| 10 B   | 9   | link-frame header chunks (`8 B header + 2 B header-CRC`) |
| 18 B   | 123 | full data blocks (`16 B data + 2 B block-CRC`) |
| 12 B   | 8   | partial-block tails (`10 B data + 2 B CRC`) |
| 7 B    | 1   | final partial tail (`5 B data + 2 B CRC`) |
| 1657 B | 1   | post-CONFIRM continuation response |

READ chunks: 9 + 123 + 8 + 1 = **141**, matching the server log's `Chunk count: 141`
and exact `Chunk sizes` list. Byte-preservation check: PASS.

### Receipt + reassembly (master_side.pcap — what the master did)
The master received the identical 145-segment size histogram — every one of the 141
chunks arrived as its own TCP segment, nothing dropped or recoalesced. DNP3 then
reassembled them:

```
frame 13   master      -> READ (al.func 1)
frame 294  outstation  -> RESPONSE (al.func 129), REASSEMBLED from 9 fragments
                          (frames 46, 80, 114, 148, 182, 216, 250, 284, 294)
frame 296  master      -> CONFIRM (al.func 0, seq 3)        <-- acceptance
frame 297  outstation  -> continuation RESPONSE (reassembled from 6 fragments)
```

i.e. 141 TCP segments -> 9 DNP3 link/transport frames -> **1 reassembled application
message** (frame 294), which the master accepted and CONFIRMed (frame 296). The master
delivered **800 measurements** (`soe.csv` rows tagged `2026-06-15T17:57`), spanning
both response fragments (`header_index` 0 and 1).

### The one "malformed" packet — Wireshark artifact, not a protocol error
Wireshark flags frame 297 (the continuation response) as
`Unknown Object\Variation … Exception occurred`. This is a **dissector limitation,
not a reassembly/acceptance failure**:
- Every link-header CRC and every data-chunk CRC in frame 297 is marked `correct` by
  Wireshark itself — bytes and reassembly are intact.
- The master's own log (`experiment_master_1781546243.log`) has **zero**
  error/warning/CRC/timeout/exception lines.
- The master parsed frame 297 and delivered its measurements (the `header_index=1`,
  Group50Var4 indices 97–99 rows come from that fragment). OpenDNP3 handled the object
  variation that Wireshark's decoder does not recognize.

### Conclusion
Validated independently at both the sending and receiving ends: the 2407 B READ
response was chopped into 141 CRC-boundary TCP segments, the master reassembled them
into one DNP3 application message, sent a CONFIRM, and decoded 800 byte-identical
measurements with no errors in its own stack. **CRC-boundary splitting is transparent
to OpenDNP3's two-layer (link + transport) reassembly.**
