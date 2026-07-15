# Replay & Split Delivery — `from_live` large response

Validates the supervisor's staged plan on the freshly captured **large multi-fragment**
response. The TCP replay/split server impersonates the outstation; the master must
believe it is still talking to a real DNP3 outstation. This phase is **byte-preserving**:
`chunk_1 + chunk_2 + … == original_response_bytes` — no DNP3 re-framing, no padding.

## Topology
```
Master (Vision)            TCP Replay/Split Server            (real outstation stopped)
10.10.54.19  ── READ ──▶   10.10.54.158:20000  (Hulk)
```
- Dev/analysis box (where this was validated over loopback): `10.10.54.133`.
- DNP3 link addresses: master = 1, outstation = 10 (frames `Dest:1 Source:10`).

## Step 1–2 — normal capture (done)
Live capture `payloads/from_live/` (master 10.10.54.19 ↔ outstation 10.10.54.158:20000).
A single integrity READ (`orig_0004`, 18 B) produced **multiple DNP3 response fragments**:
`resp_0004` 292 B + `resp_0005` 1168 B + `resp_0006` 947 B = **2407 B** across 3 TCP
segments. Confirms OpenDNP3 naturally splits a large response.

## Replay artifact
`payloads/from_live/read_response_full.bin` = `resp_0004 ++ resp_0005 ++ resp_0006`
(2407 B). Verified with `dnp3_frame_codec` / `dnp3_aware_splitter`:
- **9 link frames, all CRCs valid**, codec round-trip byte-identical.
- **1 APDU** (transport `SEQ 3..11`, FIR on first / FIN on last), app payload 2044 B,
  app-control `0xa3`, func `0x81` (RESPONSE).

## Step 5 — exact replay (`--split-mode full`)  ✔ (loopback + real rig)
Server: received 24-byte READ, sent 2407 B verbatim in **1 chunk**.
Master: link accepted all 9 frames (`PRI_UNCONFIRMED_USER_DATA Dest:1 Source:10`),
transport reassembled `SEQ 3 (FIR=1,FIN=0)` … `SEQ 11 (FIR=0,FIN=1)` → one APDU,
application parsed `FUNC: RESPONSE IIN:[0x02,0x00]`, `OnReceiveIIN` fired, clean exit.
**SOE rows delivered = 0** — expected: the replayed app-sequence does not match an
in-flight poll of this live master session (see `replay_results.md`). Not a bug.

## Step 6 — split delivery (`--split-mode fixed --fixed-size 40 --delay 10ms`)  ✔ (loopback + real rig)
Server: split into **61 chunks** (reconstruction == original verified), sent 40 B each
10 ms apart (~600 ms total). Master: reassembled the **identical** 9 segments
(`SEQ 3..11`) and parsed the **same** `RESPONSE IIN:[0x02,0x00]`. Fragmenting the
response across 61 TCP writes changes nothing the master sees — **TCP boundaries are
irrelevant to DNP3 reassembly**.

## Step 7 — DNP3-aware CRC-boundary split (`--split-mode crc --blocks-per-chunk 1`)  ✔ (offline + real rig)
The intended "DNP3-aware splitting" direction: cut the stream **at its existing CRC
boundaries** so every chunk ends on a CRC that is **already valid** — reuse the CRCs,
**recompute nothing**, concatenation byte-identical. (`dnp3_crc_splitter.DNP3CRCSplitter`,
NOT the recompute-based transport re-segmentation in `dnp3_aware_splitter.py`.)
- **Offline:** 2407 B → **141 CRC blocks**; at `blocks_per_chunk=1` all 141 chunks end on
  an already-valid CRC (verified via `dnp3_crc.verify_crc`, not recomputed); rejoin
  byte-identical. Coarser: 2/4/8 blocks → 71/36/18 chunks, all reconstruct.
- **Real rig:** Hulk served the 141-chunk CRC-split response (5 ms apart) → Vision master
  reassembled the **identical** 9 segments `SEQ 3..11` → `RESPONSE IIN:[0x02,0x00]`, clean
  exit. A structure-aware split on real CRC boundaries is transparent to the master. ✔
- NB (design doc Approach A): a CRC block is **not yet a standalone link frame** (no
  `0x0564`/address header); wrapping each block as its own addressable frame is the planned
  next build.

## Conclusion
A plain TCP socket server can impersonate the outstation well enough for an OpenDNP3
master to fully ingest/parse the captured large response, and arbitrary TCP-write
splitting (with delays) is transparent to the master. Measurement *delivery* still
requires matching the live app-sequence (future in-flight work), not this phase.

## Run on the rig (Hulk = outstation host)
```bash
# On Hulk (10.10.54.158): stop the real outstation, free the port
sudo fuser -k 20000/tcp

# Step 5 — exact replay
python3 replay_tools/dnp3_split_replay_server.py \
  --host 10.10.54.158 --port 20000 \
  --response payloads/from_live/read_response_full.bin \
  --split-mode full --hold-after-response-sec 6 --log-dir logs/replay

# Step 6 — split delivery
python3 replay_tools/dnp3_split_replay_server.py \
  --host 10.10.54.158 --port 20000 \
  --response payloads/from_live/read_response_full.bin \
  --split-mode fixed --fixed-size 40 --delay-between-chunks-ms 10 \
  --hold-after-response-sec 6 --log-dir logs/replay
```
```bash
# On Vision (10.10.54.19): point the master at Hulk
python3 pydnp3_harness/experiment_master.py \
  --host 10.10.54.158 --port 20000 --master-addr 1 --outstation-addr 10 \
  --action scan-all-classes --repeat 1 --wait-after-action 6 \
  --csv logs/master/from_live_soe.csv --log-dir logs/master
```
Validated 2026-06-11 over loopback on 10.10.54.133. **Rig-validated 2026-06-12**:
split server run on Hulk `10.10.54.158:20000` (real outstation stopped), master driven
from Vision `10.10.54.19` — Step 5 (1×2407 B) and Step 6 (61×40 B, 10 ms) both produced
the identical master-side reassembly (`SEQ 3..11` → `RESPONSE IIN:[0x02,0x00]`, 0 SOE
rows). Rig restored afterward (real outstation `DB_SIZE=100` brought back up on Hulk).
