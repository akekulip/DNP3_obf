# Ordered Confirm-Aware Replay — Successful DNP3 Application-Level Replay

The earlier split runs proved TCP-level + stack-parse delivery but **not** DNP3
application acceptance: the single-shot server answered the master's first request
(ENABLE_UNSOLICITED) with the READ response, so the master never issued a READ,
never sent a CONFIRM, and delivered 0 SOE rows.

This phase fixes that with an **ordered, confirm-aware replay** that stays fully
**byte-preserving** (CRC-boundary split, no CRC recompute, no field edits).

## Approach
`replay_tools/dnp3_ordered_replay_server.py` (`DNP3OrderedReplayServer`):
- Reconstructs the request→response sequence from the OUTSTATION-side baseline
  capture (`captures/baseline/Hulk_outstation.pcapng`, extracted to
  `payloads/replay/` with `metadata.json`). Each master request maps to the run of
  consecutive outstation responses that followed it:

  | # | master request | seq | response group | bytes |
  |---|---|---|---|---|
  | 1 | ENABLE_UNSOLICITED | 0 | resp_0001 | 17 |
  | 2 | WRITE | 1 | resp_0002 | 17 |
  | 3 | ENABLE_UNSOLICITED | 2 | resp_0003 | 17 |
  | 4 | **READ** | 3 | resp_0004+0005+0006 | 2407 |
  | 5 | **CONFIRM** | 3 | resp_0007+0008+0009 | 1657 |

- Keeps ONE connection open; on each received master message it sends the next
  response group, **split on existing CRC boundaries**, then waits for the next
  master message (so the master's CONFIRM naturally triggers the final fragment).

## Why it works byte-preservingly (the key insight)
The captured responses carry the **IIN** that drives the master's startup, and a
solicited DNP3 response echoes the request's **application sequence**. Replaying in
capture order keeps the live master on its captured trajectory: its READ lands on
**app_seq 3**, matching the captured READ response (seq 3, CON=1). So the master
**accepts** it — delivers measurements and sends a CONFIRM — with no need to rewrite
the sequence or recompute CRCs. Sequence alignment is achieved by *ordering*, not
by byte modification.

## Results
Wired up behind the no-IP runner: `python split_server.py` (ordered by default).

**Loopback (gambit) and real rig (Hulk split server <- Vision master)** both give
the identical, successful result:

- Server matched all 5 requests in order, including `READ (0x01) app_seq=3` and
  `CONFIRM (0x00) app_seq=3`.
- READ response served as **141 CRC-boundary chunks**; second fragment as **97**.
- **Master sent a DNP3 CONFIRM** (`dnp3.al.func==0`, seq 3) — application-level
  acceptance, the proof the earlier `split_reader.pcap` lacked.
- **`logs/master/soe.csv` = 800 measurements** (binary/analog/counter/time), vs 0
  before.
- On-wire (`captures/replay/ordered_rig.pcap`): outstation→master segments are all
  tiny CRC blocks (18/10/12/7 B), and the master's READ + CONFIRM are present.

## Success criteria (guide §18) — now met
1. Byte preservation: ✅ per group, `b"".join(chunks)==response`.
2. No DNP3 parser/CRC errors at the master: ✅
3. **SOE matches baseline: ✅ 800 measurements delivered** (previously the open item).
4. Valid DNP3 reassembly in Wireshark: ✅
5. DNP3 CONFIRM appears: ✅

Validated 2026-06-12. Still no CRC recompute / no byte modification — within the
current guide phase. See `from_live_split_results.md` for the prior TCP-level work.
