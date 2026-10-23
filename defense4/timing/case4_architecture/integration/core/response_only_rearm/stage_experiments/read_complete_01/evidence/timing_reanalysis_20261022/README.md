# Transit versus prior receive silence, corrected (offline, 2026-10-22)

Offline reanalysis of retained captures only. No testbed contact, no model, no compiler.

## Why

`../idle_gap_probe_20261022/localize.py` measured receive idleness up to each packet's ARRIVAL. When nothing else
arrives during the transit, that idleness equals the prior silence plus the transit itself, so a slow packet is
forced into the ">= 2 ms idle" bucket. The "27-66 us after receive activity, ~2 ms after >= 2 ms idle" result
(`COMPLETION_RECORD.md` lines 21-23) is produced by that definition.

## Definitions

- **silence_tx (corrected):** time from the last `in.pcap` record to this packet's TRANSMIT timestamp in `out.pcap`.
  It is measured before the packet entered the path.
- **silence_rx (old):** time from the last `in.pcap` record to this packet's arrival. It is kept and labelled.
- **transit:** `t(in.pcap) - t(out.pcap)`. Both captures come from tcpdump on the same Vision parent NIC
  `enp59s0f0np0` (`-Q out` and `-Q in`), so they share one host software clock. The pcap records have microsecond
  resolution. `timing.json` marks the timebase `declared_capture_contract_not_calibrated`.
- **Capture filter:** `tcp and host 192.168.10.61 and host 192.168.10.62`. Any other traffic on the NIC is
  invisible, so silence is an upper bound.
- **Exchange-level matching:** the readout's own stream reassembly and DNP3 fragment pairing
  (`analysis/hw_read_readout.py` `stream`/`fragments`), applied to request first/complete frames and response
  first/complete frames. In every arm each response is one TCP segment, so first equals complete.
- **Packet-level matching:** packets are keyed on the TCP 4-tuple, seq, ack, flags and payload. In the padded arms
  (`size_only`, `combined`) almost nothing matches: of 587 packets only 5 match, because the switch renumbers
  seq/ack on every packet, not only on the padded responses. Only exchange-level pairing is valid there.

## Files

- `transit_silence.py BLOCK... --out results.json`: computes both definitions, every exchange and packet row,
  bucket tables and matching metadata.
- `summarize.py results.json > tables.md`: the full tables (block x arm x measure x class x bucket). Each cell is
  n / median / p90 / p99 in microseconds, nearest rank.
- `results.json` (sha256 `9afe05da08517cd20bd160efccbddd6d6916446e578a039249599bf22e92a271`) and `tables.md`.

## Result (corrected definition, off arms: no T, no padding)

| block, off arm | request transit, silence < 0.5 ms | 0.5 to 2 ms | >= 2 ms |
|---|---|---|---|
| c25_02 | n75: median 124, p90 2074 | n43: median 1275, p90 3332 | n75: median 1062, p90 2216 |
| m11_09 rxdiag | n72: median 146, p90 2133 | n43: median 1248 | n78: median 889 |
| m11_09 cpulat | n77: median 38, p90 2052 | n48: median 1314 | n68: median 1135 |
| m11_09 b08-era | n78: median 1835, p90 2152 | n39: median 1100 | n76: median 873 |

- **Responses cannot test the hypothesis in this design.** The 5 ms netem response-delay fixture puts nearly every
  native response transmit at least 2 ms after the last receive in every arm. Response transit in that bucket (c25_02
  off arm): OPERATE median 1556 us, READ-integrity 1267 us, READ-mixed 1136 us, SELECT 1351 us. p90 is about
  2.1 ms and p99 is 3.4 to 5.5 ms.
- **No dose-response.** SELECT requests sent about 26 ms after the last receive have a median transit of 0.9 to 1.2 ms.
  READ requests sent about 1.2 ms after the last receive have a median of 1.0 to 1.3 ms. Silence between 0.25 ms and
  more than 5 ms gives the same distribution: medians of 1.0 to 1.9 ms, with p90 at 2.0 to 2.2 ms.
- **What survives:** packets sent within about 50 to 200 us of a receive are often fast. Outstation ACKs sent about
  28 us after a receive have a median of 50 us, yet their p90 is still about 2.1 ms. The rule is not consistent at
  equal silence: OPERATE requests sent about 175 us after a receive have a median of 88 us in c25_02 and 1905 us in
  rxdiag.
- **Circularity, demonstrated:** the c25_02 off-arm OPERATE requests all fall in the corrected < 0.5 ms bucket.
  The old definition splits the same packets into 36 fast ones (median 57 us) and 27 "idle" ones (median 1995 us).
- **The slow mode is not triggered by a later Vision transmit.** In the off arms, 0 to 2 of roughly 300 slow
  packets had any Vision transmit between their own transmit and their arrival. Arrivals also show no consistent
  phase-locking to a fixed period: the best periods differ by block, which is noise from scanning many periods.
- **Prior "124 vs 1,275 us" figures:** both medians are reproduced. The 124 us median is requests in the < 0.5 ms
  bucket. The 1,275 us median is the 0.5 to 2 ms bucket for requests, or the pooled requests and responses in the
  >= 2 ms bucket (corrected `localize.py`). The contrast is not a threshold: the < 0.5 ms bucket has p90 2074 us,
  and the >= 2 ms request bucket has median 1062 us.
- **Timing arms:** transit includes the designed holds. OPERATE requests take a median of 3.1 to 4.4 ms (op_j is
  2.4 ms). The outstation ACK takes a median of 6.3 to 6.7 ms and responses 3.1 to 3.7 ms. These are not path
  delays and are not bucketed for inference.

## Config and measurement audit

- The fixture filter lengths are correct for campaign 02. `vision_run.py:135` lists IP lengths 89, 131, 181, 287
  and 77. Padded 181 and 311 are not needed, because the outstation always sends native bytes and padding happens
  in the switch. Piggyback is 0 of 193 in every campaign-02 arm, which shows the filter took effect.
- Provenance gap: `casea_state()` (`vision_run.py:161-163`) records the route and qdisc but not the u32 filters,
  so `state.txt` cannot show which lengths were delayed.
- Units are consistent. Installed `set_params(da=7815, ...)` (`install.log:34`) equals
  `ceil((ns + 512) / 256)` from `t_config.py:27-44` for da, readiness, cap, gap, op_j and pb. c25 and the m11_09
  controls use identical `timing_params_ns`. No deadline appears on the wrong class: only OPERATE requests are held
  in T arms, while READ and SELECT requests match off.
- The `rxdiag` size_only trial failed (master rc 3, 13 frames out, 4 in, 0 exchanges), and rxdiag has no combined
  arm.
- tcpdump reports "received 1174, captured 587" per direction with 0 kernel drops (the sum of both directions).
