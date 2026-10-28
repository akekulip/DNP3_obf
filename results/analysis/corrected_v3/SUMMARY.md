# Corrected-v3 TCP reassembly over the retained c72 captures

Date: 2026-10-28. Analysis schema: `c72-corrected-v3-v1`. Checker schema: `sel751-wire-v3`.
Audit reference: `DNP3_c72_Independent_Audit_20261028.md` section 4.1. Plan phase: A3.

## Result

The v3 checker changes no historical field and no evaluation row in either campaign.

| Campaign | Connections | Exchanges (historical / v3) | Field differences | Rows changed | `ok` connections (historical / v3) |
|---|---:|---|---:|---:|---|
| `rc01_hw_c72_eval_20261027_01` (evaluation, 64 blocks) | 256 | 49,408 / 49,408 | 0 | 0 of 49,408 | 256 / 256 |
| `rc01_hw_c72_20261027_02` (qualification, 10 blocks) | 34 | 2,440 / 2,440 | 0 | 0 of 2,440 | 33 / 33 |

Qualification block 10 trial t3 (`10_d20_loss_full`) keeps its recorded FAIL under v3, with the same five
failures:
1. The master records, counts and plan differ from the frozen expected denominators.
2. The complete planned master denominators are missing or failed.
3. The master transaction failed at OPERATE.
4. OPERATE point 1 has status TIMEOUT.
5. OPERATE point 3 has status TIMEOUT.

"No row change" was the stated expectation for the evaluation captures. The qualification and recovery captures
were reported as found, and they also show no change, for the reasons below.

## What was run

```bash
python3 scripts/analysis/corrected_v3.py --output results/analysis/corrected_v3
python3 scripts/analysis/corrected_v3.py --checker-root FROZEN_TREE --output results/analysis/corrected_v3/control_frozen_v2
```

For every retained connection, the script re-runs `relay_check.analyze` on the retained `out.pcap`, `in.pcap`,
`master.json` and `result.json`. It uses the arguments that `campaign_base.relay_verdict` used:
- the master port from `trial.json` (for c2 of the reconnect block, plus `reconnect_port_offset` = 1000);
- `READ` = the trial's reads and `SELECT` = `OPERATE` = `checks.sbo_count(traffic)`;
- the block config's `read_schedule`;
- the two `relay_verdict` post-checks;
- `close_checks` for the persistence and reconnect connections.

Each v3 report is compared with the historical `relay_wire.json`:
- per connection: `ok`, failures, retransmissions, capture drops, artifacts, packet-record hashes and exchange
  count;
- per exchange: operation, workload, ACK timestamp, `complete_clrt_us`, piggyback, and the application result;
- per span: location, sequence range, offsets, first and complete timestamps, `actual_payload_lengths`, wire bytes
  and packet indices.

`eval_rows.trial_rows`, the extractor behind `rows.csv`, then runs on both reports, and every row field is
compared. The fields that exist only in v3 (`unique_bytes`, `packet_bytes`, `retransmitted_bytes`,
`retransmitted_segments`) are additions. They are not counted as differences.

## Control: the frozen v2 checker through the same pipeline

The control materializes `scripts/checks` and `scripts/hardware/active_harness` from commit `032df7989`. Its
`relay_check.py` hashes to `11bc6df72a13…`, equal to both campaign freezes. Run through the same script, it
reproduces the historical record for all 290 connections, with 0 differences. The argument reconstruction therefore
reproduces the campaigns' own verdicts, so any v3 difference would have come from v3 itself. Its outputs are in
`control_frozen_v2/`. Its records file is named `connections_v3.jsonl.gz`, but every record in it carries
`"schema": "sel751-wire-v2"`.

## Why nothing changed

- Every located span was delivered by exactly one first-arriving packet: 98,816 of 98,816 evaluation request and
  response spans, and 4,880 of 4,880 qualification spans. Coalescing, resegmentation and partial overlap, the cases
  where v2 miscounted, do not occur in these captures.
- Every retransmission here is an identical full copy of an earlier segment. The v2 count of repeated
  `(seq, payload)` pairs and the v3 count by byte overlap are therefore equal.

| Campaign | Direction | Retransmitted segments | Retransmitted bytes | Connections |
|---|---|---:|---:|---|
| evaluation | master to relay | 16 | 400 | 16, all on the first request (25 B each) |
| evaluation | relay to master | 0 | 0 | 0 |
| qualification | master to relay | 3 | 77 | 3, all on the first request |
| qualification | relay to master | 6 | 539 | 6, in the loss blocks |

In the loss blocks, the master-NIC capture records the intentionally dropped first copy before the host firewall
discards it. Both versions time the span from that first captured copy.

## Behaviour changes in v3 (future runs)

- A span's `packets` and `actual_payload_lengths` list only the packets that first delivered its bytes. The "response
  acknowledges exactly its request" check therefore ignores every retransmitted copy, not only identical ones.
- Per span, `packet_bytes = unique_bytes + retransmitted_bytes`. The per-direction `retransmissions` count is now the
  number of segments carrying an already-captured byte.
- `eval_watchdog.retransmitted_exchanges` still detects retransmissions by `(seq, payload)` duplicates. It would miss
  a resegmented retransmission; this is a remaining limitation of that watchdog.

## Bindings and scope

- `input_manifest.json` holds the SHA-256 of all 2,100 files read. It also records the checker-file hashes against
  both freezes and the Python version (3.8.10). Among the checker dependencies, only `relay_check.py` differs from
  the freezes.
- `diff.json` holds the per-connection comparison. `connections_v3.jsonl.gz` holds the compact v3 result per
  connection.
- Nothing under `results/hardware/` was written.
- This is not a re-verdict of the blocks. The switch-counter gates, standards verdicts and loss-target checks were
  not re-run. Historical verdicts keep the `sel751-wire-v2` checker they were bound to (`results/analysis/
  replay_frozen/`).

TDD evidence: `tdd_red_green.log`. The RED run against the unmodified checker had 9 failures and 2 passes; the 2
that passed are conflicting-byte guards that v2 already enforced. The GREEN run had 11 passes.
