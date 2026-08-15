# Trace Inventory for Real Size Normalization

Owner: trace inventory lane. Scope: existing offline repository evidence only. No traffic was generated, no SSH/hardware state was changed, and no fixed-cell `C`/`K` parameter was selected.

## Executive Summary

The existing traces are useful for workload sizing but not sufficient to set final fixed-volume cell parameters.

- The physical SEL-751 size evidence is overwhelmingly one small family: admitted READ requests are `20 B`, admitted SELECT/OPERATE requests are `45 B`, and eligible SEL responses reconstruct to `49 B`.
- The current defended physical mechanism changes response packet shape from `[49]` to `[28,21]` but preserves aggregate `49 B`; it is segment-shape evidence, not total-size hiding evidence.
- Physical outliers already exist in committed traces: `18 B` state READ requests and `58 B` state READ responses appear in SBO/select captures and are explicitly non-admitted by the analyzer.
- Software OpenDNP3 loopback evidence exercises larger persistent-stack responses: baseline response `243 B`; fragmentation run carries `292,292,292,292,292,292,103 B` response data, with committed documentation reporting reassembled DNP length `1574 B`.
- Cover-frame and decoy evidence demonstrate arithmetic convergence or bounded software behavior, but the documents explicitly classify those as component/software/computed evidence and note that a parsing observer can recover native size for cover framing.

For S2, these traces should drive the sizing envelope and test plan. For final `C`/`K`, S3 still needs fresh measurement at the actual protected cell boundary and public observation point in the current Vision -> Tofino -> SEL/ION testbed.

## Evidence Classes Found

| Class | Paths | Useful facts | Limits |
|---|---|---|---|
| Frozen physical SEL E_FINAL | `defense4/size/native_parity/evidence/E_FINAL/`, mirrored under `defense4/defense4_release/evidence/E_FINAL/` | 1,380 size-verdict rows; 1,280 defended response vectors `[28,21]`; 100 native `[49]`; all total `49 B`, CRC/checksum valid | Master-facing capture/reconstruction evidence; does not hide aggregate size |
| Native parity hardware campaigns | `defense4/size/native_parity/evidence/hw_campaign_20260813T172014Z/` | READ `[49]` vs protected `[28,21]`; H2 READ/SELECT parity; explicit `58 B` non-admitted state READ responses | Physical OPERATE relay-facing duplicate evidence is not present; mostly SEL-751 |
| READ/SBO baseline/joint analyzer JSON | `hw_rrc_readsbo_20260812T212234Z/analysis.json`, `hw_rrc_joint_20260812T223342Z/analysis.json` | 30 READ + 30 SELECT admitted transactions per run reconstruct to `49 B`; protected joint has `[28,21]`; state READ `58 B` in SBO captures | Analyzer scope is admitted 20/45-byte request profiles plus reported non-admitted state reads |
| Cover-frame gate | `defense4/size/evidence/cover_frame_gate/` | Link/app-context tests pass for individual cover discard; computed convergence `18/45 -> 63 B`; broadcast hazard retained | Not physical, not full TCP for cover injection; parsing observer strips cover |
| Real OpenDNP3 loopback | `defense4/size/evidence/cover_frame_gate/real_channel/` | Real socket/TCP/transport/app loopback captured: baseline `27 B` request -> `243 B` response; fragmented response segments `292 x6 + 103`, plus second `17 B` app fragment | Software loopback on `127.0.0.1`, no relay/switch, cover injection blocked by sandbox |
| SEL vs ION comparison | `defense4/size/native_parity/evidence/ion_comparison/` | SEL and ION differ natively: SEL READ `49 B`, ION READ `17 B`; SEL SELECT `49 B`, ION SELECT `32 B` per document | ION OPERATE not run; user has constrained this phase to current testbed only, not a second SmartNIC/host |

## Observed Packet and Payload Vectors

### Physical SEL-751 E_FINAL

From `defense4/size/native_parity/evidence/E_FINAL/csv/size_verdict.csv` and the release mirror:

| Source pcap class | Rows | Segment vector | Total bytes | Notes |
|---|---:|---|---:|---|
| Native size-shape-off READ | 100 | `49` | 49 | Single response segment |
| Defended READ | 600 | `28|21` | 49 | Aggregate unchanged |
| Defended SELECT | 500 | `28|21` | 49 | Aggregate unchanged |
| SBO J variants | 180 | `28|21` | 49 | 60 each for `J=2/6/12` |

CSV validation summary:

- `rows=1380`
- `class`: READ `700`, SELECT `590`, OPERATE `90`
- `segment_vector`: `28|21` `1280`, `49` `100`
- `total_bytes`: `49` for all `1380`
- `crc_valid=1`, `cksum_valid=1`, `source_copy_escape=0` for all rows

Direct `tshark` payload summaries confirm the packet-length families:

- `e1_native_size_shapeoff.pcap`: request `20 B` x100, response `49 B` x100
- `e2_def_read.pcap`: request `20 B` x600, response segments `28 B` x600 and `21 B` x600
- `e2_def.pcap`: request `45 B` x500, response segments `28 B` x500 and `21 B` x500
- `sbo_j2.pcap`, `sbo_j6.pcap`, `sbo_j12.pcap`: request `45 B` x60 and response segments `28 B` x60 + `21 B` x60, with `sbo_j6.pcap` also containing one `20 B` request and one `58 B` state-read response.

### Analyzer-Reported Physical Transactions

Committed analyzer outputs report:

- Native READ capture: 30 admitted READs, request length `20 B`, response `49 B`, seq vector `[28,21]` in the older size path, response group `10`.
- Native SBO capture: 30 admitted SELECTs, request length `45 B`, response `49 B`, seq vector `[28,21]`; plus 2 non-admitted state READs with response vector `[58]`.
- Joint protected capture: 30 READ + 30 SELECT admitted transactions; both reconstruct to `49 B`; both have seq vector `[28,21]`, arrival vector `[21,28]`; plus 2 non-admitted state READs with `[58]`.
- H1/H2 campaign:
  - `h1a_defoff_100.pcap`: 100 READs, `[49]`, total `49 B`.
  - `h1b_shaping_200.pcap`: 200 READs, `[28,21]`, total `49 B`.
  - `h2_select_120.pcap`: 120 SELECTs, `[28,21]`, total `49 B`; 2 state READ outliers `[58]`.

These are strong fixtures for a regression harness that distinguishes public packet shape from aggregate application size.

### Real OpenDNP3 Loopback

`defense4/size/evidence/cover_frame_gate/real_channel/` is not physical testbed evidence, but it is the best committed persistent-stack size evidence for larger DNP3 responses.

`cap_baseline.pcapng`, `tshark -Y 'tcp.len > 0'`:

| Direction | Payload lengths |
|---|---|
| master -> outstation | `27`, `15`, `21`, `35`, `35` |
| outstation -> master | `243`, `17`, `37`, `37` |

`cap_frag.pcapng`, `tshark -Y 'tcp.len > 0'`:

| Direction | Payload lengths |
|---|---|
| master -> outstation | `27`, `15`, `21` |
| outstation -> master | `292`, `292`, `292`, `292`, `292`, `292`, `103`, `17` |

The directory README records the fragmentation case as real transport reassembly with transport sequence `0..6`, `Reassembled DNP length: 1574`, then a second application fragment.

## Existing Parsers and Utilities

| Tool | Path | Reuse for S3/S4 |
|---|---|---|
| Transaction-aware physical analyzer | `defense4/size/native_parity/analyze_rrc_pcaps.py` | Good baseline for pairing requests/responses by TCP ACK and DNP3 function; can be adapted for fixed-cell public-flow accounting |
| Release size analysis | `defense4/size/native_parity/evidence/E_FINAL/scripts/size_analysis.py` and `size_reconstruct.py` | Good source for CRC/checksum/contiguity checks |
| Transport oracle and reconstruction tests | `defense4/size/offline/transport_oracle.py`, `stream_reconstruction.py`, `test_transport_oracle.py`, `test_transport_repairs.py` | Useful for byte-stream invariants, retransmit/SACK/fail-closed thinking; synthetic, not deployment proof |
| Cover-frame generators | `defense4/size/evidence/cover_frame_gate/src/gen_and_measure.py`, `convergence.py` | Useful for negative controls and arithmetic reachability, not selected proof against a parsing observer |
| Real channel harness | `defense4/size/evidence/cover_frame_gate/real_channel/src/rt_loopback.cpp` and `run_real_channel.sh` | Useful for software persistent-stack smoke tests of cellizer/deceller behavior before hardware |
| Relay harnesses | `defense4/defense4_release/code/harness/relay_sbo_operate_guarded.py`, `relay_operate_guarded.py`, `dnp3_wire.py` | Safety-aware hardware harness starting points, but S0-S2 should not actuate |

## Candidate Size Envelope Inputs

These are inputs, not selected parameters:

- SEL admitted request sizes seen in physical traces: `20 B` READ, `45 B` SELECT/OPERATE request.
- SEL admitted response aggregate size: `49 B`.
- Physical non-admitted state-read response outlier: `58 B`.
- ION comparison document reports native ION response sizes: `17 B` READ/null-error and `32 B` SELECT echo. Since the user constrained the phase to current testbed only and ION exists in that testbed, these should be retained as observed residual-device evidence, not generalized.
- OpenDNP3 software loopback larger responses: `243 B` baseline integrity response; `1574 B` reassembled fragmented response in the 40-binary-points software run.
- Cover arithmetic examples: `18/45 -> 63 B` serialized DNP3-link bytes; READ decoy evidence cited by `SIZE_CANDIDATE_DECISION.md` as `29/59 -> 89 B`.

Initial design implication: if the selected architecture is fixed-volume encrypted cells, `C` must be defined over the encrypted public cell payload domain, not DNP3 serialized-link bytes, TCP payload bytes, or current `[28,21]` segment vectors. `K` must cover the whole protected transaction unit including protocol headers, AEAD nonce/tag/sequence metadata, dummy cells, and direction scheduling.

## Gaps Blocking Final C/K Selection

1. No measured fixed-cell public flow exists yet.
2. No current-testbed capture yet confirms whether the relay-side trusted endpoint will be Tofino CPU punt/reinject, another existing software boundary, or a no-go.
3. No relay-facing capture proves exactly what the relay would receive after decellization; existing docs state dp68 is internal and not a host tap.
4. Existing physical evidence is mostly small SEL objects. It does not bound all DNP3 operations, unsolicited responses, file transfer, time sync, large class reads, cold reconnects, or multi-fragment application responses.
5. Existing cover-frame evidence is unsuitable as the selected proof against a TCP/DNP3 parsing observer because the repository already demonstrates or states the strip-and-recover limitation.
6. Existing OpenDNP3 loopback large-response evidence is software-only and uses 127.0.0.1, not Vision -> Tofino -> relay.
7. Request-direction normalization remains under-measured. The public observer sees request sizes and counts too; physical traces show `20 B` vs `45 B` requests.

## Recommended S3 Measurement Plan

When the design gate opens:

1. Capture at the public encrypted-cell observation point and the relay-cleartext point for the same transactions.
2. Measure both directions: master requests and relay responses.
3. Include at least these workloads: admitted READ, SELECT-only, guarded non-actuating OPERATE if authorized by existing safety protocol, state READ outlier, reconnect/session setup, and a software-only large-read stress case before hardware.
4. Record per-transaction: public packet lengths, public packet count, public total bytes, timing schedule, clear DNP3 request/response lengths, decellized relay byte identity/semantics, dummy-cell count, loss/retransmit behavior, and parser-visible residuals.
5. Treat `C/K` as provisional until replayed through a parser that aggregates by TCP stream and by transaction boundary.

## Verification Performed

Commands run read-only:

- `sed` on committed READMEs, analyzer JSON, and decision records.
- `python3 -c` summaries over committed CSV/JSON files.
- `tshark -r ... -Y 'tcp.len > 0'` over committed pcap/pcapng files.

One attempted Scapy import failed with `PermissionError(1, 'Operation not permitted')` in this sandbox, so this lane did not use Scapy for direct packet parsing. The report relies on committed analyzer outputs plus `tshark` summaries.
