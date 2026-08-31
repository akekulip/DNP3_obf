> **Historical.** A dated record of work that preceded the campaign_v1 correction of
> 2026-08-28. Where it names evidence, figures or claims as current, read it as describing
> the `final_read_sbo` state of that date. The active evidence authority is
> `defense4/timing/evidence/campaign_v1/`, the active claim authority is
> `defense4/timing/CLAIMS_AND_LIMITATIONS.md`, and the active figures are
> `paper/rewrite/figures/ndss/`. Kept for provenance.

# Provenance — from silicon to figure

Every number in the timing figures traces back through this chain. Each link is a hash or a
commit, not a description.

## The program that ran

| item | value |
|---|---|
| P4 source | `defense4_rrc_bor_unified12.p4` |
| source sha256 | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| source commit | `c18713840e8376c065909749d451a6bc9e6c5c4d` (2026-08-13 19:38:27 −0400) |
| kept at | `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` |
| compiler | `bf-p4c --target tofino --arch tna -g -DU_BOR`, Barefoot SDE 9.13.2 |
| loaded binary sha256 | `33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa` |
| fit | 12 of 12 ingress MAU stages, 6 egress, 0 errors |

The source snapshot is the blob from `c1871384`, which is the repo HEAD recorded in
`E0_testbed_preservation.md` and predates the first capture by eleven minutes. It is not the
copy at the branch tip: commit `8a6896e` added a documentation header to that file on
2026-08-14, after the campaign, changing its hash to `5b573a59…` without changing the
program. Full account in `evidence/final_read_sbo/audit/EVIDENCE_AUDIT.md` §7.

**This is the combined implementation.** It carries both the timing mechanism and the size
carve in one program. It has not been rewritten, and no rewritten program is presented as
having produced these captures. The paper reports timing only; the size code is present in
the source because it was present on the switch.

## The testbed

Master Vision `192.168.10.1` on switch port dp9 → Tofino-1 → physical SEL-751
`192.168.10.7:20000` on dp64. dp8 and dp10 are switch-internal loopbacks, not inline
devices. dp68 is an internal pktgen/recirculation port with no host-capturable tap, which is
why nothing relay-facing was observed. DNP3 link addresses: master 1, outstation 0.
`net.ipv4.tcp_timestamps=0`, confirmed independently — no capture in the set carries a TCP
timestamp option.

All captures are master-facing, taken on the master host, on one clock.

## Configuration

| parameter | value | how it is known |
|---|---|---|
| mode, Timing OFF arm | OFF | frozen README; corroborated by measured CLRT |
| mode, Obfuscated arm | D4 | frozen README; corroborated by measured CLRT |
| D_A (read path: relay ACK arrival → ACK release) | 20 ms | setup default `--d-a-ms 20`, not overridden by the frozen configure line; corroborated by request-to-ACK ≈ 20.5–20.7 ms; no `tbl_params` readback archived (PARTIAL) |
| D_R (read path: ACK release → response release; = CLRT) | 4 ms | setup default `--d-r-ms 4`; corroborated by CLRT 4.001 ms (PARTIAL) |
| A (OPERATE request → ACK release) | 20 ms | E0 record; setup module `A_DEFAULT_TICKS`; readback rows |
| R (OPERATE request → echo release) | 24 ms | E0 record; setup module `R_DEFAULT_TICKS`; readback rows |
| J codebook | {2, 6, 12} ms fixed passes | E0 record; readback asserts each stored without quantizing to zero |
| `shape_enable` | **1, in both arms** | measured directly from the captures — see below |

`shape_enable` was not recorded in any configuration log. It is established from the wire:
`shape_set.py` documents that shape=1 splits responses into 28+21 bytes and shape=0 passes
them through as a single 49-byte payload, and every response in every timing capture arrives
as 28+21. Because it was on in both arms it is a held constant, not a difference between
them; the Timing OFF to Obfuscated change in CLRT is attributable to the mode toggle alone. The
Timing OFF CLRT reported here is consequently the relay's CLRT through the shaping datapath, not
the relay's unmodified CLRT.

## The captures

Six files, one session, 2026-08-13 19:53–19:57 local (UTC−4). Hashes, per-capture times,
request counts, transaction pairing and per-field evidence are in
`evidence/final_read_sbo/CAPTURE_MANIFEST.csv` and `.json`; file hashes are also in
`evidence/final_read_sbo/MANIFEST.sha256`.

Two files from the frozen package are deliberately absent: `off_probe.pcap`, a warm-up no
result depends on, and `e1_native_size_shapeoff.pcap`, which despite its name was captured
with the timing defense active (CLRT 4.000 ms) and supports only the size claim. Both remain
in the archived E_FINAL package.

## Analysis

`analysis/pcap_reader.py` parses pcapng directly and carries integer nanoseconds. scapy is
deliberately not used: these files are pcapng despite the `.pcap` extension, and scapy 2.4.3
mis-scales pcapng timestamps by a factor of 1000.

`analysis/dnp3_timing.py` defines a transaction once — request, first ACK-bearing reply,
DNP3 response — and everything downstream reads from it. `analysis/timing_stats.py` computes
the distributions, the leakage measures and the classifier with fixed seeds.

## Reproduction

`./reproduce.sh` rebuilds every derived CSV, the statistics and all five figures from the
raw captures into `build/`, then compares against the frozen CSVs and prints the differences.
Raw captures are never written to. Pinned environment in `pyproject.toml` and
`analysis/requirements.txt`; the interpreter is resolved from `$TIMING_PYTHON`, then `uv`,
then a system Python that satisfies the requirements — no path outside the repository.

`tests/test_timing.py` runs 102 checks over the extraction and the statistics.

## What was checked, and what it showed

Regenerated values match the frozen CSVs to within one microsecond throughout. The single
exception is the defended mutual-information point estimate, which is unstable at the fourth
decimal because the predeclared bin grid has an edge at exactly 4.000 ms and 18 percent of
defended observations fall within a microsecond of it. The conclusion it supports is stable
under every grid phase tested. Details in `EVIDENCE_AUDIT.md` §11.
