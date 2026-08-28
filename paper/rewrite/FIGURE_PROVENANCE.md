> **Historical.** This document describes the `final_read_sbo` evidence and the five-figure
> manuscript that preceded the campaign_v1 correction of 2026-08-28. It is kept for provenance.
> The active evidence authority is
> [`defense4/timing/evidence/campaign_v1/`](../../defense4/timing/evidence/campaign_v1/), and the
> active figures are `paper/rewrite/figures/ndss/`.

# FIGURE_PROVENANCE.md — silicon to figure, by hash and commit

Every number in the five figures traces through this chain. Each link is a hash or a
commit, not a description. Full detail lives in `defense4/timing/PROVENANCE.md` and
`defense4/timing/evidence/final_read_sbo/audit/EVIDENCE_AUDIT.md` in this same repository.

## The program that ran

| item | value |
|---|---|
| P4 source | `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` |
| source sha256 | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| source commit | `c18713840e8376c065909749d451a6bc9e6c5c4d` (2026-08-13 19:38 −0400, 11 min before the first capture) |
| loaded binary sha256 | `33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa` |
| compiler | bf-p4c, Barefoot SDE 9.13.2, `--target tofino --arch tna -DU_BOR`; 12/12 ingress stages |

This is the **combined** program: one binary carrying both the timing mechanism and a size
carve, exactly as it ran. It is kept unmodified because it is what produced the captures. The
paper evaluates **timing features only**; the size processing it contains is not evaluated,
not claimed, and not figured.

## The captures (master-facing, one session, 2026-08-13 19:53–19:57 −0400)

| capture | sha256 | arm |
|---|---|---|
| `e1_native.pcap` | `4d0dc0c810124bb44624f2818918d7ac098a0d2d7995f32df68e8849ac9c97be` | Timing OFF |
| `e2_def_read.pcap` | `6e8e77dab757881c6b44aa20cbb9d6edc68fbbe968448cb27545a1a614b3d11a` | Obfuscated |
| `e2_def.pcap` | `c550b549db46d717d5bdb27547892a64f2a3a94601483912c5a7f3d5fd619297` | Obfuscated |
| `sbo_j2.pcap` | `66a4ba79688414562f3405d06b4bfb744514ff5139007d608ffc6a142893345b` | Obfuscated |
| `sbo_j6.pcap` | `602769a5167f8a5c3ac581fc017f6d936bfec0eca295742a202a3d35869b8da2` | Obfuscated |
| `sbo_j12.pcap` | `5d397de1e08dffdb5d0d44cdc23d4e18397db01b142c6d08ba6571cfa3040764` | Obfuscated |

Path: `defense4/timing/evidence/final_read_sbo/raw_pcaps/`. File names are the original
capture names, kept for hash continuity with the frozen evidence package; `e1_native.pcap` is
the **Timing OFF** arm, not an unmodified device baseline.

**`shape_enable` was 1 in both arms**, established from the wire: every relay response in
every capture arrives as two TCP payloads of 28 and 21 bytes, where a capture with the carve
disabled shows one 49-byte payload. Shaping is a held constant across the arms, so the
comparison isolates the timing-mode change; it is not a pure timing-only binary and not a
pure native-versus-defended experiment.

## Derived data

| file | sha256 |
|---|---|
| `derived_csv/native_txn.csv` | `00d32b843d8a63d66158b0c112bd5134a72ff6fe7f30ba7d98306e142fbfca6f` |
| `derived_csv/defended_read_txn.csv` | `3d4dbf3834cb614447f08a5c6585a6103a9cb9dc08d7ac2a57f4a7add9cc5316` |
| `derived_csv/defended_txn.csv` | `8e197157b5976fc0cda8108bb976c755834869d4a95a2e838aedc3e8d026833c` |
| `derived_csv/sbo_j2.csv` | `d7c1c99dda95d1085f8b1cd59e753af959272513238850f5c5a84fffa088c914` |
| `derived_csv/sbo_j6.csv` | `10f631fd6bec26836dce9e5dcf37af61634acd6e46b17105e71eab3f29da264e` |
| `derived_csv/sbo_j12.csv` | `62db1054009e532bf77c1f270a07327d232d67c824964b703415c2bae23d4bf1` |

Regenerated CSVs agree with these on every measured value to within one microsecond (one unit
in the last printed digit; integer-nanosecond versus float64-epoch arithmetic).

## Analysis and figure code (`defense4/timing`, at the commit recorded in `git log` for this file; legend label `Obfuscated` since 2026-08-26)

| script | sha256 |
|---|---|
| `analysis/pcap_reader.py` | `a44f10feef24ecb0d60282f5ac4556d83ce011bd24c82e854d0980cf7d301fa2` |
| `analysis/dnp3_timing.py` | `70d9b1c377bfe42ccd8f259286e1efb5aeca960ead225076ed03849c8804a07c` |
| `analysis/extract_clrt.py` | `d9c9e19529f86ea0057c615c72422b9b40684d3ecb0886dee9a7336b7d7b3554` |
| `analysis/extract_sbo.py` | `5134f61d60633487c8f4e656cd56b93953766af35dcf87950a11fdc65e51a4e9` |
| `analysis/timing_stats.py` | `a652bfd99db950ff0c86d2a5d2e7b20423ffe5f43ed88d3ad966b5a317ab33b0` |
| `analysis/figstyle.py` | `3491e2c37eedd8cf2e6b557c018f2840d40da35818f5abeea0bb1a82c4ecaca6` |
| `figures/source/_common.py` | `0ed9903f9db93268f3ea9c2abe0e2e967b25379bc873821f685a0b50dc2afb6d` |
| `figures/source/fig01_clrt_read_select_before_after.py` | `c3f94d7c9a4a606b800fc8ca06427ee243db067fb61b9a5658cb080bbc27b651` |
| `figures/source/fig02_clrt_ecdf_before_after.py` | `ba472e343cd07e163281f35ba8d32d69bdfb764b60d01ade88b87698a2d77a4f` |
| `figures/source/fig03_timing_feature_overlap_before_after.py` | `ce30fb54b9d57b074facd677bb4627a2b5f16b0508c9315932f3a32e47444f0e` |
| `figures/source/fig04_sbo_operate_timing_by_j.py` | `f975cce433a580854626ad80f500af12de6d45dcc8cb99e60cb8f280292362f0` |
| `figures/source/fig05_timing_leakage_summary.py` | `979af303217213508be0f4be7938425365da37fd5525fd412fca1a3129b3c9a1` |

Capture parsing uses `pcap_reader.py` with integer nanoseconds throughout; scapy is not a
dependency (older scapy mis-scales these pcapng files by 1000).

## Output figures (`paper/rewrite/figures/timing/`)

| file | sha256 |
|---|---|
| `fig01_clrt_read_select_before_after.pdf` | `a2259c26f5c5fedd299519c482b35e13924d6e41ee1fee9bca2ad7e2a28e9522` |
| `fig01_clrt_read_select_before_after.png` | `123d650848b3383a06f57c003e7571468670c1d86e6da626bc9109679eb2c80e` |
| `fig02_clrt_ecdf_before_after.pdf` | `ce71e8474f2677cbe5975215897617095dd6f6aed781a2608da7cac808cdb367` |
| `fig02_clrt_ecdf_before_after.png` | `6e9c852d3a76c2c8f415bb16a2f65363ed91f73e8fdefbb099367c4c46c04aa7` |
| `fig03_timing_feature_overlap_before_after.pdf` | `e7af5a2114ea629df30cc832f4ca4ff9e4d99d85430c3c6a151705b7543d8fd7` |
| `fig03_timing_feature_overlap_before_after.png` | `6bb51af6e7d8bf80f15ccf67a77724d551b6457b785e60922a8de1d8b48e089e` |
| `fig04_sbo_operate_timing_by_j.pdf` | `8bfbae4561b03c5913dee402588a373b958d711dcc0f364a586b6664a55195fa` |
| `fig04_sbo_operate_timing_by_j.png` | `2043f3168761c74410704cd5ba7da411c041e6f99d12eec73dbcb8286e986f5c` |
| `fig05_timing_leakage_summary.pdf` | `f040cc33bb5d6e09f506a4ec54343ca54a0151cf7f357aee29f337176cc42b8e` |
| `fig05_timing_leakage_summary.png` | `ed1f0198c5dc3a4b5ba94807b1bdf1a9c5bb51fbe97dc2cb02e1ac4b1c315f40` |

Produced 2026-08-26 under Python 3.8.10 / matplotlib 3.7.5 (`defense4/timing/figures/publication/ENVIRONMENT.txt`).

## Verification status

* Packet-derived results reproduce identically under Python 3.8.10 and 3.12.13; test suite
  102/102 under each.
* All input and output hashes pass; raw captures verify unchanged after every reproduction.
* **Configuration provenance is PARTIAL.** The archived `hw_config_readback.txt` is a
  hand-assembled excerpt ending in `RESULT: FAIL (n_fail=1 n_warn=0)` while showing 25 passing
  rows and no failing one; the failing assertion cannot be recovered from archived evidence.
  The file is retained unedited. The PCAP-derived timing measurements are reproducible
  regardless.
* Relay-facing `T0+J` and exactly-once delivery were never observed (the relay-facing port is
  internal, with no capturable tap).
* A new `shape_enable=0` campaign would be required to establish a truly unmodified native
  timing baseline. None has been run, and no hardware action was taken.

## Regenerating

```sh
cd defense4/timing && ./reproduce.sh          # build/figures/fig0*.{pdf,png}
cp defense4/timing/build/figures/fig0*.{pdf,png} paper/rewrite/figures/timing/
```

Then refresh the hashes here and in `FINAL_FIGURES.md`.

## Schematics (Figures 1–3)

Hand-drawn SVG sources `paper/rewrite/figures/fig_{ladder,observation,design}.svg`, drawn from
`pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`; no measured data. Exported by
`pipeline/export_schematics.sh` (Inkscape 1.x from PATH) to PDF and 600 dpi PNG and mirrored
byte-identically to `defense4/timing/figures/schematics/`. Hashes: `figures/SCHEMATICS.sha256`.
