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
| `e2_def_read.pcap` | `6e8e77dab757881c6b44aa20cbb9d6edc68fbbe968448cb27545a1a614b3d11a` | Timing ON |
| `e2_def.pcap` | `c550b549db46d717d5bdb27547892a64f2a3a94601483912c5a7f3d5fd619297` | Timing ON |
| `sbo_j2.pcap` | `66a4ba79688414562f3405d06b4bfb744514ff5139007d608ffc6a142893345b` | Timing ON |
| `sbo_j6.pcap` | `602769a5167f8a5c3ac581fc017f6d936bfec0eca295742a202a3d35869b8da2` | Timing ON |
| `sbo_j12.pcap` | `5d397de1e08dffdb5d0d44cdc23d4e18397db01b142c6d08ba6571cfa3040764` | Timing ON |

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

## Analysis and figure code (`defense4/timing`, commit `06f472c`)

| script | sha256 |
|---|---|
| `analysis/pcap_reader.py` | `a44f10feef24ecb0d60282f5ac4556d83ce011bd24c82e854d0980cf7d301fa2` |
| `analysis/dnp3_timing.py` | `70d9b1c377bfe42ccd8f259286e1efb5aeca960ead225076ed03849c8804a07c` |
| `analysis/extract_clrt.py` | `d9c9e19529f86ea0057c615c72422b9b40684d3ecb0886dee9a7336b7d7b3554` |
| `analysis/extract_sbo.py` | `5134f61d60633487c8f4e656cd56b93953766af35dcf87950a11fdc65e51a4e9` |
| `analysis/timing_stats.py` | `a652bfd99db950ff0c86d2a5d2e7b20423ffe5f43ed88d3ad966b5a317ab33b0` |
| `analysis/figstyle.py` | `d3ad87323ba61b426ea0e43b16cb3e7aacacde83d2ea5bbfe917b86db980b448` |
| `figures/source/_common.py` | `0ed9903f9db93268f3ea9c2abe0e2e967b25379bc873821f685a0b50dc2afb6d` |
| `figures/source/fig01_clrt_read_select_before_after.py` | `9e0939678ce9ee2dd75d3b1af90ed20276a524011f5133149fce1d68b55de6a4` |
| `figures/source/fig02_clrt_ecdf_before_after.py` | `e5afa2d00a49210a73991c82998b22bf7d84442ef4143d5d26f702b165cc39b0` |
| `figures/source/fig03_timing_feature_overlap_before_after.py` | `cdba06756f63c7295fffc0bbd66e5b183351e85734b9f7618b1dcb8b401e0333` |
| `figures/source/fig04_sbo_operate_timing_by_j.py` | `0be5377ba652b37f5c86634158211abdf06874133951c29320fce03f2da2146b` |
| `figures/source/fig05_timing_leakage_summary.py` | `20e88cd75dfc01c929b03754ab5e6124cb7c00d80b5f2df4d7e8ec3e442f2590` |

Capture parsing uses `pcap_reader.py` with integer nanoseconds throughout; scapy is not a
dependency (older scapy mis-scales these pcapng files by 1000).

## Output figures (`paper/rewrite/figures/timing/`)

| file | sha256 |
|---|---|
| `fig01_clrt_read_select_before_after.pdf` | `cf9a4ae9a3828c09016839e871ae6f3eafb4acd95251ff6a65d53b6138edd234` |
| `fig01_clrt_read_select_before_after.png` | `a4ef4147b8e63f12b44081fa10e9800e75d12d40fc4c3330420047659e68443f` |
| `fig02_clrt_ecdf_before_after.pdf` | `69a882a5d288d36f799a33ec2f249a3e9479a5eab120fa36cff59e410d208481` |
| `fig02_clrt_ecdf_before_after.png` | `ffea6120f4bcdb2fad248c5700a243b5533f9efec8d5d1784d10d619d9d92cd8` |
| `fig03_timing_feature_overlap_before_after.pdf` | `4de9993dc1e1991883435f8257c36cb2f290f53d595d5611a4f3924c1a898d21` |
| `fig03_timing_feature_overlap_before_after.png` | `6a13824574bc032fe613588ff1252ae7cfb07b603841ad7a115ff2c5b179f286` |
| `fig04_sbo_operate_timing_by_j.pdf` | `0a2d515565d0c910f4b7c1cc9bad54ca0232f1a9b13a6b21c9667b39c290458a` |
| `fig04_sbo_operate_timing_by_j.png` | `584b49860981c0b02bfb8032a2378158b9d509b63c91aca72cc9ef02d83b3991` |
| `fig05_timing_leakage_summary.pdf` | `9751bf73843d4226afe03042e6cc03f6a68a76c33b68e1ccdf1ee3e41d8b9479` |
| `fig05_timing_leakage_summary.png` | `97ca4d486b64025e246b3f89eac200e3916e3d703e57896ad10b320a8c5b2207` |

Produced under Python 3.8.10 / matplotlib 3.7.5 (`defense4/timing/figures/publication/ENVIRONMENT.txt`).

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
