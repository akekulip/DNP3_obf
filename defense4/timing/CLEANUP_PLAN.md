# Cleanup plan and disposition

Every candidate touched by this cleanup, classified, with the reason. Written before the
moves were made and kept as the record of what happened to what.

Classifications:

* **KEEP ACTIVE** — belongs in the active timing authority
* **MOVE TO HISTORY** — kept in the tree, out of the active path, path mapping documented
* **ARCHIVE BY TAG/BRANCH** — not carried onto this branch; recoverable from the tag, the
  original branch, the bundle, or history
* **DUPLICATE SAFE TO REMOVE** — proven identical to another copy
* **GENERATED REBUILDABLE** — rebuilt by `reproduce.sh`, not tracked
* **UNRESOLVED** — cannot be classified without new evidence or a decision

---

## Implementation

| item | class | reason |
|---|---|---|
| `defense4_rrc_bor_unified12.p4` @ `c1871384` (sha `7ce30494…`) | KEEP ACTIVE | the exact source compiled into the loaded binary; copied to `implementation/exact_experiment_source/`, unmodified |
| same file at branch tip (sha `5b573a59…`) | KEEP ACTIVE, elsewhere | stays where it is under `defense4/size/native_parity/p4/`. Documentation header added 2026-08-14, after the campaign. Not presented as the experiment source |
| `defense4_rrc_bor_unified12_setup.py`, `defense4_rrc_setup.py`, `defense4_caseA_setup.py` @ `c1871384` | KEEP ACTIVE | the control-plane import chain as it stood at capture time |
| `relay_read_g10_23.py`, `relay_sbo_operate_guarded.py`, `relay_operate_guarded.py`, `dnp3_wire.py` @ `c1871384` | KEEP ACTIVE | READ driver and guarded SELECT/OPERATE drivers |

The embedded size code inside the P4 is **not** removed. It was on the switch when the
captures were taken; removing it would misrepresent what ran.

## Evidence

| item | class | reason |
|---|---|---|
| `e1_native.pcap`, `e2_def_read.pcap`, `e2_def.pcap`, `sbo_j2/j6/j12.pcap` | KEEP ACTIVE | the six timing captures |
| `native_txn.csv`, `defended_read_txn.csv`, `defended_txn.csv`, `sbo_j{2,6,12}.csv`, `sbo_all.csv` | KEEP ACTIVE | timing-derived; `sbo_all.csv` verified to be exactly the concatenation of the three J files |
| `readbacks/` (4 files) | KEEP ACTIVE | configuration provenance, including the file that reports the unexplained failure |
| `VERDICT.json`, `verdict_stats.json`, `E0_testbed_preservation.md` | KEEP ACTIVE | frozen reference, copied into `evidence/final_read_sbo/audit/` |
| `off_probe.pcap` | ARCHIVE BY TAG/BRANCH | 8 warm-up READs; referenced only by manifest files; no result depends on it |
| `e1_native_size_shapeoff.pcap` | ARCHIVE BY TAG/BRANCH | size evidence. Its CLRT is 4.000 ms — the timing defense was active — so it is not a timing baseline. Byte-identical to `h1a_defoff_100.pcap` |
| `size_verdict.csv` | ARCHIVE BY TAG/BRANCH | size evidence |
| `figs/FIG-1 … FIG-10` (frozen) | ARCHIVE BY TAG/BRANCH | superseded by fig01–fig05; FIG-5 is a size figure |
| `scripts/size_analysis.py`, `scripts/size_reconstruct.py`, `scripts/fig5_segment_size.py` | ARCHIVE BY TAG/BRANCH | size analysis |
| `scripts/clrt_extract.py`, `sbo_timing.py`, `e4e5_analysis.py`, `fig1–4,6,7`, `_figstyle.py` | ARCHIVE BY TAG/BRANCH | superseded by `analysis/`, which is self-contained; the originals stay in the frozen package |
| `hw_campaign_20260813T172014Z/` (94 files) | KEEP ACTIVE, in place | the campaign record that resolves the readback, the two binaries and the shape semantics. Left under `defense4/size/native_parity/evidence/` |

## The duplicate E_FINAL

| item | class | reason |
|---|---|---|
| `defense4/defense4_release/evidence/E_FINAL/` | DUPLICATE SAFE TO REMOVE — **not removed** | proven identical to `defense4/size/native_parity/evidence/E_FINAL/` by shared git tree `1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c` |

Equality is proven, so removal would be safe. It was **not** removed. The release package is
a coherent self-contained artifact and deleting one of its directories would break it for no
gain; the active timing tree carries only its own selected subset, so this branch does not
contain two identical full E_FINAL trees plus a third. If the duplicate is to go, it should
go with the rest of the release package, as one decision.

## The former `defense4/timing/`

| item | class | reason |
|---|---|---|
| `defense4/timing/{analysis,bootstrap,campaigns,control,evidence,figures,p4,probes,run,tests}` | MOVE TO HISTORY | 1,106 files of earlier timing-core development moved by `git mv` to `defense4/timing/_history/`. Checked first that no frozen result depends on any of it: E_FINAL's `reproduce.sh` and all its scripts reference only paths inside E_FINAL, and the E-phase program was the unified one, not the Case-A program archived here. Path mapping is mechanical — insert `_history/` after `timing/`. Recorded in `_history/README.md` |

## Generated

| item | class |
|---|---|
| `defense4/timing/build/` | GENERATED REBUILDABLE — gitignored, rebuilt by `reproduce.sh` |

## Unresolved

| item | why |
|---|---|
| the assertion behind `RESULT: FAIL (n_fail=1)` | cannot be identified from anything archived. Configuration proof stays PARTIAL. `EVIDENCE_AUDIT.md` §6 |
| per-capture driver invocations and expected request counts | no per-run driver log survives for the E phase |
| the relay's unmodified native CLRT | no capture exists with both timing and size interventions off; would need a new campaign, which needs authorisation |

## Recoverability

Nothing classified ARCHIVE is deleted anywhere. All of it stays on
`origin/defense4-size-native-parity-crc-split` at `8a6896e`, in the tag
`archive/defense4-full-before-timing-cleanup-20260824`, in the bundle at
`/home/philip/Projects/DNP3_obf-before-timing-cleanup-20260824.bundle`, and in history. The
files also remain on this branch under `defense4/size/native_parity/evidence/E_FINAL/`; what
"archive" means here is that they are not carried into the active timing tree, not that they
were removed.
