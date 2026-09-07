# Configuration evidence, and what "gate clean" does not mean

Two things this document separates, because conflating them is how a reproduction result gets
mistaken for a provenance result.

1. For each configuration fact, which of three kinds of evidence supports it: **direct
   configuration evidence** (a readback of the device), **source-derived inference** (what the
   program must do, read from the code), or **wire observation** (what the captures show).
2. Reproduction success, provenance completeness and claim validity, which are three different
   things that the phrase "gate clean" has been used to cover.

---

## 1. `shape_enable = 0`: the earlier inference was incomplete, and it can be closed

**The objection is well founded.** The queue audit concluded `shape_enable = 0` from the wire
because "every response is a single 49-byte payload and every capture holds exactly 1,448 frames
and 130,708 bytes in both arms". Equal packet sizes do not, on their own, prove the value of a
configuration bit. In the program the size path is gated on

```
do_shape = shape_enable & payload49          (frozen source line 2514)
```

so `do_shape = 0` is consistent with `shape_enable = 0` **or** with `payload49 = 0`. The audit
did not measure `payload49`, so it could not distinguish them, and `payload49` is exactly the
kind of thing that could have been 0 for an unrelated reason: it is parser-derived and depends on
the TCP option width, and the preservation record shows TCP timestamps were deliberately
**disabled** for the earlier campaign, which changes that width.

**The gap can be closed, and this session closed it, with two measurements the audit did not
make.**

*First, `payload49 = 1` on every response.* The parser marks eligibility in four states, one per
TCP option width, selected on `(flags, data offset, IP total length)`: `dl_p49` at
`(dofs 5, 89)`, `opt4_p49` at `(6, 93)`, `opt8_p49` at `(7, 97)` and `opt12_p49` at `(8, 101)`
(frozen lines 1395 to 1406). The author's comment names the last as "the corpus's TCP-timestamp
case, which is why the previous size layer's total_len==89-only test missed the real relay
response". Measured over all 132 captures, **every one of the 63,360 outstation-to-master data
frames is `dofs = 8`, `total_len = 101`, payload 49 bytes, IP header 20 bytes** — a single
combination, with no exceptions. That is precisely `opt12_p49`, so `payload49 = 1` throughout,
in both arms.

*Second, both forwarding paths would have carved.* With `payload49 = 1`, `do_shape` reduces to
`shape_enable`, and `do_shape` is a **key of both decide tables**. On the pass-through path,
`(CLASS_RESP, …, do_shape = 1)` yields `OUT_RESP_BYPASS_SHAPE` and on the release path
`(ROLE_RESP, …, expired_resp = 1, do_shape = 1)` yields `OUT_REL_DL_SHAPE`; both map to
`cmt_shape()`, which sets `mcast_grp_a = RRC_MGID_49_28` and replicates the response into two
egress copies at dp9, RID 1 carrying bytes 0 to 28 and RID 2 bytes 28 to 49 (frozen lines 2205,
2246, 2311, 2331, 2837, 2891). A carved response is therefore **two frames on the master-facing
link instead of one**, in either arm.

*Therefore.* No capture contains a carve: every response is one frame, and the per-capture frame
count of 1,448 for 480 exchanges is the arithmetic of three frames per exchange plus the
connection's own eight, not four. With `payload49 = 1` measured and both paths keyed on
`do_shape`, `shape_enable = 0` follows for both arms.

**What kind of evidence that is.** It is a **wire observation plus a source-derived inference**,
and it is now a sound one. It is still **not direct configuration evidence**: no device readback
of the bit is archived beyond a one-line `RESULT: PASS` per block (§2). The residual assumption
is that the program on the switch is the program in the frozen source, which
`INSTRUMENTATION_AUDIT.md` §6 shows is itself only PARTIAL. The chain is: *the loaded binary
behaved as though the bit were 0, on every one of 63,360 exchanges, and the source says only a
zero bit produces that behaviour for these frames.*

## 2. The readbacks, and what a one-line readback can carry

Direct configuration evidence for `campaign_v1` is one summary line per block, produced by
`campaign_block.sh` piping `configure-all` through `tail -1`:

```
  cfg: RESULT: PASS (n_fail=0 n_warn=0)
  shape0: RESULT: PASS
```

Its evidentiary limits, stated rather than left implicit:

* **It is an aggregate.** `PASS (n_fail=0)` asserts that no assertion in the run failed. It does
  not carry the asserted values, so it cannot be checked against the intended ones. A run that
  passed while asserting the wrong number reads identically.
* **The rows are gone.** The checker prints every held row, including any `[FAIL]`. `tail -1`
  discards all of them. The retired `final_read_sbo` tree shows exactly why that matters: its
  full-looking readback ends `RESULT: FAIL (n_fail=1 n_warn=0)` while showing no failing row, and
  because no transcript survived, **the failing assertion cannot be identified to this day**.
* **It covers 126 of 132 captures.** The campaign log covers s02 through s22. **s01's six blocks
  have no archived readback line at all**; its manifest asserts "RESULT: PASS (n_fail=0
  n_warn=0) for both arms" as prose with nothing behind it. Three of those six are obfuscated
  blocks, so three captures have no direct configuration evidence for any offset.
* **s03 was restarted.** Its first attempt was interrupted after two blocks and relaunched from
  b1 with identical seeds, which is why the log holds 128 block headers for 126 retained
  captures. The retained captures are from the second attempt.
* **The sweep has no per-point readback at all.** Its offsets come from the archived
  `sweep_points.csv`, and the driver logs record the mode and the codebook but not `D_A`/`D_R`.

## 3. Per-capture evidence classes

`audit_current/outputs/CAMPAIGN_V1_CAPTURE_MANIFEST.csv` carries this per row. Summarised:

| fact | evidence class | status | captures |
|---|---|---|---|
| observation point | direct: the capture command in `campaign_block.sh` | VERIFIED | 132 |
| condition and mode | wire observation cross-checked against the driver log | VERIFIED | 132 |
| `shape_enable = 0` | wire observation + source-derived inference, closed in §1 | VERIFIED for behaviour; no direct readback | 132 |
| `D_A`, `D_R`, `A`, `R` | direct, but only as a one-line aggregate | PARTIAL | 126 |
| `D_A`, `D_R`, `A`, `R` | none archived | UNRESOLVED | 6 (s01) |
| `J` codebook | direct for the configured value; the realized draw is on an uncaptured link | PARTIAL | 66 obfuscated |
| program identity | hash recorded in the provenance JSON; the loaded binary's own compile transcript is not archived | PARTIAL | 132 |
| harness command | direct: the invocation and the preserved driver | VERIFIED | 132 |

## 4. Reproduction, provenance and claim validity are three separate results

The reproduction reports "0 problems" and the publication gate reports "0 problems". Neither
statement means what a reader might take it to mean, so here is what each one covers.

| result | what it establishes | what it does **not** establish |
|---|---|---|
| **Reproduction success.** 22 manifests and 268 entries verified, 132 captures validated, the frozen table matched row by row at 1e-6 ms, 131 tests, byte-identical across two runs | that the published numbers follow deterministically from the archived captures, and that the archived captures are the ones the manifests name | nothing about how those captures were produced, under what configuration, or whether the claims drawn from them hold |
| **Provenance completeness.** | that the captures are hash-stable and that the driver, the topology and the program hashes are recorded | it is **PARTIAL**: readbacks are one-line aggregates for 126 captures and absent for 6; the loaded binary's compile transcript is not archived; the frozen source is not byte-identical to the one in the archived compile log; no kernel or relay configuration was recorded |
| **Claim validity.** | claim by claim, in `CLAIMS_AND_LIMITATIONS.md` and `CLAIM_EVIDENCE_MATRIX_CORRECTED.md` | it is not implied by either of the above. Several claims are bounded by things no reproduction can reach: one device, one campaign, master-facing only, no relay-facing tap, no physical measurement |

**So "gate clean" means the first row and only the first row.** It is a statement that the
analysis is reproducible from the archived inputs. It is not a statement that the configuration
is proven, and not a statement that the claims are established. Where this repository has used
the phrase to suggest more, that was wrong, and the three are reported separately from here on.

A worked example of the difference: the publication gate passes and always has, while
`shape_enable` had no sound proof until §1 of this document, and three captures still have no
direct configuration evidence at all. Nothing in the gate would ever have surfaced either.

## 5. Provenance of this document

Wire measurements regenerated 2026-09-07 over all 132 captures in
`evidence/campaign_v1/s[0-9][0-9]/raw_pcaps/`. Source claims are quoted by line from
`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`, sha256 `7ce30494…`.
Readback coverage is from `evidence/campaign_v1/_bin/campaign_5h.log` and the per-session
`provenance/MANIFEST.json` files. The frozen readback failure is quoted from
`evidence/final_read_sbo/readbacks/hw_config_readback.txt`, which was not edited.
