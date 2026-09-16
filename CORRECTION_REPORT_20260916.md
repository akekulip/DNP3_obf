# Correction pass, 2026-09-16

Branch `fix/lin-paper-code-review-20260915`, starting from `932a2e9` on `main`, which is the
commit the review examined and was still the remote head when this began, so no finding had been
resolved in the meantime.

**Offline corrections, then two hardware sessions.** The corrections in §1 were made without
touching hardware. Under explicit authorisation the switch was then used twice on 2026-09-16.
The first session was compile only: `bf-p4c` on the frozen source and on the v2 candidate, with
nothing loaded and no traffic sent
(`defense4/timing/audit_current/epsilon_candidate/BUILD_ATTRIBUTION_20260916.md`). The second
session **did** load a program and send traffic: the frozen build was loaded and configured, the
relay was contacted, one DNP3 connection was driven with a firewall rule scoped to its own
4-tuple, and the master's retransmission behaviour was captured
(`defense4/timing/audit_current/master_rto_20260916/RESULT.md`). Afterwards the switch was
restored to the unrelated program it had been running, with the identical command line, and the
scratch directories were removed.

No branch was deleted, nothing was force-pushed, nothing was merged.
`defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to `18a595a`,
checked at the end of the pass.

**The corrected active code has still not been run on hardware.** `delay_admission.py`,
`rto_probe_plan.py` and `timing_only_profile.py` have been exercised only against offline
fixtures; the hardware sessions used the frozen control plane, not these modules. Nothing below
claims otherwise.

---

## 1. What changed, and what verified it

### Delay admission charged the wrong interval to the outstation's timer

`active_control/delay_admission.py` counted the configured `CLRT_new` plus allowances and omitted
the time an early response waits while the acknowledgment is still held. Under the common
native-ACK anchor that wait is `D_A + CLRT_new - CLRT_original`.

Reproduced before changing anything, with the review's fixture: `D_A = 20 ms`, configured
`CLRT_new = 4 ms`, native interval 1 ms, outstation bound 10 ms. The evaluator charged
**7.5017 ms**, returned `admitted`, and asserted `transport_safety_verified: true`. The response
actually waits **23 ms**. It now charges **27.0029 ms** and refuses.

Four further corrections in the same module: each timer is charged the whole interval it spans as
one measured network round trip, so elapsed time before the hold is inside the accounting and no
path allowance is added twice; a missing term no longer becomes zero inside a check, which now
reports `ok: None` and names the missing input; inputs are validated before any verdict, so a
negative hold, a NaN, an infinity, a zero cap or a native interval longer than the whole
request-to-response interval is rejected rather than admitted; and provenance now carries an
observation time and an applicability, judged per role, so a measurement from another connection
or build is not authoritative here while an operator-supplied application deadline is
authoritative for a requirement. The unconditional verified flag is gone; the best verdict is
`admitted_conditional` and states that its bounds are finite observed maxima.

*Verified:* 34 offline tests, including both counterexamples as regressions and a test that
raising `D_A` raises the outstation consumption, which the old arithmetic left flat.

### The probe recorded a hold it never took

`active_probe/rto_probe_plan.py`. Reproduced: a 40-second plan completed in **0.24 ms** and
recorded `held_seconds: 40.0` with status `completed`; a mocked `iptables -C` returning 2 with
"permission denied" was counted as **successful removal**; the recorded interface was never
matched on by the generated rule.

All three are fixed, with a bounded lifecycle against an injectable clock and an optional workload,
elapsed time measured rather than copied, a watchdog that still runs cleanup, cleanup protection
beginning immediately after a successful install, absence established only by return code 1, the
partial record attached to the raised error and resolved when read, and a probe-specific comment
so a delete can only remove this probe's own rule. Withholding the master's acknowledgment and
dropping the outstation's response are now separate directions with different chains.

*Verified:* 31 offline tests, all driven by a scripted runner and a fake clock. No test sets the
hardware-authorisation flag.

### The activation profile configured traffic before it established shaping

`active_control/timing_only_profile.py`. Shaping is now step 1, before ports, queues, pktgen or
the session, and is re-read from its own table after every step rather than noticed if some other
readback happened to include the field; an absent `shape_enable` is a failure rather than a zero.

Reproduced defects, all fixed: `validate()` raised `ValueError` and `OverflowError` on NaN and
infinity instead of reporting them; a positive delay of 0.0001 ms truncated to 0 ns and was
accepted as a hold; ports of 99999 and queue ids of 99 were accepted; and the partial record the
docstring promised was never attached to the raised error. The queue id and the strict priority
are validated separately, since requiring them equal was an assumption rather than a constraint.
The mode list is restricted to the modes the loaded build arms, and admission is wired in so a
refused policy is never applied. `ADAPTER_STATUS` states in the plan and every record that no
device adapter is implemented here.

*Verified:* 43 offline tests.

### Extraction was not carrying integer nanoseconds, and the captures are coarser than claimed

The documentation said integer nanoseconds end to end. True of `analysis/pcap_reader.py`, false of
`campaign_v1/repro/pcap_dnp3.py`, which produces the published numbers and converted each record
to a float second. Measured on the corpus, that cost up to **459 ns** on a cross-layer response
time. Extraction is now integer throughout.

A second finding came out of it: **every capture in `campaign_v1` is a microsecond-resolution
pcap** (`d4c3b2a1`), while the 2026-09-15 diagnostics are nanosecond (`4d3cb2a1`). The frozen
table's sub-microsecond digits, such as 26.139021 ms where the capture recorded 26.139 ms, are
float representation noise. The cross-check tolerance was 1 ns, finer than the data's own quantum,
so it was comparing roundings; the two extractors are now required to agree on the same
microsecond, which they do.

Three validator weaknesses are now checked rather than assumed: header and block CRCs are
verified instead of stepped over, an acknowledgment must carry a TCP acknowledgment number
covering the end of the request, and the duplicate key includes the connection.

*Verified:* 132 captures, 63,360 exchanges, **0 problems**, with CRC and acknowledgment-range
checking active; sweep 19 points, 5,860 transactions, 42 manifest entries, 0 problems. The CRC
implementation agrees with `active_harness/dnp3_codec.py` over all 256 single-byte inputs.

*Effect on published values:* 63,260 of 63,360 rows move, by at most **238.0 ns**, one float64
unit in the last place at that magnitude. 53 of the 114 gated manuscript values move, almost all
in the fourth decimal. Visible at reported precision: the fixed adversary reaches 0.652 rather
than 0.651 on the cross-layer response time and 0.736 rather than 0.733 on both intervals; the
request-to-acknowledgment interval rises from 0.380 rather than 0.379; the net effect against a
retrained adversary is 0.085 rather than 0.082; the obfuscated permutation test gives p = 0.084
rather than 0.096. **The headline adaptive result is unchanged at 0.651.**

### Epsilon: a decode error, and a build that cannot be attributed

Applying the patch in `epsilon_candidate/` to the verified base gives
`7d1752225e85b547…`, not the `ac3eb62a1be7e0b3…` the README, compile record and v1 result cite.
Those records describe v1; the patch is v2 and was never recorded against a compile or a binary.
v1's hashes are left where they are.

The deadline register holds `(timestamp & 0xFFFFFF00) | 1`, so the low byte is an armed marker and
not nanoseconds, and `RESULT_V2.md` subtracted the raw word. Every interval was one nanosecond
short, and the sample reported as a wrapped clock at −1 ns is a **0 ns** interval. Re-derived from
the untouched raw rows with an explicit decode version: **1,706 ns** acknowledgment lane, **1,705
ns** response lane, 12 of 12 valid on every lane where one row had been discarded on a false
explanation.

Both timestamps are ingress timestamps on a recirculating blocker, so the quantity is an internal
blocker-termination interval and a lower bound on epsilon, not a departure and not a queue-empty
time.

The resource counts turn out not to conflict: the manuscript's twelve ingress stages, six egress
stages and 112 tables come from the frozen build's own allocation summary, while the candidate's
13 and 176/182 have no preserved source at all, since its compile log carries only warnings.

### The duplicate trace shows less than it was read as showing

The filter drops every inbound 101-byte packet for the whole 25 s, not only the original, so no
copy reached the master's stack and the application recovered nothing; the capture sits ahead of
the filter. Successive gaps are **2.969, 6.001 and 11.040 s**, not 3 / 6 / 12 s, and the last copy
follows a keepalive probe by 0.47 ms while an identical probe ten seconds earlier produced none.

Most importantly the test never reached the risk. The transaction was live about 24 ms and the
first copy arrived 2.97 s later. The frozen program's generation transition is a one-shot add
predicated on a bit that applying it clears, so a copy arriving after release is stale rather than
a live duplicate. **The live-window case remains open, not closed.**

Two further readings of the frozen program: the transaction lifetime is not `D_A + CLRT_new`,
because the only retire paths are the released response and the fail-open budget, which counts
blocker passes rather than time; and a late response takes `OUT_RESP_HOLD_LATE`, which the commit
map sends to `cmt_resp_hold()` and therefore to qid4, so it is not a zero-queue bypass.

### Manuscript claims corrected against the program rather than reworded

Read and control responses were said to stay independent because each has its own registers. Every
register that records a transaction is a **single slot** and the control path writes the same
release instants at OPERATE admission, so the program protects one transaction at a time; a second
arming attempt is forwarded unprotected (`OUT_ARM_BUSY : cmt_fwd()`). A late response was said to
be forwarded at once. The mutual-information result was stated as the interval no longer carrying
information, where a permutation test that fails to reject establishes no such thing. The two
features were called independent when they are separately measurable, which is what the adaptive
attack exploits. Forwarding at original size was said to keep the mechanism invisible. The
poll-to-control median difference was 0.9 ms in one section and 0.8 ms in two others; the medians
are 2.937 and 2.116, so it is 0.8 ms.

`D_R` now names the response's whole journey from the outstation, is marked **unmeasured**, and
`m_R - t_R` is reported as the observed portion and a lower bound. The three design quantities are
stated as coupled rather than separately selectable.

The abstract is 252 words, down from 300.

### Repository guidance

Five root documents named in `README.md` and `CLAUDE.md` were dropped in the 2026-09-15 prune.
Each reference now gives the command that recovers it, at the last commit that still carried it,
and all five commands were run: `18c324f` for `REMOVAL_REPORT.md`, `VERIFICATION_REPORT.md` and
`REPOSITORY_AUDIT.md`, `6750b57` for `CLEANUP_PLAN.md`, `fb74bbd` for `REMOVAL_MANIFEST.csv`.

Three dispositions in `CORRECTION_REPORT_20260915.md` described work that has since happened. The
repository map said no manuscript claim rests on the diagnostics; it does, and now says which. The
writing guide said in one place that paragraphs 1 to 3 of the Introduction are protected and in
another that the whole Introduction is verbatim; the first is what the checker enforces.

## 2. What was already correct and is retained

The active and frozen separation, the root reproduction dispatcher, the three protected
introduction paragraphs, the linear READ histograms with their full-range companion and their bin
and run CSVs, separate configuration provenance, and the separation of master, outstation and
application constraints. None was rebuilt; each was corrected in place.

## 3. Verification

Run at `f650568`, every command from the repository's own documented entry points.

| check | result |
|---|---|
| active offline suites | **196 passed** (119 at the start, 179 before the 2026-09-16 review) |
| campaign test suite | **131 passed, 0 failed** (from 125 passed, 6 failed) |
| campaign validation | 132 captures, 63,360 exchanges, **0 problems** |
| sweep validation | 19 points, 5,860 transactions, **0 problems** |
| publication gate | **0 problems**, regenerated outputs match every published artefact |
| protected introduction | **PASS**, 3 paragraphs word for word |
| manuscript build and lin\_check | **PASS**, no hard-check failures |
| frozen tree and raw captures vs `18a595a` | **0 files changed** on all four protected paths |
| venue preflight | **FAIL**, page budget only |

```
python3 -m pytest defense4/timing/{active_control,active_harness,active_probe}/tests defense4/timing/tests -q
cd defense4/timing/evidence/campaign_v1/repro && ./reproduce.sh <OUT>
cd defense4/timing/evidence/campaign_v1/repro && ./.venv/bin/python publication_gate.py <OUT>
bash paper/rewrite/pipeline/build.sh
python3 paper/rewrite/pipeline/check_lin_intro_verbatim.py
python3 paper/rewrite/pipeline/ndss_preflight.py
python3 defense4/timing/audit_current/epsilon_candidate/run_20260915/decode_epsilon.py \
        defense4/timing/audit_current/epsilon_candidate/run_20260915/epsilon_v2.jsonl
```

The classifier was rerun, because the extraction change altered its inputs. `reproduce.sh` was run
end to end into a fresh directory; its own pytest step is what surfaced the six failing artifact
comparisons that the republished figures and the corrected row test then cleared.

## 4. Remaining blockers and evidence gaps

**The body is two pages over.** The corrected count is **15 main-body pages against a limit of
13**; the old logic reported 16 by charging the excluded Ethics section to the budget. The
counting is now right and transparent, and the overage is real. Roughly 1,600 words have to come
out of a 12,400-word body, principally from Design (2,501 words) and Evaluation (4,193). Moving
the full-range histogram to an appendix was tried and reverted: the structure gate requires Related
Work to be second-last, and relaxing its back-matter allowlist to admit a figure I had just moved
would have been loosening a gate to pass my own change. The cut has to be editorial.

**Epsilon's build attribution is RESOLVED.** Taken to the switch on 2026-09-16. The recompilation
route proposed here is indeed closed, and for a reason worth recording: `bf-p4c` stamps a random
`run_id` into every binary, so one source compiled twice gives two different hashes and a raw
`tofino.bin` hash identifies a compile event rather than a program. But the 2026-09-15 build tree
survives on the switch and answers directly: the source it holds hashes to `7d175222…`, its `out_v2` build
normalises to the same `b5780196…` as an independent recompile of this repository's patch, and its
loader log, committed under `compile_20260916/`, records that conf being loaded three minutes
before the rows were captured. `1d5470a6…` is v1's binary, inherited into the v2 result by mistake. The same
session confirmed the resource counts from the allocator: 12 ingress stages, 6 egress, 112 tables
frozen and 114 for the candidate. See
`defense4/timing/audit_current/epsilon_candidate/BUILD_ATTRIBUTION_20260916.md`.

**No hardware adapter is validated.** `timing_only_profile.py` plans and verifies through a
caller-supplied device; the bfrt transport is not implemented and a mock run is labelled as
describing the mock.

**The master's repetition threshold is measured; its timer state is not.** The first repeated
request appeared after 200.8 ms on a 2026-09-16 diagnostic connection. That is a packet
observation, not a read of the sender's RTO: no `TCP_INFO` or event counter was collected, and the
first two intervals are nearly equal, which exponential backoff does not explain. `delay_admission.py`
keeps the master's and the outstation's timers as separate named inputs.

**The duplicate live-window case is untested.** Reaching it needs an outstation whose
retransmission timer is of the same order as the hold.

**Transaction association in the epsilon rows is unverified.** `ep_cycle.py` reads by wildcard pipe
and takes the first returned word; the lanes agreeing is consistent with correct association but
does not establish it.

**One pair of perturbation captures is not an equivalence result.** A net cross-layer response time
can hide equal movement in both releases.
