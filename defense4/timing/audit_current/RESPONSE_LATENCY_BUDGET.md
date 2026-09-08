# Response latency budget: what bounds the added response holding?

Prepared 2026-09-08. Desk research only. No hardware was run and no other file was modified.

## Question

The mechanism holds the outstation's DNP3 application response so that the master-visible
acknowledgment-to-response interval (CLRT) becomes a configured constant, tested at
`D_R` = 4 ms, inside a total release budget `D` = `D_A` + `D_R` = 24 ms. How much additional
response holding is compatible with the operation being performed, and which document, if any,
sets that bound?

Two framings are kept apart throughout. A **standards bound** is a numeric limit written in a
document whose text was actually retrieved. A **deployment assumption** is a number an operator
would choose. This report finds no standards bound that governs a DNP3 poll or a DNP3
select-before-operate on this device, and one verified device-enforced deadline.

Every entry is labelled with the requirement class asked for:
**(a)** communications transfer-time requirement, **(b)** end-to-end application completion
deadline, **(c)** per-receive socket timeout, **(d)** operator or deployment assumption.

## Candidate requirements examined

| # | Document and edition | Clause / section | Class | Operation governed | Endpoints the bound is defined between | Numeric bound | Verdict for this testbed |
|---|---|---|---|---|---|---|---|
| 1 | IEEE Std 1815-2012, DNP3. Published 2012-10-10; status **Inactive-Reserved, inactivated 2023-03-30** | full text **not retrieved** (paywalled) | protocol behaviour, not (a)/(b) | DNP3 application layer generally | n/a | **none visible.** The public abstract specifies "protocol structure, functions, and interoperable application options (subset levels)" and states no response time | **UNVERIFIED.** The interior clauses were not read. Do not assert that 1815 sets, or does not set, a latency limit |
| 2 | DNP Users Group Application Note **AN2022-001, DNP3 Device Profile** (2022) | field names confirmed from the retrieved contents pages: §1.6.1 "Timeout waiting for Complete Application Layer Responses (refer 1815-2012 §4.3)", §1.6.3, §1.7.1, **§1.10.5 "Maximum Response time"**, **§3.3.10 and §3.6.8 "Maximum Time between Select and Operate"** | (c) for the master timers, (d) for the declared device values | READ, SELECT, OPERATE | per-device declaration, endpoints not retrieved | **per device; no universal value.** The document states it "DOES NOT provide guidance as to the requirements for conformance to the IEEE1815-2012 specification" | **APPLIES as the location of any bound, but supplies no number.** Only 12 pages of the PDF were retrievable; the body text of §1.10.5 and §3.3.10 was **not read**. The SEL-751A's own filled-in profile was not obtained |
| 3 | **SEL-751A Instruction Manual**, PM751A-01-NB, 20130329 printing | settings table, PDF page 465: `STIMEO1` "Select/operate time-out, seconds" | (b) device-enforced completion deadline for the control lane | SELECT to OPERATE at the outstation | outstation receipt of SELECT to outstation receipt of the matching OPERATE | **range 0.0 to 30.0 s, default 1.0 s** | **APPLIES.** This is the only verified numeric deadline any part of our transaction can violate. Adjacent verified settings on the same page: `DTIMEO1` data-link time-out 0.0 to 5.0 s, default 1; `ETIMEO1` event confirm time-out 1 to 50 s, default 5 |
| 4 | Same manual, DNP3 appendix | text at extraction line 31876 | n/a | n/a | n/a | n/a | The manual **defers** the device profile to a separate document ("The DNP3 Device Profile document, available on the supplied CD or as a download from the SEL website"). A grep of the whole 660-page manual for "response time" returns only overcurrent-curve and demand-meter uses. **No relay response-time expectation is stated in the manual** |
| 5 | **IEC 61850-5** message performance classes | standard text **not retrieved**. Values reproduced in ABB conference paper "Utilization of IEC 61850 GOOSE messaging in protection applications", Table I | (a) | IEC 61850 message types (GOOSE, MMS, SV) | transfer time t = ta + tb + tc, sending application to receiving application | as reproduced: Type 1A trip P1 10 ms / P2/P3 3 ms; Type 1B P1 100 ms / P2/P3 20 ms; **Type 2 medium speed 100 ms**; **Type 3 low speed 500 ms**; Type 5 file transfer > 1000 ms | **DOES NOT APPLY.** The classes are attached to 61850 message types and to 61850's own application-to-application transfer-time definition. Nothing retrieved extends them to a DNP3 SCADA poll. The numbers themselves are **UNVERIFIED** against the standard: they come from a vendor conference paper, not from IEC 61850-5 |
| 6 | **IEEE Std C37.1-2007**, SCADA and Automation Systems | full text **not retrieved** (paywalled). Scope quoted from the IEEE SA page: "The requirements for SCADA and automation systems in substations are defined." | unknown | substation SCADA and automation systems | unknown | **none visible** in the public metadata | **UNVERIFIED.** The scope is plausibly relevant, so this is the single most valuable document to obtain. Nothing may be quoted from it until it is read |
| 7 | NERC Reliability Standards / utility scan-rate practice | none identified | (d) | SCADA polling cadence | n/a | **none found** | **UNVERIFIED / not located.** No NERC standard setting a SCADA poll rate or a per-transaction latency was identified in this session. Absence of a located requirement is not evidence that none exists |
| 8 | **NIST SP 800-82r3** (September 2023), openly available and read | §1, "Timeliness and performance requirements" | (d) | OT systems generally | n/a | **explicitly none.** Verbatim: OT systems are "time-critical, with the criterion for acceptable levels of delay and jitter **dictated by the individual installation**" | **APPLIES as guidance only.** It supports treating the latency limit as a deployment parameter rather than a standards constant. It is not a numeric requirement |
| 9 | This testbed's master driver | `defense4/timing/active_harness/session.py`, driver `budget_ms` / `settimeout` path; audited in `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md` §1 | **(c)** | every exchange | one blocking `recv` call, re-armed per read | **3.0 s** | **APPLIES, but only as a per-receive socket timeout.** The audit is explicit: "3.0 s is not a transaction budget". It is not an end-to-end deadline and must never be reported as one |

Two informal figures raised in discussion, "about 100 ms" and "10 ms", have **no document behind
them** in anything retrieved here. The 100 ms figure coincides with the IEC 61850-5 Type 2
medium-speed class in row 5, which does not govern DNP3. Neither number should enter the
manuscript as a limit.

## What the repository currently asserts

Grep over `defense4/timing/*.md`, `defense4/timing/audit_current/` and
`paper/rewrite/sections/` for latency, deadline, budget, timeout and ms.

* **No external latency requirement is asserted anywhere in the repository.** No file cites
  IEC 61850, IEEE C37.1, a NERC standard, or a poll-rate figure. The only standards reference
  found is a citation-mapping row naming IEEE 1815-2012 in
  `paper/rewrite/pipeline/reports/LIN_TEXT_CHANGELOG.md:12`. There is therefore **no existing
  claim for this report to contradict**, and equally no external anchor for the cost.
* `defense4/timing/TIMING_MODEL.md:68-74` defines the parameters: `D_A` = 20 ms, `D_R` = 4 ms,
  `D` = 24 ms, control-lane `A` = 20 ms and `R` = 24 ms, and `H` = 30.8 ms flagged as
  "not measured and not enforced by the data plane".
* `defense4/timing/CLAIMS_AND_LIMITATIONS.md:30-36` scopes `D` to the read lane only and states
  that the read-path budget is not a schedulability argument for OPERATE.
* `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md:40-52, 216-233, 305-317` already draws the
  distinction this report needs: the 3.0 s value is a per-receive socket timeout, no transaction
  deadline exists, and the absence of a timeout is "a measured outcome" offered against the
  configured value "as scale, not as a claim".
* `paper/rewrite/sections/06_evaluation.tex:255-271` states the cost as measured and explicitly
  declines the compliance inference: it reports completion times against the 3 s timeout
  "without asserting that the two coincide". The manuscript is already correct on this point.
* `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md:283-284`: **the SEL-751A's `STIMEO1`
  value was never read back, so the configured select window on the relay is UNKNOWN.**

**Zero observed timeouts does not establish compliance with any standard.** It establishes that
no timer configured in this specific testbed expired at this specific operating point. Nothing
in this report should be used to say otherwise.

## Measured baseline and remaining budget

Configuration, from `defense4/timing/evidence/campaign_v1/repro/policy_config.json`:

| quantity | value |
|---|---|
| `D_A` (acknowledgment offset) | 20.0 ms |
| `D_R` (target CLRT) | 4.0 ms |
| release budget `D` | 24.0 ms |
| fail-open horizon `H` | 30.8 ms, control-plane computed, not measured, not data-plane enforced |
| `J` codebook (control lane) | 2, 6, 12 ms, configured, per-transaction draw unobserved |
| size carve | `shape_enable = 0` |

Measured request-to-response latency `L_R`, from
`defense4/timing/TIMING_MODEL.md:245-250` and `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md:238-245`:

| class | Timing OFF median | Obfuscated median | added | Obfuscated p99.9 | Obfuscated max |
|---|---|---|---|---|---|
| READ | 2.680 ms | 25.337 ms | 22.657 ms | 29.659 ms | 77.713 ms |
| SELECT | 2.622 ms | 25.239 ms | 22.617 ms | 29.502 ms | 29.577 ms |
| OPERATE | 3.465 ms | 24.650 ms | 21.185 ms | 30.032 ms | 33.151 ms |

Select-window exposure, from `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md:260-290`:
master-facing SELECT-sent to OPERATE-sent is 25.602 ms median and 29.968 ms max obfuscated,
against 2.990 ms Timing OFF. Relay-facing the gap is estimated at roughly 27 to 37 ms once the
configured `J` is added, and that estimate is **not a measurement** because the relay-facing
link was not captured.

Harness pacing, from `defense4/timing/evidence/campaign_v1/PROVENANCE_CONSTANTS.json:45` and
`defense4/timing/active_harness/read_driver.py:88`: `gap_ms` = 20, a fixed sleep **after** each
completed transaction. This is a laboratory cadence, not a utility poll rate, and it is not a
deadline of any kind.

**Remaining budget, computed honestly.** Three ceilings exist, and only two are measured.

1. **Mechanism envelope (measured, binding).** From
   `defense4/timing/CLAIMS_AND_LIMITATIONS.md:55-66`: at fixed `D` = 24 ms the CLRT tracks
   targets from `D_R` = 1 ms to 22 ms; ramping `D_A` at `D_R` = 4 ms, the request-to-ACK interval
   tracks the target to 30 ms (measured 30.571 ms) and then **saturates near 31.07 ms**, after
   which the CLRT itself degrades to 5.503, 7.498 and 9.507 ms at `D_A` of 32, 34 and 36 ms.
   Additional holding beyond `D_A` about 30 ms therefore breaks the mechanism before it breaks
   any timer. Headroom above the tested point: roughly **10 ms of additional `D_A`**, taking
   `D` from 24 ms to about 34 ms.
2. **Device select window (documented default, not read back).** `STIMEO1` default 1.0 s. Against
   the worst observed master-facing SELECT-to-OPERATE gap of 29.968 ms, and the estimated
   relay-facing 37 ms, the margin at the documented default is roughly 27x to 33x. This margin is
   against the **manual's default**, not against the value actually configured on the relay,
   which is UNKNOWN.
3. **Master per-receive timeout (class (c), not a deadline).** 3.0 s. Reportable as scale only.

At the tested operating point the binding constraint is the mechanism's own envelope, not any
standard and not any device timer.

## Selection argument for the tested setting

The tested setting is justified internally, and should be presented that way rather than as
compliance with an external limit.

* `D_R` = 4 ms is above the Timing OFF released interval of about 2.1 ms
  (`defense4/timing/TIMING_MODEL.md:240-242`), so the switch is always shifting a packet later
  and never has to release one earlier than it arrived. A target below the native interval is
  not schedulable.
* `D` = 24 ms exceeds the outstation's own response time by enough to place
  **99.900 % of Timing OFF read-lane exchanges** inside the budget
  (`paper/rewrite/sections/06_evaluation.tex:69`). Coverage, not a standard, chose this number.
* `D` = 24 ms sits below the fail-open horizon `H` = 30.8 ms, so a hold cannot outlast the
  reservoir's finite pass budget.
* The realized cost is 21 to 23 ms of added end-to-end latency per transaction, and the worst
  case observed was 77.713 ms.

**Explicit deployment assumption, labelled as an assumption.** Absent a retrievable standard,
the defensible statement for the paper is: *we assume a deployment in which a per-transaction
DNP3 completion cost of tens of milliseconds is acceptable, because the only device-enforced
deadline we could verify is the SEL-751A select/operate time-out, whose documented default is
1.0 s, and because NIST SP 800-82r3 states that acceptable OT delay is dictated by the
individual installation.* The assumption is bounded by the mechanism's measured envelope
(`D_A` up to about 30 ms) rather than by any external requirement.

## Explicit gaps and what would close them

| gap | what would close it |
|---|---|
| IEEE 1815-2012 interior clauses were never read; whether the standard states any timing obligation is unknown | the standard itself, in particular clause 4.3 (application layer timeouts) and clause 14 (interoperability / device profile), via IEEE Xplore or an institutional subscription |
| IEEE C37.1-2007 may or may not contain a SCADA response-time requirement | the full text of IEEE C37.1-2007. This is the highest-value single document to obtain |
| The SEL-751A's configured `STIMEO1` is UNKNOWN | a settings read-back from the relay. Barred here by the no-hardware rule; it belongs in the rerun plan, which already lists the select window as unarchived |
| The SEL-751A DNP3 Device Profile document was never obtained, so the vendor-declared "Maximum Response time" and "Maximum Time between Select and Operate" are unknown | the separate SEL DNP3 Device Profile for the SEL-751A, referenced by the manual and downloadable from SEL |
| AN2022-001 body text for §1.10.5 and §3.3.10 was not retrieved; only the contents pages parsed | a complete download of AN2022-001 from dnp.org |
| IEC 61850-5 performance-class values are taken from a vendor paper, not the standard | IEC 61850-5 itself. Even with it, the transfer verdict to DNP3 stays DOES NOT APPLY unless IEEE 1815.1-2015 is also read and shown to carry the classes across |
| No utility or NERC scan-rate requirement located | a utility SCADA design specification, or a NERC standard shown to bound scan rate. Until then, poll cadence is a deployment parameter |
| The relay-facing link was never captured, so the true SELECT-to-OPERATE gap at the relay is an estimate | relay-facing capture. Out of scope; the estimate must stay labelled as one |

## Sources

External, all opened on 2026-09-08:

* IEEE SA record for IEEE 1815-2012, title, publication date 2012-10-10, status Inactive-Reserved
  (inactivated 2023-03-30), abstract: https://standards.ieee.org/standard/1815-2012.html
* IEEE Xplore landing page for IEEE 1815-2012 (full text not accessible):
  https://ieeexplore.ieee.org/document/6327578/
* DNP Users Group Application Note AN2022-001, "DNP3 Device Profile: Guide to completion and
  understanding", 2022. Contents pages and introduction retrieved; body not retrieved:
  https://www.dnp.org/API/Evotiva-UserFiles/FileActionsServices/DownloadFile?ItemId=5009&ModuleId=9582&TabId=66
* SEL-751A Feeder Protection Relay Instruction Manual, PM751A-01-NB, 20130329 printing.
  `STIMEO1` on PDF page 465: https://nepsi.com/resource/SEL-751A-Instructions.pdf
* IEEE SA record for IEEE C37.1-2007, scope only: https://standards.ieee.org/ieee/C37.1/4292/
* ABB, "Utilization of IEC 61850 GOOSE messaging in protection applications", Table I, a
  **secondary** reproduction of the IEC 61850-5 performance classes:
  https://library.e.abb.com/public/dc853877595c4086ae649ca29924c0ec/Paper_GOOSE%20Utilisation%20in%20Protection.pdf
* NIST SP 800-82r3, "Guide to Operational Technology Security", September 2023:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf

Repository, all paths relative to `/home/philip/Projects/DNP3`:

* `defense4/timing/evidence/campaign_v1/repro/policy_config.json`
* `defense4/timing/evidence/campaign_v1/PROVENANCE_CONSTANTS.json`
* `defense4/timing/TIMING_MODEL.md`
* `defense4/timing/CLAIMS_AND_LIMITATIONS.md`
* `defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md`
* `defense4/timing/active_harness/read_driver.py`
* `paper/rewrite/sections/06_evaluation.tex`
* `paper/rewrite/pipeline/reports/LIN_TEXT_CHANGELOG.md`
