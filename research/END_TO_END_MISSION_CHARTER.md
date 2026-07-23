# END-TO-END MISSION CHARTER — DNP3 Traffic Obfuscation (physical SEL-751 + Tofino)

> This file is the verbatim mission charter provided by the user (lead systems researcher /
> implementation engineer role). It is the governing spec for the end-to-end implementation work.
> The derived, repository-checked execution plan is `research/END_TO_END_IMPLEMENTATION_PLAN.md`.
> Phase 0 is read-only; all hardware actions are gated (see section D). This prompt is NOT approval
> for any hardware gate.

## Mission

Take the existing DNP3 traffic-obfuscation work to the strongest technically honest end-to-end
implementation possible:

1. preserve the completed physical SEL-751 native baseline;
2. reconcile the project terminology and claims;
3. place a live DNP3 parser/classifier inline on Tofino in shadow mode;
4. implement a generation-safe transaction state machine;
5. reimplement and harden Defense 1;
6. reimplement and calibrate Defense 2;
7. validate both defenses first with replay and then, after explicit authorization, against the physical SEL-751;
8. regenerate the packet-size pattern using the physical SEL evidence;
9. implement a deployable two-edge outer-size-normalization prototype where the available hardware permits;
10. evaluate the timing and size mechanisms jointly without overstating what has been implemented;
11. update the project reports, diagrams, evidence manifests, and status matrix.

Work incrementally. Inspect before editing. Do not invent filenames, topology, port mappings,
commands, experimental results, or hardware capabilities.

## A. Source of truth
Inspect all relevant repository material before changing anything (reports, `research/physical_sel751/`,
`research/tofino_dcrn_feasibility/p4/ack_delay/`, `.../queue_microbench/`, the `queue-trace-level1-hw-pass`
tag, the `Traffic Trace/*.pcap`, compile/resource reports, controller/runtime scripts, switch
configuration and restoration procedures, git branch/status/tags/commits).

Preserve these completed milestones — do not amend, squash, rewrite, delete, or silently replace:
`ac29155` (physical native baseline), `d36ddb6` (300-poll CLRT distribution), `d7c9483` (validation
and timing interpretation), tag `queue-trace-level1-hw-pass`.

**Verified physical-relay configuration:** Vision `eno1` = `192.168.10.1/24`; relay `192.168.10.7/24`;
DNP3 TCP 20000; master link addr 1; outstation link addr 0; relay-allowlisted master IP 192.168.10.1;
one persistent TCP session; Class-0 READ only; no retries; no reconnects; one outstanding request; no
writes/controls/time-sync/unsolicited/restart-IIN-clearing.

**Verified physical baseline:** 300/300 successful; separate pure TCP ACK then DNP3 response in every
transaction; one TCP session; 0 retries/reconnects/retransmissions; response 134 B wire / 115 B DNP3
length / 69 points; FIR=1 FIN=1 CON=0; func 129; IIN1=0x80 IIN2=0x00 (IIN1.7 DEVICE_RESTART asserted);
median CLRT 1.899 ms; mean 2.983 ms; p95 7.426 ms; max 15.649 ms; positive temporal autocorrelation;
moving-block bootstrap intervals supersede IID-bootstrap intervals.

## B. Terminology (must be used)
Correct the "Case A / Case B" ambiguity everywhere touched.
- **ACK mode A:** separate pure TCP ACK then a DNP3 response; SEL-751 exhibits this; CLRT defined here.
- **Defense 1:** hold the separate pure ACK; release it when the matching DNP3 response is available;
  enforce ACK-before-response with a small bounded guard.
- **Defense 2:** forward the pure ACK normally; hold the matching response; release at an ACK-relative deadline.
- **ACK mode B:** ACK combined with the response; no standalone pure ACK; CLRT not defined the same way;
  AB1400 and ION7550 historical traces are examples; this mode is **not** "Defense 2".
- Do **not** use "Case B" as a synonym for Defense 2. Do **not** broaden to a universal request-relative
  "Defense 3" unless Defense 1 and 2 are complete + validated AND explicitly authorized.

## C. Non-negotiable safety & integrity
Physical SEL-751 is live protection equipment; the Tofino is shared. NEVER: DNP3 WRITE / SELECT /
OPERATE / DIRECT OPERATE / CLOSE / TRIP / RESTART / time-sync / unsolicited enable-disable / restart-IIN
clearing / relay setting change / relay reset-reboot / firmware update / factory reset / automatic retry
loop / automatic reconnect loop / >1 outstanding DNP3 request / uncontrolled traffic generation /
arbitrary address changes / cabling changes without explicit confirmation / Tofino program load without
explicit authorization / deletion-overwrite of raw evidence / modification of SHA-256 manifests to
conceal changes / claiming a test ran when it did not / claiming physical traffic when only replay was
used / claiming transparent DNP3 padding when an endpoint-visible wrapper was added / custom cryptography.

Native probes remain read-only; preserve the pins: empty startupIntegrityClassMask; empty unsolClassMask;
disableUnsolOnStartup=False; ignoreRestartIIN=True; TimeSyncMode.None; one-hour (or verifiable) no-retry;
hard termination on timeout/close/protocol-error/unexpected-completion. Any dropped DNP3/TCP session ends
a live experiment — do not reconnect and continue.

Stop immediately (live experiments) on: unexpected FIN/RST; timeout; retry/reconnect attempt; >1 READ
outstanding; unexpected DNP3 function code; IIN request-error bit; unmatched response; write/control/
time-sync appearing; loss/reorder/retransmission; unexpected Tofino fail-open; switch not restorable to
baseline; unexpected response-content change; user has not approved the exact hardware action.

## D. Human authorization gates (this prompt is NOT approval)
Proceed autonomously through: repo inspection, coding, offline compilation, unit tests, replay tests,
analysis, documentation drafts, git preparation.

- **GATE 1:** loading/replacing a program on the shared Tofino; changing TM config; changing recirc-port
  config; changing physical switch ports/cabling.
- **GATE 2:** placing physical SEL-751 traffic through an active Tofino defense; changing physical
  topology from the direct baseline; changing Vision's live network config.
- **GATE 3:** running any multi-poll physical-relay experiment through an active defense (state exact
  poll count, spacing, target, duration, capture points, stop conditions, restoration plan, commands).

At a gate, present: exact action; exact commands; active program to be replaced; restoration command +
known-good program; affected ports; expected downtime; packet-generation bounds; relay poll count;
runtime; safety checks; stop conditions; evidence outputs. Then stop and wait.

## E. Prime implementation principles
Endpoints unmodified. Existing TCP + DNP3 bytes preserved. Do not synthesize/forge inner TCP ACKs. No
TCP sequence-number translation. No DNP3 field/CRC modification for timing defenses. Recirculation is the
sparse-traffic hold primitive. TM is not the clock for an isolated sparse packet. With cover OFF: pktgen
OFF, no external filler, event/deadline release via recirculation, TM only for priority/contention/
occupancy/queue behavior. Pktgen only for a separately-authorized bounded-cover phase. Use separate
compile-time P4 variants if one program exceeds the stage budget. Do not keep appending registers/actions
after stage overflow — redesign compactly. Fail open on ambiguity: release the original packet unchanged,
clear transaction state, report the reason, never silently drop a valid protection packet.

## F–R. Phases and deliverables
Phase 0 audit → `END_TO_END_IMPLEMENTATION_PLAN.md`. Phase 1 live DNP3 shadow classifier. Phase 2 shared
generation-safe transaction/safety core. Phase 3 Defense 1 reimplementation + replay. Phase 4 Defense 2
reimplementation + calibration + replay (targets 8/12/16/20 ms). Phase 5 size inventory + pattern
regeneration from physical evidence (note: physical response is 134 B, not 128 B). Phase 6 two-edge outer
size-normalization prototype (software first; authenticated only if a real reviewed mechanism exists).
Phase 7 joint size+timing evaluation (cover OFF, one flow, one outstanding). Analysis/statistics per
section N (moving-block bootstrap primary; wire = timing authority, app log = content authority; no strong
p99 from 300 samples). Testing/verification per O. Documentation additive + honest (status matrix with
COMPLETE / PARTIAL / NOT IMPLEMENTED / BLOCKED / DEFERRED; label every figure by evidence type). Git
discipline per Q (separate commits per milestone; verify before commit; no push unless instructed). Final
deliverables per R (END_TO_END_IMPLEMENTATION_REPORT.md, FINAL_STATUS_MATRIX.csv, FINAL_ARCHITECTURE.md,
REPRODUCIBILITY.md, SAFETY_CASE.md, RESOURCE_BUDGET.md, EVIDENCE_INDEX.md, plots, updated reports,
separate SHA-256 manifests for raw/derived/validation/reports).

## S. Final response format
Report: current phase; completed phases; blocked/deferred; gates awaiting authorization; exact status of
(shadow classifier, transaction state, Defense 1, Defense 2, physical inline testing, size regeneration,
outer encapsulation, joint defense); tests/builds run; Tofino resource use; physical-relay safety
verification; key timing/size/byte-identity/TCP-health/fail-open results; evidence paths; SHA-256
manifests; commit hashes; remaining uncommitted files; exact unresolved limitations; next required human
decision. Do not summarize an unexecuted plan as completed work.

---
*Begin with Phase 0: inspect the repository; verify current state against the reports and code; produce
the gap matrix and END_TO_END_IMPLEMENTATION_PLAN.md; do not modify the Tofino or contact the physical relay.*
