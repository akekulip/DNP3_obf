# Shared Grounding Brief — ACK-Bearing DNP3 Response Timing-Normalization Study

_Every subagent on this study MUST read this file first. It is the single source of
grounding truth. Do not contradict measured facts here; if you believe one is wrong,
say so explicitly and give evidence._

## The project in one paragraph
A DNP3/SCADA traffic-**obfuscation** research effort. Goal: in-network obfuscation of a
DNP3 outstation's response **size / segmentation / timing** so a **passive on-path
observer** (reads unencrypted DNP3; does not inject/block) cannot fingerprint the device
(model, database size, load). Two obfuscation primitives already work and are
rig-validated: **CRC-boundary splitting** (reshapes size/segmentation, byte-preserving)
and **request-aware replay**. This study designs the **third, timing axis**: randomized
**timing normalization of ACK-bearing DNP3 response packets**.

## The precise subject (do not conflate)
The outstation piggybacks its DNP3 RESPONSE onto the TCP segment that ACKs the request.
So the ACK time and the response time are the **same wire observable**. The primitive is
**response-time normalization**, NOT "delay a bare TCP ACK." Keep these distinct:
1. Pure TCP ACK (no payload) — mostly absent here (piggyback-dominant).
2. **TCP ACK carrying a DNP3 response** — THE subject.
3. DNP3 application CONFIRM (FC 0x00) — present, gates multi-fragment reads.
4. DNP3 link-layer secondary ACK — **verified ABSENT** (OpenDNP3 sends only
   PRI_UNCONFIRMED_USER_DATA). There is no link-layer ACK to delay.
5. General response-release timing.

## HARD phase rule (byte-preserving — do not design outside this unless flagged as future work)
No CRC recompute · no DNP3 field/length/object modification · no random padding · no P4
deployment in this phase · no proxy/MITM · no control-command synthesis · do NOT forge
TCP ACKs · do NOT synthesize/suppress DNP3 CONFIRMs · do NOT rewrite TCP seq/ack numbers.
The ONLY lever is **hold / delay / pace the release of packets that already exist**, such
that `b"".join(chunks) == original_bytes` still holds. Manipulate only *when* an existing
packet is released. Anything requiring a synthesized/suppressed frame or seq/ack rewrite
is out of scope this phase and must be labeled a scope decision for Philip/Dr. Lin.

## Candidate policy (a hypothesis to critique, not a given)
```
candidate_release = max(response_ready_time, request_time + target_delay)   # target_delay ~ common distribution
if candidate_release - request_time <= allowed_budget: release at candidate_release
else: release immediately and record a deadline miss / policy bypass
```
Critical/protection traffic may require immediate pass-through. Safety dominates privacy.

## MEASURED FACTS (this rig; see measured_timing_data.md for full detail)
- Software OpenDNP3 outstation, Vision(master 10.10.54.19)↔Hulk(outstation 10.10.54.158:20000),
  1 G LAN, directly switched. TCP option sig `NOP-NOP-Timestamp` (Linux 6.8/i40e).
- Baseline large READ: **9/9 piggyback**, mean req→ACK **0.239 ms**, req→response **1.014 ms**.
- **CROB-count sweep (rig, measured this session):** response processing time is a
  near-perfect linear function of CROB count N. SELECT-resp slope **0.179 ms/CROB, R²=0.9985**;
  OPERATE-resp slope **0.214 ms/CROB, R²=0.9954**; OPERATE 1.62→4.90 ms over N=1→16 (3.0×).
  This is the crown-jewel leak: processing time linearly encodes request complexity /
  a database-size proxy. Single device / single rig — NOT a cross-device claim.

## Safety envelope (verified in prior work; re-verify if you can)
- Every DNP3 app/link timer in this stack is **5–60 s** (master app response 5 s;
  outstation solicited-confirm 5 s; select timeout 10 s; link keepalive 1 min).
- The **binding constraint is TCP RTO**, not any DNP3 timer: Linux `TCP_RTO_MIN` ≈ **200 ms**
  floor. Overshoot the master's effective RTO → spurious TCP retransmits, which are the
  loudest tell to both a passive observer and a DNP3/Zeek IDS. "Stay under RTO" is both the
  correctness bound AND the stealth bound. Do NOT assume 200 ms is a universal RTO — the
  effective value must be measured on the master (Vision): `sysctl net.ipv4.tcp_retries2`
  plus the RTO observed in a capture.
- Current safe default in the software path: 10 ms/chunk (≈20× margin vs RTO).
- Multi-fragment reads compound: the CONFIRM handshake serializes fragments, so
  per-fragment delay adds; each hop must still stay under RTO.

## Prior brief (READ IT): `dnp3_split_harness/docs/ack_timing_obfuscation_research.md`
Key prior conclusions to build on / test: (a) the leak is processing-time, not "the ACK";
(b) contribution is **normalization** (make devices look alike / anonymity-set) not
**randomization** (add entropy); (c) the cheapest honest result is driving
`I(processing_time; response_size) → 0` (size-decorrelation) — cheaper than full
constant-time; (d) RAINCOAT differentiation is essential (see below); (e) platform homes:
Tofino TM = native pacing/gap but NOT first-packet latency; per-packet absolute delay on
Tofino only via recirculation+register-deadline (non-idiomatic, but cheap here because
DNP3 is low-rate/small-frame); BlueField DPU = clean native home; the software replay
server GENERATES the bytes so it schedules emission directly (no "hold a live packet"
problem) — this is the immediate zero-hardware first deliverable.

## RAINCOAT differentiation (critical — the advisor Dr. Lin is a RAINCOAT author)
RAINCOAT (H. Lin et al., IEEE Transactions on Smart Grid) **randomizes** the control
center's acquisition/communication schedule to **misdirect** an attacker about grid
state. THIS work **normalizes** an outstation's per-exchange response latency to suppress
a **device-identity** leak. Different locus (in-network bump-in-the-wire vs cooperating
endpoints), different leaked quantity (device model/DB-size/load vs grid content),
different mechanism (indistinguishability/anonymity-set vs misdirection). Lead novelty
with this. VERIFY the exact RAINCOAT citation (title/authors/year/venue/DOI) — do not
guess it.

## Platform targets in scope
Software replay/split server (immediate); Intel/Barefoot **Tofino 1** (the eventual P4
target — this is a Tofino shop); NVIDIA **BlueField** DPU; **Netronome** SmartNIC; **FPGA**.

## CITATION & INTEGRITY RULES (non-negotiable)
- Do NOT invent papers, authors, venues, DOIs, standards, or hardware capabilities.
- For every paper: verify title, authors, year, venue, DOI/stable URL exist. If you only
  saw metadata/abstract, SAY SO. Prefer peer-reviewed primary sources; do not treat arXiv
  as peer-reviewed unless a peer-reviewed version is verified. Do not cite blogs for a
  technical claim when an RFC/paper/manual/source exists.
- Distinguish: measured fact · standard-defined behavior · paper-reported result ·
  vendor-documented capability · our engineering inference · untested hypothesis.
- Record for each system: software / simulation / testbed / FPGA / SmartNIC / switch ASIC /
  production hardware, and whether code/artifacts are available. Do NOT label simulation as
  hardware. Include negative results and infeasible mechanisms.
- Do NOT claim Tofino provides arbitrary per-packet sleep/timers without evidence.
- Do NOT claim response time ∝ database size in general from one PCAP — we have a measured
  CROB-count correlation on ONE device; scope claims accordingly.

## Output contract for your report
Write your full evidence report to
`research/ack_timing_normalization/agent_reports/agent_<LETTER>_<topic>.md`.
End it with two machine-mergeable blocks so the lead can assemble the central deliverables:

1) `## PAPER_MATRIX_ROWS` — one line per cited work, pipe-delimited, columns in this order:
   `title | authors | year | venue | DOI | url | peer_reviewed(yes/no/preprint) | tier(1-4) | target_protocol_or_traffic | attacker_model | defense_mechanism | timing_policy | sw_or_hw | platform | testbed | security_metric | overhead_metric | key_result | limitations | relevance_to_us | evidence_confidence(high/med/low)`
   Use `NA` for unknown fields. Escape any literal `|` in text.

2) `## BIBTEX` — verified BibTeX entries for exactly the works you cite (citekey =
   firstauthorlastname+year+firstsignificantword). No entry you did not verify.

Return to the lead (as your final message) a <=250-word summary: your top findings, the
count of Tier-1/2/3/4 papers you verified, and your single most important caveat.
