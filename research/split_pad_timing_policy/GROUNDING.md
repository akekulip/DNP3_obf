# Shared Grounding — WHEN/HOW to Split, Pad, and Normalize Timing for DNP3 Obfuscation

_Every subagent on this study MUST read this first, plus `measured_evidence.md` (this dir) and
the reuse targets below. Single source of grounding truth. Do not contradict measured facts here;
if you think one is wrong, say so with evidence. Task source: `when_how.md` (Dr. Lin)._

## The task in one paragraph
Determine a principled policy for **when** a DNP3 transaction should be **split**, **padded**, or
have its **timing normalized**, **how** to combine the three, how to implement the combined policy
at lowest overhead (software + Tofino + DPU/FPGA), and how to evaluate that it prevents
fingerprinting without breaking DNP3 correctness or grid operations. Passive on-path observer.
Research/design only — **no production source code changes.**

## REUSE, do not redo (a large verified foundation already exists)
A prior seven-agent study produced `research/ack_timing_normalization/` — read and BUILD ON it;
do not re-derive what it settled. Especially:
- `measured_timing_data.md`, and this dir's `measured_evidence.md` (timing + size + split + padding).
- `literature_review.md` + `paper_matrix.csv` (**102 verified papers**) + `bibliography.bib` — the
  literature is largely done; only add NEW works you verify, and reference existing citekeys.
- `hardware_design.md` (Tofino/DPU/FPGA feasibility), `evaluation_plan.md` (attacker ladder A1–A8,
  claim ladder, metrics), `software_design.md` (the app-layer scheduler), `sources_audit.md`,
  `research_gaps_and_novelty.md`, `advisor_brief.md`, `final_synthesis.md`.
The corrections from that study's hostile-reviewer pass are binding here too (see Integrity below).

## The THREE mechanisms (keep them distinct)
- **SPLIT** — divide an existing response into smaller wire units, preserving all original DNP3
  bytes and order. Changes per-packet size / packet count / segmentation. **Does NOT change total
  bytes** (summing chunks recovers the size).
- **PAD** — increase apparent size / packet count / volume / activity so a small transaction
  resembles a larger target. **Nine DISTINCT categories — do not treat as equivalent:**
  (1) semantic DNP3 padding, (2) valid dummy/inert DNP3 objects, (3) invalid-object padding,
  (4) padding outside the DNP3 message, (5) tunnel/encrypted-envelope padding, (6) cover
  traffic/decoy transactions, (7) packet-count padding, (8) silence hiding, (9) timing-only
  "padding" via delayed release.
- **TIMING NORMALIZATION** — control timing observables (req→first-response, inter-chunk/frame/
  segment gaps, CONFIRM→next-fragment, transaction duration, SELECT→OPERATE, polling interval,
  silence). Release at `max(response_ready, request_time + target)` with a class-independent target.

## HARD phase rule (byte-preserving) — forbidden unless explicitly labeled FUTURE work
Do NOT design mechanisms that: alter DNP3 app bytes / object counts / values / lengths; recompute
CRCs; forge TCP ACKs; rewrite TCP seq/ack; suppress required responses; synthesize CONFIRMs;
synthesize controls; implement an active TCP proxy; introduce invalid CROB indexes into a live SBO;
reorder TCP segments; change final DNP3 semantics. **Allowed now:** split at verified-safe
boundaries · control release timing · pace existing packets/chunks · select preapproved policies ·
bypass when safety/deadline requires. Anything else → a clearly separated "FUTURE, protocol-
modifying phase."

## KEY MEASURED FACTS (see measured_evidence.md for full detail + provenance)
- Response piggybacked on the ACK (9/9). Timing: SELECT/OPERATE-resp **0.179/0.214 ms/CROB,
  R²≈0.99** (n=1 per N; one device; CROB-count ≠ DB-size).
- **Size ALSO leaks CROB count: 14.6 B/CROB, R²=0.9999**, 37→256 B over N=1→16 *(n=1 per N-level,
  one device — a 10-point line, not a replicated law; same caveat as the timing line)*. ⇒ **timing
  normalization alone cannot hide CROB count**; the size leak is the harder, currently-residual one.
- Read-plane **response size ∝ point count (~5.7 B/analog point, measured)**; large READ = 12,204 B
  / 9 app frags / 49 link frames / 20 TCP segments. (Timing↔DB-size still unmeasured.)
- **Split** (CRC-boundary, byte-preserving): 2407 B → 141/71/36/18 chunks (bpc 1/2/4/8), master
  accepts all, 0 retransmits/resets, no CRC recompute; **total bytes unchanged** (sum-the-chunks).
- **Padding** = negative result: invalid-index CROBs → OUT_OF_RANGE, partial SELECT blocks OPERATE,
  **not insertable**; no safe byte-preserving DNP3 padding demonstrated.

## Binding safety constraint (from the prior study, re-verified)
The master's **effective TCP RTO** — not any DNP3 timer (5–60 s) — is binding. ~200 ms is the Linux
`TCP_RTO_MIN` floor, **not universal — MEASURE on Vision** (`sysctl net.ipv4.tcp_retries2`,
`ip route … rto_min`, observed request→first-retransmit). Overshoot ⇒ spurious retransmit = the
loudest tell to a passive observer AND a Zeek `dnp3` IDS. No link-layer ACK exists (unconfirmed
link only, verified in OpenDNP3 source). Protection tripping is sub-cycle GOOSE/hardwired, NOT DNP3;
DNP3 fields reveal operation *type*, never physical *criticality* → need an operator allowlist.

## Required taxonomy (three independent axes — use it)
- **Axis 1 SHAPE/SIZE:** total bytes · largest packet · size distribution · #packets · fragment
  count · TCP segment count · DNP3 link-frame count · app-fragment count.
- **Axis 2 TIMING:** req→first-response · inter-packet gap · burst duration · response completion ·
  CONFIRM→next-fragment · transaction duration · polling interval · silence duration.
- **Axis 3 SEMANTICS/SAFETY:** monitoring · event · control · critical control · protection ·
  unknown · unsupported.
For each transaction class, document which axes leak and which mechanisms safely address them.

## Lab / platforms
Software replay/split server (immediate); **Tofino 1** (eventual P4 target); **BlueField** DPU;
**Netronome** SmartNIC; **FPGA**. Attacker: passive on-path, may use size, volume, packet count,
segmentation, req→response delay, inter-packet gaps, TCP behavior, repeated polling.

## Integrity rules (§17 — binding; a reviewer will enforce these)
Do NOT: invent papers/standards/features/hardware capabilities/measurements; assume an abstract
proves implementation; label simulation as hardware; claim a **device-fingerprinting** result from
**one device** (say device-**configuration/complexity**); claim **database-size** leakage from the
**CROB-count** sweep (that is the SIZE↔point-count read-plane result, separate; timing↔DB-size is
unmeasured); claim **padding is solved** (only invalid-index padding tested → negative); claim
**splitting hides total transaction size** (it does not); claim timing normalization hides visible
DNP3 payload content; assume 200 ms is a universal RTO; claim Tofino supports arbitrary packet
sleep; claim DNP3 fields reveal physical criticality; recommend delaying protection traffic; hide
negative results. Prefer low-overhead/simpler solutions; separate current vs future phase; label
every claim: **[M]** measured · **[S]** standard · **[V]** vendor-doc · **[P]** paper-reported
(say if abstract/metadata only) · **[I]** inference · **[H]** hypothesis. After each highly
technical section, add a one-line plain-language explanation.

## Output contract
Write your full report to `research/split_pad_timing_policy/agent_reports/agent_<LETTER>_<topic>.md`.
If you cite works NOT already in the 102-paper matrix, end with:
- `## NEW_PAPER_MATRIX_ROWS` — pipe-delimited, columns: `title | authors | year | venue | doi | url |
  peer_reviewed | evidence_level | split_relevance | padding_relevance | timing_relevance | protocol |
  attacker_model | mechanism | sw_or_hw | platform | experiment_type | security_result |
  overhead_result | limitations | relevance` (use NA for unknowns; escape literal `|`).
- `## NEW_BIBTEX` — verified BibTeX for only the NEW works (citekey firstauthor+year+word).
Return to the lead a ≤250-word summary: top findings, which deliverable sections you cover, and your
single most important caveat.
