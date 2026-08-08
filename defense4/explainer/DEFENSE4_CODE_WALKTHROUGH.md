# Defense 4 code walkthrough

A guided tour of the actual code, with verified line anchors. It covers the data plane (the P4), the
control plane (the setup script), and the measurement harness. Line numbers are from
`../timing/p4/defense4_caseA.p4` (2994 lines, heavily commented) at the current commit; grep the named
symbol if a line has shifted.

## Data plane: `defense4/timing/p4/defense4_caseA.p4`

### Parser and direction (line ~902)

The parser (`state start` at 902) sorts each packet by where it came from: `from_relay` (992),
`from_master` (996), `from_outstation` (994), `from_loopback` (987, the dp8 recirculation of blocker
tokens), and `from_pgen` / `parse_pktgen_token` (1003, 1034, the generated 0x88C1 blockers). Direction
drives the forwarding port and the classification.

### Policy and session tables

- `tbl_params` (1874) holds the run-time policy the control plane sets: mode (OFF/D1/D2/D3/D4/FAIL_OPEN),
  the deadline words `d_ticks` (D_A) and `da_dr` (D_A+D_R), the budget, and the read length. The
  control plane writes this between drained transactions; the data plane only reads it.
- `tbl_session` (1909) pins the protected flow (the relay-facing 4-tuple), so only that flow is shaped.

### The transaction lifecycle on `reg_tag`, and the fix

The heart of the design is one stateful register, `reg_tag`, that tracks the active transaction by its
DNP3 generation (the application-control octet C0..CF). It has four RegisterActions, and the design
comments explain why a fifth is impossible on this SALU (a hard resource error, noted at 1306):

- `tag_arm` — arms the transaction once, from idle, when a READ is classified.
- `tag_rmw` — the read-modify-write used on the marking path.
- `tag_read_or_mark` — a pure read at operand zero (used by the fix, see below).
- `tag_retire_if_unmarked` — retires an unmarked generation.

The lifecycle bug was that `tag_retire_if_unmarked` ran on every acknowledgment release, so on D2/D4
the transaction retired before the response arrived and the response bypassed. The fix makes the
retire mode-aware: only the acknowledgment-only modes (`MODE_D1_EVENT` = 1 at line 547, `MODE_D3_ACK`
= 3 at line 549) retire at acknowledgment release; the must-hold modes D2/D4 keep the transaction
alive so the later response is still held. A read-only companion RegisterAction on the acknowledgment
register, `ack_rel_r` (1526, alongside `ack_rel_rmw` at 1515), restores the early-versus-late response
distinction without a write hazard. The acknowledgment-release counters split into `CD_ACK_RELEASE`
and `CD_ACK_REL_RETIRE` (659) so the evidence shows which retirement path actually ran. No new
register, SALU, PHV field, or counter was added; `reg_tag` stays at four actions.

### The response blocker gate (qid5)

`meta.expired_resp` (826) is set only when the response deadline is armed and due. The response
blocker (Q_RESP_BLOCK) drains on the deadline only when a response is actually pending; otherwise it
loops to the bounded budget rather than vanishing at T_RESP. This is the second half of the fix: a
missing or late response no longer strands the reservoir.

### Queues and blocker tokens

Four queues in strict priority (design notes near 62-116, roles at 296-298): Q_ACK_BLOCK (qid7) >
Q_ACK_HOLD (qid6) > Q_RESP_BLOCK (qid5) > Q_RESP_HOLD (qid4). The K=64 request-triggered blocker
tokens (EtherType 0x88C1) recirculate on dp8; the original acknowledgment and response stay
queue-resident and are released by the traffic manager. The strict order guarantees the acknowledgment
is never released after the response.

### Counters

`ctr_fresh` (612) counts the fresh (non-dequeued) path: ARM_FRESH, RESP_HOLD_EARLY, RESP_HOLD_LATE,
RESP_BYPASS, and so on. `ctr_deq` (648) counts the dequeued (dp8 loopback) path: the release causes and
the acknowledgment-release split. These are the counters the scorer reconciles.

## Control plane: `defense4/timing/control/defense4_caseA_setup.py`

One authority for the run-time policy. Operations (argparse at ~628): `initialize` (establish the
fixed function once), `set-policy` (mode + delays, refuses while a transaction is active),
`clear-evidence` (zero the counters), `configure`, `verify-only` and `evidence-dump` and `snapshot`
(read-only), and `restore-only`. Delays are given in milliseconds and quantized to the tick encoding
(the delay word is ticks shifted left by eight, low byte zero). No harness writes `tbl_params`
directly.

## Measurement harness: `defense4/timing/control/deploy/`

- `score_campaign.py` — the fail-closed, mode-aware scorer. Exits nonzero on any hard anomaly (a
  must-hold bypass, an ordering inversion, a stale tag, a counter that does not reconcile, a token on
  the wire, a drop, a missing or invalid PCAP, an absent counter) and passes only a fully valid block.
  A declared negative must actually be exercised.
- `campaign_driver.py` — runs on the master; one sustained TCP connection, 60 READs advancing C0..CF,
  full-Ethernet capture, one rich JSON row per poll (the 4-tuple, seq/ack, timestamps, CLRT, duplicates,
  retransmits, FIN/RST, segment count).
- `pair_bytes.py` — the paired ingress-versus-egress byte comparator (matches by direction, 4-tuple,
  seq/ack, flags, DNP3 app-sequence, length, occurrence; MAC must match; catches a one-byte change).
- `analyze_campaign.py` — condition-aware statistics, one PASS per expected block, session bootstrap,
  full distributions with tails.
- `run_campaign.sh` — the orchestrator: refuses a stale output dir, validates every capture, runs the
  scorer, the analyzer, and the comparator, records provenance and offload, and finalizes the manifest
  before choosing the exit code. `manual_campaign.sh` is the no-rollback variant used for the physical
  campaigns so a scorer flag cannot cost the deployment.
- `make_manifest.sh` — SHA-256 over every file; verified with `sha256sum -c`.
- `fixtures/` — 78 fail-closed tests proving each tool rejects the exact bad input it must.

## Controlled outstation: `defense4/timing/control/outstation/`

`software_outstation.py` is the deterministic DNP3 software outstation for the negative-test lab: a
scenario engine (`plan()`) that emits exactly the frames each of 21 controlled cases needs, validated
offline by `test_outstation_offline.py` (58 checks). Its live wire realizer is wired up when the
outstation is placed on a switch port.
