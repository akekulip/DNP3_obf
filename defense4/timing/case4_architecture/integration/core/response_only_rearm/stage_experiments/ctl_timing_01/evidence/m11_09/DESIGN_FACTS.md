# m11_09 design facts for the paper (2026-10-19)

There is no m11-specific design document. m11_09 is the N stage-cut successor of m10_03:
- E is byte-identical (`resource_review.json`: `E_byte_identical: true`);
- T changed in resource placement only;
- the release rules are therefore those written for m10_03 in
  `../m10_03/PART2_DESIGN_20261018.md` (§1, lines 13–46).

Each statement below names the line of `response_only.p4` (sha256 `f1de2b30…`, 2,551 lines) or the
evidence file that supports it. Anything not listed is not established for the paper.

## Programs and pipes

- **Pipe layout.** `Pipeline(N ingress, -, -, E egress)` is pipe p0 and `Pipeline(T ingress)` is
  pipe p1 (P:2549–2551).
  - The switch has two physical pipes, so the design uses two (P:1436–1441).
  - Pipe-local ports 68–71 are dedicated recirculation ports (P:1442).
- **N (p0 ingress, P:106–521).** It parses DNP3 over TCP and binds each connection. The program
  carries "no request padding" (P:5–6), and requests leave unchanged. It computes the link-header
  and first-block CRCs for every DNP3 kind (P:225). It hands timed traffic to T at pipe-1 port 180
  (P:1450). A source comment at P:1445–1448 still marks the packet-generator token path as "UNVERIFIED
  ON SILICON"; the campaign ran on silicon, but this note does not certify that path.
- **E (p0 egress, P:526–1360).** The response path runs in one egress pass: a response re-encoder
  fused with a TCP transport mapper (P:529–531).
  - The mapper translates sequence and acknowledgment numbers between the native and enlarged byte
    streams, in both directions (P:1132).
  - Re-encoding is gated on the mapper's commit or replay verdict, so a refused or unconfigured flow
    is never lengthened without translation (P:533–537).
  - One incremental TCP checksum covers every changed frame (P:540–546).
- **T (p1 ingress, P:1566–2519): the timing role.** The design is queue-resident (P:1421–1424):
  - the real ACK, response and OPERATE originals stay in hold queues: qid 6 and qid 4 on the
    ladder, qid 2 on the OPERATE ladder;
  - only blocker tokens (qid 7, 5 and 3) circulate.
- **Clock.** `md.now = global_tstamp[39:8] & ~1` (P:1661): 256 ns units on a 512 ns grid
  (`supported_profile.json` clock).

## Release rules (T)

A delta has passed when its sign bit is 0 (PART2 §1). The deltas are computed at P:2112–2126.

1. **The ACK commits** when `da_delta` has passed *and* a response of this generation has been
   seen. The ACK's actual release time is written as a_commit.
2. **ACK fallback:** when `readiness_delta` has passed, the ACK is released without a_commit.
3. **The response** leaves when `now ≥ a_commit + gap` (P:2115, `commit_at_gap`). The gap D runs
   from the ACK's actual release, not from a precomputed deadline.
4. **Response fallback:** at `readiness`.
5. **Piggybacked response:** with no standalone ACK, it leaves when `pb_delta` has passed.
6. **OPERATE** is held until op_t0 + J (P:2126). Its ACK and response lane is anchored at the
   OPERATE's arrival at T, so J < pb is required.

Consequences:
- request→ACK = max(da, L) for READ and SELECT, and max(da, J + L) for OPERATE;
- ACK→response = D.

With the campaign envelope (da = 31 ms ≥ L + Jmax + G), every operation's ACK leaves at about
31 ms: the measured median is 31.10–31.13 ms (`eval_m11_09_20261018_02_paper/figures/fig_operate_hold_data.csv`).

**cap** is accepted and never stored; it is a validator bound on readiness only (PART2 §1).

**Lap budget:** 240,000 laps per held packet, counted in laps, not time (P:2092; PART2 §1).

## Envelope (campaign `release/audit/common_envelope.json`)

G = 5 ms, Dmax = Jmax = 20 ms, rounded up to 1 ms.

| quantity | value (ms) |
|---|---|
| L (pilot maximum response availability) | 5.598 |
| da = C(L + Jmax + G) | 31 |
| pb = C(max(Jmax + G, da + Dmax + G)) | 56 |
| readiness = C(max(pb + G, max(da, L + Jmax) + Dmax + G)) | 61 |
| cap = C(readiness + G) | 66 |

Effective values on the 512 ns grid: 31.000576 / 56.000512 / 61.000704 / 66.000640 ms. The guards
are experimental margins, not proven bounds.

## Response-size normalization (E) — `supported_profile.json` `encoding`

- **Native responses:** READ 49 octets; SELECT and OPERATE 37 octets. **Output:** 61 octets for
  all three.
- **READ is re-encoded** (Group 10 Var 2) as three index ranges over the same points:
  (qualifier 0, 0–5), (qualifier 0, 6–9), (qualifier 1, 10–22)
  (`read_ranges`, from `read_reencode_01/profile_check.py`).
- **SELECT and OPERATE.** The 22 native application octets are split 15/6/1 across three DNP3
  transport frames of 28/19/14 octets, in one TCP segment (`control_application_partition`).
- **Conformance.** The campaign checker passed all 98,816 main responses, with the application
  sequence echoed and no CRC failure (`eval_m11_09_20261018_02_paper/tables/table_conformance.csv`).
- **History.** The two-range, 58-octet filler and response carving belong to earlier builds and
  are prohibited (`../../../../evidence/rearm_01/PLAN.md`:23–26). Do not describe them as NOMAD.

## Resources (p4c 9.13.2, `compiler_table.csv` and `compile_switch_9132/out/p*/logs/mau.resources.log`)

| program | stages | SRAM | TCAM | stateful ALU | exact-match xbar bytes |
|---|---|---|---|---|---|
| N | 11 | 101 | 60 | 17 | 438 |
| E | 12 | 55 | 30 | 8 | 304 |
| T | 11 | 49 | 60 | 13 | 294 |

Average per-stage utilization:
- pipe p0: SRAM 16.46%, TCAM 31.25%, meter ALU 52.08%;
- pipe p1: SRAM 5.57%, TCAM 22.73%, meter ALU 29.55%.

## Testbed

- **Switch.** "ufispace" (10.10.54.81), a Tofino-1 switch running SDE 9.13.2
  (`defense4/timing/SWITCH_LAYOUT.md`:10). No chassis model number is recorded; confirm it before
  naming a model in the paper.
- **Endpoints.** The OpenDNP3 master (192.168.10.61) and outstation (192.168.10.62, software
  actuation handler) run on Vision in two VEPA namespaces behind device port 9
  (`supported_profile.json` ports; `protocol/hw_vepa/README.md`:1–4).
- **Captures.** Two paired tcpdump captures on Vision's switch-facing parent NIC, shared by both
  endpoints: "out" holds what the endpoints transmit before the switch, "in" what the switch
  delivers back. The master-visible observation is "in".
- **Controller.** The campaign controller ran on Gambit.

## Not established

- A chassis model name.
- Table counts as the paper would state them (count them from `context.json` with a stated method
  first).
- The restart path on silicon (model-only).
- Physical-relay operation for m11_09.
