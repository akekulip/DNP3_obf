# Current status — SEL-751 relay as outstation (run started 2026-10-24)

One status file, updated in place. Dated history: STATUS.md; full record: COMPLETION_RECORD.md.
Directive: `Claude_SEL751_Corrected_Overnight_Directive (1).md` (repository root, untracked).

## Scope
The physical SEL-751 is the outstation. Build one relay-shape candidate (m12p_c30) whose two READ workloads and full
SBO match the relay's decoded shapes, gate it on one SDK-9.13.2 bundle, then run the four-arm and recovery blocks
against the relay through the Tofino. 100 us timing threshold unchanged. IEEE audit and paper out of scope. No Vision
reboot/kernel/firmware, keep-alive, D/J or attacker campaign, manual ownership edits, or weaker restoration.

## Three evidence tiers (keep distinct in every record)
1. Software-reference encoding tests (no hardware).
2. Software master/outstation (.61/.62) through the physical switch -- the c25-c29 runs; regression/comparison only.
3. Physical SEL-751 (.7, DNP3 addr 0) through the switch -- the ONLY tier that qualifies the relay deliverable.

## Starting state (verified 2026-10-24)
- HEAD = origin/main = 659bba2c6; ownership active False, unsafe_restoration False; no running model/compiler/campaign.
- One SDK: local 9.13.2 (~/bf-sde-9.13.2) compiles once into compile_local; model tests it and the switch loads it.
- m12p_c29 (software tier): sizing byte-exact all four arms on the software outstation; timing FAILED (p99 ~2-4 ms);
  recovery mostly pass, graceful-persistence lost one FIN at close (open). Does NOT qualify the relay.
- Relay measured 2026-10-23: mixed READ 91 B, integrity READ 134 B (addr 0/1). 247->271 was the software database and
  does not apply; 134->158 is the smallest reachable padded size. SBO on the relay not yet freshly measured.
- test_nic_repair repaired (reviewed re-pin of the deployed blobs; function unchanged); harness suite 735 pass.

## Completion criteria (relay deliverable)
| # | deliverable | criterion | state |
|---|---|---|---|
| 1 | relay baseline | native mixed/integrity READ + SBO decoded from real SEL-751 captures through the switch | open |
| 2 | shapes | two READ targets + SBO image derived from the relay natives (141/158 provisional; SBO try 60 first) | open |
| 3 | candidate | m12p_c30: relay shapes replace the fixture shapes; FIN/ACK and checker fixes; headroom retained | open |
| 4 | model gate | full v3 gate + relay-shape and FIN/ACK regressions on the one pinned 9.13.2 bundle | open |
| 5 | hardware four-arm | off/timing/size/combined on the relay; readout proves real SEL-751 responses; restore verified | open |
| 6 | hardware recovery | loss (mixed, full), persistence graceful/rst, reconnect, held OPERATE on the relay | open |
| 7 | timing | 100 us precision on the relay measured; failures stay failures | open |
| 8 | close | records, clean-worktree reproduction (c30), restoration verified | open |

## Work in progress
Step 0 done: state verified, test_nic_repair repaired, authorization corrected. Next: reusable relay master
(READ reassembly), then the native relay baseline capture and decode.
