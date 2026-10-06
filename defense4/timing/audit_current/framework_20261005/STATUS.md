# Framework track — current status (updated 2026-10-06, after the master-timer measurement)

Start here; `HANDOVER.md` has the commands and blockers, `CLAIMS_RECONCILIATION.md` the per-capability evidence, `STATUS_MATRIX.md` the full matrix.
**On `main`** since pull request #6 (merge commit `20eef2019`, 2026-10-06; previous `main` `f8be278eb`). The work was done on `codex/framework-implementation-20261005`, which is left on the remote (not deleted). From here on, work and commit directly on `main`; no new branches. All commits are by `akekulip <akekulip@gmail.com>`, author and committer, with no
co-author trailers. Offline tests: **391 pass** (58 + 98 + 39 + 49 + 147, `defense4/timing/framework/run_tests.sh`).

## Phases

| phase | status | where |
|---|---|---|
| 0 inventory, baseline, campaign_v2 reproduction | done; gate differences are path-only | `PHASE0_INVENTORY.md` |
| 1 contract, layout, declarations | done | `framework/contract`, `framework/declarations` |
| 2 response-ready release and recovery | offline-tested, compiled, **loaded and OFF-arm smoke on hardware**; holding behaviour not run on hardware | `framework/model`, `framework/tests`, `response_ready/` |
| 3 per-type cases | Case 1 (D_A = 0) and Case 2 (`MODE_D2_RESP`) offline-tested and compiled | contract, `response_ready/src` |
| 4 size and joint | software only; 120 captured segment pairs reproduced byte for byte; **no Tofino compile of the combination** | `framework/size` |
| 5 adapter and compile gates | adapter ran live inside the bring-up (`PASS`); SDE 9.13.1 and 9.13.2 builds of source `df599101…`, 7 ingress / 0 egress | `framework/control` |
| 6 BMv2 | done, software timing; gating emulated (priority queues do not gate) | `BMV2_ARTIFACT.md` |
| 7 generated ACK | software only; transport requirement unmet; not a paper case | `PHASE7_GENERATED_ACK.md` |
| 8 hardware | OFF-arm smoke 30/30 READ; master timer measured; **holding arms blocked on admission** | `HARDWARE_SMOKE_20261006.md`, `MASTER_RTO_CANDIDATE_20261006.md` |
| 9 measurement design | written | `PHASE9_MEASUREMENT_DESIGN.md` |
| 10 analysis and figures | BMv2 populations and Formby signature; no classifier (no device labels) | `framework/analysis`, `framework/results` |
| 11 figure, reconciliation, handover | mechanism diagram, claims reconciliation, handover | `framework/figures` |

## Hardware, as run on 2026-10-06 (every session ended with the original program restored and its configuration verified identical)

1. Restoration rehearsal with no candidate (cold restart, port replay from a snapshot). One benign difference on unused port 17.
2. First candidate load **failed**: two const tables over their declared size (`bf_device_add … Not enough space`). Fixed, tested, rebuilt; lab restored.
3. Candidate (source `df5991016285…`) loaded; bring-up `PASS (0 fail, 0 warn)`; 30/30 READ in the Timing OFF case, median CLRT 2.240 ms; restored.
4. Master retransmission timer measured on the candidate build: kernel RTO 201 ms, first repeat 204.4 ms; `iptables` rule removed and verified; restored.
Four restores, the switch is on `defense4_rrc_bor_unified12` / `frozen_abs.conf`, one daemon.

## What is established, in one paragraph

The candidate loads on the Tofino, brings up with strict readback and is transparent in the OFF arm. Its release rule, recovery, both cases and the split agree with an independent
model and with BMv2 on real packets, and the admission rules correctly refuse to let it hold traffic until three inputs exist on this build.

## What is not

Any holding behaviour on hardware (D_A, gap, fallback, split); the data-plane terms `detect_ms` and `release_tail_ms`; the outstation's timer and feedback path on this build; SELECT and
OPERATE (not admitted; OPERATE stays attended-only); a relay-facing capture; a Tofino fit of the split with the 7-stage release; token-loss and FIN/RST gaps in the P4 (a `KNOWN_LIMITATION` test records the first).

## Decisions still yours

- How to clear admission: a recorded operator acceptance of `provisional` for a bounded smoke, an instrumented measurement build, or a relay-facing tap (`MASTER_RTO_CANDIDATE_20261006.md`).
- The dated scope-change line in `CLAUDE.md` (it carries your own uncommitted edits, so it was left alone).
- Whether to delete the remote branch `codex/framework-implementation-20261005`; it is kept, since the repository rules forbid deleting remote branches without being told to.
