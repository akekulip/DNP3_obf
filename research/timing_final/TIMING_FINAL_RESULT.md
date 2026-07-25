# TIMING_FINAL_RESULT.md (directive §11)

The one-page result of the timing deliverable. What was built, what was measured on real hardware,
what may and may not be claimed. Numbers trace to `evidence/MANIFEST.md`.

---

## Result in one sentence

On Tofino-1, `dnp3_timing_normalizer.p4` classifies real DNP3 transactions and converts the
ACK-to-RESPONSE interval into a policy-controlled constant G by holding the *original* response
byte-for-byte in a Traffic-Manager queue until a data-plane deadline (t_ack + G) — no controller in
the fast path, no external blocker traffic — reducing the CLRT-magnitude fingerprint of the physical
SEL-751 from **2.73 bits to 0.00 bits** at millisecond resolution.

## Headline numbers

| quantity | native SEL-751 | protected (G = 25 ms) | source |
|---|---:|---:|---|
| CLRT median | 2.03 ms | 24.999 ms | `evidence/native/`, `evidence/protected/` |
| CLRT std dev | 10.33 ms | 0.010 ms | campaign, n=120 / n=100 |
| CLRT entropy @1 ms | 2.73 bits (CI [2.52, 2.84]) | **0.00 bits (CI [0,0])** | `evidence/fingerprinting/` |
| CLRT entropy @500 µs | 3.73 bits | **0.00 bits** | `evidence/fingerprinting/` |
| byte-identity of held response | — | 100/100 identical | `evidence/packet_identity/` |
| blocker frames seen by master | — | 0 | STAGE_B_RESULT.md |
| release-tail (deadline→egress) | — | 1734.5 ns, sd 7.34 ns | Fig 8, Part 12 n=100 |

## Live on-silicon confirmation (2026-07-25)

Beyond the replay campaign, the full pipeline was run **live end-to-end on the physical Tofino-1**
(`demo_all.sh`, authorized): the program was loaded onto the switch, real replay traffic was injected
from Vision and Hulk, native and protected transactions were captured and verified on hardware, and
the switch was restored to `queue_microbench` afterward.

| live run (n=30) | native (bypass) | protected (G=25 ms) |
|---|---:|---:|
| CLRT median | 1.979 ms | 25.001 ms |
| CLRT std dev | 0.0076 ms | 0.0104 ms |

30/30 responses released, **0 unmatched frames (byte-identity), 0 external blocker frames (token
isolation)**, all 10 verifier gates PASS; restoration verified. Evidence:
`evidence/live_demo/` (`LIVE_DEMO_RESULT.md`, pcaps, verifier JSON, figures, run log).

## What was built

- `p4/dnp3_timing_normalizer.p4` — the canonical program (sha 82f572ce), **10/12 ingress MAU
  stages, 0 egress stages, 0 TCAM**; compiles clean on bf-p4c 9.13.1 (local) and 9.13.2 (on switch).
- Control/run/verify tooling: `p13_guard.py` (sets policy G, tick-aligned + read-back-verified),
  the numbered lab scripts `00`–`12`, the packet verifier `08_verify.py`, and the analysis pipeline
  `analyze_clrt.py` / `fingerprint_eval.py` / `make_pub_figures.py`.
- Evidence tree `evidence/` with native, G-sweep (G ∈ {5,10,15,20,25,30,40} ms), the 100-rep
  headline at G=25 ms, the G-guard demonstration, fingerprinting JSON, 10 figures, and the switch
  restoration report.

## Validation performed

1. **Compile** on both toolchains, 0 errors, resource fit identical (no 9.13.2 drift).
2. **Independent review** — 7 review passes; the one substantive defect (B-D1, first-ACK arming
   idempotency) was fixed and re-verified on silicon (`smoke/`, `REVIEW_FINDINGS_AND_ACTIONS.md`).
3. **Campaign** — native characterization, G-sweep confirming the emitted interval tracks G, and
   100 repetitions at G=25 ms with all W-gates PASS.
4. **Fingerprinting** — Miller-Madow entropy with bootstrap CIs over the raw PCAPs, separating the
   channel the defense closes (CLRT magnitude) from the channels it does not (ACK mode, TCP stack).
5. **Restoration** — switch returned to `queue_microbench` (`evidence/final_state/`).

## Claim discipline (directive §10)

**Allowed:** a data-plane-scheduled, chaff-free, byte-preserving timing-normalization *mechanism* on
Tofino-1 that substantially reduces the CLRT-magnitude fingerprint of a real relay.

**Not claimed:** full device anonymity; size obfuscation (separate, unproven, out of scope this
week); live inline relay tolerance (this is replay of the relay's real frames, not a session held in
real time); generality across all DNP3 devices or TCP configurations; production readiness.

**Stated plainly:** ACK mode and TCP-stack characteristics remain independent fingerprinting channels
that this mechanism does not touch; on the 3-device corpus they already identify the SEL-751 at
accuracy 1.000, so closing CLRT here is a within-channel result and a working mechanism, not a
demonstrated end-to-end anonymity result.

## Reproduce the figures

```bash
~/.venvs/research/bin/python research/timing_final/scripts/make_pub_figures.py \
    --figdir research/timing_final/evidence/figures
```
