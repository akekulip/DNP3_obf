# Phase 00 Audit — Research Reviewer Worklog

**Role:** Research Reviewer (claims-to-evidence audit). **Mode:** READ-ONLY. No results
regenerated; nothing executed. Only write is this worklog.
**Root:** `/home/philip/Projects/DNP3/dnp3_split_harness/`. **Date:** 2026-07-15.

**Classification key:** MEASURED = from a real wire capture (pcap/tshark/ss on a NIC).
REPLAYED = produced by the replay/split server standing in for a device. SIMULATED = computed
from recorded trace *features* (no live packets). INFERRED = derived/reasoned, not directly
observed. PROJECTED = computed by a planner/calculator, not enforced on the wire.

**Headline:** the repo's *primary* reports and `RESUME_STATE.md` are unusually disciplined —
they self-caveat loopback≠wire, host-capture≠wire, 40 ms non-universal, replay-server≠real-device,
and (critically) that a user-space app cannot move a kernel-owned pure TCP ACK. Most audit risk is
not fabrication; it is (a) one planner (Claim 8) whose before/after is presented in derivative docs
as an achieved manipulation, and (b) two numbers (Claims 4, 6) that are loopback-/claim-backed and
get restated without their caveat.

---

## Claims-to-evidence table

### Claim 1 — "~22,988 reconstructed transactions from the six device pcaps"
| field | finding |
|---|---|
| **Class** | **MEASURED** (offline reconstruction from six real-device PCAPs in `Traffic Trace/`) |
| **Evidence** | `reports/ack_trace_characterization.json` (`meta.total_transactions=22988`, per-txn `transactions[]` array), `reports/ack_trace_characterization.csv` (22,988 data rows; last row index 22988 confirmed), `reports/ack_trace_summary.md` (per-pcap table sums to 22,988). Generator: `characterize_ack_traces.py`. |
| **Raw / machine-readable?** | **YES** — 5.0 MB CSV + 19 MB JSON with one record per transaction. Arithmetic re-checked: 798+3998+1598+7998+598+7998 = **22,988**. ✓ |
| **Scope caveats** | 22,988 counts transactions to **both** the device-specific outstation IP **and** the shared reference outstation `10.0.0.2` in each pcap; device-specific-only = **11,494** (`attacker_eval.md` line 7). It is **3 device models × 2 captures each** (base + "L"), not six independent devices. Transactions are **heuristically reconstructed** (anchored at a payload-bearing REQUEST, matched to first reverse-direction packet + first payload-bearing RESPONSE), not decoded DNP3 CONFIRMs. |
| **VERDICT** | **SUPPORTED** as a raw reconstructed-transaction count. Carry with the annotation "11,494 device-specific / 22,988 incl. reference outstation; 3 models ×2 captures." |

### Claim 2 — "SEL-751 emits a SEPARATE pure TCP ACK; AB1400 and ION7550 piggyback (combined)"
| field | finding |
|---|---|
| **Class** | **MEASURED** (from the six real-device PCAPs) |
| **Evidence** | `reports/ack_trace_summary.md` validation table (SEL-751 dev `10.0.0.1`: 4298 txns, **100.0% separate**; AB1400 dev `10.0.0.12`: 2398, **100.0% combined**; ION7550 dev `10.0.0.11`: 4798, **99.98% combined**), backed by `ack_trace_characterization.{json,csv}`. |
| **Raw / machine-readable?** | **YES** (per-txn CSV/JSON with `is_separate`/`ack_pure` fields). |
| **Scope caveats** | One physical unit per model, one lab trace. "SEL-751 / AB1400 / ION7550" = the captured device+firmware, **not the product family**. Separation is a TCP-layer heuristic (zero-payload, no-PSH ACK precedes response). Report states results are "measured on this device / trace / host." |
| **VERDICT** | **SUPPORTED** for the captured devices. Do not generalize to all units of these models. |

### Claim 3 — "A Linux ACK-separation transition occurs around ~40 ms"
| field | finding |
|---|---|
| **Class** | **MEASURED** (two-host rig, raw pcap) — **not** loopback. The loopback socket probe could NOT detect it (see note). |
| **Evidence** | `reports/ack_separation_rig_results.md` + **raw** `reports/ack_separation_rig/acksep_refine.pcap` (2.6 MB, fine grid), `acksep_serverside.pcap` (2.3 MB), `ack_separation_client_matrix.csv`. Fine grid: 38 ms → **0.00** separate-ACK fraction; **40 ms → 0.93**; 42 ms → 1.00 (1808 txns, 0 resets). Raw-packet trace quoted (pureACK len=0 at +40.20 ms). Corroborated in `ack_delay_master_report.md` §3.3 and `ack_timing_implementation_report.md` §5A. |
| **Raw / machine-readable?** | **YES** (pcaps + CSV on the outstation NIC, tshark-analysed). |
| **Scope caveats** | This is the Linux **`TCP_DELACK_MAX`** on the probe host (Ubuntu 24.04, kernel 6.8), measured against the `ack_separation_probe.py` **delay server — not a real DNP3 device**. Host-side (Hulk egress) capture: authoritative for *emission*, not a mid-path/wire observation. 40 ms is **Linux-specific, explicitly non-universal** ("other stacks/OSes differ"; `RESUME_STATE.md` line 348 "not universal"). |
| **Note (loopback vs rig)** | `reports/ack_separation_notes.md` is a *loopback* run that reports every pure-ACK cell as `unk` (no capture privilege) — it does NOT support the 40 ms claim and must not be cited for it. |
| **VERDICT** | **SUPPORTED** as a Linux-stack behavior on this rig; correctly bounded as non-universal in the primary reports. |

### Claim 4 — "RTO floor around ~211 ms"
| field | finding |
|---|---|
| **Class** | **MEASURED but LOOPBACK-only** (Linux `TCP_RTO_MIN` floor, not a wire RTO) |
| **Evidence** | `reports/rto_probe_notes.md` (smallest peer RTO **211.2 ms** via `ss` TCP_INFO `rto:`), `reports/rto_probe_results.csv` / `.json` (raw per-delay). Indirect rig corroboration: `rig_timing_matrix_results.md` (0 retransmits under 25 ms hold, "matching the loopback RTO analysis"). |
| **Raw / machine-readable?** | **YES** (csv/json) — but from **loopback** (`127.0.0.1`, Py 3.8, gambit). |
| **Scope caveats** | Report is explicit: "loopback is NOT the wire… a lower bound on the RTO floor (the RTO minimum), not authoritative wire behaviour. Do not claim loopback == wire." No **rig** RTO number was measured by `rto_probe.py`; the rig run only *infers* safety from 0 resets. 211 ms ≈ Linux RTO_MIN (200 ms + timer granularity). |
| **VERDICT** | **PARTIALLY SUPPORTED.** 211 ms is a genuine measurement of the Linux **RTO floor**; it is **not** a measured real-network RTO. Carry as "loopback RTO_MIN ≈211 ms," not as the rig/wire RTO. **REPRODUCE on the rig** for a wire RTO. |

### Claim 5 — "Fixed and bounded timing normalization tests succeeded (byte-preserving)"
| field | finding |
|---|---|
| **Class** | **REPLAYED** (rig run against the replay server) + loopback MEASURED — **not a real device** |
| **Evidence** | Rig: `reports/rig_timing_matrix_results.md` + **raw** `reports/rig_timing/rig_matrix_results.json`, per-config `*_timing_decisions.jsonl`, wire pcaps `pcap-{native,fixed25,bounded1525}.pcap`. 930 timed txns, **0 miss / 0 bypass / 0 reset**; fixed-25 pinned to 25.000 ms (median=p95=p99=max); wire fixed-25 = 25.36 ms ±0.1; **byte-preservation PASS** every response. Loopback: `reports/timing_experiment_results.csv` (`byte_identity_all_pass=True` for all 7 configs). |
| **Raw / machine-readable?** | **YES** (JSONL + pcaps + CSV, incl. an explicit byte-identity column). |
| **Scope caveats** | The "outstation" is the **replay server** (native ~1 ms), **not a real device**. Report line 25–31: this validates the **mechanism, safety, byte-preservation, TCP-health**; it does **NOT** close a real device's size/timing leak (needs the physical devices). |
| **VERDICT** | **SUPPORTED** for {mechanism works, byte-preserving, TCP-safe, pins visible time to target on real two-host hardware}. **UNSUPPORTED** if read as "hides a real device's timing fingerprint." |

### Claim 6 — "Timing-policy unit tests pass (22 tests)"
| field | finding |
|---|---|
| **Class** | **Verified-code (static count) + claim/cache-backed pass-status** |
| **Evidence** | `tests/test_timing_policy.py` — **exactly 22** `def test_` functions (counted this session). `.pytest_cache/v/cache/` present, compiled `test_timing_policy.cpython-38-pytest-8.3.5.pyc`, **no `lastfailed` file** (consistent with a clean prior run). Pass-status asserted in `ack_delay_master_report.md` (22/22) and `ack_timing_implementation_report.md`. |
| **Raw / machine-readable?** | **PARTIAL** — 22 test functions confirmed by static count (definitive). "Pass" is from report prose + absence of `lastfailed` in the pytest cache (weak positive); **not re-executed this session** (READ-ONLY). |
| **Scope caveats** | Unit tests exercise the **pure functions** (scheduler arithmetic + `plan_ack_response_release` math). They validate the *calculator*, **not** that any ACK/response reschedule occurs on real packets (see Claim 8). 5 of the tests call `plan_ack_response_release` — testing its return values, not wire enforcement. |
| **VERDICT** | **SUPPORTED** that 22 timing tests exist and target the timing logic; pass-status is claim+cache-consistent. Mark "PASS (report+cache); re-run `python3 -m pytest tests/test_timing_policy.py` to confirm this session." |

### Claim 7 — "Attacker device-classification results"
| field | finding |
|---|---|
| **Class** | **SIMULATED** (on recorded trace *features*), explicitly not a live-defended-server capture |
| **Evidence** | `reports/attacker_eval.md` + **raw** `reports/attacker_eval_results.json` (122 KB, seed 42). |
| **Numbers** | Native all-features device-ID **accuracy 0.897** (bootstrap 95% CI [0.892, 0.903], macro-F1 0.849). **Split = CAPTURE-LEVEL** (train each device's base pcap → test its disjoint larger "L" pcap); a random row split is **explicitly avoided** as leaky. Robustness = leave-one-PCAP-out GroupKFold, pooled **0.722**. Tree ensembles corroborate (RF 0.889, GB 0.917 native). |
| **Device-ID residual after defense — reported?** | **YES.** uniform_15_25 = **0.900**, constant_25 = **0.900** — stays high because the fingerprint rides response **size** (`resp_size` {37/54/61}) and **ACK-mode** (SEL-751 separate ACK), channels the timing defense does not touch. `size_only` 0.500 and `ackmode_only` 0.800 are invariant native-vs-defended by construction. |
| **Raw / machine-readable?** | **YES** (JSON). |
| **Scope caveats** | Stated §5: a **SIMULATION on trace features** (normalizes recorded `req_to_resp_ms`), not a live capture; no queueing/RTO/measurement noise modeled. Only 3 classes from 6 captures; bootstrap CIs treat correlated rows as independent → understate uncertainty. |
| **VERDICT** | **SUPPORTED** as a capture-level-split trace-feature simulation with the post-defense residual honestly reported. Carry as **SIMULATED**; the honest headline is "device-ID stays ~0.90 after timing normalization." |

### Claim 8 — `plan_ack_response_release()`: real mechanism, or pure planner?
| field | finding |
|---|---|
| **Class** | **PROJECTED / planner-only. NO packet-control enforcement. NO PCAP evidence.** |
| **Evidence (code)** | `timing_policy.py` lines 331–387: a **pure function** — docstring "no clock reads, no sleeps… Nothing here forges packets"; it "only *reschedules* two packets that already exist." **Usage grep:** called ONLY in `tests/test_timing_policy.py` (5 sites, unit tests of the math) and `trace_before_after.py:173` (a projection over the recorded CSV). It is **NOT** wired into `split_server.py` (imports `timing_policy` but uses only `profile_from_args` + `ReleaseScheduler` = the Phase-1 combined-response path) and **NOT** into `ack_separation_probe.py`. |
| **Evidence (repo self-concession)** | `rig_timing_matrix_results.md` line 107–108: "Phase-2 … a user-space server **cannot move a kernel-owned pure TCP ACK**." `RESUME_STATE.md` line 128–129: "Phase 2 scaffolded but not wired … `plan_ack_response_release` is a **scheduling calculator**." `trace_before_after.md` line 35: "a **projection** … **not a fresh live capture**." |
| **Raw / machine-readable?** | **N/A** — there is no packet-level artifact of this function driving a wire. The only ACK-separation pcaps (`acksep_refine.pcap`) come from a **different** mechanism (hold the app write ≥40 ms → kernel emits the ACK autonomously), not from this planner. |
| **Scope caveats** | The function assumes it can independently schedule an *already-existing* pure ACK. A user-space app does **not** control when the kernel emits the pure ACK (only the response `write()`). So its `ack-delay-only` and `gap-normalized` (ACK-advancing) modes are **not user-space-realizable**; only `response-delay-only` (delay the write) is. |
| **VERDICT** | **UNSUPPORTED-BY-AVAILABLE-EVIDENCE** for any enforcement claim. It is a correct, unit-tested pure planner used only for a distributional projection. No real mechanism enforces the ACK reschedule, and the repo itself says so. Carry ONLY as "Phase-2 timing calculator, not an implemented or wire-validated mechanism." |

---

## Overclaiming flags (against §H limits)

Primary reports mostly pass §H. Flags below are ranked; #1 is the one to fix.

1. **[MOST IMPORTANT] The Phase-2 ACK-delay before/after is presented as an achieved manipulation.**
   `trace_before_after.md` line 33 calls the `ack-delay-only`/`gap-normalized` results "the **literal ACK-delay manipulation applied to the real trace**," and the tutorial/briefing HTML carry an interactive "40 ms delay→ACK-mode slider" and before/after gap numbers (12.21 → 4.21 ms / 20.00 ms). These are **PROJECTED** outputs of `plan_ack_response_release`, a calculator that is (a) not wired to any packet path and (b) not user-space-realizable for the ACK-advancing modes (the kernel owns the pure ACK). **Fix:** label every Phase-2 before/after as "PROJECTED (planner); ACK-advancing modes not realizable in user space; unvalidated on the wire," and soften "literal manipulation applied."

2. **"22,988 transactions" can read as 6 independent devices / unique request-response pairs.**
   It is 3 device models × 2 captures, and **double-counts** the shared reference outstation. Annotate "11,494 device-specific."

3. **"RTO measured ≈211 ms" is restated without the loopback tag in derivative text** (e.g. `RESUME_STATE.md` line 177). Always tag it "loopback / Linux RTO_MIN floor," never the wire/rig RTO.

4. **Padded-defense device-ID "0.90 → 0.797" (pad_rig / briefing) is a trace-feature projection**, not a three-device rig capture (`pad_rig_results.md` is honest about this; ensure the briefing/tutorial do not present 0.797 as rig-measured). The **size-padding mechanism** IS rig-measured (214→361 B match, 0 resets); the **accuracy drop** is SIMULATED.

5. **rig_timing "device size/timing-leak closure"** — guard against any summary reading the 930-txn replay-server run as "closes the device fingerprint." The replay server has no size-dependent native time; closure is explicitly still open.

**§H items checked and CLEAN in the primary reports:** no claim timing normalization hides
response **size** (`attacker_eval.md` states the opposite); no claim splitting hides **total bytes**
(`RESUME_STATE` line 365/370 "total bytes unchanged," "no byte-preserving DNP3 padding exists");
40 ms explicitly **non-universal**; host-capture explicitly **≠ wire**; **no P4 resource/stage/SALU
fit claims** appear in the timing reports (P4 only mentioned as "not needed" / future).

---

## Carry-forward recommendation for RESEARCH_CLAIMS.md

**SUPPORTED (safe to carry, with the stated scope tag):**
- **C1** 22,988 reconstructed transactions — MEASURED (annotate 11,494 device-specific; 3 models ×2 captures).
- **C2** SEL-751 separate-ACK vs AB1400/ION7550 combined — MEASURED (captured devices, not families).
- **C3** ~40 ms Linux delayed-ACK separation threshold — MEASURED on rig (raw pcap), **non-universal**.
- **C5** Phase-1 fixed/bounded timing normalization is byte-preserving + TCP-safe + pins visible time — REPLAYED on rig (mechanism/safety only, replay server ≠ real device).
- **C7** Attacker device-ID fingerprint (native 0.897, capture-level split; residual ~0.90 after timing defense) — SIMULATED on trace features; residual reported honestly.

**UNSUPPORTED / DOWNGRADE / REPRODUCE:**
- **C4** RTO ≈211 ms → downgrade to "loopback RTO_MIN floor"; **REPRODUCE** on the rig for a wire RTO.
- **C6** 22 unit tests pass → carry as "22 tests exist (static-confirmed); PASS per report+pytest-cache; **re-run to confirm this session**."
- **C8** `plan_ack_response_release` enforcement → **UNSUPPORTED**; carry only as "Phase-2 planner/calculator, not implemented or wire-validated; user-space cannot move a kernel-owned pure ACK."
