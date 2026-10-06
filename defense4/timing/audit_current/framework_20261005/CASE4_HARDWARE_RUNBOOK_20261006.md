# Case 4 bounded campaign — prepared procedure, collection blocked

This is the Case 4 replacement for the experiment matrix in `PHASE8_HARDWARE_RUNBOOK.md`. The earlier runbook and OFF smoke are historical evidence. No switch state, capture availability, endpoint permission, or timer bound is inferred from those records. This procedure has not been executed. Every declaration has `hardware_authorized: false` and `blocked_pending_joint_build_and_admission`.

## Offline identities and gates

The retained timing baseline is SDE 9.13.2 build_03, source SHA256 `df5991016285b146e6dc8a7efb236e16b319fe500274386214e6aacb0529011a`, seven ingress stages and zero egress stages. Its default verifier remains a seven/zero gate. Its snapshot remains valid evidence after current source changes; it is not evidence for the changed current source or the joint mechanism.

The current timing/recovery component `response_ready/evidence/case4_recovery_build_04` has source SHA256 `3f759d06e6c610814def05ce9c83d3688b1bf8397f04000ddf546181674d2f09`, compiler `p4c 9.13.1 (SHA: e558d01)`, ten ingress stages, zero egress stages and 104 tables. The corrected joint component probe `framework/p4/evidence/build_26` compiles at ten stages in each direction with exact current timing/wire input hashes. These are local offline resource results; they do not supply the complete TCP ledger, ingress CRC/shape integration or phase-specific size/timing association, and are not deployable 9.13.2 artifacts.

`framework/control/consts.json` remains bound to the retained `df599101…` historical bring-up build. The separate `framework/control/consts_case4.json` binds the current mode values to source `3f759d06…` for offline planning and verification only. It is not live approval and must not be supplied to the historical bring-up as a replacement initializer: that script does not initialize or verify the current association, owner and expiry state, or configure the independent pulse. A current schema-bound initialization and recovery guard is still required.

From repository root, the read-only checks are:

```bash
python defense4/timing/framework/runner/cli.py plan --campaign defense4/timing/framework/declarations/case4_campaign.json
python defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/evidence/sde_9_13_2_build_03/defense4_timing.p4 defense4/timing/response_ready/evidence/sde_9_13_2_build_03
python defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/src/defense4_response_ready.p4 defense4/timing/response_ready/evidence/case4_recovery_build_04 --profile case4
python defense4/timing/framework/runner/cli.py plan --case case4 --d-a-ms 10
```

The Case 4 resource profile allows at most 12 stages per direction, checks exact source/snapshot/artifact identity, Tofino-1/TNA target and compiler identity, source/BFRT/context register capacities, PHV success, MAU compiler/run identity and compiled SALU locations/assembly. It reports `joint_mechanism_verified: false` and `deployment_authorized: false`. SDE 9.13.1 results have `deployment_build_eligible: false`; a 9.13.2 result only clears that compiler-version prerequisite. A later source change requires a fresh matching build. Resource reports must retain manifest hashes or matching original compiler copies.

The profile requests a 30 ms readiness expiry, a 100 us heartbeat period, a 1 ms gap, a fixed 40 ms cap, one native CROB plus one configured inert trailing-header decoy, two request insertion boundaries, and the 57-byte `[28,29]` split profile. The separate 49-byte `[28,21]` profile is preserved. Endpoint compatibility and exact length validation choose an admissible profile before collection. Completion, measured maximum heartbeat service, drain and release bounds are currently unavailable; a nominal loop period cannot provide a wall-clock bound. `case4` execute/verify refuse before device connection while the verified joint schema/write mapping is unavailable.

## Exact attempted-transaction matrix

| Declaration / phase | Blocks | Primary transactions | Warmups | State READs | Maximum attempts |
|---|---:|---:|---:|---:|---:|
| Main READ: D_A 5/10/15/20 ms, OFF/CASE4, three blocks per point | 24 | 12,000 | 480 | 48 | 12,528 |
| Main SELECT: D_A 10 ms, OFF/CASE4, three blocks per point | 6 | 3,000 | 120 | 12 | 3,132 |
| READ and SELECT smoke: 30 per operation per arm | 4 | 120 | 0 | 8 | 128 |
| Separate attended SBO smoke: 30 SELECT/OPERATE pairs per arm | 2 | 120 | 0 | 4 | 124 |
| Instrumentation READ: four D_A values, two arms, 30 per point | 8 | 240 | 0 | 16 | 256 |
| **Campaign** | **44** | **15,480** | **600** | **88** | **16,168** |

The 88 state READs comprise 72 before/after the main and smoke blocks and 16 before/after instrumentation. Prechecks are explicitly zero in this matrix; adding any precheck or retry requires redeclaration and consumes the same attempt ceiling. A failed SELECT suppresses OPERATE; retain both the attempted and planned denominators.

Use seed `20261006`, counterbalanced matched arms, a 500 ms timeout per transaction and 400 ms spacing between independent trials. OPERATE follows verified SELECT success immediately, with no spacing inside the pair. Charge a declared maximum 1,000 ms setup allowance per block. The conservative declared duration is **14,571,200 ms** (about 4.05 h), including full timeout budgets, inter-trial spacing and setup. Setup allowance is a declared cap, not a measured connection time: the collector must enforce it or redeclare duration before collection. Actual time, early completion and refused points are recorded independently.

Keep all warmup, precheck and state READ raw evidence. The remaining 2,192 attempts below the global 18,360 ceiling are not automatically allocated. Main is bounded engineering validation; it does not satisfy the older full-acceptance sample requirement. Apply the 10 us median-error and 99.9% within 50 us criteria only with explicit coverage limitations and separate early, late and fallback populations.

## Preconditions before authorized hardware collection

1. Produce a current-source, actual joint size/timing implementation under SDE 9.13.2; retain production and instrumented resource evidence separately. Confirm decoder/translation capacity and all programmed fields against that build's schema. The current adapter deliberately refuses invented tables and preserves its shaping-field safety check.
2. Bind measured timer, heartbeat/detection, release, drain and complete feedback-path intervals to the same endpoints/build/configuration. Record any explicitly authorized bounded exception; a provisional verdict is otherwise blocked. Distinguish RTO and TLP using endpoint evidence.
3. Verify endpoint compatibility, every CROB status, inert point, matching SELECT/OPERATE objects, retransmission/connection retirement, CRCs/checksums and supported TCP negotiation before modifying traffic. Physical OPERATE requires an attended, separately authorized run.
4. Establish current daemon owner, loaded program, ports, packet-generator applications/buffer reservations, mirror/PRE, TM queues and restoration identity through a fresh read-only snapshot. Establish actual capture visibility and capture health before traffic.
5. Stop traffic and drain previous owners before any rearm. Save the pre-write configuration before any write. Disable first, configure and read back every step, then enable last. Run benign smoke before the main matrix. No partial readback or unavailable measurement is treated as a pass.
6. Abort on corruption, unexpected actuation, stale completion, unexplained loss, stuck transactions, capture failure, readback mismatch or unverified restoration. Keep failure records and attempted denominators. Restore the saved program and configuration, read back the saved ports/TM/PRE/pktgen/policy state, and record completion only after verification.

## Bring-up inspection and remaining additions

The inherited bring-up configures packet-generator apps 1 (2K tokens, buffer offset 0) and 2 (3K tokens, buffer offset 256), using `trigger_recirc_pattern`. It does not configure the independent periodic heartbeat. The saved October 6 snapshot contains disabled app IDs 0–6 under `pktgen.app_cfg` and `tf1.pktgen.app_cfg`; this is historical state. App 3 is unused by the candidate's static setup, but current live availability is unverified. A heartbeat implementation must reserve an app and non-overlapping buffer, admit its parser value-set byte, validate its source/destination and bounds, and use disabled-first/readback/enable-last ordering. The applicable fixed-function tables are `tf1.pktgen.port_cfg`, `tf1.pktgen.pkt_buffer`, and `tf1.pktgen.app_cfg`; parser admission is configured through `d3.config_value_set`.

`hw_init_registers` only explicitly clears and reads back `reg_bor_epoch`, `reg_bor_ready`, `reg_bor_gen` and `reg_bor_topj`. It does not initialize/read back the new application association register or all request owner/TCP fields. Cold-start P4 initial values currently initialize those fields; a verified Case 4 bring-up must explicitly bind its initialization and cleanup protocol to the new schema before activation. `candidate_bringup.py`, `live_snapshot.py` and `restore_ports.py` were inspected only; they were not run against hardware in this implementation session.
