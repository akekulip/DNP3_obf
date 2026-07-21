# SEL751_DIRECT_CONNECTIVITY_PLAN.md — Physical SEL-751 bring-up plan (Phase 5)

_Master direction Phase 5 + meeting §13. Produced 2026-07-21 on `research/caseA-ditto-queue`.
This is a **plan** (off-switch). **Execution is gated** on a hardware window, the physical relay,
and a verified lab topology (master direction §10; `ASSUMPTIONS_AND_UNKNOWNS.md` #1, #3, #20).
The report `SEL751_DIRECT_CONNECTIVITY_REPORT.md` is produced **after** execution._

> **Objective (master direction Phase 5, meeting §13).** Stop relying only on replayed traces:
> establish **direct DNP3 communication with the physical SEL-751**, capture its **native**
> transaction, **verify the separate pure-ACK behaviour**, and **measure the real device's timing
> distribution** — using **only safe Class-0 READ polling**, with **no device modification**. This
> converts the biggest open assumption (rig replay ≠ live device, #1) into measured fact and fixes
> the paper baseline (real 12.9 ms, `ASSUMPTIONS_AND_UNKNOWNS.md` #2).

---

## 0. Hard safety rules (non-negotiable — master direction Phase 5, §13)

**DO NOT issue any of:** `SELECT`, `OPERATE`, `DIRECT OPERATE`, output control, configuration write,
device restart, or any unsolicited-config change. **Read-only Class-0 polling only.**
**DO NOT change the SEL-751 IP address** unless Dr. Lin explicitly approves *and* it is necessary.
**DO NOT place the Tofino inline initially** — first prove direct master↔relay comms through the
**normal lab Ethernet switch** (Tofino insertion is Step 3, after direct comms work).
**On any failure: STOP, preserve evidence, document the exact failure, contact Dr. Lin early** — do
not spend days making unsupported changes (master direction Phase 5).

---

## 1. Unknowns to resolve FIRST (do not assume — master direction §6, `ASSUMPTIONS_AND_UNKNOWNS.md` #20)

Everything below is **unverified** and must be confirmed from the lab/device, not assumed:
| Unknown | How to obtain | Why it matters |
|---|---|---|
| SEL-751 **IP address** + **subnet mask** | device front-panel / SEL config / lab records (ask Dr. Lin) | cannot reach it otherwise; §6 forbids assuming a device IP |
| DNP3 **TCP port** (commonly 20000, **verify**) | device DNP3 map / capture | wrong port → no session |
| DNP3 **outstation (link) address** | device DNP3 map | required for the master config |
| Required **master (link) address** | device's configured master | mismatch → session refused |
| Which host is **master** (Hulk or Vision) + its free NIC/IP | verify live lab topology | §Phase 5 "after verifying the actual lab topology" |
| Physical **cabling + switch port** for the relay | lab inspection | reachability |
| Is **ICMP/ping** enabled on the relay | test (Step 2) | ping may be disabled; absence ≠ unreachable |
| Relay **firmware/config** (unsolicited off?) | device settings readout | provenance for the paper (#3); ensure unsolicited OFF for clean captures |

> The 2019 capture used master `10.0.0.3` → SEL-751 `10.0.0.1:20000`
> (`CURRENT_STATE_AUDIT.md` §3) — treat these as **historical hints only**, re-verify against the
> physical device before use.

---

## 2. Step sequence (master direction Phase 5 / meeting §13)

### Step 1 — Learn the SEL-751 configuration
Connect the SEL-751 to the **normal lab Ethernet switch** (not the Tofino). Choose **Hulk or Vision**
as the DNP3 master after verifying topology. Configure the master: IP in the **same subnet** as the
relay, correct DNP3 TCP port, outstation address, master address, **Class-0 polling**, unsolicited
handling. **Do not change the SEL-751 IP** unless approved.

### Step 2 — Verify direct communication
Confirm, in order: L2 reachability; L3 reachability (ping *if enabled*); **TCP connect** to the DNP3
port; **DNP3 session establishment**; a **Class-0 READ** response; the **separate pure-ACK**
behaviour (a standalone TCP ACK before the application response — the Case-A premise); native
**ACK-to-response timing**. **No write/control at any point.**

### Step 3 — Insert the Tofino (only after Step 2 succeeds)
Topology `DNP3 master → Tofino switch → SEL-751`. Gated on a hardware window + the shared-chip
handoff (`gc-switchd`/gridcloak; master direction §10).

### Step 4 — Run native traffic (Tofino inline, no defense)
Collect **master-side** and **outstation-side** pcaps; ACK-to-response timing; response sizes; TCP
behaviour; DNP3 response correctness. Confirm the Tofino passes native traffic unchanged.

### Step 5 — Enable the defenses
Defense 1 (recirculation) → queue-based Defense 1 when available → Defense 2 → background-load
experiments. Each is a **separate gated step** with its own pre-GO checklist.

---

## 3. Measurements to capture (Step 2/4 — the paper's live baseline)

- **Native CLRT distribution** on the **physical** device: n (transactions), median, IQR, p10/p90,
  p99, min/max, outliers — the real analogue of the 12.9 ms capture baseline (fixes #2).
- **Request→ACK** and **request→response** timing (residual features, master direction §3).
- **Response sizes** and segmentation; **TCP options/flags/window**; **ACK mode** (confirm separate).
- **Readiness tail vs RTO:** measure the real device's response-readiness tail and TCP RTO to
  re-derive the safe Defense-2 target band (#12 — the rig 60 ms value must NOT be reused blindly).
- **All device settings used** (firmware, DNP3 map, unsolicited state) for provenance (#3).

Label every resulting number **"live physical SEL-751"** (master direction §12) — distinct from the
replay numbers, which stay **"SEL-751 capture-derived live-TCP replay."**

---

## 4. Evidence, rollback, STOP

- **Evidence (master direction §11):** raw pcaps (both sides), parsed CSV (per-transaction CLRT /
  req→ACK / req→resp), device settings, host commands, software/DNP3-master versions, topology,
  manifest + SHA-256. Separate `raw/ processed/ figures/ logs/ manifests/`; never modify raw.
- **Rollback / cleanup (master direction §10):** restore any co-resident switch program, ports, TM/
  queue/loopback config, NetworkManager; stop all experiment processes; verify normal forwarding;
  record final state. **Never leave an experiment loaded without explicit instruction.**
- **STOP conditions (master direction §14):** communication fails; SEL-751 config uncertain; a
  requested action would displace another experiment; TCP resets/retransmits; response before ACK;
  rollback not ready. On STOP: preserve evidence, document the exact failure, **contact Dr. Lin
  early.**

## 5. Output
`SEL751_DIRECT_CONNECTIVITY_REPORT.md` — what connected, the verified config, the measured native
distribution, the separate-ACK confirmation, and any failure documented honestly.

**Status: PLAN COMPLETE. Execution NOT_STARTED — gated on a hardware window + physical relay +
verified topology. This is also a Philip/Dr. Lin coordination item (device access, master direction
§17 action items).**
