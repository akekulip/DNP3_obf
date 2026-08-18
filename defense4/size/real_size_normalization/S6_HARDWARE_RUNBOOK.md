# Gate S6 — Attended Hardware Runbook (PLAN ONLY)

Gate: S6
Status: **PLAN. Not authorization to execute.** No step here runs until Philip
gives explicit hardware authorization, and each hardware action is attended.
Mechanism: M-001 packet-preserving Layer-2 fixed-volume AEAD cell bridge (`S3-RNL-256-v1`).

This runbook stages the size defense on the installed testbed after the software
gates (S0-S5 PASS). It is written so a later authorized session can execute it
step by step. It commits no hardware action by existing.

## Confirmed by read-only recon (2026-08-18) — see `evidence/s6_hardware/snapshots/`

Access and state verified from a `decps` SSH read-only session (no mutations):
- Vision reachable `decps@10.10.54.19` (`vision`); DNP3 NIC `enp59s0f0np0` = `192.168.10.1/24`.
- Switch reachable `decps@10.10.54.81` (`ufispace`, UFISpace S9180-32X Tofino-1, SDE 9.13.2).
- **`ens1` (MAC `00:02:00:00:03:00`) is the `bf_kpkt` CPU-port netdev** — the second-boundary hook.
- Currently loaded program: **`defense4_rrc_kernel`** (`/home/decps/rrc_build/defense4_rrc.conf`).
  Loading H0 swaps this out; this is the gated `bf_switchd` step (rollback: `swap_to_d3.sh`).
- Ports: dp8 loopback, dp9 -> Vision master, dp64 -> relay leg (1G), dp68 pktgen.
- Swap: `/home/decps/d3/swap_generic.sh <conf> <log>`; setup: `defense4_caseA_setup.py configure`
  (`DEFENSE4_HW_AUTHORIZED=1`). SEL-751/ION reachable only via Vision through dp64; not contacted.
- Vision TSO/GSO/GRO are ON (normalize before size evidence, R3).

**Gated step before H0 executes:** swapping the running `defense4_rrc_kernel` for the H0 cell-gate
restarts `bf_switchd` on the shared chip (tofino-p4 skill: explicit-approval-only). The H0 P4 and
its compile are non-disruptive; the swap/load is the approval point.

## Standing constraints (from the repo authority)

- Tofino-1 **data plane only**. Physical SEL-751 stays **READ-only**. No SELECT or
  OPERATE is required for size validation.
- Every switch write is behind: read-only snapshot -> arm watchdog (D3 rollback)
  -> change -> verify -> rollback on any failed check. Safe restore is the frozen
  Defense 2/3 build via `rollback_defense3.sh` (cold reload + arm), never a bare
  program reload (leaves ports DOWN).
- No Hulk, no added host, no SmartNIC, no gateway, no P4 cryptography.
- If a guarded SBO experiment ever becomes scientifically necessary: retain the
  exact `{1,3}` guard, refuse index 6, monitor all 32 relay outputs, attended
  session only. Not part of size validation.

## Real topology (from the S1 audit)

```
Vision host (master trust zone)         UFISpace Tofino-1 (switch)        Relay
  DNP3 master + TAP cell shim            P4 cell gate  ->  CPU cell shim   SEL-751 .7
  enp59s0f0np0 192.168.10.1/24  --25G--> dp9  --punt-->  ens1 / bf_kpkt   ION 7550 .8
        |                                  |               (RRC/BOR)       dp64 1G tcp/20000
   observed link (fixed AEAD cells on a dedicated EtherType)
```

The single unproven edge is **P4 cell gate <-> CPU cell shim** (`dp9 -> CPU
(ens1/bf_kpkt) -> timing path -> dp64`, and reverse). Per S1/S2 this is the hard
condition: if this CPU punt/reinject path cannot be proven endpoint-transparent
and bounded, real total-length hiding is impossible on this testbed and the line
stops here with an honest negative result.

## Software -> hardware component mapping

| Software (S4/S5) | Hardware placement |
| --- | --- |
| `l2_shim --role vision` | Vision TAP cell shim: master <-> TAP/veth <-> shim <-> `enp59s0f0np0`. Clear inner frames never reach the physical NIC. |
| `l2_shim --role ufispace` | UFISpace onboard-CPU cell shim on `ens1`/`bf_kpkt`. |
| `cell_link` (emulator) | The real observed `dp9` link + a Tofino P4 cell gate that classifies the fixed EtherType and steers it to/from the CPU. |
| `packet_capture` (observer) | Independent capture on the observed `dp9` segment, hardware RX-timestamped where the NIC supports it. |
| `dnp3_endpoint` (synthetic) | Real DNP3 master on Vision + physical SEL-751 relay on `dp64`, READ-only. |
| shared `--start-monotonic-ns` | Cross-host epoch sync (see Risk R1) — the software used one host's CLOCK_MONOTONIC; two hosts need PTP/NTP or a coordination handshake. |

## Phases and go/no-go gates

### H0 — Prove the Tofino CPU punt/reinject path (THE GATE)

Objective: without the cell layer, demonstrate a test frame round-tripping
transparently `Vision -> dp9 -> P4 gate -> CPU (ens1/bf_kpkt) -> reinject ->
dp64 loopback -> CPU -> dp9 -> Vision`, and the reverse, with bounded latency,
zero reordering at the boundary, and no drops.

Steps (attended, snapshot+watchdog armed):
1. Snapshot live conf/ports/TM/PRE; arm the D3 rollback watchdog.
2. Load a minimal P4 cell-gate that punts a dedicated test EtherType from `dp9`
   to CPU and reinjects CPU-originated frames toward `dp64` (and reverse). Do not
   touch the SEL/ION forwarding for other traffic.
3. From Vision, send N marked test frames; on the UFISpace CPU, echo them back
   via `bf_kpkt`. Measure per-frame round-trip latency, loss, and ordering at the
   `dp9` observation point.
4. Reverse direction: CPU-originated frames -> `dp9` -> Vision.

**Go/no-go:** proceed only if the CPU path carries frames transparently, with
loss 0 and latency bounded well inside one epoch (210 ms). If not, **STOP**:
record the negative result (`H0_CPU_PATH_RESULT.md`), roll back, and report that
real length hiding is infeasible on this testbed. Do not construct a workaround.

### H1 — Stage the two shims on the real path (READ-only)

1. Bring up the Vision TAP shim (`l2_shim --role vision`) between the master and
   `enp59s0f0np0` via TAP/veth; normalize/disable TSO/GSO/GRO at the virtual
   boundary and record the offload state.
2. Bring up the UFISpace CPU shim (`l2_shim --role ufispace`) on `ens1`/`bf_kpkt`.
3. Establish the shared epoch grid (Risk R1): synchronize the two hosts' clocks
   (PTP/NTP) and pass a common `--start-monotonic-ns`-equivalent origin, or add a
   one-time coordination handshake; record the residual cross-host skew.
4. Load the fixed-cell P4 gate; verify the observed `dp9` link carries only the
   fixed EtherType cells and forwarding for other flows is intact.

### H2 — READ-only functional validation

1. Master polls the SEL-751 (READ) through the cell bridge.
2. Capture at both trusted boundaries (Vision TAP in/out, UFISpace CPU in/out)
   and independently on `dp9`.
3. Verify with the S4 oracle (`analyze_s4.boundary_oracle`): master<->relay
   application streams byte-equal at both boundaries with gap-free reassembly,
   DNP3 CRCs and IP/TCP checksums valid; observed `dp9` shows only 256-byte cells.

**Go/no-go:** any byte-inequality or non-cell frame on `dp9` -> roll back and stop.

### H3 — Size security on hardware (READ-only)

1. Use at least two inner response lengths (different READ object ranges on the
   SEL-751 -> different response lengths) to satisfy RN-L.
2. Run the cross-workload test (`analyze_s5`/`s4_summarize` method): an idle
   window and a busy READ window of equal duration must show the observer on
   `dp9` an identical cell volume; all cells 256 bytes; per-bin MI within null;
   classifier no advantage.

### H4 — Timing composition with live RRC/BOR (optional, READ-only)

With RRC/BOR active in the switch trust zone, repeat the S5 method: vary the
observed native response timing and confirm the observed `dp9` transcript and the
master-visible timing stay schedule-determined (size/count J-independent), and the
protected CLRT policy is not altered. Keep the BOR relay-facing boundary explicit
(exactly-once/T0+J remain inferred, not observed).

## Evidence to collect

Paired trusted-boundary captures (Vision + UFISpace), the independent `dp9`
capture (hardware-timestamped), per-run metrics, the S4/S5 analyzer reports, a
cross-workload result, a claim matrix, a reproduction script, and a SHA-256
manifest — under a new `evidence/s6_hardware/` directory, never mixed with the
software evidence. No runtime keys or plaintext occupancy in the package.

## Open risks

- **R1 (cross-host epoch sync).** The software prototype used one host's
  monotonic clock for the shared epoch grid. Two physical hosts need PTP/NTP or a
  handshake; residual skew must be measured and shown smaller than the emit-slip
  budget, or the two shims' schedules drift.
- **R2 (CPU-path throughput/latency).** `bf_kpkt` userspace punt/reinject may not
  sustain the cell rate or may add jitter beyond one epoch; H0 must bound it.
- **R3 (offload normalization).** TSO/GSO/GRO on the i40e NICs reshape captured
  frames; capture at the true wire boundary or normalize and record offloads.
- **R4 (live program drift).** The currently loaded conf may be an RRC-only
  baseline, not the unified binary; do not assume a loaded program — read it.
- **R5 (single device / class).** RN-L is conditioned on a declared class; multi-
  device indistinguishability stays NOT DEMONSTRATED until a second Case-A device
  or stack is evaluated.

## Stop condition

Nothing in S6 executes without explicit authorization. H0 is the gate: a failed
CPU-path proof stops the line with an honest negative. No SELECT/OPERATE is used
for size validation.
