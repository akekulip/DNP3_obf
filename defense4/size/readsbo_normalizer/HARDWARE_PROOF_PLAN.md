# Hardware proof plan — READ↔SBO O2-indistinguishability on the rig

Turns the software model (`readsbo_normalizer.py` + `transaction_template.py`) into an on-rig proof.
**Nothing here runs until Philip authorizes each hardware step** (see Gates). The physical SELECT/
OPERATE and any P4 load are the state-changing steps and are gated individually.

## Objective
Show, on real hardware, that a **READ** transaction and a **Select-Before-Operate** transaction on the
SEL-751 are **indistinguishable to a single-packet-DPI observer (O2)** across size, segmentation,
function code, and object-group structure — while (a) the **real control actuates**, (b) the master
receives correct data and a SUCCESS command result, and (c) the SOE/event record stays clean.

## Topology (the setup we have)
```
  master (gambit 10.10.54.133 / Vision)  ──►  Tofino-1 (the switch we program)  ──►  outstations:
                                                                                    ├─ SEL-751  192.168.10.7:20000  (Case A, sep-ACK, link: outstation 0 / master 1)  ← CROB target
                                                                                    └─ ION 7550 192.168.10.8:20000  (Case B, combined-ACK, link addr 10)             ← 2nd device
```
The Tofino sits inline between the master and the outstations and runs the split+pad + parity-decoy
kernel. The observer is a passive capture on the master↔switch↔outstation path.

## Relay configuration (SEL-751) — the two-CROB decoy (Philip's design)
Configure **two binary output points** as CROB targets:
- **OUT_REAL** — the intended control (e.g. a breaker/relay output under test).
- **OUT_DECOY** — a **confirmed-safe spare** output, not wired to any critical circuit, that is safe to
  toggle repeatedly. *(Precondition: Philip confirms which point is OUT_DECOY and that it is safe.)*

The SBO command carries **both** CROBs (real point + decoy point). Both are validly requested controls,
so the select/operate echo naturally contains **two G12V1 objects** — which is the padded, parity
structure the READ side is normalized to match. On OPERATE, OUT_REAL actuates the real control and
OUT_DECOY actuates the harmless spare.

### Decoy realization — the design choice
| Approach | Decoy actuates? | Structural realism to O2/O3 | Cost |
|---|---|---|---|
| **Real decoy point (this plan)** | yes — a safe spare output toggles | strongest: the echo is a *genuine* 2-CROB echo, identical to a real multi-control | actuates a spare output; needs a confirmed-safe point |
| Phantom-addressed decoy (software model) | no | O2 fooled, but an address-parsing O3 sees the phantom link address | zero actuation |
This plan uses the **real decoy point** for maximum realism; the phantom variant stays the
zero-actuation fallback if a safe spare output is not available.

## The ION 7550 (Case B) — second-device roles
The ION 7550 has no separate ACK (no CLRT) and no CROB outputs, so the **SBO half does not apply to it**.
It contributes two things:
1. **Cross-device fingerprint reference** — capture the ION 7550's native READ profile (≈61 B, G30V1
   with the extra flag octet) and check whether the **normalized SEL-751** stream collides with it or
   stays distinct. This scopes the device-anonymity claim honestly (per-device O2 vs cross-device).
2. **READ-only generalization** — apply the READ size/segmentation normalization to the ION 7550's
   responses to show the mechanism is not SEL-specific. READ-only; no controls.

## Switch program (P4 sibling kernel — compile-only until authorized)
Per the p4-dataplane-engineer design: frozen ingress verbatim + a lean split egress. Two jobs:
1. **PAD** every response to the shared block-aligned target L (small delta over the cover kernel's
   single-insertion epoch).
2. **SPLIT** the response at 18-byte CRC-block boundaries into the target segment pattern (transport-
   stateless: per-segment seq = base + constant; clone/mirror for packet multiplication).
Plus request-direction parity decoys (phantom SELECT/OPERATE into the READ transaction) for the O2 claim.
Build first as compile-only (bf-p4c 0-errors) with the emulator + conformance harness; **do not load**
until Gate P.

## Run procedure
1. **Baselines (READ-only, no controls):** capture native READ (SEL-751), native READ (ION 7550), and —
   after Gate O — a native SBO on the SEL-751 (real point only). Record O1/O2 feature vectors.
2. **Load the kernel** (Gate P). Verify forwarding is intact and fail-open works.
3. **Normalized captures:** READ-with-decoys and SBO-with-decoys through the switch.
4. **Verify O2 parity on the wire:** per-direction frame count, per-frame size, segmentation pattern,
   function-code multiset, and object-group multiset are **equal** for the READ and SBO transactions.
5. **Verify semantics:** master command result = SUCCESS; OUT_REAL actuated exactly once; OUT_DECOY
   toggled harmlessly; master measurement DB shows only real points; **SOE/event record has no spurious
   entries**.
6. **Cross-device check:** compare normalized SEL-751 vs native ION 7550 O2 vectors; report collision or
   residual honestly.

## Oracles / evidence
- Passive pcap on both segments → the O2 feature-vector comparison (reuse `transaction_template.py`'s
  extractors on captured frames).
- SEL-751 front-panel / status word → confirm OUT_REAL operation and OUT_DECOY toggle.
- Master `ISOEHandler` + command callback → correct data, SUCCESS, zero spurious measurements.
- All artifacts hashed into an evidence manifest, as with the other gates.

## Gates (each requires Philip's explicit authorization AT execution time)
- **Gate P — load P4 / TM / port config on the Tofino.** Not done from this session.
- **Gate O — physical SELECT/OPERATE on the SEL-751.** This actuates real outputs; it is the one
  irreversible step. Requires: (a) OUT_DECOY confirmed safe, (b) OUT_REAL intended, (c) explicit go.
- The ION 7550 and all READ paths stay **non-actuating** throughout.
- Standing rule unchanged: absent Gate O, the SEL-751 is READ-only.

## Ready now (software / compile-only) vs needs the rig
- **Ready now:** the reference model (done), the P4 sibling-kernel build + emulator + conformance harness
  (compile-only), the pcap O2-comparison tooling, the evidence-manifest scaffolding.
- **Needs the rig + gates:** the relay CROB config, the kernel load, the physical SBO, the captures.
