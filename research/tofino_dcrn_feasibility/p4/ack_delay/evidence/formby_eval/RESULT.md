# Formby CLRT fingerprinting vs Case-A ACK-delay defense — evaluation (2026-07-20)

Evaluates the Formby et al. (NDSS 2016) CLRT device-fingerprinting attack against Case-A on Tofino
silicon, using the real SEL-751 traffic + a rig-synthesized second separate-ACK device. Design by the
research-scientist (Formby-paper-grounded: model-free 1-D AUROC headline + ACK-mode positive control).

## Results
E1 — SEL-751 CLRT fingerprint collapse (native vs Case-A, same rig path):
- Cliff's delta = 1.000 [1.000,1.000], KS = 1.000 (native and Case-A CLRT completely disjoint).
- median CLRT 17.35 ms (native) -> 0.026 ms (Case-A) = **667x collapse**, byte-preserving.
- Static Formby template (native band [10.5,24.2] ms): identification rate native 0.99 -> **Case-A 0.00**.
- ACK-mode positive control: recall native 1.00 / Case-A 1.00 (Case-A does NOT remove the separate ACK).

E2 — CLRT-value device separability on a mode-matched 2-device anonymity set
(device1=SEL-751 native 17 ms, device2=synthetic 35 ms; both separate-ACK):
- 1-D AUROC: **NATIVE 1.000 -> CASE-A 0.571** [0.507,0.648] (chance 0.5).
- 2-class balanced accuracy: **NATIVE 1.000 -> CASE-A 0.611** (chance 0.5).

## Headline
Against an unmodified Formby CLRT attacker, Case-A drives CLRT-value device separability from AUROC
1.00 (perfectly separable) to ~0.57 (near chance) and static-template identification from 0.99 to
0.00, byte-preserving, while ACK-mode stays 1.00/1.00. The device's characteristic CLRT fingerprint is
neutralized. (The residual AUROC 0.57 > 0.5 is guard-delta jitter — the collapsed value is ~constant
but not perfectly so; an adaptive attacker could key on "separate ACK with near-zero CLRT = defended".)

## Mandatory caveats
1. Anonymity-set-of-one: only SEL-751 has a CLRT on the real corpus (AB1400/ION7550 are combined-ACK,
   no CLRT). device2 is RIG-SYNTHESIZED so E2 is a real 2-device separability test, not a strawman.
2. CLRT-VALUE only: Case-A collapses the CLRT value; ACK-mode and response SIZE survive. A joint
   mode+size attacker is only partially defeated (size is the residual floor, ~0.50 in the prior joint eval).
3. Replay, not live relay: rig reproduces response latency + bytes + separate-ACK structure but not the
   SEL-751's own ~4 ms kernel ACK delay (rig-native 17.35 ms vs capture 12.90 ms); the collapse mechanism
   is independent of that offset. Causal baseline uses rig-native (same replay path).

Figure: formby_clrt_collapse.png. Data: clrt_dataset.json + the 4 rig pcaps. Repro: formby_eval.py.
