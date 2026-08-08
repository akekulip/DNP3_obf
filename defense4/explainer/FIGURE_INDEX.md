# Defense 4 figure index

Every measured figure is generated from committed data by reproducible code and records its
source-data hash and sample counts. Schematics are checked against the P4 and setup code.

| figure | type | source | shows |
|---|---|---|---|
| `../timing/evidence/final_run/campaignA_corrected_binary/fig_clrt_ecdf.png` (`.pdf`) | measured | `fig_clrt_ecdf.py` over Campaign A block JSONs (hash in `.meta.json`) | native OFF CLRT versus the D1-D4 modes; the normalization and the late tail |
| `../timing/evidence/final_run/campaignB_corrected_binary_seed20260807/fig_clrt_ecdf.png` | measured | same code, Campaign B (randomized) | reproduction of the normalization |
| `../timing/figures/normalization.png` (`.pdf`) | measured | `analyze_normalization.py` over A+B (hash 18407e17) | per-session medians + p5/p95 per mode; the spread/entropy collapse |
| `../timing/figures/fig_topology.png` (`.pdf`) | schematic (matplotlib) | topology + P4 ports | testbed and adversary placement |
| `../timing/figures/fig_mechanism.png` (`.pdf`) | schematic (matplotlib) | P4 queue selection | four-queue hold-and-release mechanism + blocker recirculation |
| `../timing/figures/fig_timing_sequence.png` (`.pdf`) | measured schematic | per-mode median read->ACK / read->RESP (A+B) | where each mode releases ACK and RESPONSE, and the resulting CLRT |
| `DEFENSE4_MECHANISM_DIAGRAMS.md` §1 | schematic (Mermaid) | topology + P4 | testbed and adversary placement |
| `DEFENSE4_MECHANISM_DIAGRAMS.md` §2 | schematic (Mermaid) | P4 queue selection | four-queue strict-priority mechanism + packet journey |
| `DEFENSE4_MECHANISM_DIAGRAMS.md` §3 | schematic (Mermaid) | timing semantics | t_A, T_A, T_RESP, fail-open horizon, arrival buckets |
| `DEFENSE4_MECHANISM_DIAGRAMS.md` §4 | schematic (Mermaid) | reg_tag lifecycle | transaction state machine, including the fixed bug |
| `DEFENSE4_MECHANISM_DIAGRAMS.md` §5 | schematic (Mermaid) | mode table | the five modes as one framework |

Measured figures still to generate when their experiments run: paired byte-identity per-frame map
(software outstation, dual capture), before/after classification confusion matrices (needs a second
comparable device or a labeled controlled-profile study), and the compiler-derived ingress-stage map
(from the reproducible-compile artifacts).
