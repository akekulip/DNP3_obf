# Defense 4 lifecycle-fix — BF-SDE 9.13.2 deployment compile

Corrected source `defense4/timing/p4/defense4_caseA.p4` (fix commit e47bcaa), compiled on the
deployment compiler on ufispace (decps@10.10.54.81) in an isolated dir; the running D4 was not touched.

| item | value |
|---|---|
| source sha256 | `1242ca4d68e78430587b01c15f69befa9d7bd33c57a11445579773389ba33127` |
| compiler | `p4c 9.13.2 (SHA 1baf055)`, `bf-p4c --target tofino --arch tna` |
| errors / warnings | **0 errors**, 2 benign parser-unroll warnings |
| tofino.bin sha256 | `97175e7dc1a77c3cdbe235baa13b906e18d3227bf09cb84cfacfee6f0a928a19` |
| tofino.bin size | 1418611 bytes (pre-fix was 1416979) |
| ingress stages | **12 / 12** (unchanged); egress 0 |
| SRAM / TCAM | 47 / 10 (unchanged) |
| logical tables | 107 (pre-fix 104; +3 for the fix, absorbed within 12 stages) |

The corrected program PLACES at 12/12 ingress. The seven lifecycle changes (mode-conditioned
ACK-release retire, qid5 terminate-when-pending, read-only ack_rel_r for RESP_HOLD_EARLY/LATE, and
the counter/gate refinements) fold into existing gateways; the LTID-saturated stage 8-11 tail
identified as the placement risk absorbed them without a stage increase. Raw resource artifacts are
alongside this file (table_summary, mau.resources, phv_allocation_summary, metrics/mau/phv/resources
json, table_dependency_summary, compile logs). The binary is not committed; its hash is recorded here.
