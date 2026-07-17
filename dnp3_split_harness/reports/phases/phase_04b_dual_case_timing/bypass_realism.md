# Phase 04B — Bypass-check realism (corrective.md §12)

The Python policy oracle (`phase04b_dcrn_policy.py`) defines a broad bypass set. This table states,
honestly, which checks the **actual tc/eBPF wire executor** (`bpf/phase04b_dcrn.c`) implements, which
are enforced by the unprivileged harness/allowlist, which are only detectable after capture, and which
are not implemented. **Any check not implemented in the data plane defaults to bypass and/or a narrowed
allowlist.** The first executable version is deliberately **READ-only and single-outstanding**.

| Safety check | Status in the wire executor | How it is handled |
|---|---|---|
| Pure-ACK classification (payload==0, ACK, !SYN/FIN/RST, covers request) | **IMPLEMENTED_IN_BPF** | egress `dcrn_classify_reverse` + `dcrn_ack_covers` |
| ACK-bearing RESPONSE (payload>0, covers request) | **IMPLEMENTED_IN_BPF** | egress `dcrn_classify_reverse` |
| Arm only a payload-bearing master→outstation DNP3 **READ** (handshake excluded) | **IMPLEMENTED_IN_BPF** | ingress `is_read_request` (start bytes 0x0564 + func byte @ offset 12) |
| Missing request state → fail open | **IMPLEMENTED_IN_BPF** | egress returns `TC_ACT_OK` when no armed flow |
| Unsafe target (≥ Dhigh) → bypass | **IMPLEMENTED_IN_BPF** | ingress `dcrn_target_safe` |
| Transaction complete → bypass trailing packets | **REMOVED (caused a bug)** | the response_seen guard bypassed every post-first transaction on a persistent connection; removed. Trailing client-ACKs are already excluded by the READ-only + covers checks |
| ACK that does not cover the armed request → bypass | **IMPLEMENTED_IN_BPF** | `dcrn_ack_covers` false → BYPASS |
| Single-outstanding / concurrent-request protection | **IMPLEMENTED_IN_USERSPACE_CONTROL** | the harness issues one outstanding READ per flow; the BPF re-arms on a new READ (does not track concurrency) |
| READ-only allowlist (SELECT/OPERATE/unsolicited excluded) | **IMPLEMENTED_IN_BPF (arming) + USERSPACE (traffic scope)** | ingress arms only func==READ; the campaign replays only solicited READ |
| Known / re-measured RTO (Dhigh valid) | **IMPLEMENTED_IN_USERSPACE_CONTROL** | the loader compiles Dhigh from the measured RTO; if RTO unknown, do not run |
| Map exhaustion | **IMPLEMENTED_IN_BPF (LRU fail-open)** | `LRU_HASH` evicts the oldest flow; an evicted flow's reverse packets fail open (native) |
| Duplicate-ACK detection | **DETECTED_POST_CAPTURE_ONLY** | not parsed in BPF; the analysis flags dup-ACKs from the PCAP; a dup-ACK on an armed flow before the response could be mis-scheduled — the loss-free lab conditions avoid it, and any occurrence is a reported anomaly |
| SACK interpretation | **NOT_IMPLEMENTED / POST_CAPTURE** | TCP options are not parsed in this version |
| Window-update recognition | **PARTIAL** | a window update *after* the response is bypassed (response_seen guard); a window update *before* the response is not distinguished from a pure ACK — post-capture flags it; steady-state polling avoids it |
| Keepalive recognition | **NOT_IMPLEMENTED / POST_CAPTURE** | not distinguished in BPF; the campaign uses active polling, not idle keepalives |
| Reverse DNP3 CONFIRM-ACK classification | **PARTIAL** | the outstation→master CONFIRM case is handled by the response_seen guard (post-response) + READ-only arming; a mid-transaction CONFIRM is out of the allowlisted scope |
| Retransmission / loss-recovery awareness | **NOT_IMPLEMENTED / POST_CAPTURE** | not tracked in BPF; the analysis reports any retransmission and treats affected transactions as anomalies |

**Consequence for the campaign.** Because several TCP-state bypasses are post-capture-only, the first
DCRN wire runs are confined to a clean, loss-free, single-outstanding, solicited-READ workload, and the
analysis **explicitly reports** any dup-ACK, SACK, window-update-before-response, keepalive,
retransmission, or reset it observes — those transactions are excluded from the "clean" effectiveness
claim and counted as anomalies. Extending robust in-BPF detection of these is future work; it is not
claimed here.
