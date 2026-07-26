# Live inline CLRT normalization on the physical SEL-751 — 2026-07-25

First run of the DNP3 timing normalizer **inline with the real relay**, on real DNP3 traffic.
All prior results were replay. Read-only Class-0 READs (function 1) only; no writes, no controls.

## Topology (proven single-path)

    Vision 192.168.10.1 ──25G── dp9 │TOFINO dnp3_timing_normalizer_inline│ dev_port64 ──1G── unmanaged sw ──100M── SEL-751 192.168.10.7

`E1/33` = dev_port 64 @ `BF_SPEED_1G` / `FEC_NONE` / `AN_FORCE_DISABLE`; dp8 = MAC-near loopback
(blocker ring); `strict_priority_verified: true`.

**Single-path proof** — relay leg UP: ping 3/3 · `dev_port 64` deleted: **0/3, 100% loss** ·
re-enabled: 3/3. The relay has no route to the master except through the Tofino.

## Result — CLRT (relay pure-ACK -> DNP3 response), measured on the master leg

| | n | median | mean | min | max | **sd** |
|---|---|---|---|---|---|---|
| NATIVE (no blockers)   | 10 | 2.126 ms | 4.096 ms | 1.061 | 22.660 | **6.261 ms** |
| PROTECTED (K=64, G=25) | 11 | 25.057 ms | 25.049 ms | 24.998 | 25.077 | **0.028 ms** |

- Spread collapses **6.261 -> 0.028 ms sd (224x tighter)**; range 21.6 ms wide -> 0.079 ms wide.
- Every protected transaction lands on G=25 ms. On-chip: `reg_deadline - reg_t_ack = 24,999,849 ns`.

## Integrity / liveness

- All responses **54 bytes** in both runs; every poll decoded as DNP3 **function 0x81 (129)**.
- `_ws.malformed = 0` and **`tcp.analysis.flags = 0`** in BOTH captures: no retransmission, no
  dup-ACK, no reordering. The 25 ms hold is well inside the relay's RTO.
- 11/11 protected polls answered; connection healthy throughout.

## Honest scope

- Claim is the **CLRT timing channel only** — not size, not ACK mode, not device anonymity.
- **NOT a byte-identity proof.** Native and protected payloads legitimately differ (live relay data
  + DNP3 transport sequence counter), and the relay leg cannot be tapped (unmanaged switch, no SPAN),
  so an in-vs-out comparison of the same frame is not available here. Byte-identity was established
  100/100 in the replay campaign, where the same frame could be compared on both sides.
- **G must exceed native.** Native max observed 22.660 ms (first cold poll) against G=25 ms — only
  2.3 ms of headroom. A transaction whose native CLRT exceeds G passes through unprotected with no
  wire-visible symptom. Warm polls sat at 1.06-4.02 ms. Consider G=40 ms.
- n is small (10/11). A longer campaign is the obvious next step.
