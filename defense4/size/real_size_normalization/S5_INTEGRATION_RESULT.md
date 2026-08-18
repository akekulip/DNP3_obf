# Gate S5 Result — Cell Layer vs Timing (native-delay independence)

Gate: S5
Status: **PASS (software prototype). No hardware. Does not re-implement RRC/BOR.**
Mechanism: M-001 packet-preserving Layer-2 fixed-volume AEAD cell bridge (`S3-RNL-256-v1`).
Evidence: `evidence/s5_integration/` (`S5_SUMMARY.json`, manifest).

## What S5 asks and what this shows

S5 asks whether the cell layer composes with the timing mechanisms without the
cellization leaking timing or the timing changing the outer transcript. The cell
layer emits ACK and response cells on a fixed outer slot schedule every epoch
(request 0-750 us, ACK 1000-1250 us, response 200000-203250 us, tail
203500-203750 us), filling with authenticated cover when data is not ready. So
the observed transcript should not depend on *when* the relay actually responds.

This is tested directly by sweeping the relay's native response delay — a proxy
for the variable timing the RRC/BOR policy would otherwise expose, and for the
BOR hold J — with `run_s4_namespace.sh --response-delay-ms`, and analysing with
`analyze_s5.py`.

## Result (native delay J = 0, 120, 300 ms; fixed window; 40 exchanges each)

| J (ms) | observer cells | observer bytes | modal cells/epoch | master latency median |
| --- | --- | --- | --- | --- |
| 0 | 4406 | 1,127,936 | 22 | 209.6 ms |
| 120 | 4406 | 1,127,936 | 22 | 419.8 ms |
| 300 | 4406 | 1,127,936 | 22 | 419.7 ms |

- **Outer cell size/count does not depend on J.** The observed cell count and
  byte count are identical across all three native delays (spread 0 cells); the
  per-epoch modal count is 22 at every J. Cover cells absorb the delay.
- **Application delivery is preserved at every J.** The trusted-boundary
  byte-equality oracle passes for all three runs.
- **Cellization does not leak the native response time.** The master-visible
  latency is quantized to whole epochs, and two different native delays collapse
  to the same observed value: J = 120 ms and J = 300 ms both yield ~420 ms
  (the response missed one response slot and was carried in the next), while
  J = 0 yields ~210 ms. An observer therefore learns only which epoch the
  response landed in, never the actual native delay — the outer timing carries
  the schedule, not J.

## Mapping to the S5 requirements

- *ACK and response outer slots remain at the A/R policy* — the outer schedule is
  fixed by the codec and the observed transcript is unchanged across J. PASS.
- *Outer cell size/count does not depend on J* — identical transcript across J. PASS.
- *Cellization does not alter the protected CLRT policy* — the master-visible
  timing is the fixed outer slot schedule (epoch-quantized), independent of the
  native delay; 120 ms and 300 ms are indistinguishable in the observed timing. PASS.
- *The BOR evidence boundary remains explicit* — see below.
- *Failure behavior cannot actuate a control* — the cell layer is fail-closed
  with no NACK/retransmission/escape/clear fallback (S3 spec), so a failed slot
  delivers zero bytes rather than a partial or fallback frame; and this software
  harness carries synthetic exchanges with no control-actuation path. PASS
  (by construction; no actuation is possible here).

## Explicit boundary (not demonstrated here)

- This does **not** re-implement the SEL-751 separate-ACK CLRT-to-~4 ms
  normalization or the BOR relay-facing hold, exactly-once release, or T0+J
  behavior. Those are the P4/hardware mechanisms of the native-parity line and
  keep their existing hardware evidence boundary (relay-facing exactly-once and
  T0+J were inferred, not directly observed, even on silicon).
- The normalized master-visible timing here is the outer slot schedule (a policy
  choice: ~210 ms response-slot spacing), not a specific 4 ms CLRT target.
  Configuring the slots to a chosen A/R value is a policy-parameter change, not
  demonstrated.
- Software only: rootless namespaces; no Vision, Tofino, physical relay, or P4.
- Overload beyond the fixed cell budget is untested (as in S4).

## Reproduction

```bash
PYTHONPATH=<repo> for J in 0 120 300; do \
  bash defense4/size/real_size_normalization/software/run_s4_namespace.sh \
    --mode pipeline --out evidence/s5_integration/j_$J --exchanges 40 \
    --duration 45 --timeout 43 --hold-open --response-delay-ms $J ; done
PYTHONPATH=<repo> python3 -m defense4.size.real_size_normalization.software.analyze_s5 \
  --evidence defense4/size/real_size_normalization/evidence/s5_integration
```

## Stop condition

S5 is complete as an isolated software result. It does not proceed to S6 (attended
hardware) without a new explicit instruction and the same hardware authorization
and safety guards as the earlier campaign.
