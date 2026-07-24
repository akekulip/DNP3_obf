# Defense-1 / Defense-2 parser-hardened dp9/dp11 variants — offline-ready (2026-07-24)

Applies the two proven Phase-1 corrections to the Defense-1 and Defense-2 programs so they can run on the
current topology once authorized: (1) **role remap** master=Vision=dp9(dir0), outstation=Hulk=dp11(dir1)
(`PORT_MASTER=9w9`, `PORT_OUTSTATION=9w11`; recirc `PORT_RECIRC=9w68` unchanged); (2) **parser hardening**
(the same `parse_dnp3_dl` length-gate that fixed the link-only-frame drop — both frozen defenses have the
identical latent parser bug). Frozen `dcrn_defense1.p4` / `dcrn_defense2.p4` are NOT modified.

## Files
- `dcrn_defense1_hardened_dp9_dp11.p4` — compiles bf-p4c 9.13.1, 0 errors, 2 benign warnings (12/12 ingress).
- `dcrn_defense2_hardened_dp9_dp11.p4` — compiles bf-p4c 9.13.1, 0 errors, 2 benign warnings (10/12 ingress).

## Offline status
- Both compile and fit (same stage budget as their frozen originals — the changes are 2 port constants +
  one parser length-select branch).
- Reference-model behavior is unchanged (the variants alter only ports + parser, not the hold/deadline
  logic): `tests/test_defense1.py` 17/17, `tests/test_defense2.py` 10/10, `test_hardening_fix124.py` 12/12
  remain the offline gate.
- Link-only frames now pass through the defense unchanged (non-transaction frames never arm/hold; the
  parser fix stops the drop).

## NOT done (gated / next authorized step)
- **Hardware campaigns:** load each variant on dp9/dp11, disabled-mode passthrough regression (byte-identity,
  0 drops incl. link-only), then bounded enabled-mode tests with counters/latency/loss/order/resources, and
  restore the microbench after each campaign. This is the next step — same load/verify/restore pattern proven
  for the shadow (`gate1_run.py`, `dnp3_shadow_setup.py --program … --master-port 9 --outstation-port 11`).
- **Still human-gated (unchanged):** generation-enforcement redesign, Defense-2 `G_i` set (contradiction C2),
  recirc/qid calibration, size-regeneration architecture. None invented here.
