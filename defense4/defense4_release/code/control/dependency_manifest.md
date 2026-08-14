# Control-plane dependency manifest

The on-switch configuration is layered. This package includes the top two layers for reference; the
lower layers and the full Barefoot SDE runtime live in the main repository and on the testbed.

## Import chain (on-switch configuration)

```
defense4_rrc_bor_unified12_setup.py   (this package — installs unified RRC+BOR: ports, TM queues,
  │                                     pktgen apps, PRE, mirror, session, J codebook, timing)
  └─ imports defense4_caseA_setup.py   (this package — timing param + 4-queue idiom helpers)
       └─ imports the Defense-3 setup module (d3)   (main repo: defense3 control tree — port
                                                      bring-up, mirror/PRE/value-set primitives)
```

## What is required to actually run the setup

Running `defense4_rrc_bor_unified12_setup.py` against real silicon requires **all** of:

- Intel Barefoot **SDE 9.13.1** (bf-p4c + `bfrt_grpc` runtime), with the compiled binary loaded;
- the physical testbed (Tofino-1 + SEL-751) wired as in `docs/` §2;
- the environment gate `DEFENSE4_HW_AUTHORIZED=1` (every hardware op refuses without it);
- the lower Defense-3 control module on `PYTHONPATH` (main repo).

The setup defaults to an **offline dry-run** that builds an in-process model and runs a fail-closed
readback self-test — it touches no gRPC and needs no SDE. Use the dry-run to inspect the intended
configuration; the live path is testbed-only.

## What runs with no hardware and no SDE (this package is self-contained for these)

- **Offline verification:** `../analysis/bor_unified_lifecycle.py`,
  `../analysis/validate_decide_vs_oracle.py` — pure Python, standard library.
- **Guarded-control safety test:** `../harness/test_relay_operate_guard.py` — pure Python.
- **Evidence reproduction:** `../../evidence/E_FINAL/reproduce.sh` — regenerates every derived CSV/
  verdict from the raw pcaps (needs a Python with `scapy`; see `tests/run_all.sh`).

## Rollback / watchdog

`rollback_rrc.sh` and `watchdog_rrc.sh` are the operational safety scripts (verified teardown to a
benign forwarding state; there is no config snapshot — rollback is a forward teardown). They are
testbed scripts and are included for review.
