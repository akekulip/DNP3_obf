# Shadow classifier — on-switch 9.13.2 compile record (GATE-1 non-destructive step)

**2026-07-23. Authorized GATE-1 actions 1–4 performed (stage + on-switch compile + record + restore
info). `bf_switchd` was NOT touched; the shared Tofino still runs the queue microbench. The physical
relay was not contacted. Load + replay were NOT performed — held on a port-discovery ambiguity (below).**

## What was done (non-destructive)
1. Staged `dnp3_shadow.p4` to `decps@10.10.54.81:/home/decps/dnp3_shadow/` — staged sha256
   `e08f2844d699a7ce8743b079385760e9af8a03e7dd1bae859005914e6d06f580` **= local file exactly**.
2. Compiled on the switch host with **BF-SDE 9.13.2** (compile only, no load).

**Exact compile command** (env sourced, run in `/home/decps/dnp3_shadow/`):
```
export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH
bf-p4c --target tofino --arch tna -g -o build_9132 dnp3_shadow.p4 > compile_9132.log 2>&1
```

## Result — PASS, parity with local 9.13.1
- **Compiler:** `p4c 9.13.2 (SHA: 1baf055)`. **EXIT_CODE = 0.** **0 errors, 2 warnings** (the same benign
  TNA `min_parse_depth_accept_loop` unroll notices seen locally — not unsupported behavior).
- **Ingress stages: 4 / 12 (stages 0–3 occupied)** — identical to the local bf-p4c 9.13.1 result. **TCAM 0.**
  Full per-stage/per-table resource table in `mau.resources.log`; metrics in `metrics.json`.
- **Output hashes** (`onswitch_output_hashes.txt`):
  - source `dnp3_shadow.p4` = `e08f2844…` (matches local + `git` blob)
  - `dnp3_shadow.conf` = `1d8edfac…` (stable)
  - `pipe/tofino.bin` = `95994b45…` (note: `tofino.bin` embeds a build-id and is **not byte-reproducible**
    across compiles — a known bf-p4c property; the `.conf` and source hashes are the stable references)

## Restore path — VERIFIED (read-only)
- **Active program before (and still, unchanged):** `/home/decps/queue_microbench/out/queue_microbench_abs.conf`
  (the queue microbench).
- **Known-good restore command:** `/home/decps/queue_microbench/launch_mb.sh` (captured verbatim in
  `RESTORE_launch_mb.sh.txt`): `bf_switchd … --conf-file …/queue_microbench_abs.conf --init-mode=cold`.

## STOP before load — port discovery is AMBIGUOUS (GATE-1 rule)
> **RESOLVED 2026-07-23** by `../GATE1_REPLAY_TOPOLOGY_RECONCILIATION.md`: a cabling map +
> live MAC match confirm **dp8 = Vision, dp9 = Hulk** (both single-NIC hosts). The viable
> path is two-host transit (**Candidate B / B2**): inject Hulk→dp9, capture Vision←dp8. No
> re-cabling and no host bring-up needed; one gated switch-side action (enable dp8/dp9).
> The load stays held pending a fresh authorization covering that enable.

The GATE-1 authorization: *"If compilation, staging, port discovery, or restoration is ambiguous, stop
without loading anything."* Compilation, staging, and restoration are unambiguous and pass. **Port
discovery for the bounded replay does not.** Grounded observations (read-only):
- The shadow forwards **dp8 (PORT_VISION) ↔ dp9 (PORT_HULK)** as a two-port bump-in-the-wire.
- **`dev_port` 8 and 9 read `n/a`** in the current (queue-microbench) `$PORT` table; **dp68 is down**.
- **Hulk's 25 GbE data NIC `enp59s0f0np0` is DOWN**; only the 10 GbE `enp59s0f1np1` is up.
- The prior queue-microbench rig was a **hairpin** (inject on dp8, observe on dp9, return on the 25 GbE
  NIC), **not** a symmetric two-port dp8→dp9 forward with a separate inject and capture point.

Therefore there is **no unambiguous inject-on-dp8 / capture-on-dp9 replay path** to verify the shadow's
byte-identity and classification. Rather than invent the topology or bring a data NIC up on assumptions,
the load is held.

## To proceed to the load + replay (needs a human decision / one authorized action)
Confirm the replay rig unambiguously, e.g.:
- which Hulk NIC physically connects to **dp8** and which to **dp9** (and bring up the 25 GbE data link);
- or the intended bump-in-the-wire inject + capture points for the committed 300-poll pcap replay;
- confirm dp8/dp9 come up under the shadow program's own port bring-up (`dnp3_shadow_setup.py --run`)
  once loaded, and that a capture point exists on the dp9 side.

Once the replay path is unambiguous, the remaining GATE-1 steps (load → runtime config → bounded replay →
capture → verify → restore) can run under this same authorization.
