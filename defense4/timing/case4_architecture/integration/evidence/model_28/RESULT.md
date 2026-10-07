# model_28: S3-0 cross-pipe and mirror probe (gate G-XPIPE) on the local Tofino-1 model

Program: `integration/core/xpipe/xpipe_probe.p4`, source sha256 `9146f57abdf39c9987ee206c50008a73f40a1b70b4fd1c0e996890cc956dc1ba`
(compile_04; 2 ingress + 1 egress stages; pipes p0..p3 via `Switch(p0, p1, p2, p3)`, identical logic per pipe; `core/scan_static_entries.py` clean).
It uses synthetic non-DNP3 frames: Ethernet(0x88b5) + 16-byte private prefix + payload. Per pipe it counts ingress arrivals per local port, egress traversals, e2e-mirror
copies and generator packets, and latches the last prefix it saw, so internal hops are observable without a wire tap.
Final run: `run9`, 19/19 cases pass. Command:
`cd integration && ./core/launch_model.sh -p evidence/model_28/compile_04/out -o evidence/model_28/runN -P "<41 device ports>" -d core/cases/xpipe_cases.py`
(`core/cases/xpipe_pktgen.py` is the generator-only detail run, `run7_pktgen`.)

## Verdict: cross-pipe forwarding IS usable on the model. Option C of STEP3_DESIGN 2.2 stays primary; the option-B fallback is NOT triggered by S3-0.
(a) pipe 0 ingress to pipe 1 ingress, prefix preserved: port 9 -> egress to dev 196 (pipe 1 local 68, bypass) -> arrives at pipe 1 ingress 68 (counter +1, `p1.Egress.arr_eg[68]` +0)
    and pipe 1 latched epoch 0x11111111, generation 0x22222222, expected 0x00050001, event|reserved 0x01050000 = exactly the sent prefix (`a_prefix_preserved_at_pipe1_ingress`).
(b) pipe 1 ingress -> pipe 0 egress at 64 and at 9 (`ucast_egress_port` in another pipe, bypass_egress 0): pipe 0 egress counters +1 and one frame on each front port, identical to the input:
    in  `0a00000000020a000000000188b51111111122222222000500010105000078706970652d70726f62652d30313233343536373839`
    out `0a00000000020a000000000188b5111111112222222200050001010500007870...` (same bytes, model zero-pads to 60).
(c) e2e mirror from pipe 0 egress: `$mirror.cfg` session 5 (EGRESS, ucast_egress_port 68) accepted; the clone traverses pipe 0 egress at port 68 (`p0.Egress.arr_mir[68]` +1),
    recirculates and re-enters pipe 0 ingress 68 (`p0.Ingress.arr_ig[68]` +1) with the prefix intact (`c_mirror_copy_prefix_at_pipe0_ingress68`); the original still leaves port 64.
    Delta: `{'p0.Egress.arr_eg[64]': 1, 'p0.Egress.arr_mir[68]': 1, 'p0.Ingress.arr_ig[68]': 1, 'p1.Ingress.arr_ig[68]': 1}`.
(d) packet generator: RUNS on the model, in all four pipes. Port cfg, buffer and one-shot timer app accepted; readback `trigger_counter 4, batch_counter 4, pkt_counter 12` (4 pipes x 3 packets),
    the periodic app fired 3416 times in 15 s. In the final probe each pipe counted `pgen_arr +3`. Quirks: generator packets reach ingress with `ingress_port == 0` (NOT 68) and a 6-byte timer
    header; the first probe, keyed on port 68, saw nothing (run7_pktgen) until the parser recognised the timer header (compile_04). Only 3 of the expected 12 frames were captured at port 64
    within the capture window (counters show all 12 arrived), so frame-level generator checks need a longer window. Silicon behavior unverified.
(e) legal ports and the READ handoff: see `PORTS_PROPOSAL.md`. Short form: local 68-71 recirculate in every pipe, `$PORT` refuses them (nothing to add); local >= 72 aborts the model start
    (`Invalid port 72 in PortToVeth mapping`, run1); local 64-67 behave differently per pipe. N's `READ_HANDOFF_PORT` 66 (pipe 0) leaves the chip, T's `T_IN` 69 (pipe 0) recirculates into N's own pipe:
    they never meet. Proposed: N sends to dev 325 (pipe 2 local 69) = T ingress, verified (case f, prefix preserved, then to egress 64 and 9); three-hop pipe 0 -> pipe 2 -> pipe 1 -> egress 64 passes (case g).

## Other facts recorded
* Per-pipe-program tables only accept the all-pipes target (`pipe_id 0xffff`); `p0.Ingress.fwd` refuses `pipe_id 0` with INVALID_ARGUMENT (bfrt names are `p<N>.Ingress.*`, action names `Ingress.*`).
* `$PORT` add for pipe 0 local 64-67 and front ports works, for local 64-71 of pipes 1-3 and local 68-71 of pipe 0 it is refused with INVALID_ARGUMENT; the paths still work without it.
* bf-p4c accepts `Switch(p0,p1,p2,p3)` with four Pipeline instances; the conf lists p0..p3 with `pipe_scope` [0]..[3] and the model loads it.
* e2e mirror needed a non-constant field list (`{ m.pkt_type }`; a constant fails: "Non-zero constant value 8w2 in digest field list is not supported on tofino", compile_02).
* Retained failures kept as evidence: `compile` (MirrorId_t width), `compile_02` (constant digest field), `run1` (port 72), `compile_03`/`run7_pktgen` (generator keyed on port 68).
* Tool changes: `core/launch_model.sh` dedupes ports and fails fast on device-add errors; `model_driver.py` accepts `p<N>.` table names and a per-call pipe target.

## Not shown / limits
Model only: no timing, no queue behavior, no ordering of replicas, no hardware loopback capability of any physical port, no PRE/multicast cross-pipe, generator port numbering on silicon.
Hardware gates G-PORTS and G-XPIPE remain required before any of these port numbers is used on the switch. Nothing was run on hardware.
Sizes: ~240 MB on disk, almost all raw `model.out` from the generator runs; `.gitignore` in this directory excludes the raw logs.
