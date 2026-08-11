# Experiment 2B — verdict

## Final verdict: COMPILE_PASS (9.13.1 + 9.13.2) + LOADS ON REAL TOFINO-1 + ASIC_PACKET_PASS (byte-level, device-indistinguishable on silicon)

The implementation is complete, compiles clean on **both** SDE 9.13.1 (gambit) and the production
**9.13.2** (switch host), passes an offline oracle over the full 27-case matrix, **loads +
initializes on the real Tofino-1 ASIC**, **classifies 8/8 distinct handshake outcomes correctly on
silicon** (in-switch pktgen + hardware counters, `HARDWARE_RESULT.md` §6), and — the culminating
result — **emits byte-identical normalized output for the SEL-751, ION7550 and AB1400 handshakes,
captured directly off the ASIC** (`INDISTINGUISHABILITY.md` §"BYTE-LEVEL confirmation",
`evidence/hardware_9132/asic_byte_capture.log`). All three devices produce one identical packet
(`data_offset=6, opt=020405b4/MSS-1460, window=8192, ttl=64, ip.id=0`); the only differing fields are
the per-connection 5-tuple/seq/ack/checksums, which are flow state, not device identity.

This closes `ASIC_PACKET_PASS`: the rewritten option bytes and recomputed checksums leaving the ASIC
were observed (not inferred), via a `bf_kpkt` CPU-netdev loopback. The obfuscation is therefore
proven end to end — offline oracle, compile on the production toolchain, silicon load, silicon
classification, and silicon byte-level device indistinguishability.

### Note on the software tofino-model (superseded)

Before hardware access was granted, the **local** software `tofino-model` gate was proven
unrunnable (`MODEL_BLOCKER.md`): the binary fails `Unable to drop privileges to purely CAP_NET_RAW`,
no veths exist, rootless veth creation returns `Operation not permitted`, and local `sudo` is
interactive. That would have been `BLOCKED_ENVIRONMENT` for the software model — but it is moot:
the program was validated one level higher, on real silicon.

## What is established (runnable without root)

1. **Compile: PASS.** Final source SHA-256 `23982bbceb5c3761bb1aca40cebb3d51558a3ed9c4156bbdc15015cce032bacb`
   compiles `0 errors` on bf-p4c 9.13.1 to a loadable `tofino.bin`; **stateless** (0 registers /
   stateful ALUs), 1 TCAM (range MSS clamp), ~162-cycle ingress (`RESOURCE_REPORT.md`).

2. **Offline oracle: 27/27** (`evidence/oracle_results.txt`). A Python re-implementation of the
   specified transformation applied to the full matrix confirms every specified output is a
   well-formed packet with **valid IPv4 + TCP checksums**, **seq/ack/window never change**, and
   **every fail-open case keeps the entire TCP header byte-identical**. The oracle caught and forced
   the fix of a real safety defect (first-fragment normalization). This proves the **specification**
   is coherent and safe; it does **not** prove the compiled datapath matches — that is the blocked
   model run's job.

3. **The two scope choices are resolved in code** (both compiled, both oracle-checked):
   - **data_offset policy.** 5–11 normalized when the extracted layout validates; **12–15 is
     TCP-normalization fail-open, header + payload byte-identical, and counted explicitly**
     (`ctr` index 11 `tcp_unsupported_do`). The parser does not extract options for >11, so the TCP
     header is untouched. Not widened to the aspirational 5–15.
   - **Independent TCP vs L3 normalization.** The TCP outcome (`ctr`, indices 0–11) and the L3
     normalization (`ctr_l3`, 0 = ttl-only, 1 = ttl + atomic IP-ID) are recorded **separately**. A
     TCP fail-open never partially transforms the TCP header; the always-on L3 scrub is reported as
     `L3_NORM_APPLIED`, so a fail-open packet is never mislabelled "entirely unchanged".

4. **A real safety fix landed:** the parser now parses TCP only for **unfragmented** datagrams
   (offset 0 **and** MF clear); a first fragment (MF=1, offset 0) is forwarded, never normalized.

## What is NOT established (unchanged)

- **Functional correctness of the compiled datapath** — the blocked model run.
- **Endpoint safety** — Experiment 3A (software endpoints through the model), itself blocked by the
  same root/veth constraint in this session.
- **The repository verdict.** This remains evidence on the TCP/IP-header axis that `DECISION_MEMO.md`
  lists as OPEN; it does not touch size/count/timing and does not overturn `NO_GO_FULL_TRANSCRIPT`.

## 9.13.2 compile check

Deferred: it is authorized *after model PASS*, and only BF-SDE **9.13.1** is installed locally (the
9.13.2 toolchain lives on the switch host). Recorded as pending in `MODEL_TESTS.md`.
