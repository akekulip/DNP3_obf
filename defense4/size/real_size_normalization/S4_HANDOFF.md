# Gate S4 Implementation Handoff

Date: 2026-08-14

Branch: `defense4-real-size-normalization`

Status: **component checkpoint only - S4 is not passed**

## Pick up here

Start from the component-checkpoint commit that adds `software/l2_shim.py`, `software/cell_link.py`, `software/packet_capture.py`, `software/dnp3_endpoint.py`, `software/packet_oracle.py`, and their tests. The immediately preceding gate-opening commit is `854e67d` (`defense4: open S4 namespace prototype gate`).

The first implementation task is to add one shared absolute monotonic start to both shim processes. `l2_shim.py` currently begins its 210-ms epoch schedule at each process's own startup time; that is insufficient for the combined fixed direction/slot timing claim. Add a required `--start-monotonic-ns`, sleep/pump to that barrier, record it in metrics, and test the schedule calculation before writing the namespace runner.

Then implement and run the rootless namespace campaign described below. Do not use or claim the earlier in-process/veth draft evidence; it was not compliant with `S4_SOFTWARE_SPEC.md` and was excluded from git.

## Completed and verified

- Gate S4 boundaries, architecture, no-proxy rule, capture oracles, thresholds, and claim boundary are committed in `S4_SOFTWARE_SPEC.md` and `HARNESS_BOUNDARIES.md`.
- A rootless capability probe succeeded outside the Codex command sandbox: a mapped-root user/network namespace could create a veth, set fixed MACs, and bind an `AF_PACKET` raw socket.
- `software/l2_shim.py` implements raw complete-frame capture/injection, runtime-only 64-byte keys, the unchanged S3 codec, a bounded order-preserving FIFO, slot classification, public counter-window grouping, fail-closed decode, PCAP output, and local metrics. It contains no TCP socket API.
- `software/cell_link.py` implements a test-only two-interface raw Ethernet forwarder with deterministic post-emission drop, duplicate, reorder, and replay rules.
- `software/packet_capture.py` independently captures complete outer frames and emits classic PCAP plus optional public metadata.
- `software/dnp3_endpoint.py` implements native real-TCP master and relay roles with 100 balanced checksum-valid synthetic DNP3 exchanges across wire lengths `17, 49, 56, 75, 104`.
- `software/packet_oracle.py` validates DNP3 header/data CRCs, Ethernet/IPv4/TCP parsing, IPv4/TCP checksums, and basic TCP sequence continuity.
- Fresh verification:
  - `python3 -m pytest -q defense4/size/real_size_normalization/software defense4/size/real_size_normalization/offline/test_s3_offline.py`
  - result: `86 passed in 0.62s` outside the socket-restricted Codex sandbox;
  - `python3 -m py_compile defense4/size/real_size_normalization/software/*.py` passed;
  - `git diff --check` passed.

## Not completed - do not claim

- No integrated four-role network-namespace topology has run.
- No native endpoint packet has crossed both shims.
- No independent observed-link PCAP or trusted-boundary paired PCAP has been accepted.
- No 100-exchange namespace campaign, direct-veth latency baseline, lifecycle/reconnect campaign, or live link-loss/TCP-retransmission case has run.
- No S4 observer analysis, exact frame-sequence oracle, resource/latency/rate gate, manifest, claim matrix, or result document exists.
- No independent code/evidence review has approved the S4 implementation.
- Nothing in this checkpoint demonstrates Vision, Tofino, RRC/BOR, the physical relay, RN-T, or production deployment.

## Known integration repairs

1. **Synchronize epochs.** Add the shared monotonic start described above. Record actual per-cell deadline error or enough public timing data to compute p99 and maximum deadline slip.
2. **Harden reorder faults.** `cell_link.FaultPlan` currently holds one reorder event globally. Key held state by ingress/egress or direction so an opposite-direction arrival cannot flush a held frame through the wrong egress. Replay selection must likewise preserve the archived event's direction/egress.
3. **Add absolute endpoint timing.** Endpoint JSONL currently records elapsed milliseconds but not an absolute monotonic send/receive timestamp. Add log-safe monotonic timestamps so application cases can be mapped to public outer epochs without using secret occupancy metadata.
4. **Make the TCP oracle retransmission-aware.** The basic continuity oracle intentionally flags a repeated sequence. The loss campaign needs a separate result that labels exact retransmission as expected, rejects conflicting overlap, and proves recovered application-stream equality.
5. **Add lifecycle support.** The relay endpoint exits after one connection. Run separate endpoint processes or extend it for three clean reconnects, while keeping ARP, SYN/SYN-ACK/ACK, FIN/RST, and idle epochs inside fixed cells as required by the spec.
6. **Add readiness/error surfaces.** The raw link, capture, and shim CLIs lack ready files. Add ready files or another bounded startup barrier so the runner never races process initialization.

## Namespace runner to add

Create `software/run_s4_namespace.sh` (or an equivalently auditable Python orchestrator) using the existing rootless PID-held namespace pattern:

```text
master ns: m_ep 10.44.0.1/24, MAC 02:44:00:00:00:01
    <-> Vision shim ns: v_in | v_out MAC 02:00:00:00:00:01
    <-> parent test-link interfaces: l_left | l_right
    <-> UFISpace-role shim ns: u_out MAC 02:00:00:00:00:02 | u_in
    <-> relay ns: r_ep 10.44.0.2/24, MAC 02:44:00:00:00:02
```

Requirements:

- enter only a fresh `unshare --user --map-root-user --net --fork` environment; do not use `--mount-proc` on this host because that capability probe failed;
- hold child network namespaces by PID and join with `nsenter -t PID -n`; do not create named `/run/netns` state;
- give IP addresses only to `m_ep` and `r_ep`; do not install static neighbor entries;
- disable IPv6 and veth offloads where supported;
- generate 64 random key bytes in a mode-`0600` file under `/tmp`, wait until both shims load it, then unlink it; never log or commit it;
- run the link emulator in the parent test namespace and capture the Vision-side outer interface independently;
- run a complete fixed number of epochs and enforce an external timeout;
- preserve all process logs and exit codes without recording plaintext or cell occupancy.

The component CLI surfaces are:

```bash
python3 -m defense4.size.real_size_normalization.software.l2_shim --help
python3 -m defense4.size.real_size_normalization.software.cell_link --help
python3 -m defense4.size.real_size_normalization.software.packet_capture --help
python3 -m defense4.size.real_size_normalization.software.dnp3_endpoint --help
```

## Campaign and evidence order

1. Run a 5-exchange namespace smoke and fix all packet, startup, schedule, and teardown defects.
2. Run the same endpoint workload on a direct veth for a latency baseline.
3. Run the 100-exchange balanced no-fault namespace campaign.
4. Run separate lifecycle/idle/three-reconnect cases.
5. Run deterministic cell reorder/duplicate/replay/auth/overflow/timeout unit or namespace cases.
6. Run one post-emission cell-loss case and prove native TCP retransmits through a later complete fixed epoch.
7. Generate `evidence/s4_software/` only from the integrated namespace campaign: four trusted-boundary PCAPs, one independent observer PCAP, observer CSV/statistics using 1,000 permutations and 2,000 bootstraps, frame/TCP/DNP3 oracles, fault results, latency/rate/resource metrics, claim matrix, reproduction script, and SHA-256 manifest.
8. Write `S4_SOFTWARE_RESULT.md`, run independent code/evidence review, fix every blocking finding, commit verification, and stop before S5.

## Safety and repository state

- Do not SSH to Vision or Tofino for S4.
- Do not touch P4/BFRT, live interfaces, RRC/BOR state, physical relay traffic, or package installation.
- Keep `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md` untracked and excluded from every commit.
- All commits must use `akekulip <akekulip@gmail.com>` as author and committer.
- Stale noncompliant generated evidence was moved out of the worktree to `/tmp/d4-s4-stale-evidence.EymAhb/`; it is recoverable during this host session but must not be promoted or reused.

## Stop condition

The next agent stops when S4 is independently verified and committed as an isolated rootless network-namespace software result. It must not proceed to S5 or any live testbed action without a new explicit instruction.
