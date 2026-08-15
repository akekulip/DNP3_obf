# S1 Verification

Verifier: `s1_verifier`

Gate: S1 topology and capability audit

Date: 2026-08-15 UTC
Scope: `defense4/size/real_size_normalization/SIZE_TOPOLOGY_CAPABILITY_AUDIT.md`

## Verdict

PASS, with explicit proof gaps preserved.

S1 satisfies the gate as a truthful read-only topology/capability audit. It does not prove the selected mechanism is deployable, and it correctly marks the Tofino onboard CPU path as plausible but unproven.

## Success Criteria Checked

- Current topology is limited to Vision, one UFISpace Tofino-1/onboard CPU, and the existing SEL/ION relay leg.
- S1 distinguishes frozen authority from live switch state.
- Vision-side software shim capability is directly evidenced.
- UFISpace `ens1`/`bf_kpkt` is directly evidenced without upgrading it to a proven relay-edge boundary.
- Standard crypto/offload/tunnel claims are local, not inferred from product families.
- Capture, MTU, clock, and relay reachability claims are bounded.
- The stop rule remains explicit: if the CPU punt/reinject path cannot be proven, real total-length hiding is impossible in this testbed.

## Evidence

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md` requires S1 to be a read-only audit and requires stopping if no trusted depadding/decapsulation boundary can be added.
- `defense4/README.md` states the frozen authority is one Tofino-1 with Vision on dp9, SEL on dp64, dp8/dp10 internal loopbacks, and dp68 internal pktgen/recirc.
- `defense4/CLAIMS.md` states total DNP3 length is not hidden and `49` remains `28+21=49`.
- `defense4/size/native_parity/evidence/E_FINAL/E0_testbed_preservation.md` confirms dp68 is not a capturable relay-facing tap and the prior relay-facing BOR limitation is load-bearing.
- `ssh decps@10.10.54.19 ...` reproduced Vision facts: hostname `vision`, kernel `6.8.0-136-generic`, 72 CPUs, Xeon Gold 6140, AES/PCLMUL/AVX flags, `enp59s0f0np0` UP at `192.168.10.1/24`, MTU 1500/max 9702, 25 Gb/s full-duplex link, `i40e`, Python `3.12.3`, `cryptography 41.0.7`, `AESGCM` and `ChaCha20Poly1305` imports OK, OpenSSL `3.0.13`.
- `ssh decps@10.10.54.19 ethtool -k enp59s0f0np0` reproduced offload facts: TSO/GSO/GRO on; ESP, TLS TX/RX/record, and MACsec hardware offloads fixed off.
- `ssh decps@10.10.54.19 command -v wg/ipsec/swanctl` produced no paths, supporting the no-installed-tunnel claim for Vision.
- `ssh decps@10.10.54.19 ... ping/dev-tcp ...` verified SEL `.7` and ION `.8` are reachable by ping and TCP/20000 from Vision.
- `ssh decps@10.10.54.81 ...` reproduced UFISpace facts: hostname `ufispace`, kernel `5.4.0-216-generic`, live `bf_switchd` using `/home/decps/rrc_build/defense4_rrc.conf`, active program `defense4_rrc_kernel`, Xeon D-1527 with AES/PCLMUL/AVX flags, `ens1` UP with link-local IPv6 only, MTU 1500/max 9710, driver `bf_kpkt`, version `9.13.2-281-cpr`, Python `3.8.10`, `cryptography 2.8`, `AESGCM` and `ChaCha20Poly1305` imports OK, OpenSSL `1.1.1f`.
- `ssh decps@10.10.54.81 lsmod` and `/sys/module/bf_kpkt/parameters/*` reproduced `bf_kpkt` loaded with `kpkt_mode=1`, `kpkt_rx_count=256`, `kpkt_hd_room=32`, `intr_mode=msi`, and `kpkt_dr_int_en=1`.
- `ssh decps@10.10.54.81 command -v wg/ipsec/swanctl` produced no paths, supporting the no-installed-tunnel claim for UFISpace.
- `rg -n "bf_kpkt|ens1|punt|reinject|CPU_PORT|PORT_CPU" defense4/size/native_parity/p4 defense4/defense4_release/code || true` produced no matches, supporting S1's claim that current Defense 4 sources do not expose an explicit CPU-shim path.
- `ssh decps@10.10.54.81 test -r ...` verified the local SDE source paths cited by S1 exist for `shared/parde.p4`, `shared/port.p4`, and `bf_kpkt_net.c`.

## Gaps

- No S1 evidence proves `dp9 -> P4 punt -> ens1 -> userspace -> reinject -> dp64`, or the reverse relay-response path.
- No S1 evidence proves the exact CPU dev-port/value-set mapping, packet metadata contract, or CPU-origin classification needed for endpoint-transparent forwarding.
- No S1 evidence proves resource fit or latency/throughput of a future CPU-steering design beside the frozen unified RRC/BOR authority.
- No live `$PORT`/BFRT table dump was taken for this verification because S1 already records that the existing script expects the frozen unified program while the live process is running `defense4_rrc_kernel`.
- UFISpace NTP is only verified as synchronized by `timedatectl`; no current offset bound is available because `chronyc` is absent there.

## Risks

- The phrase "Tofino data plane can classify fixed outer cells, steer them to the CPU..." should continue to be read as a conditional implementation capability, not a proven property of the current Defense 4 P4 program.
- Future S2/S3 work must not treat `ens1` being UP or `bf_kpkt` being loaded as sufficient evidence of a relay-edge trusted boundary.
- Because `wg`, `ipsec`, and `swanctl` are absent on both endpoints, any standard tunnel path is a future installation/configuration decision and must not be represented as currently available.
- Host offloads on Vision are currently enabled, so later observer-link captures must control or explicitly account for them.

## Required Corrections

None required for S1 before advancing to S2. The existing S1 artifact preserves the decisive conditional stop rule and avoids the unsafe overclaim that a second trusted boundary has already been established.
