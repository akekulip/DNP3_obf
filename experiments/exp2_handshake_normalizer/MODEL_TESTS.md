# Experiment 2B — model functional tests

**Status: HARNESS READY, NOT YET EXECUTED.** The tofino-model + bf_switchd + PTF stack is present
locally and the compiled program produces all loadable artifacts, but the functional model run was
**not performed in this turn**. No functional PASS/FAIL is claimed. This is the immediate next gate.
Do not read the compile PASS as a functional PASS — see `VERDICT.md`.

## Why the run is well-scoped (and low-risk when done)

The three ingress tables (`t_norm`, `t_exp`, `t_clamp`) use compile-time **`const entries`**, so the
data plane is fully populated at load time — **no runtime table programming is required**. Loading
the program (switchd reads `build/handshake_normalizer.conf` → `context.json` + `tofino.bin`) is
sufficient to make the pipeline behave. The program forwards `egress_port = ingress_port ^ 1`, so a
test injects on veth for port 0 and captures on veth for port 1.

## Procedure (local, SDE 9.13.1)

```bash
SDE=/home/philip/bf-sde-9.13.1
sudo $SDE/install/bin/veth_setup.sh                                    # veth pairs for the model
$SDE/run_tofino_model.sh -p handshake_normalizer \
      -c experiments/.../build/handshake_normalizer.conf &            # terminal 1 (model)
$SDE/run_switchd.sh -p handshake_normalizer \
      -c experiments/.../build/handshake_normalizer.conf &            # terminal 2 (loads program)
# wait for switchd "bf_switchd: WARM_INIT ... complete", then:
$SDE/run_p4_tests.sh -p handshake_normalizer -t tests/ptf            # terminal 3 (PTF)
```

The fixtures in `tests/ptf/test.py` are built with scapy and were verified to build and re-parse
correctly (data_offset 6–11, all in the supported range) — see the fixture check in the commit's
evidence. What they cannot tell us without the model is whether the *pipeline* produces the expected
outputs; that is exactly what this run establishes.

## Test matrix (26 cases; `tests/ptf/test.py` implements the core; the rest are one fixture each)

| # | Case | Expected |
|---|---|---|
| 1 | SEL751 full-option SYN (do=10/11) | canonical do=6, MSS 1460, options dropped, checksums valid |
| 2 | ION7550 MSS-only SYN (do=6) | layout kept, MSS 1460, checksums valid |
| 3 | AB1400 SYN, MSS 1478 | MSS clamped to 1460, canonical do=6 |
| 4 | small MSS (536) SYN | MSS preserved (never raised), canonical do=6 |
| 5 | input TTL 128 | output TTL 64 |
| 6 | SYN, 2nd option = MD5 (kind 19) | **fail open** — forwarded unchanged (do != 6) |
| 7 | established ACK + Timestamp + DNP3 payload | **fail open** — forwarded, payload byte-preserved |
| 8 | UDP | forwarded (not a handshake) |
| 9 | SYN-ACK minimal (MSS-only, do=6) | normalized (MSS canonicalized) |
| 10 | SYN-ACK non-minimal (MSS+TS) | **fail open** — forwarded unchanged |
| 11 | SYN with payload / TFO cookie | **fail open** — forwarded unchanged |
| 12 | SYN, MSS not first option | **fail open** |
| 13 | data_offset 5 SYN (no options) | **fail open** (no MSS to canonicalize) |
| 14 | data_offset 11 SYN (max supported) | normalized to do=6 |
| 15 | atomic datagram (DF set) | ip.id zeroed |
| 16 | non-atomic (MF/fragment) | not parsed as TCP; forwarded, ip.id kept |
| 17 | established, no options | forwarded, TTL scrubbed, byte-preserved |
| 18 | ARP / non-IPv4 | forwarded unchanged |
| 19 | IPv4 with IP options (ihl>5) | not parsed as TCP; forwarded |
| 20 | IPv4 header checksum after ttl/id edit | valid |
| 21 | TCP checksum after option rewrite | valid |
| 22 | TCP window value | preserved (residual leak, per Exp 1) |
| 23 | sequence/ack numbers | never modified |
| 24 | outcome counter increments | one increment on the correct index per packet |
| 25 | non-eligible SYN counter (fail-open index) | increments |
| 26 | forwarded byte length of a normalized SYN | shrunk by the removed option bytes |

Cases 6–8 assert fail-open/forwarding without an exact expected packet (they check `data_offset`,
payload preservation, or mere delivery); the normalization cases assert an exact expected packet so
the recomputed checksums are validated by PTF's byte compare.
