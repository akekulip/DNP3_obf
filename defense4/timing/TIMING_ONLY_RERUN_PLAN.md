# Timing-only rerun plan

**Nothing here has been executed.** No program was loaded, no traffic-manager or relay
configuration was changed, the relay was not contacted, and no capture was taken. This document
is the package to approve or reject.

It exists because four questions the manuscript would like to answer cannot be answered from
`campaign_v1`, and one published description of the sweep turns out to be wrong. Both are set
out below before any command.

---

## 1. Why a rerun, stated as specific gaps

| # | gap | why `campaign_v1` cannot close it |
|---|---|---|
| G1 | the switch's own release instants `e_a`, `e_r` | only `m_0`, `m_a`, `m_r` were captured; everything inside the switch is inferred from the program |
| G2 | the realized per-transaction `J`, and the relay-facing release at `t_0 + J` | dp64 has no host-capturable tap and dp68 is internal |
| G3 | exactly-once release toward the relay | same tap problem; release multiplicity is not observable master-facing |
| G4 | whether the relay retransmitted a held response | the program suppresses a position-matched response retransmission, so it would be absorbed inside the switch |
| G5 | the master's realized TCP retransmission timeout, and the relay's select-validity window | neither the kernel version nor the relay setting was archived |
| G6 | a hardware fixed-shift control | see §2: the loaded binary has no working shift mode |

G1 is the one that changes what can be claimed. With `e_a` and `e_r` per transaction, the
statement "the released interval follows the configured target" becomes a switch-side
measurement rather than an inference from a master-side interval, and the ≈0.78 ms excess the
mechanism adds beyond `D_A` (`TIMING_MODEL.md` §5) can be attributed to the switch or to the
host path rather than left unattributed.

## 2. A correction the plan depends on: the binary has exactly one holding policy

The loaded program declares six modes: `MODE_OFF`, `MODE_D1_EVENT`, `MODE_D2_RESP`,
`MODE_D3_ACK`, `MODE_D4_DUAL`, `MODE_FAIL_OPEN` (lines 632 to 637). Its decision table arms a
transaction only for `MODE_D4_DUAL`:

```
(… CLASS_ARM, V_ARM_FRESH, … MODE_D4_DUAL …) : dec_o(OUT_ARM_FRESH);   /* line 2846 */
(… CLASS_ARM, V_ARM_FRESH, … MODE_OFF      …) : dec_o(OUT_ARM_BUSY);   /* line 2847 */
(… CLASS_ARM, …                             …) : dec_o(OUT_ARM_BUSY);   /* line 2849 */
```

Every mode other than D4 falls through to `OUT_ARM_BUSY`: no deadline is written and both
packets are forwarded. The wire agrees. Two sweep points were configured in the other modes and
both measured native timing:

| point | mode | `D_A` | `D_R` | measured CLRT | measured request-to-ACK |
|---|---|---|---|---|---|
| `sw_off` | OFF | — | — | 2.093 ms | 0.558 ms |
| `sw_D2_0_24` | D2 | 0 | 24 | 2.108 ms | 0.550 ms |
| `sw_D3_20_0` | D3 | 20 | 0 | 2.098 ms | 0.558 ms |

Under D2 with `D_R` = 24 the response should have been held about 24 ms; it was not. Under D3
with `D_A` = 20 the acknowledgment should have been held 20 ms; it was not.

The control plane is not the reason. Imported offline with no SDE, it exposes all six modes and
accepts `--mode D2` and `--mode D3` without complaint:

```sh
cd implementation/control && D4_CASEA_SETUP=$PWD/defense4_caseA_setup.py python3 -c "…"
# chain imports OK
# modes available: ['D1', 'D2', 'D3', 'D4', 'FAIL_OPEN', 'OFF']
```

So the configuration was accepted and the data plane did not act on it. Anyone reconfiguring
this switch should know that a mode can be set successfully and still do nothing.

Two consequences.

1. **The sweep is 16 configured D4 policy points and 3 native controls, not "18 configured
   release policies and one control".** The count of 19 is right; its composition as published
   in `README.md` §3 is not. `sweep_block.sh` labels D2 and D3 `COND=obfuscated`, which is how
   they came to be counted as policies. Claim C2 is unaffected: all eight points it quotes at
   fixed `D` = 24 ms are D4.
2. **There is no fixed-shift arm available on this hardware.** A constant shift needs both
   instants delayed by the same amount from their own arrivals, which no reachable mode does.
   The analytical constant-shift reference in `EVIDENCE_AUDIT.md` §3 is therefore not a
   convenience: it is the only shift comparison obtainable without a new program, and a new
   program is barred by this repository's own rules and would no longer be the binary whose
   hash the evidence chain records. The rerun does **not** propose one, and the manuscript
   should keep calling that reference analytical.

## 3. What the rerun measures, and how

### Instrumentation that needs no new P4

The loaded program already latches switch-side instants in single-slot registers, write-if-zero:

| register | instant | read by the preserved control plane? |
|---|---|---|
| `reg_ts_read` | the READ seen at ingress, `t_0` | no |
| `reg_ts_ack_arm` | the deadline armed at the relay acknowledgment, `t_a` | **yes** |
| `reg_ts_first_block` | first blocker token dequeue | **yes** |
| `reg_ts_block_term` | blocker reservoir drained | **yes** |
| `reg_ts_ack_release` | the acknowledgment dequeued toward the master, `e_a` | **yes** |
| `reg_ts_resp_release` | the response dequeued toward the master, `e_r` | no |

Four of the six are already cleared and read by `defense4_caseA_setup.py` (lines 186, 471).
Adding `reg_ts_resp_release` and `reg_ts_read` to those two lists is a control-plane change of
two list entries, written in the corrected active tree and never in the frozen files. That
alone closes G1.

The source even carries the author's own test for whether the reservoir gates the release:
`(reg_ts_ack_release - reg_ts_ack_arm) mod 2^32` should centre on `D_A + 1.711 µs` with a
spread of tens of nanoseconds; if the spread is microseconds, the reservoir is not what gates
the release (comment at lines 1997 to 2002). That test has never been run.

**The cost, stated plainly.** These registers are size 1 and write-if-zero, so per-transaction
readback needs a clear and a read between transactions, over gRPC. That does not fit inside the
campaign's 20 ms gap. So paired switch-side instants come from a **separate low-rate arm**, not
from the main campaign, and the two are not pooled. A low-rate arm also changes the load, which
is itself a reason to keep it separate and to report it as its own condition.

### Arms

| arm | mode | `D_A` | `D_R` | shape | rate | purpose |
|---|---|---|---|---|---|---|
| A0 | OFF | — | — | 0 | campaign | native baseline through the same processing path |
| A1 | D4 | 20 | 4 | 0 | campaign | reproduce the published operating point |
| A2 | D4 | 20 | 4 | 0 | low, paired readback | G1: `t_0`, `t_a`, `e_a`, `e_r` per transaction |
| A3 | OFF | — | — | 0 | low, paired readback | the same readback with no hold, to separate switch overhead from host path |
| A4 | D4 | 20 | 4 | 0 | campaign, TCP instrumented | G5: master-side RTO and retry evidence |
| A5 | D4 | 30, 32, 34 | 4 | 0 | campaign | the envelope edge, where CLRT rose to 5.503, 7.498, 9.507 ms |

A0 and A1 interleaved within each session, as `campaign_v1` did, three of each per session.
A2 and A3 are their own sessions. No arm changes `shape_enable`, which stays 0 and is verified
from the wire as well as from the readback.

G2, G3 and G4 are **not** in this plan. They need a relay-facing tap on dp64, which does not
exist, and G3 additionally needs release multiplicity at the relay. Adding a tap is a physical
change to the topology and a separate authorization; §7 lists it as a prerequisite, not a step.

### Prespecified counts, order and stopping

* Sessions: 8. Per session, 6 campaign blocks: A0, A1, A1, A0, A1, A0, order fixed per session
  from a published table so the arm order is balanced across sessions and not chosen after the
  fact.
* Per campaign block: 400 READ and 40 SBO, `--min-gap 6 --gap-ms 20`, one seed per block,
  recorded before the run. Identical to `campaign_v1`, so the two are comparable.
* A2 and A3: 200 transactions each at one transaction per 250 ms, which leaves room for a clear
  and a read between transactions.
* A5: 200 READ and 20 SBO per point, three points.
* Warm-up: the first block of each session is discarded, declared before the run, because
  `campaign_v1` shows a cold-start effect in its first exchanges. It is discarded by position,
  never by value.
* Stopping rule: the run stops when the prespecified counts are met, or on any abort condition
  in §6. It does not stop early because a result looks good, and it is not extended because a
  result looks bad.
* Precision: the published `D_R` = 4 ms operating point has a within-arm standard deviation of
  0.628 ms for READ. Eight sessions of three obfuscated blocks give 9,600 obfuscated READ
  exchanges in total, which puts the standard error of a per-session median far below the
  0.031 ms 99th percentile release error. The binding constraint on this rerun is not sample size; it is
  G1 instrumentation. Counts are chosen to match `campaign_v1` for comparability, not to chase
  a power target.

## 4. Exact commands

Hosts and paths as recorded in `evidence/campaign_v1/PROVENANCE_CONSTANTS.json` and
`_bin/campaign_block.sh`. `10.10.54.81` is the switch control host, `10.10.54.166` is the master
(Vision), the relay is `192.168.10.7:20000` reached through dp64.

### 4.1 Before the first run: prove the binary is the one the evidence names

```sh
ssh decps@10.10.54.81 'sha256sum ~/rrc_bor_build_v2/defense4_rrc_bor_unified12.p4 \
    ~/rrc_bor_build_v2/tofino/defense4_rrc_bor_unified12/pipe/tofino.bin'
# must be 7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861  (source)
#     and 33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa  (loaded binary)
```

If either differs, **stop**: the run would not be the program the evidence chain records.

### 4.2 Configure one campaign block

Unchanged from `campaign_v1`, so the arms stay comparable:

```sh
# obfuscated
ssh decps@10.10.54.81 "cd ~/rrc_bor_build_v2/control && \
  SDE_INSTALL=~/Downloads/bf-sde-9.13.2/install \
  PYTHONPATH=~/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino:~/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages \
  DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=~/d4_build/control/defense4_caseA_setup.py \
  python3 defense4_rrc_bor_unified12_setup.py configure-all \
    --mode D4 --read-len 0 --d-a-ms 20 --d-r-ms 4 --op-a-ms 20 --op-r-ms 24 --j-set '2 6 12'"
# native: --mode OFF --read-len 0
```

**Then force and verify the size path off**, and this time keep the whole transcript rather
than its last line:

```sh
ssh decps@10.10.54.81 "cd ~/rrc_bor_build/control && … python3 shape_set.py 0"      # expect PASS
```

### 4.3 Capture and drive

```sh
ssh decps@10.10.54.166 '
  sudo nohup timeout 200 tcpdump -i enp59s0f0np0 -s0 --time-stamp-precision=nano \
       -w /tmp/<session>/<tag>.pcap "host 192.168.10.7 and tcp" &
  sleep 4
  cd ~/native_parity && python3 campaign_run.py --session <s> --block <b> \
     --condition <native|obfuscated> --mode <OFF|D4> --j-ms "2,6,12" \
     --n-read 400 --n-sbo 40 --min-gap 6 --gap-ms 20 --seed <seed> \
     --out /tmp/<session>/<tag>.jsonl'
```

For A4 the driver is replaced by the corrected `active_harness/read_driver.py` and
`active_harness/sbo_driver.py` with `--budget-ms` set deliberately, and the TCP state is
recorded around each block (§4.5).

### 4.4 A2 and A3: the paired switch-side readback

Requires the two-entry control-plane addition of §3, staged in the active tree. Per
transaction: clear the six timestamp registers, issue one transaction, read them back, record
the six words with the transaction identifier. The analyzer takes the differences modulo 2^32,
as the source comment prescribes. Wall-clock joining is not used; the transaction identifier is
the key.

### 4.5 What must be archived that `campaign_v1` did not archive

Per run, and this is the part that turns G5 from unknown into measured:

```sh
ssh decps@10.10.54.166 'uname -a; \
  sysctl net.ipv4.tcp_rto_min net.ipv4.tcp_syn_retries net.ipv4.tcp_retries2 \
         net.ipv4.tcp_timestamps net.ipv4.tcp_sack net.ipv4.tcp_low_latency; \
  ss -tin dst 192.168.10.7'                       # rto, rtt, retrans, per connection
nstat -az TcpRetransSegs TcpExtTCPTimeouts TcpExtTCPLossProbes   # before and after each block
```

Also archived per block, none of which exists for `campaign_v1`: the **full** `configure-all`
transcript rather than its last line; the full `shape_set.py` transcript; the relay's DNP3
select-validity setting, read from the relay and recorded verbatim; and the switch's
`CF_RESP_DUP_SUPP` counter before and after each block, which is the closest available proxy
for G4 without a tap.

## 5. Clock, capture loss and provenance checks

* `tcpdump` with `--time-stamp-precision=nano`, and the analyzer asserts the pcap magic is the
  nanosecond variant. `campaign_v1`'s captures are nanosecond pcapng despite a `.pcap`
  extension, which has already caused one three-orders-of-magnitude parsing trap with older
  scapy (`README.md` §5).
* Capture loss: assert per capture that frames, wire bytes, exchange count and TCP connection
  count match the expected constants, as `validate_campaign.py` already does. A capture that
  misses a frame fails the gate rather than being analyzed.
* Clock: the master's own clock is the only one in the master-facing measurement, so no
  cross-host synchronization is needed for `m_0`, `m_a`, `m_r`. The switch-side words of A2 and
  A3 are on the switch's own 32-bit tick clock and are only ever differenced against each other
  on that clock. The two clocks are never subtracted, and no cross-clock quantity is reported.
  If one is ever wanted, NTP offset and drift on both hosts must be recorded first.
* Per-run hashes of source, loaded binary and every capture, and the readback transcripts,
  archived before and after each run, into a directory that is **not** under
  `evidence/campaign_v1/`.

## 6. Guards, abort conditions and rollback

Unchanged from the campaign, and none is relaxed:

* Control frames target only DNP3 binary-output indices `{1, 3}` (remote bits RB02 and RB04),
  proven by the isolation audit to have empty fanout. Index 6, which drives OUT102 breaker
  close, and every index outside the set, is refused at frame construction by
  `relay_operate_guarded._assert_authorized`, and again by the post-build sentinel. The
  corrected drivers import that guard rather than reimplementing it.
* Every hardware operation refuses unless `DEFENSE4_HW_AUTHORIZED=1`.
* Relay outputs are checked before and after every session, and the run **aborts** on any
  output or TRIP assertion.

Abort immediately, and do not continue to the next block, on any of:

1. a source or binary hash that does not match §4.1;
2. `configure-all` reporting anything but `n_fail=0 n_warn=0`, or `shape_set.py` reporting
   anything but `PASS shape_enable=0`;
3. any relay output or TRIP contact asserting;
4. any CROB status other than SUCCESS, or any `NO_SELECT`;
5. any TCP retransmission, reset, or a rise in `TcpRetransSegs` across a block;
6. a capture whose frame or byte count does not match the expected constant;
7. any transaction whose request-to-response latency exceeds 200 ms, which is the RTO floor and
   the point at which the timeout analysis of `TIMEOUT_AND_RETRANSMISSION_AUDIT.md` stops
   holding.

Rollback: `defense4_rrc_bor_unified12_setup.py rollback`, then `disable-bor`, then re-verify
with `verify`. The binary is not reloaded and not replaced at any point in this plan.

## 7. Prerequisites that are not yet satisfied

1. **Authorization to run hardware at all.** This repository's `CLAUDE.md` forbids further
   experimentation; that rule has to be lifted explicitly for this plan, naming it.
2. The two-entry control-plane addition of §3, written and dry-run offline first. The chain
   imports with no SDE, so the dry-run is real work that can be done before any approval.
3. Timeout-boundary behaviour tested offline or against a simulator **before** any physical
   boundary test. Abort condition 7 exists precisely so the boundary is never explored on the
   relay. The corrected harness's 42 offline tests cover the master side of it; a simulated
   outstation would be needed for the rest.
4. For G2, G3 and G4: a relay-facing tap on dp64, which is a physical topology change and a
   separate authorization. Without it those three gaps stay open whatever this plan measures.
5. The relay's select-validity setting, read and recorded. This needs a relay configuration
   read, which is a relay interaction and is also gated.

## 8. What this rerun would and would not license

**Would.** A switch-side measurement of `e_a` and `e_r`, so release accuracy becomes a
measurement rather than an inference. An attribution of the ≈0.78 ms excess to the switch or to
the host path. A measured master-side RTO and retry record, replacing the unknown in
`TIMEOUT_AND_RETRANSMISSION_AUDIT.md`. A recorded select-validity window, replacing the second
unknown. The author's own reservoir test, run at last. Full configuration transcripts, which
would move configuration provenance from PARTIAL toward VERIFIED.

**Would not.** Anything about physical operation time. A physical-operation claim needs a
defined physical event and a measurement of it, which means contact or breaker instrumentation
and an actuating experiment on a point that is deliberately isolated in this rig. This plan
does not promise it and must not be read as a route to it. Nor would it establish exactly-once
release, the realized `J`, multi-device indistinguishability, or cross-day stability, none of
which is a sample-size question.

Configuration choices in §3 are the published operating point and the measured envelope edge.
They are not chosen because they plot well, and the envelope edge is included precisely because
it is where the mechanism degrades: at `D_A` of 32, 34 and 36 ms the released interval rises to
5.503, 7.498 and 9.507 ms against a 4 ms target, and the request-to-response latency reaches
40.6 ms. The tradeoff between suppression, added latency, deadline misses and protocol
correctness is the point of including it.

---

**Stop here.** The next action is a decision, not a command. Approving this plan means
approving, explicitly: lifting the no-experimentation rule for it, configuring the traffic
manager per block, and sending physical READ, SELECT and OPERATE traffic to the SEL-751A on
isolated points `{1, 3}`. Nothing in §4 has been run.
