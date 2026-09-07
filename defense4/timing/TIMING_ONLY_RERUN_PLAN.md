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
2. **There is no fixed-shift arm available on this hardware.** A constant translation needs each
   release instant computed from *that packet's own arrival*, with a constant difference between
   the two delays; equal delays are only the special case of zero difference. Every implemented
   mode computes releases from absolute deadlines instead, so none produces a translation
   whatever its offsets (`SHIFT_VS_REPLACEMENT.md` §3).
   The analytical constant-shift reference in `EVIDENCE_AUDIT.md` §3 is therefore not a
   convenience: it is the only shift comparison obtainable without a new program, and a new
   program is barred by this repository's own rules and would no longer be the binary whose
   hash the evidence chain records. The rerun does **not** propose one, and the manuscript
   should keep calling that reference analytical.

## 3. What the rerun measures, and how

### Instrumentation: withdrawn, and what it actually costs

An earlier version of this plan claimed the loaded program already latches the switch-side
instants, that four of six timestamp registers were already read by the control plane, and that
`e_r` was therefore "a two-entry control-plane change, no new P4". **All of that is withdrawn.**
The full evidence is in `audit_current/INSTRUMENTATION_AUDIT.md`; the three load-bearing facts:

1. **No timestamp write action is ever executed.** All 27 `.execute(` sites in the program are
   accounted for and none targets a `ts_*_w` action. bf-p4c agrees: the archived campaign
   compile log reports `ts_first_block_w`, `ts_ack_arm_w`, `ts_block_term_w` and
   `ts_ack_release_w` as `unused instance`. The registers hold their init value 0 forever, and
   the control plane's clear-and-read path returns zeros.
2. **Four of the ten are not even compiled.** `reg_ts_read` and `reg_ts_resp_release`, the two
   the plan wanted most, sit behind `#ifdef D3_SYNTH_EVENTS`, which the loaded build did not
   define. The compiler's silence about them corroborates it, as does the source's own
   instruction that the live campaign build must not define that macro.
3. **None of them would be a wire departure anyway.** Every write would take
   `ig_intr_md.ingress_mac_tstamp`, an **ingress** timestamp, inside `control Ingress`. A
   "release" timestamp written on a dequeued packet records its **re-entry from the internal
   loopback**, not its departure at dp9. There is no egress-side timestamp register anywhere in
   the program.

So gap G1 cannot be closed by configuration. It needs a **new P4 and a new binary**, whose
smallest form is set out in `INSTRUMENTATION_AUDIT.md` §7: two execute call sites for the two
already-compiled ingress actions, plus a genuinely new **egress**-side register to observe a
departure, plus a generation tag so a readback can be attributed to a transaction, plus control
plane to clear and read it.

**That is a separately identified build.** It compiles to a different binary with a different
hash, it is not the program the published evidence rests on, it needs its own approval before
deployment, and any campaign run under it must be reported as a different build and never
pooled with `campaign_v1`.

**Consequence for this plan.** Arms A2 and A3 below, the paired switch-side readback arms, are
**not executable under the loaded binary** and are marked accordingly. They are retained as a
specification of what a future instrumented build would have to do, not as steps to approve
now. Everything else in the plan runs on the loaded binary unchanged, and G1 stays open.

The author's own untried check is likewise unreachable: `(reg_ts_ack_release - reg_ts_ack_arm)
mod 2^32` cannot be evaluated when neither register is ever written.

### Arms

| arm | mode | `D_A` | `D_R` | shape | rate | purpose |
|---|---|---|---|---|---|---|
| A0 | OFF | — | — | 0 | campaign | native baseline through the same processing path |
| A1 | D4 | 20 | 4 | 0 | campaign | reproduce the published operating point |
| ~~A2~~ | D4 | 20 | 4 | 0 | — | **NOT EXECUTABLE on the loaded binary.** Would have given `t_0`, `t_a`, `e_a`, `e_r` per transaction; the instrumentation is inert, see above. Retained only as a specification for a future instrumented build |
| ~~A3~~ | OFF | — | — | 0 | — | **NOT EXECUTABLE on the loaded binary**, same reason |
| A4 | D4 | 20 | 4 | 0 | campaign, TCP instrumented | G5: master-side retransmission-timeout and retry evidence, with the kernel state archived (§4.5) |
| A5 | D4 | 32, 34, 36 | 4 | 0 | campaign | the envelope edge; at these settings the measured CLRT was 5.503, 7.498 and 9.507 ms against a 4 ms target (`sweep_points.csv`) |
| A6 | D4 | 20 | 4 | 0 | campaign | **runs first**: driver A/B, frozen `campaign_run.py` against the corrected drivers, to measure rather than assume that the driver change is harmless (§4.3) |

A0 and A1 interleaved within each session, as `campaign_v1` did, three of each per session. A2
and A3 cannot run on this binary and are not part of what is being proposed. No arm changes
`shape_enable`, which stays 0.

G2, G3 and G4 are **not** in this plan. They need a relay-facing tap on dp64, which does not
exist, and G3 additionally needs release multiplicity at the relay. Adding a tap is a physical
change to the topology and a separate authorization; §7 lists it as a prerequisite, not a step.

### Prespecified counts, order and stopping

* Sessions: 8. Per session, 6 campaign blocks: A0, A1, A1, A0, A1, A0, order fixed per session
  from a published table so the arm order is balanced across sessions and not chosen after the
  fact.
* Per campaign block: 400 READ and 40 SBO, `--min-gap 6 --gap-ms 20`, one seed per block,
  recorded before the run. Identical to `campaign_v1`, so the two are comparable.
* A2 and A3: not executable; no counts are proposed.
* A5: 200 READ and 20 SBO per point, three points, at `D_A` of 32, 34 and 36 ms. These
  are the settings at which the sweep measured 5.503, 7.498 and 9.507 ms; the plan
  previously listed 30, 32, 34 in the arm table while attributing those measurements to
  them, which was a transcription error. `D_A` = 30 ms is the last setting that still
  holds target, so it belongs to A1's neighbourhood rather than to the edge arm.
* A6: six blocks in one session, three per driver, 400 READ and 40 SBO each, identical seeds.
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

**The entry point is the corrected driver, not the frozen one.** The archived
`campaign_run.py` cannot support the correctness claims this rerun is for: it sends the OPERATE
without requiring the SELECT to have succeeded, it re-arms its receive timeout on every read so
nothing bounds a transaction, it discards buffered bytes past a frame, it validates no CRC, and
it never ties a response to its request by sequence number. Those are the defects
`active_harness/` exists to fix, and running the rerun on the defective driver would reproduce
them.

```sh
ssh decps@10.10.54.166 '
  sudo nohup timeout 200 tcpdump -i enp59s0f0np0 -s0 --time-stamp-precision=nano \
       -w /tmp/<session>/<tag>.pcap "host 192.168.10.7 and tcp" &
  sleep 4
  cd ~/active_harness && DEFENSE4_HW_AUTHORIZED=1 python3 read_driver.py --live \
     --count 400 --gap-ms 20 --budget-ms 500 --out /tmp/<session>/<tag>_read.jsonl
  cd ~/active_harness && DEFENSE4_HW_AUTHORIZED=1 python3 sbo_driver.py --live \
     --count 40 --gap-ms 20 --budget-ms 500 --indices 1,3 \
     --out /tmp/<session>/<tag>_sbo.jsonl'
```

The frozen `campaign_run.py` interleaved READ and SBO on one connection from a seeded schedule.
The corrected drivers are separate programs, so an interleaving runner over the same session is
the one piece of new driver code the rerun needs.

**It has not been written.** This is a blocking prerequisite, listed as such in §7, not an
implementation detail to be settled during the run. When it is written it must be a thin
scheduler that calls `session.Session.transaction` and `sbo_driver.one_sbo` and adds no protocol
logic of its own, it must reproduce the frozen driver's seeded interleaving so the arms stay
comparable, and it must be covered by the offline suite before any hardware use.

**Two behavioural differences from the frozen driver, and an arm to measure them.** The
corrected session sets `TCP_NODELAY`, which `campaign_run.py` left off, and it imposes a real
monotonic transaction deadline where the frozen driver had none. Neither should move a
master-facing interval, because the request bytes are built by the same frozen builders and the
master never had unacknowledged data outstanding at send time in `campaign_v1`. But "should not"
is an assumption, so:

* **Arm A6, driver A/B.** At the published operating point, alternate blocks between the frozen
  `campaign_run.py` and the corrected drivers, three blocks each in one session, same seeds and
  spacing. Compare the released interval, the request-to-acknowledgment interval and the
  end-to-end latency between the two drivers. If they agree within the measured run-to-run
  spread, the driver change is shown harmless and every other arm can use the corrected
  drivers. If they do not, the difference is a result and must be reported before anything else
  in the rerun is interpreted.

A6 runs first. The frozen driver stays byte-identical and is invoked from its archived copy at
`evidence/campaign_v1/s01/tools/campaign_run.py`, never edited.

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
2. **A new P4 build, if G1 is to be closed at all.** Not a control-plane addition: see
   `INSTRUMENTATION_AUDIT.md` §7. It is a separate program, a separate binary hash and a
   separate approval, and it is not part of what this plan asks for. Without it G1 stays open
   and arms A2 and A3 do not run.
3. **The interleaving runner, which does not yet exist** (§4.3). Without it there is no program
   to drive an A0/A1 block in the corrected harness, so no arm of this plan can run.
4. Timeout-boundary behaviour tested offline or against a simulator **before** any physical
   boundary test. Abort condition 7 exists precisely so the boundary is never explored on the
   relay. The corrected harness's 42 offline tests cover the master side of it; a simulated
   outstation would be needed for the rest.
5. For G2, G3 and G4: a relay-facing tap on dp64, which is a physical topology change and a
   separate authorization. Without it those three gaps stay open whatever this plan measures.
6. The relay's select-validity setting, read and recorded. This needs a relay configuration
   read, which is a relay interaction and is also gated.

## 8. What this rerun would and would not license

**Would.** A measured master-side retransmission timeout and retry record, replacing the first
unknown in `TIMEOUT_AND_RETRANSMISSION_AUDIT.md`. A recorded select-validity window, replacing
the second. Full configuration transcripts and a per-point readback, which would move
configuration provenance from PARTIAL toward VERIFIED. A second independent session group at the
published operating point, and the envelope edge remeasured.

**Would not, contrary to the earlier version of this plan.** A switch-side measurement of `e_a`
or `e_r`; an attribution of the ≈0.7 ms excess to the switch rather than the host path; or the
author's reservoir test. All three need instrumentation that does not exist in this binary.

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
