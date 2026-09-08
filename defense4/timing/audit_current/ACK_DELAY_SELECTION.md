# Selecting the acknowledgment hold `D_A`: how much more holding this deployment tolerates

Written 2026-09-08. Every repository fact is quoted with `file:line` or the exact file read
this session; every external fact carries its URL and clause. No hardware was touched and no
traffic was generated.

## Question

The mechanism holds the outstation's TCP acknowledgment of the master's request for `D_A`
before releasing it toward the master. The campaign ran at `D_A` = 20 ms. How much further can
`D_A` be raised before TCP transport behaviour on the master is disrupted?

Short answer: **TCP is not the binding constraint here, and the question as posed is never
reached.** The mechanism's own fail-open horizon caps the achievable hold near 30 ms, roughly
6.4x below the lowest retransmission floor any mainstream stack is documented to use, and the
deployment's admissibility policy caps it lower still. What TCP would tolerate on this host is
**unmeasured**: the master's retransmission timer was never read.

## What RFC 6298 specifies

Read this session from <https://www.rfc-editor.org/rfc/rfc6298> (RFC 6298, *Computing TCP's
Retransmission Timer*, Paxson et al., June 2011). Clause numbers are the RFC's own.

| clause | what it says, as written |
|---|---|
| §2.1 | before any RTT measurement, "the sender SHOULD set RTO <- 1 second"; a note records that RFC 2988 used 3 seconds and "A TCP implementation MAY still use this value (or any other value > 1 second)" |
| §2.2 | on the first measurement `R`: `SRTT <- R`, `RTTVAR <- R/2`, `RTO <- SRTT + max(G, K*RTTVAR)`, "where K = 4" |
| §2.3 | on a subsequent measurement `R'`: `RTTVAR <- (1 - beta)*RTTVAR + beta*|SRTT - R'|` then `SRTT <- (1 - alpha)*SRTT + alpha*R'`, in that order, "SHOULD be computed using alpha=1/8 and beta=1/4", then `RTO <- SRTT + max(G, K*RTTVAR)` |
| §2.4 | "Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second" |
| §2.5 | "A maximum value MAY be placed on RTO provided it is at least 60 seconds" |
| §4 | clock granularity `G` is unconstrained, but "if the K*RTTVAR term in the RTO calculation equals zero, the variance term MUST be rounded to G seconds"; finer granularities (<= 100 ms) "perform somewhat better" |
| §5.5 | on expiry, "The host MUST set RTO <- RTO * 2" |
| §5.7 | if the timer expired awaiting the SYN's ACK with an RTO below 3 s, RTO "MUST be re-initialized to 3 seconds when data transmission begins" |
| §6 | "An attacker could cause a TCP sender to compute a **large** value of RTO by adding delay to a timed packet's latency, or that of its acknowledgment" |

Three consequences for `D_A`. (i) **The standard's floor is 1 second** (§2.4); mainstream
kernels do not honour it, which is why the operative floor must be read off the host rather than
the RFC. (ii) **A uniform hold raises the sender's RTO, it does not lower it**: under §2.3 a
constant `D_A` shifts every RTT sample equally, so `SRTT` converges toward the held value while
`|SRTT - R'|`, hence `RTTVAR`, stays small, and §6 states the same direction. The danger is a
*variable* hold, or one exceeding the floor before the estimator adapts, not a steady one.
(iii) **A late acknowledgment is a spurious retransmission, not a broken connection** (§5.4,
§5.5): one duplicate segment plus an RTO doubling that collapses back on the next sample (note
after §5.7).

## What this deployment's stack is

### Verified

* **The master is a Python program on a plain blocking TCP socket, not OpenDNP3.** Driver
  `evidence/campaign_v1/s01/tools/campaign_run.py`, sha256
  `3994aca143b07b067417f4fcca5c3e57a8c1c06f3e4c6f617ad0ae97bb83ca48` (recomputed this session);
  `def recv(s, timeout=3.0):` line 30, `s.settimeout(timeout)` line 31,
  `except socket.timeout: return buf` line 34. That is a **per-receive** timeout re-armed on
  each read; nothing in the program bounds a whole transaction.
* **The master host is Vision, 192.168.10.1, interface `enp59s0f0np0`**
  (`evidence/campaign_v1/PROVENANCE_CONSTANTS.json`, `hardware.master`), management address
  `10.10.54.166` (`TIMING_ONLY_RERUN_PLAN.md:179`; used as `VI=` in
  `evidence/campaign_v1/_bin/campaign_block.sh:8`).
* **The host is Linux**, established only indirectly: the sole archived TCP setting anywhere is
  `net.ipv4.tcp_timestamps`, a Linux sysctl (`TIMEOUT_AND_RETRANSMISSION_AUDIT.md:127-130`,
  citing `evidence/final_read_sbo/audit/E0_testbed_preservation.md`).
* **MSS, SACK-permitted, window scale and timestamps were negotiated on all 132 connections.**
  `audit_current/outputs/timeout_and_tcp_audit.json`, `tcp_options`: one observed pair,
  `SYN=[MSS, SACK_PERM, TS, NOP, WS] | SYN-ACK=[MSS, NOP, WS, NOP, NOP, SACK_PERM, NOP, NOP,
  TS]`, count 132. Under RFC 6298 §3 the timestamp option lets every acknowledgment serve as an
  RTT sample, so the estimator adapts quickly to a steady hold.

### Unverified

* **`net.ipv4.tcp_rto_min` and the kernel version were never read.** A whole-repo search for
  `tcp_rto_min` returns only prose and forward-looking plans:
  `TIMEOUT_AND_RETRANSMISSION_AUDIT.md:116,122,302`; `TIMING_ONLY_RERUN_PLAN.md:271`;
  `figures/model/fig_m02_timeout_model.provenance.json:54`;
  `audit_current/tools/make_model_figures.py:33-34,295,330`; and the policy default at
  `implementation/control/parameter_policy.py:59`. **No readback exists.**
* **The 200 ms figure is a reference value; that framing is confirmed.**
  `make_model_figures.py:33-34` reads "REFERENCE VALUES, not measurements of this host. Linux's
  documented TCP_RTO_MIN is 200 ms and RFC 6298 section 2.4 recommends a 1 s floor. The host's
  kernel version and tcp_rto_min were never [read]", and line 295 labels the plotted value
  `source="Linux TCP_RTO_MIN; host value not recorded"`. It is **not** upgraded below.
* **The archived `tcp_timestamps=0` belongs to the earlier `final_read_sbo` campaign, not to
  `campaign_v1`,** and the wire shows it had been restored: timestamps are negotiated on all 132
  `campaign_v1` captures (above), which requires `tcp_timestamps=1`.
* **The relay's own RTO, and the outstation's select-validity window, are not recorded**
  (`TIMEOUT_AND_RETRANSMISSION_AUDIT.md:302-310`; `CLAIMS_AND_LIMITATIONS.md` L11).

## Measured evidence in this repository

Recomputed or re-read this session, not taken on the audit's word.

| quantity | value | file it comes from |
|---|---|---|
| TCP request retransmissions, Timing OFF / Obfuscated | **0 / 0** | `audit_current/outputs/timeout_and_tcp_audit.json`, `totals.native\|request_retransmissions`, `totals.obfuscated\|request_retransmissions` |
| TCP response retransmissions | 0 / 0 | same, `*\|response_retransmissions` |
| requests observed | 31,680 / 31,680 = **63,360** | same, `*\|requests` |
| duplicate ACKs, resets, SACK blocks, sends with bytes outstanding | 0 in every category, both arms | same, `*\|duplicate_ack`, `*\|reset`, `*\|sack_option_seen`, `*\|sent_with_bytes_outstanding` |
| acknowledgments: standalone vs piggybacked | 31,680 vs 0, per arm | same, `*\|standalone_ack`, `*\|piggybacked_ack` |
| worst request-to-ACK wait `L_A`, whole campaign | **29.150 ms** (obfuscated OPERATE) | same, `intervals.obfuscated\|OPERATE\|L_A.max` |
| worst obfuscated request-to-response `L_R` | **77.713 ms** | same, `worst_case_request_to_response_ms`, computed at `tools/timeout_and_tcp_audit.py:350` as the max over the three obfuscated classes |
| worst `L_R` in either arm | 83.862 ms (Timing OFF READ) | same, `intervals.native\|READ\|L_R.max` |
| per-receive socket timeout | **3.0 s**, re-armed per read | `evidence/campaign_v1/s01/tools/campaign_run.py:30-34` |
| application-layer outcome | 63,360 rows, **0 invalid**, max wall-clock `rtt_ms` 84.110 ms, statuses = `{None: 52800, SUCCESS: 10560}`, no other status value | recomputed this session over `evidence/campaign_v1/s[0-9][0-9]/app_jsonl/*.jsonl` |

Classified so it is not over-read: zero is a **measured outcome on the master-facing tap
only**, with a detector matching `(direction, sequence, payload length)` that would miss a
repacketized retransmission (`TIMEOUT_AND_RETRANSMISSION_AUDIT.md:170-186`). It is not a
measurement of the master's RTO, and no event in this corpus can be turned into one because
**no retransmission was observed at all**. Had one occurred it would have bounded that
connection's RTO at that instant after any §5.5 backoff, not established a universal value.

### Configured offsets

`evidence/campaign_v1/PROVENANCE_CONSTANTS.json`, `config.obfuscated_arm`: `D_A_ms` 20,
`D_R_ms` 4, `A_ms` 20, `R_ms` 24, `J_codebook_ms` [2, 6, 12]. Per `TIMING_MODEL.md` §2, `D_A` is
anchored at `t_a`, the relay's acknowledgment arriving at the switch, and the release deadline is
`t_a + D_A`; the OPERATE lane instead uses the absolute deadline `t_0 + A`.

## The time budget at the hold point

The hold does not begin at the master's send instant. Decompose the master's unacknowledged
interval, which is exactly the interval that arms the master's retransmission timer under
RFC 6298 §5.1:

```
L_A  =  P_fwd  +  D_A  +  P_rev  +  eps
```

* `P_fwd` = `m_0 -> t_a`: request leaves the master NIC, crosses the switch, reaches the relay,
  and the relay's acknowledgment returns to the switch. **Not directly observable**
  (`TIMING_MODEL.md` §2: `t_a` is a dp64-ingress event and there is no relay-facing tap).
* `D_A` = the configured hold, 20 ms. `P_rev` = `e_a -> m_a`, switch egress to master NIC, also
  not separately observable. `eps` = release variability.

`P_fwd + P_rev + eps` is bounded by the Timing OFF arm, where no hold applies: READ `L_A`
median **0.555 ms**, p99.9 **4.750 ms**, max **5.903 ms** (`timeout_and_tcp_audit.json`,
`intervals.native|READ|L_A`). The composite is measured in the Obfuscated arm: READ `L_A` median
**21.336 ms**, p99.9 **25.645 ms**, max **25.769 ms**, with `mechanism_overhead.READ` recording
`excess_ms` = **0.781 ms** over `D_A` plus the Timing OFF median. Worst anywhere: **29.150 ms**.

Headroom, as an inequality evaluated against the only floors that can be justified:

```
D_A + (P_fwd + P_rev + eps)_worst  +  M  <  RTO_effective
```

| floor used | provenance of the floor | headroom over the worst observed 29.150 ms | ratio |
|---|---|---|---|
| 1000 ms | RFC 6298 §2.4, standards floor | 970.9 ms | 34.3x |
| 200 ms | Linux documented `TCP_RTO_MIN`, **reference value, not this host** | 170.9 ms | 6.9x |
| 180 ms | the repo's own guard, 200 ms floor less a 20 ms margin (`parameter_policy.py:59-60`) | 150.9 ms | 6.2x |
| this host's actual RTO | **not recorded** | **unknown** | **unknown** |

Every row but the last is arithmetic on an assumed value. The last row is the honest one.

### The constraint that actually binds, and it is not TCP

Two mechanism-internal limits sit an order of magnitude below every TCP floor above.

**1. The admissibility policy refuses `D` above about 24.8 ms.**
`implementation/control/parameter_policy.py:95-99` computes `H = B * K / rate_dp8` from
`BUDGET_DEFAULT = 18000` (line 40), `K_TOKENS = 64` (line 37), `RATE_DP8_PPS = 37.4e6` (line 38):
`H` = 18000 x 64 / 37.4e6 = **30.802 ms**. Then `D_max = H - a_bound - t_detect - t_drain -
t_tail - M` (lines 102-105) with `ACK_BOUND_MS_DEFAULT = 3.0` (line 54),
`SAFETY_MARGIN_MS_DEFAULT = 3.0` (line 56) and `(1217+1736+1736) ns = 0.004689 ms` (lines 46-49):

```
D_max = 30.802 - 3.0 - 0.004689 - 3.0 = 24.797 ms      on D = D_A + D_R
```

At the campaign's `D_R` = 4 ms this admits `D_A` <= **20.8 ms**, so the tested `D_A` = 20 ms
sits 0.8 ms inside its own policy ceiling; the module's docstring says as much: "with a_bound =
3 ms and M = 3 ms, D_max ~ 24.8 ms, so the D = 16 ms campaign passes and D = 40 ms is refused."
The module's RTO check, `rto_ok = h < (rto_min_ms - rto_margin_ms)` (line 144), tests the
**horizon** and not `D_A`: 30.802 < 180, passing with 5.8x to spare.

**2. Measured saturation: the acknowledgment stops tracking `D_A` at about 30 ms.**
From `evidence/campaign_v1/sweep/sweep_points.csv`, read this session, at `D_R` = 4 ms:

| `D_A` (ms) | 4 | 12 | 20 | 28 | 30 | 32 | 34 | 36 | 36 (repeat) |
|---|---|---|---|---|---|---|---|---|---|
| `ack_med_ms` | 4.576 | 12.990 | 21.318 | 29.480 | 30.571 | 31.072 | 31.071 | 31.073 | 31.071 |
| `clrt_med_ms` | 4.000 | 4.000 | 3.999 | 3.999 | 4.001 | 5.503 | 7.498 | 9.507 | 9.501 |

The wait saturates at **31.07 ms** and the release loses its pin. The repository attributes the
ceiling to the fail-open horizon - "The saturation matches the program's fail-open horizon
`H = 30.8 ms`, the safety bound after which a held packet is released regardless"
(`evidence/campaign_v1/figures/FIGURES.md:165-171`) - the offset arising because `H` is counted
from the request, not the acknowledgment. `H` itself "is a control-plane quantity computed from
the pass budget and reservoir depth, not a bound the data plane enforces or that was measured
directly" (`CLAIMS_AND_LIMITATIONS.md` L11), but the saturation **is** measured, twice at 36 ms.

The deployment therefore cannot be pushed into the TCP-risk region by raising `D_A`: past about
30 ms the extra request is not realized and the mechanism's guarantee degrades first. 31.07 ms
against the reference 200 ms floor is 6.4x; against RFC 6298's 1 s floor, 32x.

## Supported operating range for the tested deployment

For **this** master, **this** relay, **this** loaded program and **this** traffic pattern:

* **`D_A` = 20 ms with `D_R` = 4 ms is a tested setting**, not a proven safe bound. What is
  established at it is an outcome, not a margin: 0 TCP retransmissions in 63,360 exchanges on
  the master-facing tap, 0 application timeouts, 0 invalid rows, and 10,560 of 10,560 SBO status
  rows `SUCCESS` with no `NO_SELECT`.
* **`D_A` up to about 20.8 ms at `D_R` = 4 ms is admissible under the deployment's own policy**
  (`D_max` = 24.797 ms on `D = D_A + D_R`). Above that the policy module refuses to write
  `tbl_params`.
* **`D_A` between about 21 and 30 ms is mechanically realized but outside that policy**: the
  acknowledgment still tracks the target to 30.571 ms with the release pinned at 4.001 ms, but
  the pass budget is no longer clear of the horizon by the configured margins, and those points
  rest on medians over 200 to 400 READ transactions with no per-point control-plane readback
  (`CLAIMS_AND_LIMITATIONS.md` L11) and no archived per-exchange maxima.
* **`D_A` at or above 32 ms is not usable**: the hold saturates and the defense's own release
  pin fails (CLRT median 5.503, 7.498, 9.507 ms).
* **No claim of a universal safe bound is made.** A master with a smaller retransmission floor,
  a different kernel, or an application deadline of tens of milliseconds rather than the 3.0 s
  per-receive socket timeout used here would have to be re-evaluated from scratch.

## What remains unresolved, and the exact measurement that would close it

**Unresolved:** the master's actual retransmission timeout. Every TCP margin above rests on a
documented Linux constant rather than a reading of Vision. The zero retransmission count is
unaffected by this gap; the *headroom* is not. If this host runs a `tcp_rto_min` well below
200 ms, the 6.9x figure shrinks accordingly.

**The single measurement that would close it,** already scheduled at
`TIMING_ONLY_RERUN_PLAN.md:270-273`, run on the master host `decps@10.10.54.166` (Vision,
confirmed as master at `TIMING_ONLY_RERUN_PLAN.md:179`) while a session is open:

```sh
uname -a
sysctl net.ipv4.tcp_rto_min net.ipv4.tcp_syn_retries net.ipv4.tcp_retries2 \
       net.ipv4.tcp_timestamps net.ipv4.tcp_sack net.ipv4.tcp_low_latency
ss -tin dst 192.168.10.7      # per-connection rto, rtt, rttvar, retrans
```

`ss -tin` is the decisive one: it reports the kernel's own `rto` and `rttvar` for the live
connection, the realized value of RFC 6298 §2.3 under the hold, rather than a floor inferred
from a constant. Pair it with `nstat -az TcpRetransSegs TcpExtTCPTimeouts TcpExtTCPLossProbes`
before and after each block, as the plan specifies, so a retransmission the pcap detector would
miss is still counted by the kernel.

Two further gaps, not to be conflated with that one: the relay's own RTO and whether it
retransmitted a held response (invisible to a master-facing tap because `CF_RESP_DUP_SUPP`
absorbs a position-matched duplicate inside the switch), and the SEL-751A's select-validity
window. Neither bears on `D_A` selection through TCP on the master side; both bear on how far
`D_R` and the total `D` can go.

## Sources

**External, fetched 2026-09-08:** RFC 6298, *Computing TCP's Retransmission Timer*,
<https://www.rfc-editor.org/rfc/rfc6298> - clauses 2.1-2.5, 3, 4, 5.1, 5.4, 5.5, 5.7, 6.

**Repository, read 2026-09-08** (paths relative to `defense4/timing/`):
`TIMEOUT_AND_RETRANSMISSION_AUDIT.md` (116, 122, 127-130, 170-186, 302-310);
`TIMING_MODEL.md` §1-2; `CLAIMS_AND_LIMITATIONS.md` C2, C3, L10-L12;
`TIMING_ONLY_RERUN_PLAN.md` (179, 226, 255-278); `audit_current/CONFIGURATION_EVIDENCE.md` §1-4;
`audit_current/outputs/timeout_and_tcp_audit.json` (`totals`, `intervals`, `tcp_options`,
`mechanism_overhead`, `worst_case_request_to_response_ms`);
`audit_current/tools/timeout_and_tcp_audit.py:350`;
`audit_current/tools/make_model_figures.py:33-34, 295, 330`;
`implementation/control/parameter_policy.py:1-30, 37-40, 46-60, 95-108, 130-150`;
`evidence/campaign_v1/PROVENANCE_CONSTANTS.json`;
`evidence/campaign_v1/s01/tools/campaign_run.py:30-34` (sha256 recomputed this session);
`evidence/campaign_v1/_bin/campaign_block.sh:8`; `evidence/campaign_v1/sweep/sweep_points.csv`;
`evidence/campaign_v1/sweep/sweep_timing.json`; `evidence/campaign_v1/figures/FIGURES.md:165-171`;
`evidence/campaign_v1/figures/fig_c08_operating_envelope.caption.md:7`;
`evidence/campaign_v1/s[0-9][0-9]/app_jsonl/*.jsonl` (63,360 rows, aggregated this session).
