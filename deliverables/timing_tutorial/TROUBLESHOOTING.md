# Troubleshooting the DNP3 Timing-Normalizer Lab Demo

A symptom-based guide for the runnable timing-normalizer demonstration
(`research/timing_final/`). Each entry names one observable symptom and gives the
likely cause, a read-only diagnostic command, the output you should see when the
lab is healthy, a safe (non-destructive) correction, and the point at which you
must stop and ask Philip for authorization before going further.

## How to read this guide

Every diagnostic below is read-only: it pings, reads a process list, reads a
counter, or reads a capture file. None of them change switch state, relay state,
or host configuration. The `make` targets used as diagnostics (`make status`,
`make preflight`) only read; the targets that change the switch (`make load`,
`make configure-tm`, `make restore`) are the gated correction steps and are
called out explicitly where they apply.

## The lab, in one picture

- **Switch (Tofino-1)** `10.10.54.81` — runs `bf_switchd`; under test it is bound
  to the P4 program `dnp3_timing_normalizer`; at rest it is restored to
  `queue_microbench` (launched by `/home/decps/queue_microbench/launch_mb.sh`,
  config `queue_microbench_abs.conf`).
- **Vision (master side)** `10.10.54.19` management; must retain `192.168.10.1`
  on its relay-facing NIC; data NIC `enp59s0f0np0` faces switch port dp9 (dir0).
- **Hulk (outstation side)** `10.10.54.158`; data NIC faces switch port dp11 (dir1).
- **Physical SEL-751 relay/outstation** `192.168.10.7:20000` (MODE B live,
  read-only Class-0 polling only; the Tofino is NOT inline with it).
- **Internal loopback** dp8 (port group 2) carries the recirculating blocker
  tokens.
- **Queues** `Q_BLOCK` qid7 (strict HIGH priority) starves `Q_RESP` qid1 (strict
  LOW priority) to hold a response.
- **Blocker tokens** are internal-only packets, EtherType `0x88c1`. They must
  **never** appear on any external interface.

## Global stop rule

Stop and request Philip's explicit authorization before any action beyond the
read-only diagnostics and the gated `make` correction targets in this guide.
That specifically includes: physical recabling or moving fibres; any relay action
beyond read-only Class-0 polling (no writes, no controls, no configuration
changes on the SEL-751); firmware or operating-system changes on any host or on
the switch; enabling priority flow control (PFC); sending any DNP3 control or
write traffic; and any destructive repository action (history rewrite,
force-push, deleting evidence). When a correction below would exceed those
limits, the entry says so.

---

## Connectivity and hosts

#### 1. Switch not reachable at 10.10.54.81

- **Symptom:** `make preflight` reports `[FAIL] switch reachable at 10.10.54.81`,
  or every switch-side step times out.
- **Likely cause:** the switch is powered down, its management interface is down,
  a cable is unseated, or the management network is disrupted between the dev box
  and the switch.
- **Diagnostic command:** `ping -c1 -W2 10.10.54.81`
- **Expected healthy output:** one ICMP reply with `0% packet loss` (round-trip
  time typically well under a millisecond on the management LAN).
- **Safe correction:** confirm you are on the management network and retry the
  ping; verify the dev box has a route to `10.10.54.0/24`
  (`ip route get 10.10.54.81`). These checks are read-only.
- **When to stop and ask for authorization:** if the switch is unreachable after
  the read-only checks, stop. Power-cycling the switch, reseating cables, or any
  physical intervention on the switch requires Philip's authorization.

#### 2. Vision not reachable at 10.10.54.19

- **Symptom:** `make preflight` reports `[FAIL] Vision reachable at 10.10.54.19`;
  injector and capture steps that target Vision fail to connect.
- **Likely cause:** Vision is powered off or rebooting, its management NIC is
  down, or SSH is not answering.
- **Diagnostic command:** `ping -c1 -W2 10.10.54.19 && ssh decps@10.10.54.19 'hostname'`
- **Expected healthy output:** one ICMP reply with `0% packet loss`, then Vision's
  hostname printed by the SSH command.
- **Safe correction:** retry once (transient SSH or network blips are common);
  confirm the route with `ip route get 10.10.54.19`. Read-only only.
- **When to stop and ask for authorization:** if Vision stays unreachable, stop.
  Rebooting Vision, touching its power, or recabling requires Philip's
  authorization.

#### 3. Vision missing 192.168.10.1

- **Symptom:** `make preflight` reports `[FAIL] Vision holds 192.168.10.1`, or a
  script aborts with "Vision has no interface holding 192.168.10.1". This is a
  hard preflight requirement: the relay-facing address must be present.
- **Likely cause:** the relay-facing NIC lost its address after a reboot or NIC
  reset, or the address was removed manually and not restored.
- **Diagnostic command:** `ssh decps@10.10.54.19 "ip -o -4 addr show | grep ' 192.168.10.1/'"`
- **Expected healthy output:** exactly one line naming the relay-facing interface
  and the address `192.168.10.1/24`.
- **Safe correction:** this address must be present for the demo, but re-adding an
  IP address changes host network configuration. Report the finding first; do not
  re-add it silently.
- **When to stop and ask for authorization:** stop and ask before adding or
  changing the address (for example `ip addr add 192.168.10.1/24 dev <iface>`),
  because it is a host configuration change. Get Philip's authorization, then
  restore exactly `192.168.10.1/24` on the relay-facing NIC.

#### 4. Hulk not reachable at 10.10.54.158

- **Symptom:** `make preflight` reports `[FAIL] Hulk reachable at 10.10.54.158`;
  outstation-side injection or capture on Hulk fails.
- **Likely cause:** Hulk is powered off or rebooting, its management NIC is down,
  or SSH is not answering.
- **Diagnostic command:** `ping -c1 -W2 10.10.54.158 && ssh decps@10.10.54.158 'hostname'`
- **Expected healthy output:** one ICMP reply with `0% packet loss`, then Hulk's
  hostname.
- **Safe correction:** retry once; confirm the route with
  `ip route get 10.10.54.158`. Read-only only.
- **When to stop and ask for authorization:** if Hulk stays unreachable, stop.
  Power or physical intervention on Hulk requires Philip's authorization.

---

## Switch program and Traffic Manager

#### 5. More than one bf_switchd process

- **Symptom:** `make preflight` reports `[FAIL] exactly one bf_switchd running
  (found: 2)`; the switch behaves inconsistently or gRPC binding is flaky.
- **Likely cause:** a previous load left a stale `bf_switchd`, or a launch was
  started twice, so two instances contend for the ASIC.
- **Diagnostic command:** `ssh decps@10.10.54.81 'pgrep -a bf_switchd'`
- **Expected healthy output:** exactly one `bf_switchd` line (one PID).
- **Safe correction:** the supported way to return to a single, correctly bound
  `bf_switchd` is `make restore`, which stops stray instances and relaunches the
  restore program idempotently. Prefer that over manually killing processes.
- **When to stop and ask for authorization:** stop before manually issuing
  `pkill`/`kill` against `bf_switchd` outside the gated scripts, or before any
  reboot of the switch — both are switch-state changes requiring Philip's
  authorization.

#### 6. Wrong P4 program loaded

- **Symptom:** `make status` fails to read the expected registers, or preflight
  reports the bound program is neither `dnp3_timing_normalizer` (under test) nor
  `queue_microbench` (at rest).
- **Likely cause:** a partial or aborted load left the wrong pipeline bound, or a
  different experiment's program is still resident.
- **Diagnostic command:** `make preflight` (its "switch program binding" section
  prints `bound P4 program: <name>`).
- **Expected healthy output:** `bound P4 program: dnp3_timing_normalizer` during a
  demo, or `bound P4 program: queue_microbench` at rest.
- **Safe correction:** to run the demo, load the correct program with the gated
  `make load` (it snapshots state and asks for confirmation). To return the
  shared switch to its baseline, use `make restore`.
- **When to stop and ask for authorization:** `make load` and `make restore` both
  swap `bf_switchd` and change what the shared switch runs; run them knowingly.
  Stop and ask before loading any program other than these two, or before any
  manual `bf_switchd` swap outside the scripts.

#### 7. BFRT binding failure

- **Symptom:** `make status` exits `FATAL: no P13READ line from the switch`, or a
  script reports `bind_pipeline_config` raised an exception; the control plane
  cannot attach to the running pipeline.
- **Likely cause:** `bf_switchd` is not up, the bfrt gRPC server is not listening
  on `localhost:50052`, the pipeline is still initializing, or the client bound
  the wrong program name.
- **Diagnostic command:** `ssh decps@10.10.54.81 'pgrep -xc bf_switchd; ss -ltn | grep 50052'`
- **Expected healthy output:** the process count `1`, and a listening socket on
  port `50052`.
- **Safe correction:** if `bf_switchd` is up and `50052` is listening, wait a few
  seconds for pipeline init and re-run `make status`. If `bf_switchd` is not up or
  is not bound, `make restore` (or `make load` for the demo program) brings it up
  cleanly.
- **When to stop and ask for authorization:** stop before restarting `bf_switchd`
  by hand or touching the SDE installation; use the gated targets, and escalate to
  Philip if binding still fails after a clean restore.

#### 8. Queue priority readback incorrect

- **Symptom:** `make status` shows `Q_BLOCK max_priority` not strictly greater
  than `Q_RESP max_priority`, or shows a shaper enabled on `Q_BLOCK`; responses
  are not held even though the deadline arms.
- **Likely cause:** the strict-priority field (`max_priority`) was never set (so
  the queues fall back to a fair split), or a stale max-rate shaper from the
  `queue_microbench` baseline left `Q_BLOCK` ineligible so `Q_RESP` leaks.
- **Diagnostic command:** `make status`
- **Expected healthy output:** `queue priorities: Q_BLOCK max_priority=<high> >
  Q_RESP max_priority=<low> (shaper on Q_BLOCK: False)` — Q_BLOCK strictly above
  Q_RESP, and no shaper on Q_BLOCK.
- **Safe correction:** re-run `make configure-tm`, which re-applies the two-level
  strict priority (Q_BLOCK qid7 HIGH over Q_RESP qid1 LOW) and explicitly clears
  and verifies that no shaper is left on Q_BLOCK.
- **When to stop and ask for authorization:** `make configure-tm` is the intended
  correction. Stop and ask before enabling PFC or hand-editing TM shaper/priority
  registers outside that script.

#### 9. dp8 loopback not enabled

- **Symptom:** protected trials do not hold — the response egresses at native
  timing — and blocker-related counters do not advance as expected;
  `ctr_block_term_timeout` or `ctr_release_fail_open` may be nonzero.
- **Likely cause:** the internal loopback on dp8 (port group 2) is not enabled, so
  the blocker tokens cannot recirculate and the reservoir cannot be sustained; the
  mechanism then fails open and releases the response.
- **Diagnostic command:** `make status`
- **Expected healthy output:** during a hold, `deadline_armed=1`, `ctr_block_enq`
  advancing, and `ctr_block_term_timeout`, `ctr_release_fail_open`, and
  `ctr_bypass:1` all `0`.
- **Safe correction:** re-run `make configure-tm`, which (re)configures the
  loopback port (`--port-l 8 --pg-l 2`) along with the queues; then re-run
  `make run-protected` and re-check `make status`.
- **When to stop and ask for authorization:** if the loopback still will not come
  up after `make configure-tm`, stop. Manual switch-port configuration outside the
  script, or any physical/cabling change, requires Philip's authorization.

---

## Capture and decode

#### 10. No packets in PCAP

- **Symptom:** the capture file is empty or has a handful of frames; `make analyze`
  reports an empty or inconclusive capture.
- **Likely cause:** the injector never ran, the capture was started on an
  interface carrying no traffic, the BPF capture filter excluded the traffic, or
  the capture was stopped before traffic flowed.
- **Diagnostic command:** `tcpdump -r <file>.pcap | wc -l`
- **Expected healthy output:** a nonzero count on the order of the number of
  transactions injected (each transaction produces request, ACK, and response
  frames).
- **Safe correction:** confirm the capture interface (see symptom 11), confirm the
  injector ran (`make run-native` or `make run-protected`), and confirm the
  capture filter admits the traffic — the demo filter is
  `(tcp port 20000) or (ether proto 0x88c1)`. Re-run the capture and injection.
- **When to stop and ask for authorization:** these are read-only and re-run
  actions. Stop and ask only if diagnosing the emptiness would need relay control
  traffic or physical changes.

#### 11. PCAP captured on wrong interface

- **Symptom:** the capture is empty or missing the normalized traffic even though
  the demo ran; frames appear on a different interface than expected.
- **Likely cause:** the capture was taken on the relay-facing NIC during a MODE
  replay run (which flows on the dp9-facing data NIC), or on the data NIC during a
  MODE live run (which flows on the relay-facing NIC holding `192.168.10.1`).
- **Diagnostic command:** `ssh decps@10.10.54.19 'ip -o link show; ip -o -4 addr show'`
- **Expected healthy output:** the data-plane NIC `enp59s0f0np0` (dp9-facing) is
  UP for MODE replay; the interface holding `192.168.10.1` is UP for MODE live.
- **Safe correction:** for MODE replay capture on Vision's data NIC
  (`enp59s0f0np0`); for MODE live capture on the auto-detected relay-facing
  interface. Re-run `make capture` with the correct `--host`/`--iface`/`--mode`;
  the capture script auto-selects the right interface per mode by default.
- **When to stop and ask for authorization:** read-only and re-run only. No
  escalation needed unless it points to a missing relay address (see symptom 3).

#### 12. DNP3 not decoded by Wireshark

- **Symptom:** frames on TCP port 20000 are visible but Wireshark shows them as
  plain TCP, not DNP3; `dnp3.al.func` filters match nothing.
- **Likely cause:** the DNP3 dissector is not enabled or is not mapped to port
  20000, or the frames were captured truncated (snaplen too small) so the DNP3
  layer is cut off.
- **Diagnostic command:** `tshark -r <file>.pcap -d tcp.port==20000,dnp3 -Y 'dnp3.al.func==129' | head`
- **Expected healthy output:** one or more DNP3 application-layer response frames
  (`dnp3.al.func == 129`); READ requests appear as `dnp3.al.func == 1`.
- **Safe correction:** decode as DNP3 with `-d tcp.port==20000,dnp3` (as above),
  and ensure captures use full frames — the demo capture already uses `-s 0`. If
  frames are truncated, re-capture with full snaplen.
- **When to stop and ask for authorization:** read-only. No escalation needed;
  this is an analysis-side setting.

---

## Mechanism and runtime behavior

#### 13. Pure ACK misclassified

- **Symptom:** the classifier treats a bare transport ACK as a DNP3 request or
  response (or the reverse), so the deadline arms on the wrong frame or fails to
  arm; CLRT measurements look wrong.
- **Likely cause:** a pure ACK (`tcp.len == 0`) was matched as data, or a
  data-bearing frame was mistaken for a pure ACK, in the capture or the analysis.
- **Diagnostic command:** `tshark -r <file>.pcap -Y 'tcp.port==20000 && tcp.len==0 && tcp.flags.ack==1' | wc -l`
- **Expected healthy output:** a count consistent with one transport ACK per
  transaction; those pure-ACK frames carry no DNP3 application layer, and DNP3
  responses (`dnp3.al.func == 129`) are separate, data-bearing frames.
- **Safe correction:** verify ACK-versus-data classification in the capture using
  the filters above (a pure ACK has `tcp.len == 0`; a DNP3 response has a nonzero
  payload). Re-run `make analyze`, which distinguishes the ACK from the response
  when computing CLRT.
- **When to stop and ask for authorization:** read-only analysis. No escalation
  needed.

#### 14. Response released immediately

- **Symptom:** in a protected run the response egresses at (near) native timing
  instead of at the guard interval G; the protected CLRT does not sit at G.
- **Likely cause:** the queue is not actually being held — most often the
  strict-priority `max_priority` is unset or a stale Q_BLOCK shaper is present
  (symptom 8), the dp8 loopback is down so the reservoir cannot be sustained
  (symptom 9), or G is below the device's native CLRT so there is nothing to hold
  (symptom 17).
- **Diagnostic command:** `make status`
- **Expected healthy output:** during a hold, `deadline_armed=1`,
  `ctr_response_zero_hold` not advancing, and `ctr_release_fail_open` and
  `ctr_block_term_timeout` both `0`.
- **Safe correction:** re-run `make configure-tm` (fixes priority/shaper and
  loopback), confirm G exceeds the native CLRT (use G = 25 ms for the SEL-751),
  then re-run `make run-protected`.
- **When to stop and ask for authorization:** `make configure-tm` and re-running
  the demo are the corrections. Stop and ask before hand-editing TM registers or
  enabling PFC.

#### 15. Response never released

- **Symptom:** in a protected run the response does not egress at all; the
  transaction stays held past the deadline; `deadline_armed` remains `1`.
- **Likely cause:** the blocker reservoir did not drain on the deadline (the
  termination condition was not met), so `Q_BLOCK` stays non-empty and starves
  `Q_RESP` indefinitely. The design fails open on the pass budget to prevent this,
  so a genuinely stuck hold points at a configuration or state fault.
- **Diagnostic command:** `make status`
- **Expected healthy output:** after a completed transaction, `deadline_armed=0`,
  `ctr_release_deadline` advanced by one per released response, and
  `ctr_resp_release` equal to the number of responses.
- **Safe correction:** run `make restore`, which reads final on-chip state, checks
  for a still-armed deadline or a live blocker reservoir, and returns the switch
  to the `queue_microbench` baseline; then re-run the demo from a clean state.
- **When to stop and ask for authorization:** `make restore` is safe and
  idempotent. Stop and ask before any manual register write to force a release, or
  before restarting `bf_switchd` outside the gated scripts. Never drop or hold a
  real SCADA response deliberately.

#### 16. Fail-open triggered unexpectedly

- **Symptom:** `make status` shows `ctr_release_fail_open` or
  `ctr_block_term_timeout` greater than zero after a protected run; the hardened
  verifier fails the trial on the release-cause gate.
- **Likely cause:** the blocker loop could not sustain the reservoir or a token
  exhausted its pass budget before the deadline arrived — the mechanism released
  the response rather than hold it indefinitely. Common roots are dp8 loopback
  down (symptom 9), reservoir depth K below 64, or priority/shaper misconfig
  (symptom 8).
- **Diagnostic command:** `make status`
- **Expected healthy output:** `ctr_release_fail_open 0` and
  `ctr_block_term_timeout 0` on a healthy hold; releases are attributed to the
  deadline (`ctr_release_deadline`), not to fail-open.
- **Safe correction:** re-run `make configure-tm` (priority, shaper, loopback),
  confirm the reservoir depth K is at least 64 (the configured default), then
  re-run `make run-protected` and re-check the counters.
- **When to stop and ask for authorization:** the corrections above are safe.
  Fail-open is the intended safety behavior — never disable it to force a hold.
  Stop and ask before any change aimed at overriding fail-open.

#### 17. Low-G warning

- **Symptom:** a run warns that G is at or below the device's native CLRT, or
  `ctr_response_zero_hold` advances; the G-selection guard flags
  `protection = false` for transactions.
- **Likely cause:** the guard interval G was set below the outstation's native
  CLRT, so the response is already late by the time the deadline passes and the
  mechanism degenerates to pass-through (no real holding occurs).
- **Diagnostic command:** `make analyze PCAP=<native-run>.pcap` to read the native
  CLRT distribution, then compare with your chosen G.
- **Expected healthy output:** the native CLRT p99 is well below G. For the
  SEL-751 the native p99 is about 11.42 ms, so the demo default G = 25 ms sits
  comfortably above it and every transaction is genuinely held.
- **Safe correction:** raise G above the p99 native CLRT of the slowest device in
  the anonymity set with `make configure-tm G_MS=<value>` (25 ms is the validated
  default), then re-run `make run-protected`.
- **When to stop and ask for authorization:** setting G via `make configure-tm` is
  safe. No escalation needed; this is a policy value, not a switch-state or host
  change.

#### 18. Blocker token visible externally

- **Symptom:** a capture on an external interface contains frames with EtherType
  `0x88c1`; the isolation gate in the verifier fails (`tokens_escaped > 0`).
- **Likely cause:** blocker tokens, which are internal-only scheduling packets on
  the dp8 loopback, are leaking out a host-facing port — a serious
  misconfiguration of port steering or the loopback path. Blocker tokens must
  never leave the switch.
- **Diagnostic command:** `tshark -r <file>.pcap -Y 'eth.type==0x88c1' | wc -l`
- **Expected healthy output:** `0` — no `0x88c1` frames on any external interface.
- **Safe correction:** stop injecting, run `make restore` to return the switch to
  its baseline, and re-examine the configuration before running again; do not
  continue a demo that is leaking tokens.
- **When to stop and ask for authorization:** stop and ask Philip. A token leak is
  a safety-relevant fault; do not attempt manual port-steering fixes on the shared
  switch without authorization.

#### 19. Retransmission

- **Symptom:** the capture shows TCP retransmissions or fast retransmissions on
  the DNP3 flow; CLRT measurements are inflated or noisy.
- **Likely cause:** a held response was delayed long enough that the sender's
  retransmission timer fired, a frame was dropped, or the guard interval G is set
  large relative to the transport retransmission timeout.
- **Diagnostic command:** `tshark -r <file>.pcap -Y 'tcp.analysis.retransmission || tcp.analysis.fast_retransmission' | wc -l`
- **Expected healthy output:** `0` retransmissions on a healthy replay run.
- **Safe correction:** confirm G is a sensible value (25 ms for the demo, well
  under any transport RTO), re-run the trial, and check for drops. In MODE replay
  the byte-preserving hold should not induce retransmissions at the demo G.
- **When to stop and ask for authorization:** read-only diagnosis and re-run are
  safe. Stop and ask before changing transport settings on the relay or before any
  action against the physical SEL-751 beyond read-only Class-0 polling.

#### 20. Missing response

- **Symptom:** a request and its transport ACK appear in the capture, but no DNP3
  response frame follows for that transaction; the verifier reports fewer
  responses than transactions.
- **Likely cause:** the response was captured on the wrong interface (symptom 11),
  the response was still held when capture stopped (symptom 15), a frame was
  dropped, or the outstation/replay source did not emit a response for that
  request.
- **Diagnostic command:** `tshark -r <file>.pcap -Y 'dnp3.al.func==129' | wc -l`
- **Expected healthy output:** one DNP3 response (`dnp3.al.func == 129`) per
  transaction — a count equal to the number of transactions injected.
- **Safe correction:** confirm the capture interface and mode (symptom 11), let
  the run complete before stopping capture, and re-run the trial. Compare the
  response count against `ctr_resp_release` from `make status`.
- **When to stop and ask for authorization:** read-only and re-run only. Stop and
  ask before any relay action beyond read-only Class-0 polling to force a response.

---

## Cleanup

#### 21. Cleanup script interrupted

- **Symptom:** `make restore` was interrupted (Ctrl+C, dropped SSH, or a mid-run
  error), leaving uncertainty about whether the switch is back on the baseline and
  whether injectors and captures were stopped.
- **Likely cause:** the restore run did not finish, so it is unclear whether
  `bf_switchd` is bound to `queue_microbench`, whether generators are still
  running, or whether any transaction remains armed.
- **Diagnostic command:** `make restore` (re-run it — it is idempotent and safe to
  run again).
- **Expected healthy output:** the restoration report ends with `RESTORATION:
  PASS`, confirming exactly one `bf_switchd` bound to `queue_microbench`, all three
  hosts reachable, Vision retaining `192.168.10.1`, and no injector/capture or
  armed transaction left behind.
- **Safe correction:** simply re-run `make restore`; it re-stops any leftover
  injectors and captures on Vision and Hulk, re-reads final counters, and
  re-verifies the baseline binding without harm if the lab is already clean.
- **When to stop and ask for authorization:** if `make restore` reports
  `RESTORATION: FAIL` after re-running — for example it cannot bind
  `queue_microbench`, a host stays unreachable, or a transaction stays armed —
  stop and escalate to Philip. Do not manually kill `bf_switchd`, rewrite switch
  state, or force the baseline by hand without authorization.
