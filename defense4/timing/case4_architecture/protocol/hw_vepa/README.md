# Software-endpoint runs through the switch (one port, two VEPA namespaces)

Runs a real OpenDNP3 master and outstation (`framework/size/endpoint_gate/SocketGatePad58B.cpp`) on Vision
through the Tofino, with both endpoints behind dev_port 9. First used for the padding evidence in
`../evidence/hw_vepa_padding_01` and `_02`.

| file | where it runs | what it does |
|---|---|---|
| `campaign.py` | workstation | the single four-arm campaign entry point: reads `campaign.json`, binds build and endpoint identity, and orchestrates the hw/ composite installer, the Vision endpoint runner, per-arm snapshots, verification, extraction and restoration (`plan` prints the exact commands, `run --apply` executes them, restore is in a `finally`) |
| `switch_swap.sh`, `launch_composite.sh` | switch | stop the running `bf_switchd` and cold-launch another program (composite or production), failing unless `:50052` is serving with no `device_add` error |
| `run.py` | workstation | one standalone (pure-E) run end to end: slot rows, counters before, endpoints, counters after, copy, wire + clrt check; fails the run on an endpoint/extractor/checksum/extraction error |
| `vision_run.py` | Vision, `sudo python3` | namespace TCP profile (checked), NIC flag, endpoints, direction-split captures with capture-ready confirmation, try/finally cleanup and tcpdump drop stats |
| `switch_slot.py` | switch | clears and installs slot 0 (`vepa` tuple or the rig's `relay` slot) |
| `switch_counters.py` | switch | outcome counter, slot-0 mapper registers, dev 9/64 port counters (read-only) |
| `wire_check.py` | workstation, stdlib | independent pairing by tuple/incarnation/sequence; lengths, DNP3 CRCs, checksums, translation |
| `clrt_check.py` | workstation, stdlib | per-exchange timing by tuple/incarnation/app-sequence association; integer-microsecond intervals |
| `campaign.json` | — | the one config: endpoints, ports/map, build hashes, feature bits, timing/K, fixture, trials, schedule, loss, seeds |
| `PINNING.md`, `requirements.txt` | — | the OpenDNP3 commit and Python/host-tool pins |

```bash
# the whole campaign (reads campaign.json; see its _notes before running)
python3 hw_vepa/campaign.py validate --arms combined   # final selected builds + endpoint identity
python3 hw_vepa/campaign.py validate --all-builds       # explicit historical-build audit
python3 hw_vepa/campaign.py deploy [--dry-run]   # tools into <switch_remote_dir>/aux and vision_run.py, sha256-verified; changes no state
python3 hw_vepa/campaign.py plan [--arms combined]   # the exact commands run would execute; executes none
DEFENSE4_HW_AUTHORIZED=1 python3 hw_vepa/campaign.py run --apply [--arms size_only,combined]   # hardware; gated

# or a single standalone pure-E run
python3 hw_vepa/run.py deploy
python3 hw_vepa/run.py setup          # clean TCP profile in the namespaces, disable-source-pruning on
python3 hw_vepa/run.py run NAME --master-port 54410 --reads 10 --out evidence/<dir>
python3 hw_vepa/run.py restore        # sysctls and NIC flag back, relay slot reinstalled
```

Tests. All run under a plain `python3 -m pytest` (Python 3.8, standard library only; no test needs the research
venv, and `run.py` falls back to the current interpreter when `$RESEARCH_PYTHON` is unset). Two markers
(`tests/conftest.py`) name the tests that need files outside this directory; they skip, never fail, when those are
absent (`HW_VEPA_EVIDENCE_ROOT` overrides the evidence root, default `integration/evidence`):

| marker | needs | tests |
|---|---|---|
| `build_tree` | the compiled build `out/` and compile `manifest.json` that `campaign.json` binds to (`route_ab_01/mirror_fix_01/hw_compile_switch_9132`; all four hashed outputs must exist) | `test_campaign_bindings.py::test_shipped_config_is_fully_bound_with_the_real_pins`, `::test_validate_passes_with_the_real_pins`; `test_deploy.py::test_run_deploys_before_it_observes_the_switch` |
| `evidence_tree` | committed hardware captures (`p2_production_01/p_unshaped` pcaps and snapshots) | `test_checks.py::RealEvidence` |

Everything else builds its own fixtures (synthetic pcaps, a fake process boundary, a throwaway compile manifest) in a
cleaned temporary directory.

```bash
python3 -m pytest hw_vepa/tests -m "not build_tree and not evidence_tree"   # pure-source set (bare checkout)
python3 -m pytest hw_vepa/tests                                             # full set (tree present)
```

`wire_check.py` and `clrt_check.py` no longer need scapy (built-in pcap reader, checksum and DNP3 CRC), so
`python3 -m pytest hw_vepa/tests` runs on a fresh clone with no install step.

Deployed tools. Nothing the campaign needs lives in an ad hoc scratch path on the switch or the workstation: `deploy` (also the first step of `run`) copies every switch tool and `launch_composite.sh` / `switch_swap.sh` into the configured `<switch_remote_dir>/aux`, verifies each one's sha256 there, and every emitted command refers to that directory (a test scans for it). The pre-run port snapshot and per-unit logs live under `<switch_remote_dir>/snap` and the evidence directory. Tests use `TemporaryDirectory` with cleanup and read no scratch fixtures.

Campaign bring-ups. N does not re-arm after a connection and a closed tuple stays in TIME-WAIT for 60 s, so a
second connection on an installed tuple cannot work. `campaign.json` `trial_mode` is therefore either
`per_trial_cold` (default: every trial of every arm is its own cold bring-up -- swap, restore ports, install, T,
snapshot, run, snapshot, teardown -- on a NEW master port from `traffic.master_port_range`, incrementing per
trial, even for arms that share a build) or `one_connection` (one bring-up and one connection per arm carrying
`reads_per_trial x trials_per_arm` READs). After the last bring-up the run restores the state it observed before
starting: the configured production program, a port snapshot taken at the start, the relay slot, Vision, then a
ping.

Build identity. The final arm selection, including scenario/paired overrides, determines the builds validated, bound and deployed. Unused historical builds are checked only by `validate --all-builds`. Each selected build's `hashes` pin `bfrt.json`, `p0/tofino.bin`, `p1/tofino.bin` and `p1/response_only.bfa`,
checked three ways (config, compile `manifest.json`, file on disk) by `validate` and `run`. The `.bfa` is the file the
installer's mirror-defect guard reads, so pinning it ties the checked file to the loaded binaries; every
`bringup_composite.py` command (dry-run and apply) passes `--expect p1/response_only.bfa=<sha256>`.

Deterministic loss. `vision_run.py run ... --drop CLASS[:N]` drops exactly the Nth packet of one class (direction,
IP total length, TCP flags; the table is `loss.py` `CLASSES`, computed from the real wire shapes: READ request 60,
SELECT/OPERATE request 75, native responses 89/77, padded responses 98, pure ACK 40) at the INGRESS of the receiving
namespace (`ip netns exec ... iptables`): M>O classes in `ns_vepa_b`, O>M classes in `ns_vepa_a`, so the frame has
already crossed the switch. Exactness does not rely on polling: occurrence N is N-1 `ACCEPT` rules and one `DROP` rule,
each a burst-1 `-m limit --limit 1/hour` match, so the kernel hands the Nth packet to the DROP rule atomically and no
packet can slip past between a counter read and a delete. The rules are removed in a `finally` and the chain compared
with its prior state; the counters (`DROP` 1 packet of exactly the class's IP length, `ACCEPT`s N-1) are recorded as
`loss` in `result.json` with `exact` true/false. The counters prove the rule fired, not which packet it was: `tcpdump`
taps the NIC before netfilter, so the dropped frame is still in `in.pcap`. Which packet it was is established
afterwards from the captures (see the loss analysis), by position in the class and the retransmission that follows.
`vision_run.py` and `loss.py` are deployed together and both hash-verified.

Reconnect scenario. `campaign.py run --scenario reconnect --reconnect-policy characterize|protected` runs
c1 on the installed port, c2 on a new port with no switch rows, and c3 on the same installed tuple after
TIME-WAIT clears. Each connection has its own endpoint JSON and captures; the switch is not reset between
connections. The compatibility default `characterize` requires c1/c2 and retains c3 failures. `protected`
also requires c3 to pass the selected arm's endpoint, extractor, integrity, padding and applicable READ
precision checks. Config `scenarios.reconnect.policy` can select the policy; the CLI overrides it.

Every required connection must have successful extractors, readable evidence, all 23 correct seed points
per READ, exactly one real SELECT and OPERATE, zero decoys, and clean returned CRC/checksums. Lengths are
checked per function: native READ49, SELECT/OPERATE37; padded responses58. The effective policy and
per-connection failures are retained even when c3 is characterized.

Report. `python3 hw_vepa/campaign.py report --run-dir <evidence_dir>/<run_id>` (or `python3 hw_vepa/report.py RUN_DIR`)
prints one table per fixture/arm/preset, one column per trial, from `campaign_run.json` and the trial files: loop
packets and bytes (sum over ports 48/180/181/182 of the `$FramesTransmittedAll` / `$OctetsTransmittedTotal` deltas,
plus per port), original re-waits, blocker laps (only if the build's snapshot has diag counters), READ CLRT
median/IQR/p95/p99 with population and sample SD, request->ACK and request->response median/p95, the error against
the intended gap (`timing_params_ns.gap`), completion/retransmission counts, padding coverage and growth, READ
triggers, generated packets, stale tokens and the received-vs-good octet gap. All deltas are after minus before, as in
`evidence/mirror_fix_silicon_01`. For a paired run it adds A-B per condition.

Loss and reconnect trials. `campaign.py plan|run --loss PRESET` runs one trial per entry of `loss.presets.PRESET` (each
`{class, n}` is one `vision_run.py --drop class:n`, each its own cold bring-up); `--scenario reconnect` runs the
three-connection scenario. A loss trial is gated differently from a clean one: the iptables counters must be exact and
the rules removed; the dropped packet must be found in the capture (`loss.identify`, by class and occurrence); a dropped
data packet must be retransmitted and recovery (the retransmitted response, or the next outstation frame after a
retransmitted request) must come within `loss.max_recovery_s` (default 5 s); the master must complete every READ with
the seed values; exactly one real SELECT and one real OPERATE callback and no decoy; no CRC or checksum error and no
unmatched returned frame; and master-visible growth must equal 9 B per READ response plus 21 B per control response
actually delivered (0 with padding off). Retransmissions are allowed and counted. A failed recovery is a recorded
result: the trial is marked failed, the next trial still runs, the exit status is nonzero. The stale-token bound,
loop-port gaps and snapshot evidence still apply. `report` prints a loss table (packet, completion, recovery,
retransmissions, exactly-once, growth, completion delta against a clean trial of the same arm in the run) and a
reconnect table (per connection: role/port, connect, completion, response lengths, padded, retransmitted, timeout).
In the reconnect trial c1 must complete with the arm's response lengths and c2 (a port with no switch rows) must
complete natively; the effective reconnect policy determines whether c3 is required to pass.

Trial gate (expectations). Each trial is judged by `checks.py` from its own evidence (before/after snapshot deltas,
`master.json`, `outstation.json`, `wire.json`, `timing.json`); any violation fails the trial and the campaign. The table
lives in `campaign.json` under `expectations` (this is its only copy; README restates it):

| scope | expectation |
|---|---|
| every trial | master success; every READ completes with all 23 seed values and matches the seed; exactly one real SELECT and OPERATE when `traffic.run_sbo=true` (default), zero real callbacks and zero SBO exchanges when false; zero decoy; clean returned DNP3 CRC and IP/TCP checksum |
| padding on | every READ, SELECT and OPERATE response is 58 B on the master side; master-visible growth over native (READ 49, SELECT/OPERATE 37) is positive and recorded |
| padding off | responses native (READ 49 B, SELECT/OPERATE 37 B); growth 0 |
| T on | For R complete READs and P piggyback responses: `ACK_COMMIT=R-P`, `ACK_FALLBACK=0`, `RESP_RELEASE=R-P`, `RESP_FALLBACK=P`; `OP_RELEASE=1` with SBO, otherwise0. READ generator triggers remainR and generated tokens2kR, including piggyback |
| T off | ACK commit/fallback, response release/fallback and OPERATE release deltas are0 |
| fixture `separate_ack` | READ piggyback fraction in [0, 0.05] (the request is ACKed separately) |
| fixture `piggyback` | READ piggyback fraction in [0.95, 1] |
| builds flagged `mirror_fix` (T on) | READ generator trigger delta equals the READs; generated READ packets equal 2k per trigger (`service.k`, the installer `--k`); OPERATE trigger delta equals the SBOs run; `OUT_TOKEN_STALE` delta is at most the build's `max_token_stale` (default 0; the observed value is recorded in every trial). Builds before the compiler-mirror fix selected T's deparser mirror entry 0, which gave several triggers per READ and thousands of stale tokens, so the counts only hold, and are only checked, on the flagged build (`mirror_fix_01`) |
| builds flagged `mirror_fix` (T off) | READ and OPERATE generator trigger and packet deltas are 0 (as the T-off silicon evidence shows) |
| loop ports 48 / 180 / 181 / 182 | delta of (`$OctetsReceived` - `$OctetsReceivedinGoodFrames`) is 0, or the build's `allowed_loop_octet_gap[role]` (default 0; the pre-RESET-fix build shows 80 on `t_in`). A larger gap fails with the byte count |

READ precision qualification applies to T1 separate-ACK clean blocks, including c1/c3 in protected
reconnect mode. Use `timing_params_ns.gap` as the target; there is no campaign `--t-gap` override.
At least20 READ rows must be complete, non-piggyback and single-attempt. `clrt_check.stats` computes the
p99 of the absolute CLRT error, which must be at most100us. Reports retain the denominator, mutually
exclusive exclusions (incomplete, piggyback, multiple attempts, missing CLRT), signed/absolute distributions
and worst tails. Loss, piggyback and T0 trials do not qualify this timing claim. An explicit
`evaluation={"purpose":"stale_source_characterization","read_precision":false}` profile can run short
attribution probes; their failures are retained and subsequent probes continue, with campaign exit1 if
any trial failed. One eligible READ never establishes timing precision.

On builds marked `diagnostic:true`, every snapshot must report indices19..24. Their sum replaces
production `OUT_TOKEN_STALE` index6 for the strict bound (default0); a missing value fails. The diagnostic
index6 is zero by design and cannot establish zero stale. Counters19/20 distinguish OPERATE blocker
mismatch after/before its deadline;21/22 are ACK/response blockers,23 OPERATE tokens,24 READ tokens.
Snapshot errors remain visible and return nonzero. Attribution of19 requires phase, actual OP release
and callback evidence; the runner keeps the ordinary strict0 failure.

Missing or unreadable evidence is itself a failure. The observed values (outcome deltas, piggyback fraction, growth,
loop-port gaps) are written into `campaign_run.json` per trial. When anything fails, the collection phase still
fetches the snapshots, endpoint outputs, pcaps, switch log, manifest and teardown output before the restore, and
`campaign_run.json` `collections` lists each fetch with ok/error.

Endpoint controls. `traffic.read_pause_ms` (default25), `run_sbo` (defaulttrue) and `close_grace_ms`
(default0) become explicit Vision flags and `CASE4_*` environment values. Millisecond controls are bounded
0..5000; explicit values must match the master's effective JSON. Process lifetimes include these delays.
`hosts.vision_run_dir` determines identity checks, traffic and collection. Vision resolves binary,lib and
runs beside its deployed script. New controls profiles use the separate
`/home/decps/pad58b_rearm_controls_20261012` fixture with separate binary/lib/source pins; the old fixture
remains pinned. Run records retain effective policy, stale bound, exact config-file hash, canonical effective
config hash, runner hashes, compile source identity and endpoint identity.

Profiles under `config/` are Case4 engineering evidence, separate from frozen paper `campaign_v2`:

| profiles | workload |
|---|---|
| `stale_diag_sbo_14892.json`, `stale_diag_sbo_3723_grace250.json`, `stale_diag_read_only_3723.json` | one READ,3ms fixture, source attribution; strict0 and explicit precision exemption |
| `precision_5ms_gap800us_14892.json`, `precision_5ms_gap950us_14892.json`, `precision_10ms_gap950us_14892.json`, `precision_25ms_gap800us_14892.json` | three cold trials of50 READs each; combined arm,14892PPS; last profile readiness35ms |
| `fourarm_separate_ack_14892.json` | all four arms,3x20 READs per arm |
| `fourarm_piggyback_14892.json` | all four arms,1x20 READs per arm; precision not qualified |

Precision/four-arm profiles preserve the immutable `mirror_fix_01` baseline artifact hashes. The hardware
owner creates a separately bound config copy for any lifecycle candidate. Readiness is30ms except35ms in
the25ms profile; cap40ms is accepted but unused in the current T implementation and is not a deadline.
The950us target exercises a non-aligned gap. Neither profile proves relay RTO assumptions or a transport
accuracy bound beyond the host capture clock.

Start phase and spacing. `vision_run.py run` takes `--gap-ms` (spacing between READs) and `--start-delay-ms N
--start-seed S`: the master connects after a delay drawn uniformly in 0..N ms from a generator seeded with S, so the
same seed replays the same start phase; the applied delay is written to `result.json`. `campaign.json` sets the
defaults (`fixture.delay_ms`, `traffic.gap_ms`, `traffic.start_delay_ms`); every trial records its
`conditions` (delay_ms, gap_ms, start_delay_ms, start_seed = `seeds.rng_seed` + trial number).

Paired blocks. `campaign.py plan|run --paired NAME` runs a `paired_blocks` entry: for each condition (and repeat)
presets A and B each get their own cold bring-up under IDENTICAL conditions (fixture delay, gap, start delay and
seed), the order alternating between consecutive pairs (A,B then B,A ...). `campaign_run.json` `pairs` lists each
pair's condition, order, labels and verdict; each trial records its `preset`.

Facts the runner depends on:
- **Source pruning.** Vision's i40e NIC drops reflected frames whose source MAC is its own unless
  `disable-source-pruning` is on. Changing the flag resets the NIC's PF; the link returns in a few seconds.
  Original value: `off`.
- **One master port per run.** The switch matches the exact 4-tuple, and a tuple whose master just closed stays
  in TIME-WAIT for 60 s. `--master-port` pins the port through `ns_vepa_a`'s `ip_local_port_range` and installs
  the matching rows, so take the next port for the next run. The runner still waits if the port is busy.
- **Clean TCP profile.** The mapper arms only on a handshake without timestamps, SACK or window scaling. These
  are set inside the two namespaces only. Originals: 1/1/1 and port range `32768 60999`.
- **Fresh run directories.** A label is never reused. Capture files that already exist in a sticky directory
  under another owner are silently not rewritten on this kernel.
- **While the `vepa` slot is installed, the relay path is down:** dev 9 forwards to dev 9, so 192.168.10.1 cannot
  reach the SEL-751. `restore` puts the relay slot back.
- On Vision, `decps` has passwordless sudo only for python3, tcpdump and iptables, which is why everything
  privileged goes through `sudo python3`.
- Never stop the switch daemon with `pkill -f` over ssh: the pattern matches the remote shell itself.

Protected reconnect additionally gates the readable before/after switch snapshots for both installed
connections: `2 * reads` READ triggers, `2k * 2 * reads` READ tokens, two SBO triggers/releases
when SBO is enabled, strict stale-source bounds and loop integrity. The unknown-port c2 completes
natively and contributes no installed T counts. Complete and piggyback READ totals from c1/c3
set the aggregate commit/release/fallback expectations. A failed c2 stops traffic before c3;
c3 is retained as not comparable. Each connection records its existing source-port wait's elapsed
seconds, polls and free/busy/probe-error result; no second TIME-WAIT barrier is added.

Endpoint defaults are sent explicitly as `--read-pause-ms 25 --run-sbo 1 --close-grace-ms 0` and
retained in effective traffic settings. Configurations omitting these controls stay compatible
with the frozen binary's older JSON. Explicit control profiles, or JSON exposing any control
field, require all three effective fields to match.

An explicit `evaluation={"purpose":"timing_precision_characterization","read_precision":true}`
profile retains strict failed trial verdicts and continues subsequent clean blocks only when every
failure is the READ p99 absolute-error threshold, at least20 READs remain eligible, and the precision
gate was enabled. Campaign exit remains1 if any block fails; the original failure strings, precision
distributions, and per-trial continuation decision/reason are retained alongside effective evaluation
purpose and config/source identities. Missing or insufficient timing evidence, application/integrity
failures, stale bounds, and infrastructure failures stop the campaign. This purpose cannot disable the
precision gate. It supports bounded timing characterization without changing qualification profiles.
