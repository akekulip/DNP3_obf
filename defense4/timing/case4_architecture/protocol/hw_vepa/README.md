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
python3 hw_vepa/campaign.py validate      # structure + build/endpoint identity (nonzero while anything is unbound)
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
| `build_tree` | the compiled build `out/` and compile `manifest.json` that `campaign.json` binds to (`route_ab_01/sbo_admission_01/hw_compile_switch_9132`) | `test_campaign_bindings.py::test_shipped_config_is_fully_bound_with_the_real_pins`, `::test_validate_passes_with_the_real_pins`; `test_deploy.py::test_run_deploys_before_it_observes_the_switch` |
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

Report. `python3 hw_vepa/campaign.py report --run-dir <evidence_dir>/<run_id>` (or `python3 hw_vepa/report.py RUN_DIR`)
prints one table per fixture/arm/preset, one column per trial, from `campaign_run.json` and the trial files: loop
packets and bytes (sum over ports 48/180/181/182 of the `$FramesTransmittedAll` / `$OctetsTransmittedTotal` deltas,
plus per port), original re-waits, blocker laps (only if the build's snapshot has diag counters), READ CLRT
median/IQR/p95/p99 with population and sample SD, request->ACK and request->response median/p95, the error against
the intended gap (`timing_params_ns.gap`), completion/retransmission counts, padding coverage and growth, READ
triggers, generated packets, stale tokens and the received-vs-good octet gap. All deltas are after minus before, as in
`evidence/mirror_fix_silicon_01`. For a paired run it adds A-B per condition.

Trial gate (expectations). Each trial is judged by `checks.py` from its own evidence (before/after snapshot deltas,
`master.json`, `outstation.json`, `wire.json`, `timing.json`); any violation fails the trial and the campaign. The table
lives in `campaign.json` under `expectations` (this is its only copy; README restates it):

| scope | expectation |
|---|---|
| every trial | master success; every READ completes with all 23 seed values and matches the seed; exactly one real SELECT and one real OPERATE; zero decoy; no DNP3 CRC or IP/TCP checksum errors on returned frames |
| padding on | every READ, SELECT and OPERATE response is 58 B on the master side; master-visible growth over native (READ 49, SELECT/OPERATE 37) is positive and recorded |
| padding off | responses native (READ 49 B, SELECT/OPERATE 37 B); growth 0 |
| T on | `OUT_ACK_COMMIT` and `OUT_RESP_RELEASE` deltas equal the READ count; `OUT_OP_RELEASE` delta is 1 when the SBO ran; `OUT_ACK_FALLBACK` and `OUT_RESP_FALLBACK` deltas are 0 on `separate_ack` (the piggyback T-on counts are assumed, not measured) |
| T off | `OUT_ACK_COMMIT`, `OUT_RESP_RELEASE`, `OUT_OP_RELEASE` deltas are 0 |
| fixture `separate_ack` | READ piggyback fraction in [0, 0.05] (the request is ACKed separately) |
| fixture `piggyback` | READ piggyback fraction in [0.95, 1] |
| builds flagged `mirror_fix` (T on) | READ generator trigger delta equals the READs; generated READ packets equal 2k per trigger (`service.k`, the installer `--k`); OPERATE trigger delta equals the SBOs run; `OUT_TOKEN_STALE` delta is 0. Builds before the compiler-mirror fix selected T's deparser mirror entry 0, which gave several triggers per READ and thousands of stale tokens, so the counts only hold, and are only checked, on the flagged build (`mirror_fix_01`) |
| builds flagged `mirror_fix` (T off) | READ and OPERATE generator trigger and packet deltas are 0 (as the T-off silicon evidence shows) |
| loop ports 48 / 180 / 181 / 182 | delta of (`$OctetsReceived` - `$OctetsReceivedinGoodFrames`) is 0, or the build's `allowed_loop_octet_gap[role]` (default 0; the pre-RESET-fix build shows 80 on `t_in`). A larger gap fails with the byte count |

Missing or unreadable evidence is itself a failure. The observed values (outcome deltas, piggyback fraction, growth,
loop-port gaps) are written into `campaign_run.json` per trial. When anything fails, the collection phase still
fetches the snapshots, endpoint outputs, pcaps, switch log, manifest and teardown output before the restore, and
`campaign_run.json` `collections` lists each fetch with ok/error.

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
