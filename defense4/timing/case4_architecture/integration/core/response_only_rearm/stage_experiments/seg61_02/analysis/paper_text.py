"""Caption, method and limitation text for every paper output of paper_evidence.py.

Numbers quoted here were read from the generated _data.csv files of the same build; the
generator's --check mode fails if any input or output changes, so a stale number cannot pass
silently without the hashes moving too.
"""

ARMS_NOTE = ('Arms: No obfuscation (off), Timing (timing_only), Size (size_only), Timing+Size (combined); '
             'the code names in parentheses are the campaign field values.')
SCOPE = ('Campaign eval_m11_09_20261018_02 on candidate m11_09 (physical Tofino-1, OpenDNP3 software '
         'endpoints, fixed 5 ms fixture); 154/154 blocks completed; 98,816 main exchanges.')

TEXT = {
    'fig_motivation': dict(
        caption='The same Class 0 READ poll on two physical IEDs behind the testbed switch. The SEL-751 acknowledges '
                'every request with a separate TCP segment (100/100), so its CLRT exists (median 2.79 ms); the '
                'ION7550 never does (0/100): its delayed-ACK stack lets the response carry the acknowledgment, so '
                'there is no CLRT to measure.',
        method='paper_inputs/motivation: four 25-poll runs per device, 2026-08-03, restored byte-for-byte from git '
               'commit 7c4a5a7 (research/device_ack_mode/evidence/20260803_native; SOURCES.txt lists path and '
               'SHA-256). Values are the per-transaction rows the probe wrote at capture time; '
               'seg61_02/analysis/motivation_crosscheck.py re-extracts them from the pcapng files with scapy and '
               'paper_inputs/motivation/CROSSCHECK.json records that it reproduced the mode of all 200 transactions '
               'and the medians to 1 µs.',
        limitations='READ polls only, one unit of each model, read-only probing; no SELECT or OPERATE was sent to '
                    'the ION7550. These captures predate NOMAD and motivate it; they are not part of the '
                    'evaluation campaign.'),
    'fig_clrt_four_arm': dict(
        caption='Master-visible CLRT of all four arms at D = 10 ms, J = 2.4 ms. (a) Full range on 0.25 ms bins, '
                'log ordinate: No obfuscation and Size sit at the native 5.3 ms, Timing and Timing+Size at the '
                'configured D. (b) The timed arms within 0.1 ms of D on 5 µs bins.',
        method='All 16 rounds of the condition (training and test), every exchange of the arm, from release/rows.csv '
               'clrt_ms (host-observed, ACK to response, Vision capture). Percent of the arm total per bin; values '
               'beyond 22 ms fall in the last bin. ' + ARMS_NOTE,
        limitations='Host-observed timestamps at microsecond capture resolution; the capture clock is declared, '
                    'not calibrated. One condition shown; the others are in fig_precision_tail. ' + SCOPE),
    'fig_precision_tail': dict(
        caption='Complementary CDF of |CLRT − D| for the timed arms, all eight conditions pooled, per operation. '
                'Medians are 10–16 µs; 99th percentiles 58–86 µs; between 0.14% and 0.46% of exchanges exceed '
                '100 µs and the worst reaches 1.93 ms (SELECT, Timing+Size).',
        method='results/precision_residuals.csv, test rounds 9–16, precision-applicable rows only; absolute error '
               'floored at 1 µs for the log axis. Dashed line: the 100 µs reporting criterion.',
        limitations='Pooling hides a small operation-dependent offset at D = 10 ms (fig_precision_bias). '
                    'Precision is reported, not gated (Philip, 2026-10-18). The ~1 ms tail is the inherited '
                    'host-observed single-exchange delay localized downstream of the switch egress parser on m9d; '
                    'it is not re-measured on m11_09. ' + SCOPE),
    'fig_precision_bias': dict(
        caption='Signed median CLRT − D of the timed arms per condition and operation. At D = 5, 15 and 20 ms '
                'the three operations sit within 3 µs of each other (about 0, +7 and +11 µs). At D = 10 ms, in all '
                'five J conditions, READ and SELECT arrive 20–29 µs early while OPERATE stays within 5 µs of D.',
        method='results/precision_residuals.csv (residual_ms = CLRT − D), test rounds 9–16, medians per arm, '
               'condition and operation; interquartile ranges in the data file.',
        limitations='The cause of the D = 10 ms offset is not established; it is the measured difference the '
                    'adaptive attacker exploits there (OPERATE recall 0.51 at D = 10 ms, J = 2.4 ms). ' + SCOPE),
    'fig_replacement': dict(
        caption='NOMAD replaces timing rather than shifting it. (a) CLRT per operation at D = 10 ms, J = 2.4 ms: '
                'a constant shift of No obfuscation onto the Timing+Size median keeps OPERATE about 60 µs below '
                'READ and SELECT, while measured Timing+Size brings all three within 25 µs. (b) Variance of CLRT '
                'in K = 32 held-out windows: the timed arms are about 3× lower than the untimed arms at the median.',
        method='(a) release/rows.csv, all rounds of D10_J2p4; the counterfactual adds one constant (pooled '
               'Timing+Size median minus pooled No obfuscation median) to every No obfuscation CLRT. '
               '(b) results/oracle_windows.csv, test split, K = 32, all conditions; boxes are quartiles, whiskers '
               '1.5 IQR, fliers omitted; variances floored at 1e-7 ms² for the log axis.',
        limitations='Software endpoints have tight native CLRT (sample SD 0.06–0.11 ms per operation at this '
                    'condition), so the native spread is small. The difference that remains under Timing+Size '
                    '(OPERATE about 25 µs from READ/SELECT) occurs at D = 10 ms only (fig_precision_bias) and is '
                    'the source of the adaptive residual in fig_residual_sources. Windows are oracle-assisted '
                    '(operation-grouped). ' + SCOPE),
    'fig_operate_hold': dict(
        caption='The OPERATE hold J acts before delivery to the outstation and does not reach the master. '
                '(a) Measured hold on the outstation side follows the configured J (2.52–20.12 ms medians). '
                '(b) Master-visible request-to-response time of OPERATE stays at 41.1 ms for every J under the '
                'timed arms and at 5.4 ms without timing.',
        method='release/rows.csv, OPERATE exchanges of the five D = 10 ms conditions, all rounds; (a) realized_j_ms, '
               '(b) rt_ms medians. Points are offset horizontally by arm for visibility.',
        limitations='realized_j_ms is measured from the paired captures, not from switch timestamps. No obfuscation '
                    'and Size coincide. Physical-relay OPERATE was not run; endpoints are software. ' + SCOPE),
    'fig_attackers': dict(
        caption='Balanced accuracy of the Random-Forest attacker for three operations (chance 1/3, dashed). Fixed: '
                'trained on No obfuscation rounds 1–8 and applied unchanged; adaptive: retrained on each arm. '
                'Under Timing+Size the fixed attacker is at chance in every condition; the adaptive joint attacker '
                'keeps 0.36–0.46.',
        method='results/attack_summary.csv, test rounds 9–16 per condition. Feature sets: CLRT; ACK + CLRT; '
               'response size; joint (ACK, CLRT, response size). Settings: 200 trees, min_samples_leaf 5, '
               'balanced class weights, seed 0. ' + ARMS_NOTE,
        limitations='With joint or size features the fixed attacker also falls to chance on Size, where a retrained '
                    'attacker recovers 0.58–0.65, so part of the fixed drop is distribution shift (on CLRT alone the '
                    'fixed attacker keeps 0.41–0.47 on Size); the adaptive panels are the conservative '
                    'measure. Transaction-class results for the evaluated attacker; not device identification. '
                    + SCOPE),
    'fig_confusion': dict(
        caption='Confusion matrices of the joint attacker at D = 10 ms, J = 2.4 ms (row-normalized). The fixed '
                'attacker labels every Timing+Size exchange READ; the adaptive attacker cannot separate READ from '
                'SELECT and recognizes OPERATE in 51% of cases.',
        method='Counts from the confusion field of results/attack_summary.csv (rows true, columns predicted, in the '
               'order READ, SELECT, OPERATE of publication_analysis.CLASSES), test rounds 9–16.',
        limitations='One condition. ' + SCOPE),
    'fig_residual_sources': dict(
        caption='Where the remaining information sits (post hoc, adaptive attacker, locked splits). (a) Three-way '
                'accuracy under Timing+Size by the fields an observer on the master link uses: the native request '
                'alone gives 0.667 (it separates READ from select-before-operate), the defended response alone '
                '0.35–0.47, and both together 0.69–0.80. (b) READ versus SELECT is at chance once response size is '
                'normalized (0.48–0.55) and perfectly separable without it; the READ preceding-gap task gives '
                '0.52–0.64 without timing and 0.46–0.57 with it.',
        method='tables/posthoc_attacks.csv: per condition and arm, Random Forest with the campaign settings trained '
               'on rounds 1–8 and tested on rounds 9–16 of the same arm. Field groups: request (request size and '
               "the master's transmitted request packet count), response (ACK, CLRT, request-to-response, response "
               'size, delivered response packet count), and both. The gap task labels each READ by whether its '
               'preceding same-session request gap exceeds the training median. The dashed line in (a) is the '
               'pre-registered metadata diagnostic.',
        limitations='Post hoc: these estimators were not pre-registered and do not replace the primary statistic. '
                    'Point estimates; per-block ranges are in the table. Every packet count is constant in this '
                    'campaign (1 request, 2 response packets), so counts carry no information. Requests are native '
                    'by design, so the request-side 0.667 is outside what NOMAD normalizes. ' + SCOPE),
    'fig_dj_curves': dict(
        caption='Reduction in balanced accuracy, No obfuscation minus Timing+Size, along D (J = 2.4 ms) and J '
                '(D = 10 ms), with conditional 95% paired-block bootstrap intervals. Fixed joint: 0.61–0.64; '
                'adaptive joint: 0.50–0.61; adaptive metadata diagnostic: 0.15–0.27.',
        method='results/paired_reductions.csv: 10,000 resamples of the 8 matched test blocks, seed 20260828. The '
               'D = 10 ms, J = 2.4 ms fixed joint point is the pre-registered primary statistic, 0.617 '
               '[0.593, 0.635].',
        limitations='Secondary intervals are pointwise, with no near-chance guarantee; the resamples do not add '
                    'experiments beyond the 8 test blocks. ' + SCOPE),
    'fig_windows': dict(
        caption='Windowed multinomial Naive Bayes on CLRT (oracle-assisted, operation-grouped windows). (a) Balanced '
                'accuracy per condition against window size K; under Timing+Size the fixed attacker is at chance '
                'and the adaptive one varies widely. (b) Held-out windows per condition and arm fall from 192 to '
                '24 as K grows; at K = 64 the median window spans 2.8 s untimed and about 10 s timed.',
        method='results/attack_summary.csv (feature nb) and results/oracle_windows.csv, test split. 199 regular '
               'bins on [0, H) plus overflow, H = max(1 µs, 1.05 × maximum training CLRT); non-overlapping windows '
               'within connection, session and split.',
        limitations='Oracle-assisted windows group exchanges by true operation, which a passive observer cannot '
                    'do without labels; at K = 64 each estimate rests on 24 windows. ' + SCOPE),
    'fig_envelope': dict(
        caption='Response availability on the outstation side, request to native response, against the frozen '
                'envelope (dashed): pilot maximum L = 5.60 ms; da / pb / readiness / cap = 31 / 56 / 61 / 66 ms. '
                'No main-campaign exchange became available after da; the latest was 26.45 ms (OPERATE including '
                'J = 20 ms).',
        method='release/rows.csv response_availability_ns, all 16 rounds; envelope from '
               'release/audit/common_envelope.json (common across conditions, frozen before feasibility).',
        limitations='The guards are experimental margins, not proven worst-case bounds; cap is not a demonstrated '
                    'hard deadline. Main-campaign availability exceeded the pilot maximum L (up to 8.0 ms without '
                    'J) but stayed below da. ' + SCOPE),
    'fig_latency': dict(
        caption='Master-visible request-to-response time per condition: median (marker) to maximum (line). Under '
                'the timed arms it is about da + D (36.1–51.1 ms medians, maxima 37.2–52.3 ms); every exchange stays '
                'below the 201 ms minimum observed TCP retransmission timeout and the 500 ms endpoint timeout.',
        method='release/rows.csv rt_ms, all 16 rounds; timer values from release/audit/common_envelope.json.',
        limitations='Software endpoints; timers of physical devices may differ. ' + SCOPE),
    'table_resources': dict(
        caption='Data-plane resources of m11_09 on Tofino-1 (p4c 9.13.2): stages and allocated SRAM/TCAM blocks, '
                'stateful ALUs and exact-match crossbar bytes per program, and average per-stage utilization per pipe.',
        method='paper_inputs/compiler: copies of ctl_timing_01/evidence/m11_09/compiler_table.csv (compile_switch_9132 '
               'rows) and of compile_switch_9132/out/p{0,1}/logs/mau.resources.log (Average row), each log checked '
               'against the hash in the compile manifest.',
        limitations='p0 hosts N (ingress) and E (egress); its average spans both. Compiler allocation, not runtime '
                    'occupancy.'),
    'table_sizes': dict(
        caption='Observed TCP payload sizes. Requests stay native (READ 20 B, SELECT/OPERATE 35 B); responses are '
                '49 B (READ) and 37 B (SELECT/OPERATE) without size normalization and 61 B for every operation '
                'with it.',
        method='release/rows.csv request_len and resp_len (master-facing capture), all 16 rounds.',
        limitations='Response-size claims cover the evaluated READ and SBO formats only. ' + SCOPE),
    'table_outcomes': dict(
        caption='Delivery and switch outcomes per arm: no retransmission, repeated attempt, master timeout, '
                'incomplete exchange or capture drop; every timed exchange committed its ACK and released its '
                'response without fallback, and every OPERATE was released once.',
        method='results/counter_utility.csv (per-trial switch counter deltas, summed) and release/rows.csv. '
               'OUT_HELD_REWAIT counts recirculation re-waits; OUT_TOKEN_STALE/STALE_BLOCKER count blocker tokens '
               'retired after their packet left (protocol/hw_vepa/README.md).',
        limitations='Counters are switch-side aggregates per trial without per-exchange attribution. ' + SCOPE),
    'table_conformance': dict(
        caption='Protocol conformance of every main trial (128 per arm). Every response passed the IEEE 1815 '
                'standards checker with its transport and application sequence intact, no DNP3 CRC failed, no '
                'packet was unmatched, duplicated or reordered, every READ matched its seeded values and every '
                'SELECT authorized its OPERATE. With size normalization all responses are 61 bytes and, in each '
                'size-normalized arm, 16,384 select-before-operate responses travel as multi-segment transport.',
        method='paper_inputs/conformance_trials.csv, written by seg61_02/analysis/paper_conformance.py from each '
               "trial's standards.json, standards_verdict.json, wire.json, master.json and outstation.json, each "
               'checked against eval_m11_09_20261018_02_EVIDENCE.sha256. app_seq_echoed counts responses whose '
               'wire, native and request application sequence numbers agree.',
        limitations='Conformance is judged by the campaign checker against OpenDNP3 software endpoints; a physical '
                    'relay was not exercised. ' + SCOPE),
    'table_timeline': dict(
        caption='Median instants, relative to the request, that place the release-timeline schematic at '
                'D = 10 ms, J = 10 ms: native ACK and response times (No obfuscation), the measured OPERATE hold, '
                'and the released ACK and response times (Timing+Size), with the frozen envelope.',
        method='release/rows.csv medians per arm and operation at D10_J10, all 16 rounds; native times of OPERATE '
               'are measured after delivery, so the schematic adds the hold J before them.',
        limitations='Medians of host-observed values place a schematic; they are not a single transaction. '
                    + SCOPE),
    'table_point_map': dict(
        caption='DNP3 analog input points of an SEL protective relay: each measurement, from phase currents to '
                'power factor and four auxiliary inputs, is carried as a numeric index 0–20 whose meaning only the '
                "device's configuration supplies.",
        method='paper_inputs/sel_point_map/sel_analog_point_map.csv, as supplied by Philip on 2026-10-19 '
               '(SOURCE.md); the one combined row for indices 17–20 is expanded to one row per index.',
        limitations='Relay model, firmware and the settings export it comes from are not yet recorded; the map '
                    'illustrates index mapping for the Background and is not an evaluation input.'),
    'table_crawler': dict(
        caption='DNP3 security support documented by five IED vendors for 55 devices, by vendor and by '
                'generation: 48 document none, 4 encryption with authentication, 2 authentication only and 1 an '
                'unconfirmed option; every legacy and mature device documents none.',
        method='paper_inputs/crawler/ied_security_devices.tsv (crawler output supplied 2026-10-19, SOURCE.md); '
               'counts recomputed from the 55 rows reproduce the three supplied summary tables exactly. '
               'dnp3_native_security excludes devices whose only security is outside DNP3 (CIP Security with '
               'DNP3 through an add-on module) and the unconfirmed option.',
        limitations='Vendor documentation, not deployment: a supported feature may be unused. Two of the four '
                    'encrypted entries secure EtherNet/IP, not DNP3; three rows are not DNP3 outstations by '
                    'their own field. The draft text cites different totals (99 / 32 / 6 / 1). Crawler code and '
                    'run identity are not in the repository.'),
    'table_primary': dict(
        caption='Primary statistic and every balanced accuracy at D = 10 ms, J = 2.4 ms.',
        method='results/paired_reductions.csv (primary row) and results/attack_summary.csv.',
        limitations=SCOPE),
    'posthoc_attacks': dict(
        caption='Post hoc adaptive attacker results by field group and the two binary tasks, per condition and arm.',
        method='seg61_02/analysis/paper_attacks.py on release/rows.csv with the campaign loader and Random-Forest '
               'settings; trained on rounds 1–8, tested on rounds 9–16 of the same arm; block_min/block_max are '
               'per-test-block balanced accuracies.',
        limitations='Not pre-registered; reported as supporting analysis only. ' + SCOPE),
}

__all__ = ['TEXT']
