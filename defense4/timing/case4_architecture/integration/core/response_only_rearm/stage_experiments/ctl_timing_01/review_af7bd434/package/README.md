# Review reproductions for af7bd434

Pinned repository: https://github.com/akekulip/DNP3_obf
Commit: af7bd434595d51b9644d6e67d5302ad74c6ab642.
Run against an isolated checkout. No hardware commands are included.

```
python3 reset_race_probe.py /absolute/path/to/DNP3
python3 reproduce_remaining_acceptance.py /absolute/path/to/DNP3
```

The first script sweeps READ/SELECT reset interleavings in the existing source interpreter. The second reproduces two acceptance coverage holes using temporary evidence copies. Retained JSON files show the results before and after the patch. Source simulation is not compiled-model or silicon proof.

Apply the four-file acceptance patch from the repository root after inspection:

```
git apply --check /path/to/acceptance_coverage.patch
git apply /path/to/acceptance_coverage.patch
```

Run the affected model-summary and isolation-v3 tests with pytest, then rerun the counterexamples. The isolated audit ran 56 relevant tests successfully; see patched_tests.log. This patch does not fix the P4 reset race or qualify a hardware candidate.

Independent capture verification (Python standard library):

```
python3 verify_diag_pcaps.py /path/to/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns
```

This decoder targets the retained classic-PCAP Ethernet/IPv4/TCP captures, not arbitrary PCAP formats. It correlates host packet pairs with diagnostic register entries, checks observed index reuse, and preserves every timed tail. It does not verify all DNP3 CRCs or establish physical wire-transmit timestamps. Captures remain in the source repository; they are not duplicated here.
