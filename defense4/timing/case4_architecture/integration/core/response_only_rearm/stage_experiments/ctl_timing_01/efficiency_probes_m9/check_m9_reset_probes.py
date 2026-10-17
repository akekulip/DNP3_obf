"""Run m9 reset regressions against each audit probe, in the source interpreter only."""
import json
from pathlib import Path
import sys

repo, generated = map(lambda x: Path(x).resolve(), sys.argv[1:])
ct = repo / 'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/ctl_timing_01'
sys.path.insert(0, str(ct / 'tests'))
import test_reset_then_syn as test

results = []
for name in ('n_bank_diffs', 't_single_child', 'n_zero_unused_timestamp'):
    test.M9 = generated / (name + '.p4')
    test.SOURCES = {'m9': test.M9}
    count = 0
    for laps in (1, 2, 3, 4, 6, 10):
        test.test_reset_reaches_the_outstation_once_and_the_tuple_reconnects('m9', laps)
        count += 1
    test.test_a_reset_with_no_following_syn_still_closes_once('m9'); count += 1
    test.test_m9_reset_wait_is_bounded_by_the_retry_budget(); count += 1
    test.test_m9_one_lap_contention_actually_takes_the_wait_path(); count += 1
    for laps in (5, 12, 31):
        test.test_m9_a_cell_busy_longer_than_a_lifecycle_then_free_still_closes(laps)
        count += 1
    test.test_m9_a_duplicate_rst_during_the_wait_resets_once(); count += 1
    test.test_m9_open_limitation_an_owner_changing_event_still_loses_the_reset(); count += 1
    results.append(dict(probe=name, passed=count, preserved_known_limitation=True))
print(json.dumps(dict(instrument='source interpreter only', results=results), indent=2))
