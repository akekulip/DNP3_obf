from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import focused_report as report


def test_metrics_distinguish_total_added_and_late():
    rows=[]
    for rep in (0,1):
        for op in report.OPS:
            for arm in ('native','obfuscated'):
                for i in range(2):
                    rows.append(dict(replicate=rep,txn_class=op,arm=arm,
                        rt_ms=3 if arm=='native' else 6+i,
                        ack_ms=5,clrt_ms=1+i,ack_minus_selected_ms=.1,
                        response_minus_selected_ms=.1 if i==0 else 1.1,
                        selected_da_ms=5,selected_gap_ms=1,selected_r_ms=6))
    metrics=report.metrics(rows)
    for s in metrics.values():
        assert s['rt_ms']['median_ms']==6.5
        assert s['added_pooled_median_ms']==3.5
        assert s['paired_block_median_difference_ms']['median_ms']==3.5
        assert s['late_over_1ms']==dict(count=2,total=4,fraction=.5)


def test_distribution_rejects_unusable_data():
    for values in ([],[1,float('nan')],[1,float('inf')]):
        with pytest.raises(ValueError):report.distribution(values)
