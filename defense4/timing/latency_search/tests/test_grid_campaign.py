from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import grid_campaign as g


def test_grid_is_400_distinct_adjacent_pairs():
    s=g.rc.build_schedule(random_plan_paths=[Path(n+'.json') for n in g.names()],
        repeats=100,seed=g.SEED,off_every=1,count=100)
    p=g.pairing(s)
    assert len(s)==800 and sum(b.count*3 for b in s)==240000
    assert len(p)==400
    assert len({x['native'] for x in p})==400
    for rep in range(100):
        assert {x['policy'] for x in p if x['round']==rep}==set(g.names())
    assert len({tuple(x['policy'] for x in p if x['round']==rep) for rep in range(100)})>1


def test_only_da_center_changes():
    plans=[g.rc.policy_planner.build_plan(center_da_ms=d,center_gap_ms=1.,amplitude_ms=.5,mode='joint') for d in g.DELAYS]
    for d,p in zip(g.DELAYS,plans):
        assert len(p.entries)==16
        assert p.j_set_ms==(.25,.5,1.)
        for old,new in zip(plans[0].entries,p.entries):
            assert new.low==old.low and new.high==old.high
            assert new.da_offset_ms==old.da_offset_ms and new.gap_offset_ms==old.gap_offset_ms
            assert new.op_r_ticks<30000000
            # Fixed-width quantization permits at most one 256 ns step discrepancy.
            assert abs((new.d_ticks-old.d_ticks)-(d-5)*1000000)<=256
            assert abs(new.gap_ms-old.gap_ms)<=.000256


def test_wrong_pair_order_rejected():
    s=g.rc.build_schedule(random_plan_paths=[Path(g.names()[0]+'.json')],repeats=1,seed=0,off_every=1)
    with pytest.raises(ValueError):g.pairing(s[::-1])


def test_preflight_rejects_live_random_entries_or_down_port():
    ports=[dict(key={'$DEV_PORT':{'value':p}},data={'$PORT_UP':True,'$PORT_ENABLE':True,
        '$LOOPBACK_MODE':'BF_LPBK_MAC_NEAR' if p in (8,10) else 'BF_LPBK_NONE'}) for p in (8,9,10,64)]
    doc=dict(random_entries=[],ports=ports)
    g.verify_snapshot(doc)
    with pytest.raises(ValueError):g.verify_snapshot(dict(doc,random_entries=[{}]))
    ports[0]['data']['$PORT_UP']=False
    with pytest.raises(ValueError):g.verify_snapshot(doc)
