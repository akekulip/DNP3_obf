"""Epoch/owner routing must match the prior branch for every command byte."""
import itertools
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def current_dispatch():
    source = (ROOT/'p4/response_only.p4').read_text()
    body = re.search(r'\btable continuation_t\{.*?const entries=\{(.*?)\}',source,re.S).group(1)
    entries = [(tuple(None if k=='_' else int(k.split('w')[-1],0) for k in key.split(',')), action, argument)
               for key,action,argument in re.findall(r'\(([^()]+)\):(\w+)\(([^()]*)\);',body)]
    def choose(values):
        for key, action, argument in entries:
            if all(k is None or k == v for k,v in zip(key,values)):
                return action, argument
        return 'deny',''
    return choose

def test_single_terminal_table_preserves_prior_branch():
    choose = current_dispatch()
    for epoch, kind, stage, op, owner in itertools.product((0,1,0xffffffff),range(256),range(4),range(2),(0,1,0xffffffff)):
        if epoch:
            expected = 'abort_work'
        elif kind in (8,25,24,10,12) or (kind == 17 and stage == 2):
            expected = 'abort_work' if owner else 'next_stage'
        else:
            expected = 'carry_current' if op == 1 and owner == 0 else 'abort_work'
        for phase in (1,2):
            assert choose((phase,epoch,kind,stage,op,owner,0,0)) == (expected,'')

def test_completion_and_invalid_phase_keep_prior_action_and_arguments():
    choose = current_dispatch()
    rows = json.loads((ROOT/'tests/fixtures/p4/n_continuation_tables.json').read_text())['read_terminal']
    frozen = [(tuple(None if k=='_' else int(k.split('w')[-1],0) for k in key), action, argument)
              for key,action,argument in rows]
    for kind,owner,epoch,direction,packet in itertools.product(range(256),(0,1,0xffffffff),(0,1,0xffffffff),range(4),(0,3,5,6,7,9,11)):
        expected=('terminal_abort','')
        values=(kind,owner,epoch,direction,packet)
        for key,action,argument in frozen:
            if all(k is None or k==v for k,v in zip(key,values)):
                expected=(action,argument)
                break
        assert choose((3,epoch,kind,2,1,owner,direction,packet)) == expected
    for phase in (0,4,5,0xffffffff):
        for kind in range(256):
            assert choose((phase,0,kind,2,1,0,1,6)) == ('deny','')

def test_event_wire_format_is_unchanged():
    source = (ROOT/'p4/response_only.p4').read_text()
    assert 'header n_event_h{bit<8> phase;bit<8> code;bit<16> reserved;}' in source
    assert 'hdr.event.event' not in source
    assert 'hdr.event.phase=hdr.event.phase+8w1;' in source
    assert 'hdr.event.code=8w255;' in source
