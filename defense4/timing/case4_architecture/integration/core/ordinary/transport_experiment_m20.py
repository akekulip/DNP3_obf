#!/usr/bin/env python3
"""Research-only scratch generator for stage_fit_m20 (role==0 dispatch flattening).

Does NOT edit transport.py. Builds on transport_experiment_m19.generate_m19()
(fix A: separate m.profile0 field; fix B: construct_t-independent CRC hashing)
and adds Fix C, the same class of fix m16 already validated for role==4
(stage_fit_m16_02, "role-dispatch flattening", 13 -> 9 stages): role==0 is
currently the trailing bare `else` of a FOUR-WAY chained
`if(role==3){}else if(role==4){}else if(role==1||2){}else{ROLE0}` dispatch.
`table_dependency_graph.log` from stage_fit_m19_01 shows role==0's own
admission table (`profile_0`) control-depends (`CONTROL_COND_FALSE`) on
`cond-33` (the role==1||2 test), which in turn depends on `cond-31`/`cond-30`
-- conditions that sit INSIDE role==4's own geometry branch body, not on the
simple `m.role` test itself. This is exactly the "tables after an if/else
join are placed after the whole branch" pattern N's stage_fit_analysis_01
documented and fixed by flattening joins (change 4): the compiler's gateway
merging threads role==0's entry through the FULL preceding branches' bodies
because of the "else" chaining, even though `m.role` is a parser-time value
with no real dependency on role==4's internal geometry computation.

Fix C makes role==0 an INDEPENDENT top-level `if(m.role==8w0){...}` sibling
instead of the final `else`, closing the role==3/role==4/role==1||2 chain on
its own. This is a pure control-flow equivalence transform: the parser sets
`m.role` to exactly one of {0,1,2,3,4} (confirmed in m.p4's parser states),
so "whatever falls through the other three branches is role==0" and
"m.role==8w0 explicitly" are the same set of packets. No table, key, action,
or admission predicate changes; only which CONTROL_COND edges the compiler
must thread through do.
"""
import hashlib
import json
from pathlib import Path

import transport
import transport_experiment_m19 as m19

HERE = Path(__file__).resolve().parent
replace = transport.replace


def generate_m20():
    roles = m19.generate_m19()
    m = roles['m3.p4']

    old = ('   }else{deny();}\n'
           '  }else{profile.apply();\n'
           '  if(m.enabled==1w1&&m.profile0==1w1){')
    new = ('   }else{deny();}\n'
           '  }\n'
           '  if(m.role==8w0){profile.apply();\n'
           '  if(m.enabled==1w1&&m.profile0==1w1){')
    m = replace(m, old, new)

    roles['m3.p4'] = m
    return roles


def main():
    out = HERE / 'transport_candidate_next20'
    out.mkdir(exist_ok=True)
    roles = generate_m20()
    for name, text in roles.items():
        if name == 'm3.p4':
            (out / name).write_text(text)
    inputs = {
        'generated': {'m3.p4': hashlib.sha256((out / 'm3.p4').read_bytes()).hexdigest()},
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_generator_sha256': hashlib.sha256((HERE / 'transport.py').read_bytes()).hexdigest(),
        'full_target': False,
        'note': 'scratch research generator (stage_fit_m20); transport.py NOT modified',
    }
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    print(json.dumps(inputs, indent=2))


if __name__ == '__main__':
    main()
