#!/usr/bin/env python3
"""Re-run the per-attempt candidate61 profile check over every retained candidate61 standards artifact.

  python3 profile_recheck.py [-o profile_recheck.json]

For each hw_campaigns/**/standards.json whose identity.profile is candidate61, the capture directory beside it is
checked with read_reencode_01/profile_check.py against that artifact's own expected lengths and master port.
Retained raw data is read only. The output lists every trial with its verdict, attempts and retransmissions.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGNS = HERE.parent / 'evidence/hw_campaigns'
sys.path.insert(0, str(HERE.parents[1] / 'read_reencode_01'))
import profile_check  # noqa: E402


def recheck(root=CAMPAIGNS):
    rows = []
    for path in sorted(Path(root).glob('**/standards.json')):
        artifact = json.load(open(path))
        if (artifact.get('identity') or {}).get('profile') != 'candidate61':
            continue
        checker = (artifact.get('observed') or {}).get('checker_result') or {}
        result = profile_check.check(path.parent, checker.get('master_port'), artifact['expected']['lengths'],
                                     checker.get('outstation_port', 20000))
        rows.append({'trial': str(path.parent.relative_to(root)), 'conformant': result['conformant'],
                     'responses': result.get('responses'), 'attempts': result.get('attempts'),
                     'retransmissions': result.get('retransmissions'), 'failures': result['failures'][:4]})
    return {'checker': 'read_reencode_01/profile_check.py', 'profile_check_sha256': profile_check._sha(
        (HERE.parents[1] / 'read_reencode_01/profile_check.py').read_bytes()),
            'trials': len(rows), 'conformant': sum(r['conformant'] for r in rows),
            'with_retransmissions': sum(1 for r in rows if r['retransmissions']), 'rows': rows}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output')
    a = ap.parse_args(argv)
    out = recheck()
    if a.output:
        Path(a.output).write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({k: out[k] for k in ('trials', 'conformant', 'with_retransmissions')}))
    for r in out['rows']:
        if not r['conformant']:
            print('NOT CONFORMANT', r['trial'], r['failures'][:1])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
