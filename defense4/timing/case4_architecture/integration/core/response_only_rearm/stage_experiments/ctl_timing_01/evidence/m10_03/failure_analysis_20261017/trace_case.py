"""Ordered key decisions for every model-log record containing a hex pattern (one case's connection)."""
import json, re, subprocess, sys
log, pattern, out = sys.argv[1], sys.argv[2], sys.argv[3]
subprocess.run([sys.executable, 'trace_model_log.py', log, out, pattern], capture_output=True)
recs = sorted(json.load(open(out)), key=lambda r: r['wall'])
KEY = re.compile(r'reset|close|first_close|abort|snapshot|retry|owner_cas|claim|publish|release|rewait|fallback|flush|admit|hold_|stale|epoch_drop|old_epoch|resp_go|ack_go|commit|export|live_')
for r in recs:
    f = r['frame'].replace(' ', '')
    acts = [re.sub(r'^\d+ ', '', e).replace('Execute Action: ', '').replace('Execute Default Action: ', 'D:')
            for e in r['events'] if 'Execute' in e]
    acts = [a for a in acts if KEY.search(a) and 'epoch' not in a.split('.')[-1][:5]]
    print(r['wall'][6:], r['kind'], r['head'][11:45].strip(), len(f) // 2, f[24:32] if r['kind'] == 'I' else '', '|', ' '.join(a.split('.')[-1] for a in acts)[:300])
