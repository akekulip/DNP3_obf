"""Shaper quantization probe (control-plane only, no traffic): for one HOLD queue (dev 182 qid 6, pipe 1) write
sched_shaping PPS at a range of requested rates and read the achieved max_rate back; then restore the original."""
import sys, json
sys.path.insert(0, '/home/decps/Philip_repo/dnp3-defense4/response_only_diag_01/src/integration/core/response_only/hw')
import switch as S
sw = S.Switch('response_only', 140)
pg, q, cfg = sw.resolve_queue(182, 6, 1)
t = sw.table('tf1.tm.queue.sched_shaping'); tg = sw.target(1)
key = [('pg_id', pg, None), ('pg_queue', q, None)]
orig = sw.get('tf1.tm.queue.sched_shaping', 1, key)
print('original', json.dumps(orig, default=str))
rows = []
for req in (100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000, 15000, 20000, 30000, 50000, 100000, 200000):
    t.entry_mod(tg, [sw.key(t, key)], [sw.data(t, [('unit', 'PPS'), ('max_rate', req), ('max_burst_size', 1)])])
    got = sw.get('tf1.tm.queue.sched_shaping', 1, key)
    rows.append((req, got.get('max_rate'), got.get('unit'), got.get('max_burst_size')))
    print('req %7d -> achieved %9s  (%+.1f%%)  %s burst %s' % (req, got.get('max_rate'), 100.0 * (got.get('max_rate', 0) - req) / req, got.get('unit'), got.get('max_burst_size')))
# restore
t.entry_mod(tg, [sw.key(t, key)], [sw.data(t, [('unit', orig['unit']), ('max_rate', orig['max_rate']), ('max_burst_size', orig['max_burst_size'])])])
print('restored', json.dumps(sw.get('tf1.tm.queue.sched_shaping', 1, key), default=str))
sw.close()
