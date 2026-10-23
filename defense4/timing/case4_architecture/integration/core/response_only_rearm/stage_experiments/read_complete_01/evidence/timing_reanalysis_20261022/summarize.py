"""Markdown tables from results.json (transit_silence.py): transit (us) by prior receive-silence bucket.
  python3 summarize.py results.json > tables.md"""
import json
import sys

BUCKETS = ('<0.5ms', '0.5-2ms', '>=2ms')
R = json.load(open(sys.argv[1]))


def cell(c):
    return '%d / %s / %s / %s' % (c['n'], int(c['median']), int(c['p90']), int(c['p99'])) if c and c.get('n') else '0'


for definition, title in (('silence_tx_us', 'CORRECTED silence (last receive -> this packet TRANSMIT)'),
                          ('silence_rx_us', 'OLD silence (last receive -> this packet ARRIVAL; circular)')):
    print('\n## %s\n\ncells: n / median / p90 / p99 transit, us (nearest rank)\n' % title)
    print('| block | arm | measure | class | ' + ' | '.join(BUCKETS) + ' |')
    print('|---|---|---|---|' + '---|' * len(BUCKETS))
    for block in sorted(R):
        for arm in ('off', 'timing_only', 'size_only', 'combined'):
            if arm not in R[block]:
                continue
            tab = R[block][arm]['tables'][definition]
            for measure in ('resp_first', 'resp_complete', 'req_first', 'O2M_ack'):
                for cls in sorted(tab.get(measure, {})):
                    if measure == 'O2M_ack' or cls != 'ALL' or definition == 'silence_tx_us':
                        row = tab[measure][cls]
                        print('| %s | %s | %s | %s | %s |' % (block.replace('rc01_hw_', ''), arm, measure, cls,
                                                            ' | '.join(cell(row.get(b)) for b in BUCKETS)))
print('\n## Matching and capture metadata\n')
print('| block | arm | resolution | out/in records | packet matched | unmatched out (by class) | unmatched in | '
      'exchanges paired |')
print('|---|---|---|---|---|---|---|---|')
for block in sorted(R):
    for arm, v in sorted(R[block].items()):
        m = v['meta']
        print('| %s | %s | %s | %d/%d | %d | %s | %d | %d |' % (
            block.replace('rc01_hw_', ''), arm, ','.join(m['resolution']), m['out_records'], m['in_records'],
            m['packet_matched'], m['packet_unmatched_out'] or 0, m['packet_unmatched_in'], m['exchanges']['paired']))
