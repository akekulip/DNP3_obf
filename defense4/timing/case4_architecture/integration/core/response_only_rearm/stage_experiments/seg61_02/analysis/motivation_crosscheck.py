"""Re-extract the motivation captures from their pcapng files and compare with the probe's rows.

Writes paper_inputs/motivation/CROSSCHECK.json. Needs scapy (the research environment), not the
campaign's pinned one, so paper_evidence.py only reads the committed result.

    python motivation_crosscheck.py MOTIVATION_DIR
"""
import json
import statistics
import sys
from pathlib import Path

from scapy.all import IP, TCP, rdpcap


def extract(pcap, device_ip):
    packets = rdpcap(str(pcap))
    out = []
    requests = [p for p in packets if IP in p and TCP in p and p[IP].dst == device_ip and len(p[TCP].payload) > 0]
    for q in requests:
        t0 = float(q.time)
        after = [p for p in packets if IP in p and TCP in p and p[IP].src == device_ip and float(p.time) >= t0]
        ack = next((p for p in after if len(p[TCP].payload) == 0 and not p[TCP].flags.R
                    and p[TCP].ack >= q[TCP].seq + len(q[TCP].payload)), None)
        resp = next((p for p in after if len(p[TCP].payload) > 0), None)
        separate = ack is not None and resp is not None and float(ack.time) <= float(resp.time)
        out.append(dict(separate=separate, read_to_resp_ms=(float(resp.time) - t0) * 1e3,
                        clrt_ms=(float(resp.time) - float(ack.time)) * 1e3 if separate else None))
    return out


def main(directory):
    d = Path(directory)
    report = {}
    for dev in ('sel751', 'ion7550'):
        rows, pcap = [], []
        for r in (1, 2, 3, 4):
            probe = json.loads((d / ('%s_r%d.json' % (dev, r))).read_text().split(' ', 1)[1])
            rows += probe['rows']
            pcap += extract(d / ('%s_r%d.pcap' % (dev, r)), probe['relay'])
        clrt_p = [x['clrt_ms'] for x in pcap if x['clrt_ms'] is not None]
        clrt_j = [x['clrt_ms'] for x in rows if x.get('clrt_ms') is not None]
        report[dev] = dict(transactions_probe=len(rows), transactions_pcap=len(pcap),
                           separate_probe=sum(x['mode'] == 'SEPARATE' for x in rows),
                           separate_pcap=sum(x['separate'] for x in pcap),
                           clrt_median_probe_ms=statistics.median(clrt_j) if clrt_j else None,
                           clrt_median_pcap_ms=round(statistics.median(clrt_p), 6) if clrt_p else None,
                           read_to_resp_median_probe_ms=statistics.median(x['read_to_resp_ms'] for x in rows),
                           read_to_resp_median_pcap_ms=round(statistics.median(x['read_to_resp_ms'] for x in pcap), 6))
    (d / 'CROSSCHECK.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main(sys.argv[1])
