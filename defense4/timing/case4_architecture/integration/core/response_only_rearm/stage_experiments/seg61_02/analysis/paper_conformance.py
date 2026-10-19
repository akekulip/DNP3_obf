"""Per-trial protocol-conformance record of the main campaign, from the retained block evidence.

The raw block evidence (about 11 GB) stays on Gambit's disk and is not committed; its file hashes
are committed in eval_m11_09_20261018_02_EVIDENCE.sha256. This script reads only the per-trial
verdict files, checks each against that hash list, and writes one committed CSV row per trial, so
paper_evidence.py can build the conformance table from committed data.

    python paper_conformance.py CAMPAIGN_DIR OUT_CSV
"""
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

FILES = ('standards.json', 'standards_verdict.json', 'wire.json', 'master.json', 'outstation.json',
         'profile_verdict.json')
MAIN = re.compile(r'_r(\d\d)_(D\d\d_J[0-9p]+)$')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def trial_row(trial, block, rnd, condition, arm):
    d = {f: json.loads((trial / f).read_text()) for f in FILES}
    obs = d['standards.json']['observed']
    checker = obs['checker_result']
    verdicts = checker['verdicts']
    wire, master, outst = d['wire.json'], d['master.json'], d['outstation.json']
    return dict(
        block_id=block, round=rnd, condition_id=condition, arm=arm, trial=trial.name,
        responses=checker['responses'], verdicts=len(verdicts),
        verdicts_ok=sum(bool(v.get('ok')) for v in verdicts),
        transport_ok=sum(bool(v.get('transport_ok')) for v in verdicts),
        app_seq_echoed=sum(v.get('wire_app_seq') == v.get('native_app_seq') == v.get('request_app_seq') for v in verdicts),
        multi_segment=sum(int(v.get('segments', 1)) > 1 for v in verdicts),
        wire_lengths='|'.join(sorted({str(v.get('wire_len')) for v in verdicts})),
        checker_conformant=bool(checker.get('conformant')), checker_failures=len(checker.get('failures', [])),
        select_authorizes_operate=obs.get('select_authorizes_operate'), operate_success=obs.get('operate_success'),
        aggregate_verdict=obs.get('aggregate_verdict'), standards_ok=d['standards_verdict.json'].get('ok'),
        wire_sent=wire['sent'], wire_returned=wire['returned'], wire_matched=wire['matched'],
        unmatched=len(wire['unmatched_sent']) + len(wire['unmatched_returned']),
        duplicates=len(wire['duplicate_returned']), reordered=len(wire['reordered_returned_indices']),
        dnp3_crc_bad=len(wire['sent_integrity']['dnp3_crc_bad']) + len(wire['returned_integrity']['dnp3_crc_bad']),
        master_success=master.get('success'), reads_requested=master.get('reads_requested'),
        reads_completed=master.get('reads_completed'), reads_match_seed=master.get('all_reads_match_seed'),
        sbo_cycles=master.get('sbo_cycles'), outstation_select=outst.get('select_real'),
        outstation_operate=outst.get('operate_real'), source_sha256=hashlib.sha256(
            ''.join(sha256(trial / f) for f in FILES).encode()).hexdigest())


def main(campaign, out_csv):
    campaign = Path(campaign)
    listed = {}
    for line in (campaign.parent / (campaign.name + '_EVIDENCE.sha256')).read_text().splitlines():
        digest, path = line.split(None, 1)
        listed[path.strip().lstrip('*')] = digest
    rows = []
    for block in sorted((campaign / 'blocks').iterdir()):
        m = MAIN.search(block.name)
        if not m:
            continue
        for trial in sorted((block / 'separate_ack').glob('*/*')):
            for f in FILES:
                rel = str((trial / f).relative_to(campaign.parent))
                rel_alt = str((trial / f).relative_to(campaign))
                want = listed.get(rel) or listed.get(rel_alt)
                if want is None or want != sha256(trial / f):
                    raise SystemExit('unlisted or changed evidence file: ' + rel)
            rows.append(trial_row(trial, block.name, int(m.group(1)), m.group(2), trial.parent.name))
    if len(rows) != 512:
        raise SystemExit('expected 512 main trials (128 blocks x 4 arms), found %d' % len(rows))
    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)
    print('%d trials written' % len(rows))


if __name__ == '__main__':
    main(*sys.argv[1:3])
