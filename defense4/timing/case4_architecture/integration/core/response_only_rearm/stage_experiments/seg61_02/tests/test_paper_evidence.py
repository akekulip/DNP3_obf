"""Contract tests for the paper evidence generators (paper_evidence, paper_attacks, paper_conformance).

Run in the campaign's pinned environment, e.g.
  uv run --offline --no-project --python 3.13.12 --with-requirements \
      evidence/evaluation_campaigns/eval_m11_09_20261018_02/results/requirements.lock.txt \
      python -m unittest tests/test_paper_evidence.py
(pytest is not in the pinned lock; the gated suite also collects this file with pytest.)
The last test rebuilds the committed paper outputs and compares hashes; it is skipped only when the
uncommitted release/rows.csv is absent from this machine.
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'analysis'))
import paper_attacks  # noqa: E402
import paper_conformance  # noqa: E402
import paper_evidence  # noqa: E402
import publication_analysis  # noqa: E402
from paper_text import TEXT  # noqa: E402

CAMPAIGN = HERE / 'evidence/evaluation_campaigns/eval_m11_09_20261018_02'
PAPER = HERE / 'evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper'


class Text(unittest.TestCase):
    def test_every_output_has_caption_method_limitations(self):
        source = (HERE / 'analysis/paper_evidence.py').read_text()
        names = set(re.findall(r"w\.(?:figure|table)\([^']*'([a-z_]+)'", source)) | {'posthoc_attacks'}
        self.assertTrue(names)
        self.assertEqual(names, set(TEXT))
        for name in names:
            for key in ('caption', 'method', 'limitations'):
                self.assertGreater(len(TEXT[name][key].strip()), 20, (name, key))
                self.assertNotIn('TODO', TEXT[name][key])

    def test_arm_labels_cover_campaign_arms(self):
        self.assertEqual(paper_evidence.ARMS, publication_analysis.ARMS)
        self.assertEqual(set(paper_evidence.LABEL), set(publication_analysis.ARMS))


class Confusion(unittest.TestCase):
    def test_labels_follow_the_campaign_class_order(self):
        # confusion_scores indexes rows and columns by CLASSES; an alphabetical order mislabels them
        self.assertEqual(paper_evidence.OPS_SORTED, publication_analysis.CLASSES)
        cm = publication_analysis.confusion_scores(
            [dict(truth='OPERATE', prediction='OPERATE'), dict(truth='READ', prediction='SELECT'),
             dict(truth='SELECT', prediction='SELECT')])['confusion']
        self.assertEqual(cm[paper_evidence.OPS_SORTED.index('OPERATE')][paper_evidence.OPS_SORTED.index('OPERATE')], 1)
        self.assertEqual(cm[paper_evidence.OPS_SORTED.index('READ')][paper_evidence.OPS_SORTED.index('SELECT')], 1)


class Attacks(unittest.TestCase):
    def test_feature_groups_follow_capture_direction(self):
        # "out" = what the endpoints transmit, "in" = what the switch delivers; a master-link observer sees
        # the master's transmitted request (out_request_*) and the delivered response (in_response_*).
        for name, fields in paper_attacks.GROUPS.items():
            self.assertTrue(set(fields) <= publication_analysis.ALLOWED_FEATURES, name)
            self.assertFalse({f for f in fields if f.startswith('in_request') or f.startswith('out_response')}, name)
        self.assertEqual(set(paper_attacks.GROUPS['master_link']),
                         set(paper_attacks.GROUPS['request']) | set(paper_attacks.GROUPS['response']))

    def test_preceding_gap_is_within_session(self):
        rows = [dict(example_id='a', session_id='s1', request_timestamp_ns='1000000'),
                dict(example_id='b', session_id='s1', request_timestamp_ns='4000000'),
                dict(example_id='c', session_id='s2', request_timestamp_ns='4500000')]
        self.assertEqual(paper_attacks._preceding_gaps(rows), {'b': 3.0})

    def test_rejects_rows_whose_split_disagrees_with_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'rows.csv'
            path.write_text('example_id,condition_id,arm,operation,split,round,session_id\n'
                            'x,D10_J2p4,off,READ,training,9,s\ny,D10_J2p4,off,READ,testing,10,s\n')
            with self.assertRaises(ValueError):
                paper_attacks.run(tmp)


class Inputs(unittest.TestCase):
    def test_build_refuses_rows_not_in_release_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / 'a/b/c/d/campaign'
            (campaign / 'release').mkdir(parents=True)
            (campaign / 'release/rows.csv').write_text('arm\noff\n')
            (campaign / 'release/release_manifest.json').write_text(json.dumps({'artifacts': {'rows.csv': '0' * 64}}))
            with self.assertRaises(SystemExit):
                paper_evidence.build(campaign, Path(tmp) / 'out')

    def test_conformance_refuses_unlisted_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / 'camp'
            trial = campaign / 'blocks/camp_r09_D10_J2p4/separate_ack/off/t0'
            trial.mkdir(parents=True)
            for f in paper_conformance.FILES:
                (trial / f).write_text('{}')
            (Path(tmp) / 'camp_EVIDENCE.sha256').write_text('')
            with self.assertRaises(SystemExit):
                paper_conformance.main(campaign, Path(tmp) / 'out.csv')


def _data(name, sub='figures'):
    import csv
    path = PAPER / sub / (name + ('_data.csv' if sub == 'figures' else '.csv'))
    with open(path, newline='') as handle:
        return list(csv.DictReader(handle))


def _span(values, fmt):
    return '%s–%s' % (fmt % min(values), fmt % max(values))


@unittest.skipUnless(PAPER.exists(), 'paper outputs not built')
class CaptionNumbers(unittest.TestCase):
    """Every number a caption states is recomputed from the generated data, so a stale caption fails."""

    def assertQuoted(self, name, text):
        self.assertIn(text, TEXT[name]['caption'], name)

    def test_precision(self):
        d = _data('fig_precision_tail')
        self.assertQuoted('fig_precision_tail', _span([float(r['abs_error_us']) for r in d if r['quantile'] == '0.5'], '%d') + ' µs')
        self.assertQuoted('fig_precision_tail', _span([round(float(r['abs_error_us'])) for r in d if r['quantile'] == '0.99'], '%d') + ' µs')
        out = [100 * (1 - int(r['within_100us']) / int(r['n'])) for r in d if r['quantile'] == '1.0']
        self.assertQuoted('fig_precision_tail', 'between %.2f%% and %.2f%%' % (min(out), max(out)))
        self.assertQuoted('fig_precision_tail', '%.2f ms' % (max(float(r['abs_error_us']) for r in d) / 1000))

    def test_precision_bias(self):
        d = _data('fig_precision_bias')
        d10 = [r for r in d if r['condition_id'].startswith('D10_')]
        early = [-float(r['median_signed_residual_us']) for r in d10 if r['operation'] in ('READ', 'SELECT')]
        self.assertQuoted('fig_precision_bias', _span(early, '%d') + ' µs early')
        self.assertLessEqual(max(abs(float(r['median_signed_residual_us'])) for r in d10 if r['operation'] == 'OPERATE'), 5)

    def test_residual_sources(self):
        d = [r for r in _data('fig_residual_sources') if r['task'] == 'operation']
        get = lambda g: [float(r['balanced_accuracy']) for r in d if r['feature_group'] == g]
        self.assertEqual({round(x, 3) for x in get('request')}, {0.667})
        self.assertQuoted('fig_residual_sources', _span(get('response'), '%.2f'))
        self.assertQuoted('fig_residual_sources', _span(get('master_link'), '%.2f'))

    def test_dj_curves(self):
        d = _data('fig_dj_curves')
        get = lambda a, f: [float(r['reduction']) for r in d if r['attacker'] == a and r['feature'] == f]
        for att, feature in (('fixed', 'joint'), ('adaptive', 'joint'), ('adaptive', 'metadata_diagnostic')):
            self.assertQuoted('fig_dj_curves', _span(get(att, feature), '%.2f'))

    def test_latency_and_operate(self):
        d = [r for r in _data('fig_latency') if r['arm'] in ('timing_only', 'combined')]
        self.assertQuoted('fig_latency', _span([float(r['median_ms']) for r in d], '%.1f') + ' ms medians')
        self.assertQuoted('fig_latency', 'maxima ' + _span([float(r['max_ms']) for r in d], '%.1f'))
        d = [r for r in _data('fig_operate_hold') if r['arm'] in ('timing_only', 'combined')]
        self.assertQuoted('fig_operate_hold', _span([float(r['realized_j_median_ms']) for r in d], '%.2f'))
        self.assertEqual({'%.1f' % float(r['rt_median_ms']) for r in d}, {'41.1'})

    def test_envelope_and_counts(self):
        d = _data('fig_envelope')
        pairs = [r for r in d if r.get('series') == 'all pairs']
        self.assertEqual(len(pairs), 12)
        self.assertEqual(sum(int(r['above_da']) for r in pairs), 0)
        self.assertQuoted('fig_envelope', '%.2f ms' % max(float(r['max_ms']) for r in pairs))
        conf = _data('table_conformance', 'tables')
        per_arm = {int(r['multi_segment']) for r in conf if r['wire_response_bytes'] == '61'}
        self.assertEqual(len(per_arm), 1)
        self.assertQuoted('table_conformance', '{:,}'.format(per_arm.pop()))


def _pinned_environment():
    import platform
    import matplotlib
    import numpy
    import sklearn
    want = json.loads((CAMPAIGN / 'results/environment.json').read_text())
    have = {'matplotlib': matplotlib.__version__, 'numpy': numpy.__version__, 'scikit-learn': sklearn.__version__}
    return platform.python_version() == want['python'] and have == want['packages']


@unittest.skipUnless((CAMPAIGN / 'release/rows.csv').exists() and PAPER.exists(), 'release rows not on this machine')
@unittest.skipUnless(_pinned_environment(), 'byte identity is defined in the pinned environment only')
class Reproduction(unittest.TestCase):
    def test_committed_outputs_rebuild_byte_identically(self):
        done = subprocess.run([sys.executable, str(HERE / 'analysis/paper_evidence.py'), str(CAMPAIGN), str(PAPER),
                               '--check'], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('byte-identical', done.stdout)


if __name__ == '__main__':
    unittest.main()
