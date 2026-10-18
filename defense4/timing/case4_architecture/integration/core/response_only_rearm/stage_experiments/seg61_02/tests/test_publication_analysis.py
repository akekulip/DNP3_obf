"""Offline contract tests; fixtures are never publication hardware evidence."""
import importlib.util
import csv
import json
from pathlib import Path
import shutil
import sys
from collections import defaultdict
import tempfile
import unittest

import numpy as np

MODULE = Path(__file__).resolve().parents[1] / 'analysis/publication_analysis.py'


class PublicationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('publication_analysis', MODULE)
        cls.pa = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pa)
        sys.path.insert(0,str(MODULE.parent))
        import reproduce_evaluation
        cls.repro = reproduce_evaluation

    def row(self, i, **changes):
        row = dict(example_id=str(i), block_id='b1', condition_id='D10_J2p4',
                   arm='off', operation='READ', round=1, split='training',
                   connection_id='c', session_id='s', sequence=i,
                   observed_at_ms=i, ack_ms=1., clrt_ms=2., rt_ms=3., resp_len=40)
        row.update(changes)
        return row

    def test_feature_whitelist_rejects_identity_and_plaintext(self):
        for field in ('operation', 'sequence', 'condition_id', 'request_function', 'session_id'):
            with self.assertRaises(ValueError):
                self.pa.feature_matrix([self.row(0)], [field])

    def test_missing_metrics_are_excluded_and_counted_without_imputation(self):
        matrix, used, missing = self.pa.feature_matrix(
            [self.row(0), self.row(1, clrt_ms=None)], ['clrt_ms'])
        self.assertEqual(matrix.tolist(), [[2.]])
        self.assertEqual(used, [0])
        self.assertEqual(missing, {'clrt_ms': 1})

    def test_negative_clrt_is_rejected_and_counted_without_hiding_attempt(self):
        matrix,used,missing=self.pa.feature_matrix([self.row(0,clrt_ms=-1.)],['clrt_ms'])
        self.assertEqual(used,[])
        self.assertEqual(missing,{'clrt_ms_invalid':1})
        windows,accounting=self.pa.make_windows([self.row(0,clrt_ms=-1.)],8)
        self.assertEqual(windows,[])
        self.assertEqual(accounting['rejected'],1)

    def test_histogram_exact_high_edge_is_overflow(self):
        counts = self.pa.histogram([0., .5, 1., 100.], 1.)
        self.assertEqual(int(counts[0]), 1)
        self.assertEqual(int(counts[99]), 1)
        self.assertEqual(int(counts[199]), 2)
        self.assertEqual(int(counts.sum()), 4)

    def test_precision_tails_preserve_nearest_rank_p99_and_missing_costs(self):
        rows=[self.row(i,clrt_ms=10.+i/1000.,arm='combined') for i in range(100)]
        costs=self.repro.cost_table(rows)
        missing=next(r for r in costs if r['condition_id']=='D10_J2p4' and r['arm']=='combined'
                     and r['metric']=='internal_bytes' and r['operation']=='all')
        self.assertIsNone(missing['mean'])
        _,summary=self.repro.precision_tables(rows)
        record=next(r for r in summary if r['condition_id']=='D10_J2p4' and r['arm']=='combined' and r['operation']=='READ')
        self.assertAlmostEqual(record['abs_error_p99_ms'],.098)
        self.assertAlmostEqual(record['abs_error_max_ms'],.099)
        self.assertEqual(record['within_100us'],100)

    def test_windows_do_not_cross_session_split_or_missing_observation(self):
        rows = [self.row(i) for i in range(16)]
        rows += [self.row(100+i, session_id='other') for i in range(7)]
        rows += [self.row(200+i, split='testing', round=9) for i in range(7)]
        rows[4]['clrt_ms'] = None
        windows, accounting = self.pa.make_windows(rows, 8)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['member_ids'], [str(i) for i in range(5, 13)])
        self.assertEqual(accounting['missing'], 1)
        self.assertEqual(accounting['leftover'], 21)
        self.assertEqual(len(set(sum([w['member_ids'] for w in windows], []))), 8)

    def test_missing_timestamp_breaks_windows_and_unknown_order_rejects_group(self):
        rows=[self.row(i) for i in range(16)]
        rows[4]['observed_at_ms']=None
        windows,accounting=self.pa.make_windows(rows,8)
        self.assertEqual(windows[0]['member_ids'],[str(i) for i in range(5,13)])
        self.assertEqual(accounting['missing'],1)
        self.assertEqual(accounting['leftover'],7)
        for field in ('sequence','connection_id','session_id'):
            rows=[self.row(i) for i in range(16)]
            rows[4][field]=None
            windows,accounting=self.pa.make_windows(rows,8)
            self.assertEqual(windows,[],field)
            self.assertEqual(accounting['rejected'],16,field)

    def test_ledger_gate_binds_window_ids_and_refuses_unsupported_cost_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            row=self.row(1,trial='trial',realized_j_ms=None)
            original=dict(row,exchange_id='1',txn_class='READ',record_type='captured_exchange',
                capture_out_sha256='out',capture_in_sha256='in',condition='D10_J2p4',
                ack_latency_ns=1000000,clrt_ns=2000000,response_latency_ns=3000000)
            artifacts=[dict(path='out.pcap',kind='capture',sha256='out'),dict(path='in.pcap',kind='capture',sha256='in')]
            ledger=dict(records=[original])
            self.pa.validate_ledger_rows(root,artifacts,ledger,[row])
            for field,value in (('connection_id','invented'),('session_id','invented'),('sequence',999),
                ('trial','invented'),('condition_id','D20_J2p4'),('round',10),('split','testing')):
                changed=dict(row,**{field:value})
                with self.subTest(field=field),self.assertRaises(ValueError):
                    self.pa.validate_ledger_rows(root,artifacts,ledger,[changed])
            for field in ('internal_bytes','timestamp_precision_ns','loss','fallback','realized_j_ms','correct'):
                with self.subTest(cost=field),self.assertRaises(ValueError):
                    self.pa.validate_ledger_rows(root,artifacts,ledger,[dict(row,**{field:999.})])

    def test_legacy_entrypoint_and_dependency_replacements_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out';out.mkdir()
            evil=root/'evil.py';evil.write_text("raise RuntimeError('must not execute')")
            data=dict(root=root,manifest=dict(legacy_script_file='evil.py',legacy_tables=[dict(condition_id='D10_J2p4',path='table.csv')],
                artifacts=[dict(path='evil.py',sha256=self.pa.sha256(evil),kind='script')]))
            with self.assertRaises(ValueError):
                self.repro.legacy_descriptive(data,out)
            repo=MODULE.parents[9]
            entry=root/'legacy_repo'/self.repro.LEGACY_ENTRY_RELATIVE
            dependency=root/'legacy_repo'/self.repro.LEGACY_DEPENDENCY_RELATIVE
            entry.parent.mkdir(parents=True);dependency.parent.mkdir(parents=True)
            shutil.copyfile(repo/self.repro.LEGACY_ENTRY_RELATIVE,entry)
            dependency.write_text('raise RuntimeError("replacement dependency")')
            data['manifest']['legacy_script_file']=str(entry.relative_to(root))
            data['manifest']['artifacts']=[dict(path=str(p.relative_to(root)),sha256=self.pa.sha256(p),kind='script')
                                           for p in (entry,dependency)]
            with self.assertRaisesRegex(ValueError,'dependency'):
                self.repro.verified_legacy_script(data)
            shutil.copyfile(repo/self.repro.LEGACY_DEPENDENCY_RELATIVE,dependency)
            data['manifest']['artifacts'][1]['sha256']=self.pa.sha256(dependency)
            self.assertEqual(self.repro.verified_legacy_script(data),entry)
            (entry.parent/'csv.py').write_text('raise RuntimeError("unlisted import")')
            with self.assertRaisesRegex(ValueError,'unapproved Python'):
                self.repro.verified_legacy_script(data)

    def test_internal_bytes_and_j_are_derived_from_bound_raw_trial_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            roles=('n_ack_return','t_in','hb_return','held_return')
            artifacts=[dict(path='out.pcap',kind='capture',sha256='out'),dict(path='in.pcap',kind='capture',sha256='in')]
            for phase,octets in (('before',100),('after',200)):
                path=root/'snapshots'/('trial_'+phase+'.json');path.parent.mkdir(exist_ok=True)
                self.pa.write_json(path,dict(loop_ports={role:{'$OctetsReceived':octets} for role in roles}))
                artifacts.append(dict(path=str(path.relative_to(root)),kind='counters',sha256=self.pa.sha256(path)))
            rows=[];captured=[]
            for operation,count in (('READ',65),('SELECT',64),('OPERATE',64)):
                for _ in range(count):
                    row=self.row(len(rows),operation=operation,trial='trial',internal_bytes=2.1,
                                 realized_j_ms=2.4 if operation=='OPERATE' else None)
                    original=dict(row,exchange_id=row['example_id'],txn_class=operation,record_type='captured_exchange',
                        complete=True,capture_out_sha256='out',capture_in_sha256='in',
                        ack_latency_ns=1000000,clrt_ns=2000000,response_latency_ns=3000000,
                        operate_hold_ns=2400000 if operation=='OPERATE' else None)
                    rows.append(row);captured.append(original)
            ledger=dict(records=captured)
            self.assertTrue(self.pa.validate_ledger_rows(root,artifacts,ledger,rows))
            rows[0]['internal_bytes']=2.2
            with self.assertRaisesRegex(ValueError,'raw trial RXoctet'):
                self.pa.validate_ledger_rows(root,artifacts,ledger,rows)
            rows[0]['internal_bytes']=2.1
            rows[-1]['realized_j_ms']=2.5
            with self.assertRaisesRegex(ValueError,'realized_j_ms'):
                self.pa.validate_ledger_rows(root,artifacts,ledger,rows)
            rows[-1]['realized_j_ms']=2.4
            (root/'snapshots/trial_after.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'snapshot hash mismatch'):
                self.pa.validate_ledger_rows(root,artifacts,ledger,rows)

    def test_counter_utility_preserves_observed_zeroes_and_fixture_unavailability(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.pa.write_json(root/'campaign_run.json',dict(arms=[dict(arm='off',trials=[dict(label='trial',ok=True,
                observed=dict(outcomes={'OUT_ACK_FALLBACK':0,'OUT_RESP_FALLBACK':0},generation_exhausted=0,token_stale=0,
                              read_precision=dict(eligible=65,pass_=True,p99_nearest_rank_abs_error_us=20)),
                vision=dict(tcpdump={'out':{'dropped_kernel':0},'in':{'dropped_kernel':0}}))])]))
            self.pa.write_json(root/'publication_ledger.json',dict(records=[dict(record_type='captured_exchange',
                trial='trial',arm='baseline',complete=True,retransmitted=True)]))
            artifacts=[dict(path=name,kind='audit',block_id='b',sha256=self.pa.sha256(root/name))
                       for name in ('campaign_run.json','publication_ledger.json')]
            data=dict(root=root,manifest=dict(artifacts=artifacts),schedule=[dict(block_id='b',round=9,split='testing',condition_id='D10_J2p4')])
            values=self.repro.counter_utility(data)
            self.assertEqual(values[0]['outcome_OUT_ACK_FALLBACK'],0)
            self.assertEqual(values[0]['outcome_OUT_RESP_FALLBACK'],0)
            self.assertEqual(values[0]['generation_exhausted'],0)
            self.assertEqual(values[0]['ledger_complete'],1)
            self.assertEqual(values[0]['ledger_retransmitted'],1)
            self.assertEqual(values[0]['tcpdump_out_dropped_kernel'],0)
            self.assertEqual(values[0]['read_precision_p99_nearest_rank_abs_error_us'],20)
            fixture=self.repro.counter_utility(data,fixture=True)
            self.assertEqual(fixture[0]['status'],'unavailable')
            self.assertNotIn('outcome_OUT_ACK_FALLBACK',fixture[0])
            (root/'campaign_run.json').write_text('{}')
            with self.assertRaises(ValueError):
                self.repro.counter_utility(data)

    def test_bootstrap_preserves_paired_round_blocks(self):
        baseline = {i: float(i) for i in range(9, 17)}
        defended = {i: float(i)-.2 for i in range(9, 17)}
        result = self.pa.paired_bootstrap(baseline, defended)
        self.assertAlmostEqual(result['estimate'], .2)
        self.assertAlmostEqual(result['lower'], .2)
        self.assertAlmostEqual(result['upper'], .2)
        self.assertEqual(result['resamples'], 10000)
        with self.assertRaises(ValueError):
            self.pa.paired_bootstrap(baseline, {9: 0.})

    def test_fit_refuses_test_rows_and_frozen_predict_is_portable(self):
        rows = [self.row(i, operation=('READ','SELECT','OPERATE')[i%3],
                         clrt_ms=float(i%3), resp_len=40+i%3) for i in range(36)]
        with self.assertRaises(ValueError):
            self.pa.fit_models(rows+[self.row(100, split='testing', round=9)])
        lock = self.pa.fit_models(rows)
        restored = json.loads(json.dumps(lock, allow_nan=False))
        predictions = self.pa.predict_models(rows, restored)
        self.assertTrue(predictions)
        self.assertEqual(predictions, self.pa.predict_models(rows, restored))
        self.assertTrue(all('probabilities' in r for r in predictions))
        changed = [dict(r) for r in rows]
        changed[0]['clrt_ms'] = 999.
        with self.assertRaises(ValueError):
            self.pa.verify_training_lock(changed, restored)

    def test_frozen_json_forest_preserves_sklearn_probabilities(self):
        matrix=np.array([[i/17.,(i%7)/3.] for i in range(90)])
        model=self.pa.RandomForestClassifier(**self.pa.RF_SETTINGS).fit(matrix,
            [self.pa.CLASSES[i%3] for i in range(90)])
        frozen=json.loads(json.dumps(self.pa._freeze_rf(model)))
        np.testing.assert_allclose(self.pa.frozen_probabilities(frozen,matrix),model.predict_proba(matrix),rtol=0,atol=1e-12)

    def test_main_rejects_fixture_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'release_manifest.json').write_text(json.dumps(
                {'schema_version': 1, 'evidence_kind': 'supervision_fixture'}))
            with self.assertRaises(ValueError):
                self.pa.validate_release(root)
            with self.assertRaises(ValueError):
                self.pa.safe_path(root, '../escape')
            outside=root.parent/'outside'
            outside.write_text('outside')
            (root/'link').symlink_to(outside)
            with self.assertRaises(ValueError):
                self.pa.safe_path(root,'link')
            outside.unlink()

    def build_release(self, root, training):
        schedule = []
        cohort = []
        artifacts = []
        rows = []
        for round_number in range(1,17):
            rotation = (round_number-1)%8
            conditions = list(self.pa.CONDITIONS)
            conditions = conditions[rotation:]+conditions[:rotation]
            a = (round_number-1)%4
            arms = list(self.pa.ARMS[-a:]+self.pa.ARMS[:-a]) if a else list(self.pa.ARMS)
            for condition,_,_ in conditions:
                block_id = 'r%d_%s'%(round_number,condition)
                split = 'training' if round_number<=8 else 'testing'
                schedule.append(dict(block_id=block_id,round=round_number,split=split,condition_id=condition,arms=arms))
                if training and round_number>8:
                    continue
                cohort.append(dict(block_id=block_id,complete=True,
                    expected_per_arm={arm:193 for arm in arms},observed_per_arm={arm:193 for arm in arms}))
                for kind in ('capture','counters'):
                    path=block_id+'.'+kind
                    (root/path).write_text('explicit synthetic test fixture')
                    artifacts.append(dict(path=path,sha256=self.pa.sha256(root/path),kind=kind,block_id=block_id))
                for arm in arms:
                    index=0
                    for operation,count in (('READ',65),('SELECT',64),('OPERATE',64)):
                        for member in range(count):
                            available = condition=='D10_J2p4' and (not training or arm=='off') and member<8
                            row=self.row(index,example_id=block_id+'_'+arm+'_'+str(index),block_id=block_id,
                                condition_id=condition,round=round_number,split=split,arm=arm,operation=operation,
                                ack_ms=1. if available else None,clrt_ms=float(('READ','SELECT','OPERATE').index(operation)+1) if available else None,
                                rt_ms=None,resp_len=40 if available else None)
                            rows.append(row)
                            index+=1
        self.pa.write_json(root/'schedule.json',schedule)
        self.pa.write_json(root/'cohort.json',dict(schema_version=1,blocks=cohort))
        with open(root/'rows.csv','w',newline='') as handle:
            writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
            writer.writeheader();writer.writerows(rows)
        for path,kind in (('rows.csv','rows'),('schedule.json','schedule'),('cohort.json','cohort')):
            artifacts.append(dict(path=path,sha256=self.pa.sha256(root/path),kind=kind))
        manifest=dict(schema_version=1,evidence_kind='synthetic',campaign_id='fixture',
            conditions=[dict(condition_id=c,D_ms=d,J_ms=j) for c,d,j in self.pa.CONDITIONS],
            schedule_file='schedule.json',cohort_file='cohort.json',rows_file='rows.csv',artifacts=artifacts)
        if not training:
            # Preserve exact frozen training values from the actual fit input.
            before=self.pa.load_rows(root/'training_rows.csv')
            training_by={r['example_id']:r for r in before}
            rows=[training_by[r['example_id']] if r['split']=='training' else r for r in rows]
            with open(root/'rows.csv','w',newline='') as handle:
                writer=csv.DictWriter(handle,fieldnames=sorted(rows[0]))
                writer.writeheader();writer.writerows(rows)
            next(a for a in artifacts if a['kind']=='rows')['sha256']=self.pa.sha256(root/'rows.csv')
            manifest['model_lock_file']='model_lock.json'
            artifacts.append(dict(path='model_lock.json',sha256=self.pa.sha256(root/'model_lock.json'),kind='model_lock'))
        self.pa.write_json(root/'release_manifest.json',manifest)

    def structural_hardware_fixture(self, root):
        """Ephemeral validator probe, never passed to main result generation."""
        manifest=self.pa.read_json(root/'release_manifest.json')
        manifest.update(evidence_kind='hardware',hardware_provenance=dict(platform='Tofino-1',target='m11_09',
            endpoint='OpenDNP3',source_sha256='a'*64))
        grouped=defaultdict(list)
        for row in self.pa.load_rows(root/'rows.csv'):
            grouped[row['block_id']].append(row)
        for artifact in manifest['artifacts']:
            path=root/artifact['path']
            if artifact['kind']=='capture':
                path.write_bytes(b'\xd4\xc3\xb2\xa1'+bytes(37))
            elif artifact['kind']=='counters':
                self.pa.write_json(path,{'explicit_structural_test_fixture':True})
            artifact['sha256']=self.pa.sha256(path)
        for block_id,rows in grouped.items():
            capture=next(a['sha256'] for a in manifest['artifacts'] if a.get('block_id')==block_id and a['kind']=='capture')
            captured=[]
            for row in rows:
                original={k:v for k,v in row.items() if v is not None}
                original.update(exchange_id=row['example_id'],txn_class=row['operation'],record_type='captured_exchange',
                                capture_out_sha256=capture,capture_in_sha256=capture)
                for metric,source in (('ack_ms','ack_latency_ns'),('clrt_ms','clrt_ns'),('rt_ms','response_latency_ns')):
                    original[source]=None if row.get(metric) is None else row[metric]*1000000
                captured.append(original)
            paths=[]
            for name,value in (('campaign_run.json',dict(ok=True,source_identity=dict(build_sources={'fixture':{'source_sha256':'a'*64}}))),
                               ('restore_verify.json',dict(ok=True)),('publication_ledger.json',dict(records=captured))):
                path=root/'audit'/block_id/name;path.parent.mkdir(parents=True,exist_ok=True)
                self.pa.write_json(path,value);paths.append(path)
            post=root/'audit'/block_id/'evaluation_postcheck.json'
            self.pa.write_json(post,dict(ok=True,evidence_kind='hardware',block_id=block_id,
                campaign_record_sha256=self.pa.sha256(paths[0]),ledger_sha256=self.pa.sha256(paths[2])))
            for path in paths+[post]:
                manifest['artifacts'].append(dict(path=str(path.relative_to(root)),sha256=self.pa.sha256(path),kind='audit',block_id=block_id))
        for artifact in manifest['artifacts']:
            if artifact['kind']!='validation':
                artifact.setdefault('evidence_kind','hardware')   # as evaluation_prepare.artifact labels them
        lock=self.pa.read_json(root/'model_lock.json');lock['evidence_kind']='hardware'
        self.pa.write_json(root/'model_lock.json',lock)
        lock_hash=self.pa.sha256(root/'model_lock.json')
        next(a for a in manifest['artifacts'] if a['kind']=='model_lock')['sha256']=lock_hash
        self.pa.write_json(root/'fit_attestation.json',dict(campaign_id='fixture',model_lock_sha256=lock_hash,
            fit_after_round=8,before_round=9,ok=True))
        manifest.update(fit_attestation_file='fit_attestation.json')
        manifest['artifacts'].append(dict(path='fit_attestation.json',sha256=self.pa.sha256(root/'fit_attestation.json'),
                                          kind='fit_attestation',evidence_kind='hardware'))
        self.pa.write_json(root/'release_manifest.json',manifest)

    def test_main_validation_rejects_hashed_heldout_boundary_and_cost_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.build_release(root,training=True)
            self.repro.fit_lock(root,root/'model_lock.json',fixture=True)
            shutil.copyfile(root/'rows.csv',root/'training_rows.csv')
            self.build_release(root,training=False)
            self.structural_hardware_fixture(root)
            manifest=self.pa.read_json(root/'release_manifest.json')
            self.pa.write_json(root/'model_summary.json',dict(validation_only=True))
            manifest['artifacts'].append(dict(path='model_summary.json',kind='validation',evidence_kind='model_validation',
                                               sha256=self.pa.sha256(root/'model_summary.json')))
            self.pa.write_json(root/'release_manifest.json',manifest)
            # This validates structural provenance only; no main claims are emitted.
            data=self.pa.validate_release(root)
            rows=data['rows']
            target=next(row for row in rows if row['split']=='testing')
            manifest=data['manifest']
            validation=next(a for a in manifest['artifacts'] if a['kind']=='validation')
            validation['kind']='capture'
            self.pa.write_json(root/'release_manifest.json',manifest)
            with self.assertRaisesRegex(ValueError,'nonhardware'):
                self.pa.validate_release(root)
            validation['kind']='validation';validation['evidence_kind']='hardware'
            self.pa.write_json(root/'release_manifest.json',manifest)
            with self.assertRaisesRegex(ValueError,'validation prerequisite'):
                self.pa.validate_release(root)
            validation['evidence_kind']='model_validation'
            changes=(('connection_id','invented'),('session_id','invented'),('sequence',999999),('trial','invented'),
                     ('condition_id','D20_J2p4'),('round',10),('split','training'),
                     ('internal_bytes',9999),('timestamp_precision_ns',1),('loss',0),('fallback',0),('realized_j_ms',123),('correct',1))
            for field,value in changes:
                previous=target.get(field)
                target[field]=value
                with open(root/'rows.csv','w',newline='') as handle:
                    writer=csv.DictWriter(handle,fieldnames=sorted({k for row in rows for k in row}))
                    writer.writeheader();writer.writerows(rows)
                next(a for a in manifest['artifacts'] if a['kind']=='rows')['sha256']=self.pa.sha256(root/'rows.csv')
                self.pa.write_json(root/'release_manifest.json',manifest)
                with self.subTest(field=field),self.assertRaises(ValueError):
                    self.pa.validate_release(root)
                target[field]=previous

    def test_portable_fixture_replay_is_deterministic_and_cannot_claim_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'release';root.mkdir()
            self.build_release(root,training=True)
            self.repro.fit_lock(root,root/'model_lock.json',fixture=True)
            shutil.copyfile(root/'rows.csv',root/'training_rows.csv')
            self.build_release(root,training=False)
            copy=Path(directory)/'moved';shutil.copytree(root,copy)
            result=self.repro.replay_fixture(root,Path(directory)/'one',figures=True)
            second=self.repro.replay_fixture(copy,Path(directory)/'two')
            self.assertFalse(result['main_result_claims'])
            self.assertEqual(len(list((Path(directory)/'one/figures').glob('*.pdf'))),7)
            self.assertTrue(all(p.stat().st_size>1000 for p in (Path(directory)/'one/figures').glob('*.pdf')))
            self.assertEqual(result,second)
            for name in ('predictions.csv','attack_summary.csv','paired_reductions.csv','coverage.csv','membership.csv','results.json'):
                self.assertEqual((Path(directory)/'one'/name).read_bytes(),(Path(directory)/'two'/name).read_bytes())
            with self.assertRaises(ValueError):
                self.repro.reproduce(copy,Path(directory)/'main')
            manifest=self.pa.read_json(copy/'release_manifest.json')
            manifest.update(evidence_kind='hardware',hardware_provenance=dict(platform='Tofino-1',target='m11_09',
                endpoint='OpenDNP3',source_sha256='a'*64))
            self.pa.write_json(copy/'release_manifest.json',manifest)
            with self.assertRaisesRegex(ValueError,'pcap|unlabelled'):   # rejected either way (review A6)
                self.pa.validate_release(copy)
            (copy/'rows.csv').write_text('tampered')
            with self.assertRaises(ValueError):
                self.pa.validate_fixture_release(copy)


if __name__ == '__main__':
    unittest.main()
