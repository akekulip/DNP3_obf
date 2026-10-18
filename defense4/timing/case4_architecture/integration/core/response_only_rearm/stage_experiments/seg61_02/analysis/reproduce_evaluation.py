"""Offline locked replay: reproduce_evaluation.py RELEASE_DIR --output OUT_DIR.

Training hook: reproduce_evaluation.py RELEASE_DIR --fit-lock RELEASE_DIR/model_lock.json
Only explicit Python replay_fixture() permits analysis-only synthetic fixtures.
"""
import argparse
import csv
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from collections import defaultdict

import numpy as np

import publication_analysis as pa

LEGACY_ENTRY_RELATIVE = Path('defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/leakage_four_arm.py')
LEGACY_DEPENDENCY_RELATIVE = Path('defense4/timing/evidence/campaign_v2/repro/leakage_campaign.py')
# Approved unchanged implementations, pinned independently of release assertions.
LEGACY_ENTRY_SHA256 = 'af2dea676ea2e286c97ca91f697e4b37c4d512a280eb4d921bd600b1c8f5855c'
LEGACY_DEPENDENCY_SHA256 = '50ff14548ba21336ccfa802b589bc568bd9a7537100697ee4a3d6fd413cecb15'


def write_csv(path, rows, fields=None):
    rows = list(rows)
    fields = fields or sorted({key for row in rows for key in row})
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value,sort_keys=True,allow_nan=False) if isinstance(value,(dict,list))
                             else value for key,value in row.items()})


def fit_lock(directory, output, fixture=False):
    data = (pa.validate_fixture_release if fixture else pa.validate_release)(directory, training=True)
    output = Path(output)
    if output.exists():
        raise ValueError('model lock already exists; refusing overwrite')
    lock = pa.fit_models(data['rows'])
    lock.update(campaign_id=data['manifest']['campaign_id'], evidence_kind=data['manifest']['evidence_kind'],
        training_schedule_sha256=pa.digest([b for b in data['schedule'] if b['round']<=8]),
        training_release_manifest_sha256=data['manifest_sha256'],
        analysis_scope='analysis-only fixture' if fixture else 'hardware training-only lock')
    output.parent.mkdir(parents=True,exist_ok=True)
    # Exclusive create makes retried hooks fail closed instead of replacing a fitted lock.
    with open(output,'x') as handle:
        handle.write(json.dumps(lock,sort_keys=True,indent=2,allow_nan=False)+'\n')
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd=os.open(str(output.parent),os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return dict(path=str(output),sha256=pa.sha256(output),models=len(lock['models']),
                unavailable=len(lock['unavailable']),training_rows=len(data['rows']))


def distribution_table(rows):
    """Exact shared edges across arms per condition/metric; never truncate tails."""
    result = []
    for condition,_,_ in pa.CONDITIONS:
        for field in ('ack_ms','clrt_ms','resp_len','rt_ms'):
            source = [r for r in rows if r['condition_id']==condition and r.get(field) is not None]
            if not source:
                continue
            low,high = min(r[field] for r in source),max(r[field] for r in source)
            if low==high:
                high = low+max(.001,abs(low)*.01)
            edges = np.linspace(low,high,51)
            for arm in pa.ARMS:
                values = [r[field] for r in source if r['arm']==arm]
                counts,_ = np.histogram(values,bins=edges)
                cumulative = 0
                for index,count in enumerate(counts):
                    cumulative += int(count)
                    result.append(dict(condition_id=condition,metric=field,arm=arm,bin=index,
                        left=float(edges[index]),right=float(edges[index+1]),count=int(count),
                        cumulative=cumulative,n=len(values),last_bin_inclusive=index==49,
                        full_min=min(values) if values else None,full_max=max(values) if values else None))
    return result


def cost_table(rows):
    result = []
    fields = ('rt_ms','internal_bytes','timestamp_precision_ns','loss','fallback','realized_j_ms','correct')
    for condition,_,_ in pa.CONDITIONS:
        for arm in pa.ARMS:
            source = [r for r in rows if r['condition_id']==condition and r['arm']==arm]
            for operation in ('all',)+pa.CLASSES:
                subset = source if operation=='all' else [r for r in source if r['operation']==operation]
                for field in fields:
                    if field=='internal_bytes' and operation!='all':
                        continue  # A trial aggregate does not identify operation-specific bytes.
                    observed = [r for r in subset if r.get(field) is not None]
                    values = [r[field] for r in observed]
                    scope='per observed exchange; descriptive, clustered within round'
                    if field=='internal_bytes':
                        trials={}
                        for row in observed:
                            key=(row['block_id'],row['arm'],row.get('trial') or row['session_id'])
                            value=trials.setdefault(key,row[field])
                            if value!=row[field]:
                                raise ValueError('inconsistent repeated trial-average internal bytes')
                        values=list(trials.values())
                        scope='trial-average bytes per exchange; repeated ledger values counted once per trial'
                    result.append(dict(condition_id=condition,arm=arm,operation=operation,metric=field,attempted=len(subset),
                        observed=len(observed),missing=len(subset)-len(observed),n_measurements=len(values),scope=scope,
                        mean=float(np.mean(values)) if values else None,
                        p50=nearest_rank(values,.5),p95=nearest_rank(values,.95),p99=nearest_rank(values,.99),
                        maximum=max(values) if values else None,
                        sample_sd=float(np.std(values,ddof=1)) if len(values)>1 else None,
                        quantile_method='nearest-rank'))
    return result


def nearest_rank(values,quantile):
    return sorted(values)[max(0,math.ceil(quantile*len(values))-1)] if values else None


def precision_tables(rows):
    targets={condition:d for condition,d,_ in pa.CONDITIONS}
    residuals=[]
    grouped=defaultdict(list)
    for row in rows:
        if row.get('clrt_ms') is None:
            continue
        error=row['clrt_ms']-targets[row['condition_id']]
        item=dict(example_id=row['example_id'],block_id=row['block_id'],condition_id=row['condition_id'],
            arm=row['arm'],operation=row['operation'],round=row['round'],clrt_ms=row['clrt_ms'],
            target_D_ms=targets[row['condition_id']],residual_ms=error,abs_error_ms=abs(error),
            precision_applicable=row['arm'] in ('timing_only','combined'))
        residuals.append(item)
        grouped[row['condition_id'],row['arm'],row['operation']].append(item)
    summaries=[]
    for (condition,arm,operation),items in sorted(grouped.items()):
        values=[r['abs_error_ms'] for r in items]
        summaries.append(dict(condition_id=condition,arm=arm,operation=operation,n=len(items),
            precision_applicable=arm in ('timing_only','combined'),criterion_ms=.1,
            within_100us=sum(value<=.1 for value in values),
            abs_error_p50_ms=nearest_rank(values,.5),abs_error_p99_ms=nearest_rank(values,.99),
            abs_error_max_ms=max(values),abs_error_sample_sd_ms=float(np.std(values,ddof=1)) if len(values)>1 else None,
            quantile_method='nearest-rank; full tails retained'))
    return residuals,summaries


def counter_utility(data,fixture=False):
    """Actual trial aggregates; they are never per-exchange loss/correctness labels."""
    if fixture:
        return [dict(status='unavailable',scope='analysis-only fixture; no hardware utility claim')]
    result=[]
    by_block=defaultdict(list)
    for artifact in data['manifest']['artifacts']:
        if artifact['kind']=='audit':
            by_block[artifact.get('block_id')].append(artifact)
    for block in data['schedule']:
        artifacts=by_block[block['block_id']]
        if not artifacts:
            continue
        raw={}
        hashes={}
        for name in ('campaign_run.json','publication_ledger.json'):
            candidates=[a for a in artifacts if Path(a['path']).name==name]
            if len(candidates)!=1:
                raise ValueError('utility aggregates require unique hash-bound campaign/ledger audits')
            artifact=candidates[0]
            path=pa.safe_path(data['root'],artifact['path'])
            if pa.sha256(path)!=artifact['sha256']:
                raise ValueError('utility audit hash mismatch')
            raw[name]=pa.read_json(path)
            hashes[name]=artifact['sha256']
        ledger=raw['publication_ledger.json']['records']
        for arm_record in raw['campaign_run.json'].get('arms',[]):
            arm='off' if arm_record['arm']=='baseline' else arm_record['arm']
            for trial in arm_record.get('trials',[]):
                observed=trial.get('observed') or {}
                outcomes=observed.get('outcomes')
                label=trial.get('label')
                captured=[r for r in ledger if r.get('record_type')=='captured_exchange' and r.get('trial')==label
                          and ('off' if r.get('arm')=='baseline' else r.get('arm'))==arm]
                item={key:block[key] for key in ('block_id','condition_id','round','split')}
                item.update(arm=arm,trial=label,status='observed aggregate',trial_ok=trial.get('ok'),
                    scope='per trial; no per-exchange attribution or independent-packet inference',
                    campaign_record_sha256=hashes['campaign_run.json'],ledger_sha256=hashes['publication_ledger.json'],
                    outcomes_available=isinstance(outcomes,dict),generation_exhausted=observed.get('generation_exhausted'),
                    token_stale=observed.get('token_stale'),ledger_captured=len(captured),
                    ledger_complete=sum(r.get('complete') is True for r in captured),
                    ledger_incomplete=sum(r.get('complete') is False for r in captured),
                    ledger_complete_unknown=sum(r.get('complete') is None for r in captured),
                    ledger_retransmitted=sum(r.get('retransmitted') is True for r in captured),
                    ledger_retransmission_unknown=sum(r.get('retransmitted') is None for r in captured))
                if isinstance(outcomes,dict):
                    for key,value in outcomes.items():
                        item['outcome_'+key]=value  # Preserve observed zeroes; never fill missing keys.
                for operation in ('read','select','operate'):
                    precision=observed.get(operation+'_precision') or {}
                    for key in ('eligible','pass','p99','p99_nearest_rank_abs_error_us','max_absolute_error_us','p99_convention'):
                        item[operation+'_precision_'+key]=precision.get(key)
                    absolute=precision.get('absolute_error_us') or {}
                    for key in ('max','sd_sample'):
                        item[operation+'_precision_absolute_error_'+key]=absolute.get(key)
                capture=(trial.get('vision') or {}).get('tcpdump') or {}
                for direction in ('out','in'):
                    for key in ('captured','received','dropped_kernel'):
                        item['tcpdump_'+direction+'_'+key]=(capture.get(direction) or {}).get(key)
                result.append(item)
    return result or [dict(status='unavailable',scope='no retained per-trial hardware utility observations')]


def verified_legacy_script(data):
    root=Path(data['root']).resolve()
    artifacts={a['path']:a for a in data['manifest']['artifacts']}
    name=data['manifest'].get('legacy_script_file')
    if not name or name not in artifacts:
        raise ValueError('legacy analysis requires explicitly hash-bound approved source')
    entry=pa.safe_path(root,name)
    if tuple(entry.parts[-len(LEGACY_ENTRY_RELATIVE.parts):])!=LEGACY_ENTRY_RELATIVE.parts:
        raise ValueError('legacy source must retain the approved repository hierarchy')
    if (artifacts[name]['sha256']!=LEGACY_ENTRY_SHA256 or pa.sha256(entry)!=LEGACY_ENTRY_SHA256):
        raise ValueError('legacy entrypoint differs from approved unchanged algorithm')
    legacy_root=entry.parents[9]
    dependency=legacy_root/LEGACY_DEPENDENCY_RELATIVE
    dependency_name=str(dependency.relative_to(root))
    if (dependency_name not in artifacts or artifacts[dependency_name]['sha256']!=LEGACY_DEPENDENCY_SHA256
            or not dependency.is_file() or pa.sha256(dependency)!=LEGACY_DEPENDENCY_SHA256):
        raise ValueError('legacy dependency differs from explicitly hash-bound approved algorithm')
    allowed={entry,dependency}
    if any(path not in allowed for path in legacy_root.rglob('*.py')) or any(legacy_root.rglob('*.pyc')):
        raise ValueError('unapproved Python source/bytecode in legacy reproduction tree')
    return entry


def legacy_descriptive(data, out):
    """Invoke the unchanged legacy CLI only for explicit hash-bound eligible tables."""
    records = data['manifest'].get('legacy_tables',[])
    result = []
    artifacts = {a['path']:a for a in data['manifest']['artifacts']}
    legacy=verified_legacy_script(data) if records else None
    for record in records:
        path = pa.safe_path(data['root'],record['path'])
        sidecar = record['path']+'.counts.json'
        if record['path'] not in artifacts or sidecar not in artifacts or not legacy.exists():
            result.append(dict(condition_id=record.get('condition_id'),status='ineligible',
                               reason='requires legacy script and hashed table/counts sidecar'))
            continue
        destination = out/('legacy_descriptive_'+str(record['condition_id'])+'.json')
        proc = subprocess.run([sys.executable,'-I','-B',str(legacy),str(path),str(destination)],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        result.append(dict(condition_id=record.get('condition_id'),status='complete' if proc.returncode==0 else 'ineligible',
            returncode=proc.returncode,stdout=proc.stdout,stderr=proc.stderr,
            scope='unchanged legacy estimator; descriptive spread, separate from locked holdout inference'))
    if not records:
        result.append(dict(status='unavailable',reason='no explicit eligible legacy extraction table supplied'))
    pa.write_json(out/'legacy_descriptive_status.json',result)
    return result


def export_environment(out, data):
    packages = {name:importlib.metadata.version(name) for name in ('numpy','scikit-learn','matplotlib')}
    environment = dict(python=platform.python_version(),implementation=platform.python_implementation(),
        platform=platform.platform(),packages=packages,manifest_sha256=data['manifest_sha256'],
        seeds=dict(random_forest=0,bootstrap=pa.SEED),bootstrap_resamples=10000)
    pa.write_json(out/'environment.json',environment)
    (out/'requirements.lock.txt').write_text('\n'.join(name+'=='+version for name,version in sorted(packages.items()))+'\n')
    scripts = out/'scripts'
    scripts.mkdir()
    for name in ('publication_analysis.py','reproduce_evaluation.py','publication_figures.py'):
        source = Path(__file__).with_name(name)
        if source.exists():
            shutil.copyfile(source,scripts/name)
    pa.write_json(out/'source_hashes.json',{p.name:pa.sha256(p) for p in sorted(scripts.iterdir())})
    shutil.copyfile(data['root']/'release_manifest.json',out/'input_release_manifest.json')
    (out/'REPRODUCE.txt').write_text(
        'Use the recorded Python and requirements.lock.txt versions. No network is required.\n'
        'python scripts/reproduce_evaluation.py /path/to/original_release --output /path/to/new_output\n'
        'All release files remain relative/hash-bound; outputs contain no absolute source paths.\n')


def replay_data(data, out, fixture=False, figures=True):
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError('output directory must be empty; refusing mixed/stale results')
    out.mkdir(parents=True,exist_ok=True)
    rows = data['rows']
    lock = pa.read_json(pa.safe_path(data['root'],data['manifest']['model_lock_file']))
    pa.verify_training_lock(rows,lock)
    testing = [r for r in rows if r['split']=='testing']
    predictions = pa.predict_models(testing,lock)
    summaries,comparisons = pa.summarize_predictions(predictions)
    write_csv(out/'predictions.csv',predictions)
    write_csv(out/'attack_summary.csv',summaries)
    flat_comparisons = []
    for comparison in comparisons:
        for metric,interval in comparison['intervals'].items():
            row = dict({k:v for k,v in comparison.items() if k!='intervals'},metric=metric,**interval)
            row['primary'] = bool(comparison.get('primary')) and metric=='balanced_accuracy'   # one primary row (review)
            flat_comparisons.append(row)
    write_csv(out/'paired_reductions.csv',flat_comparisons)
    write_csv(out/'coverage.csv',pa.coverage(rows))
    membership = [{field:r.get(field) for field in ('example_id','block_id','condition_id','arm','operation',
                    'round','split','connection_id','session_id')} for r in rows]
    write_csv(out/'membership.csv',membership)
    window_rows,window_accounting = [],[]
    for k in (8,32,64):
        # Report accounting independently for every cohort group, including missing windows.
        grouped = defaultdict(list)
        for row in rows:
            grouped[tuple(row[f] for f in ('condition_id','arm','round','split','operation'))].append(row)
        for key,subset in sorted(grouped.items()):
            windows,accounting = pa.make_windows(subset,k)
            window_rows.extend({field:value for field,value in w.items() if field!='values'} for w in windows)
            window_accounting.append(dict(zip(('condition_id','arm','round','split','operation'),key),k=k,**accounting))
    write_csv(out/'oracle_windows.csv',window_rows)
    write_csv(out/'window_accounting.csv',window_accounting)
    write_csv(out/'distributions.csv',distribution_table(testing))
    write_csv(out/'costs.csv',cost_table(testing))
    write_csv(out/'counter_utility.csv',counter_utility(data,fixture=fixture))
    residuals,precision=precision_tables(testing)
    write_csv(out/'precision_residuals.csv',residuals)
    write_csv(out/'precision_summary.csv',precision)
    # Every model/feature condition is disclosed, even unavailable fits.
    pa.write_json(out/'model_inventory.json',dict(models=[{k:v for k,v in m.items() if k!='estimator'} for m in lock['models']],
                                               unavailable=lock['unavailable'],settings=lock['settings']))
    legacy = legacy_descriptive(data,out) if not fixture else [dict(status='analysis-only fixture; legacy main comparison disabled')]
    result = dict(schema_version=1,analysis_scope='analysis-only fixture' if fixture else 'main hardware held-out evaluation',
        main_result_claims=not fixture,manifest_sha256=data['manifest_sha256'],model_lock_sha256=pa.sha256(
        pa.safe_path(data['root'],data['manifest']['model_lock_file'])),attempted=len(rows),testing_attempted=len(testing),
        predictions=len(predictions),comparisons=comparisons,legacy_descriptive=legacy,
        limitations=['Conditional intervals resample eight paired round blocks, conditional on this frozen training set.',
          'Secondary intervals are pointwise; no near-chance guarantee.',
          'Operation-grouped windows are oracle-assisted; no device-class inference.',
          'Missing metrics/costs are explicit, excluded per estimator, and never imputed.',
          'Native competence is a descriptive chance+0.05 flag; all results remain disclosed.',
          'Hash validation proves portable integrity and recorded provenance, not physical device authenticity.'])
    pa.write_json(out/'results.json',result)
    export_environment(out,data)
    if figures:
        from publication_figures import render
        render(out)
    pa.write_json(out/'output_hashes.json',{str(p.relative_to(out)):pa.sha256(p) for p in sorted(out.rglob('*')) if p.is_file()})
    return result


def reproduce(directory, out):
    return replay_data(pa.validate_release(directory),out)


def replay_fixture(directory, out, figures=False):
    """Explicit synthetic replay; output asserts main_result_claims=false."""
    return replay_data(pa.validate_fixture_release(directory),out,fixture=True,figures=figures)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release_dir',type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output',type=Path)
    mode.add_argument('--fit-lock',type=Path)
    args = parser.parse_args(argv)
    try:
        result = fit_lock(args.release_dir,args.fit_lock) if args.fit_lock else reproduce(args.release_dir,args.output)
    except (ValueError,KeyError,OSError,TypeError) as error:
        parser.exit(2,'evaluation refused: '+str(error)+'\n')
    print(json.dumps(result if args.fit_lock else {key:result[key] for key in (
        'analysis_scope','main_result_claims','attempted','predictions','manifest_sha256')},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
