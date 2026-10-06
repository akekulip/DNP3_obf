#!/usr/bin/env python3
"""Read-only diagnostics for the frozen adaptive-attacker delay-grid run."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from sklearn.decomposition import PCA
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

LATENCY_DIR = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(LATENCY_DIR))
import evaluate_focused as evaluator
import grid_analysis

OPS = ('READ', 'SELECT', 'OPERATE')
COLORS = {'READ': '#0072B2', 'SELECT': '#D55E00', 'OPERATE': '#009E73'}
MARKERS = {'correct': 'o', 'incorrect': 'x'}
PRIMARY_FEATURES = {'clrt', 'ack_clrt'}
PRIMARY_SCENARIOS = {'adaptive_on_obfuscated', 'adaptive_on_offset_residuals'}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text('')
        return
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def stats(values) -> dict:
    x = np.asarray(values, dtype=float)
    x = x[np.isfinite(x)]
    if not len(x):
        return dict(n=0)
    q = np.percentile(x, [10, 25, 50, 75, 90, 95, 99])
    return dict(n=int(len(x)), mean=float(x.mean()), sd=float(x.std(ddof=0)),
        variance=float(x.var(ddof=0)), p10=float(q[0]), p25=float(q[1]),
        median=float(q[2]), p75=float(q[3]), p90=float(q[4]),
        p95=float(q[5]), p99=float(q[6]), minimum=float(x.min()), maximum=float(x.max()))


def read_predictions(record: dict) -> dict:
    path = Path(record['predictions'])
    if sha(path) != record['predictions_sha256']:
        raise ValueError(f'Prediction ledger hash mismatch: {path}')
    rows = {}
    with gzip.open(path, 'rt') as stream:
        for line in stream:
            item = json.loads(line)
            start = item['txn_index'] if record['pool'] == 1 else item['pool_start']
            key = (str(item['group']), item['block'], item['actual'], int(start))
            if key in rows:
                raise ValueError(f'Duplicate prediction identity: {key}')
            rows[key] = str(item['predicted'])
    if len(rows) != record['n_test_signatures']:
        raise ValueError(f'Prediction count mismatch for {path}')
    return rows


def key_for_pooled(row: dict, pool: int) -> tuple:
    start = row['txn_index'] if pool == 1 else row['pool_start']
    return (str(row['session']), row['block'], row['txn_class'], int(start))


def choose_best(records: list[dict], pool: int, features: set[str]) -> dict:
    eligible = [r for r in records if r['pool'] == pool
        and r['scenario'] in PRIMARY_SCENARIOS and r['feature'] in features]
    if not eligible:
        raise ValueError(f'No adaptive records for pool={pool}, features={features}')
    # Stable tie breaking does not change the frozen scores or their bounds.
    return sorted(eligible, key=lambda r: (-r['mean_accuracy'], r['feature'],
        r['scenario'], r['model'], r['representation']))[0]


def choose_gap_best(records: list[dict], pool: int) -> dict:
    eligible = [r for r in records if r['pool'] == pool
        and r['scenario'] == 'adaptive_on_obfuscated'
        and r['feature'] in {'request_gap', 'ack_clrt_gap'}]
    if not eligible:
        raise ValueError(f'No adaptive gap records for pool={pool}')
    return sorted(eligible, key=lambda r: (-r['mean_accuracy'], r['feature'], r['model']))[0]


def attack_records(result: dict, task: str) -> list[dict]:
    return result['tasks'][task]['records']


def exact_test_vectors(test_rows: list[dict], record: dict, levels: dict,
                       predictions: dict) -> tuple[list[dict], np.ndarray, list[str]]:
    spec = dict(classes=record['class_order'], representation=record['representation'],
                pool=record['pool'], feature=record['feature'])
    pooled = evaluator.pooled(test_rows, spec, levels, 'obfuscated')
    matrix = evaluator.base.a._pooled_feature_matrix(pooled, record['feature'])
    feature_names = list(evaluator.base.a.FEATURE_SETS[record['feature']])
    if record['pool'] > 1:
        feature_names = [f'{name}_{agg}' for name in feature_names
                         for agg in ('mean', 'std', 'min', 'max')]
    joined = []
    seen = set()
    for i, row in enumerate(pooled):
        key = key_for_pooled(row, record['pool'])
        if key not in predictions:
            raise ValueError(f'Missing held-out prediction identity: {key}')
        if key in seen:
            raise ValueError(f'Duplicate pooled feature identity: {key}')
        seen.add(key)
        joined.append(dict(row, predicted=predictions[key], correct=(predictions[key] == row['txn_class']),
                           feature_index=i))
    if seen != set(predictions):
        raise ValueError('Pooled feature and prediction identities differ')
    y_true = [row['txn_class'] for row in joined]
    y_pred = [row['predicted'] for row in joined]
    from sklearn.metrics import confusion_matrix, balanced_accuracy_score
    actual_confusion = confusion_matrix(y_true, y_pred, labels=record['class_order']).tolist()
    if actual_confusion != record['confusion_matrix']:
        raise ValueError('Reconstructed confusion matrix differs from frozen record')
    if abs(balanced_accuracy_score(y_true, y_pred) - record['mean_accuracy']) > 1e-12:
        raise ValueError('Reconstructed balanced accuracy differs from frozen record')
    return joined, matrix, feature_names


def timing_distribution_rows(subsets: dict, plans: dict) -> list[dict]:
    output = []
    fields = ('ack_ms', 'clrt_ms', 'rt_ms', 'request_gap_ms')
    for policy, (rows, protocol, levels) in subsets.items():
        da = float(plans[policy]['center_da_ms'])
        for arm in ('native', 'obfuscated'):
            for operation in OPS:
                selected = [r for r in rows if r['arm'] == arm and r['txn_class'] == operation
                            and int(r['replicate']) in protocol['test_repetitions']]
                for field in fields:
                    values = [float(r[field]) for r in selected if r.get(field) not in (None, '')]
                    if not values:
                        continue
                    output.append(dict(policy=policy, da_ms=da, arm=arm, operation=operation,
                                       measure=field, **stats(values)))
        obf = [r for r in rows if r['arm'] == 'obfuscated'
               and int(r['replicate']) in protocol['test_repetitions']]
        for operation in OPS:
            selected = [r for r in obf if r['txn_class'] == operation]
            for observed, level_key, label in (('ack_ms', 'da_ms', 'ack_residual_ms'),
                                               ('clrt_ms', 'gap_ms', 'clrt_residual_ms')):
                vals = [float(r[observed]) - evaluator.levels_attack.nearest(
                    float(r[observed]), levels[level_key]) for r in selected]
                output.append(dict(policy=policy, da_ms=da, arm='obfuscated', operation=operation,
                                   measure=label, **stats(vals)))
    return output


def pool_inventory_rows(results: dict) -> tuple[list[dict], dict]:
    inventory, winners = [], {}
    for policy, result in results.items():
        for task in ('three_class', 'read_select'):
            records = attack_records(result, task)
            for record in records:
                if record['scenario'] not in PRIMARY_SCENARIOS:
                    continue
                if record['feature'] not in PRIMARY_FEATURES:
                    continue
                inventory.append(dict(policy=policy, task=task, pool=record['pool'],
                    scenario=record['scenario'], model=record['model'],
                    representation=record['representation'], feature=record['feature'],
                    accuracy=record['mean_accuracy'], n_test_signatures=record['n_test_signatures'],
                    class_order='|'.join(record['class_order']),
                    class_recall='|'.join(f'{x:.9f}' for x in record['per_class_recall']),
                    confusion_json=json.dumps(record['confusion_matrix'], separators=(',', ':')),
                    rounds_json=json.dumps(record['fold_scores'], separators=(',', ':'))))
            for pool in (1, 5, 20):
                winner = choose_best(records, pool, PRIMARY_FEATURES)
                winners[(policy, task, pool)] = winner
    return inventory, winners


def gap_inventory_rows(results: dict) -> list[dict]:
    output = []
    for policy, result in results.items():
        for task in ('three_class', 'read_select'):
            records = attack_records(result, task)
            for record in records:
                if record['scenario'] != 'adaptive_on_obfuscated' or record['feature'] not in {'request_gap', 'ack_clrt_gap'}:
                    continue
                output.append(dict(policy=policy, task=task, pool=record['pool'],
                    model=record['model'], feature=record['feature'],
                    accuracy=record['mean_accuracy'], n_test_signatures=record['n_test_signatures'],
                    class_order='|'.join(record['class_order']),
                    class_recall='|'.join(f'{x:.9f}' for x in record['per_class_recall']),
                    confusion_json=json.dumps(record['confusion_matrix'], separators=(',', ':'))))
    return output


def pooled_distribution_rows(policy_data: dict, winners: dict) -> list[dict]:
    output = []
    for (policy, task, pool), (rows, protocol, levels, result) in policy_data.items():
        winner = winners[(policy, task, pool)]
        predictions = read_predictions(winner)
        test = evaluator.split_rows(rows, protocol, 'test')
        joined, matrix, feature_names = exact_test_vectors(test, winner, levels, predictions)
        for j, name in enumerate(feature_names):
            groups = {}
            for item in joined:
                groups.setdefault((item['txn_class'], item['predicted'], item['correct']), []).append(matrix[item['feature_index'], j])
            for (actual, predicted, correct), values in groups.items():
                output.append(dict(policy=policy, da_ms=float(policy[2:].split('_', 1)[0]),
                    task=task, pool=pool, model=winner['model'], representation=winner['representation'],
                    feature_set=winner['feature'], feature=name, actual=actual, predicted=predicted,
                    correct=bool(correct), **stats(values)))
    return output


def plot_ecdfs(distribution_rows: list[dict], out: Path, subsets: dict, residual=False) -> None:
    measures = ('ack_residual_ms', 'clrt_residual_ms') if residual else ('ack_ms', 'clrt_ms')
    labels = ('ACK timing after the D_A choice is removed (ms)', 'CLRT after the D_R choice is removed (ms)') if residual else ('Request-to-ACK (ms)', 'ACK-to-response CLRT (ms)')
    fig, axes = plt.subplots(4, 2, figsize=(7.16, 6.15), sharex=False)
    for row, da in enumerate((5, 10, 15, 20)):
        policy = f'da{da}_gap1_joint_amp0p5'
        data = [r for r in distribution_rows if r['policy'] == policy and r['arm'] == 'obfuscated']
        for col, (measure, label) in enumerate(zip(measures, labels)):
            ax = axes[row, col]
            for op in OPS:
                d = next((r for r in data if r['operation'] == op and r['measure'] == measure), None)
                if d is None:
                    continue
                # Re-read the held-out row-level samples for an exact ECDF.
                rows, proto, levels = subsets[policy]
                vals = []
                for r in rows:
                    if r['arm'] != 'obfuscated' or r['txn_class'] != op or int(r['replicate']) not in proto['test_repetitions']:
                        continue
                    value = float(r['ack_ms'] if measure.startswith('ack') else r['clrt_ms'])
                    if measure.endswith('residual_ms'):
                        level_key = 'da_ms' if measure.startswith('ack') else 'gap_ms'
                        value -= evaluator.levels_attack.nearest(value, levels[level_key])
                    vals.append(value)
                x = np.sort(np.asarray(vals))
                y = np.arange(1, len(x) + 1) / len(x)
                ax.plot(x, y, color=COLORS[op], linewidth=.8, label=op)
            # Keep rare tails in the accompanying statistics table; use a shared
            # 99.5th-percentile display limit so the central distributions remain legible.
            all_values = []
            for op in OPS:
                drows, dproto, dlevels = subsets[policy]
                for item in drows:
                    if item['arm'] != 'obfuscated' or item['txn_class'] != op or int(item['replicate']) not in dproto['test_repetitions']:
                        continue
                    value = float(item['ack_ms'] if measure.startswith('ack') else item['clrt_ms'])
                    if measure.endswith('residual_ms'):
                        level_key = 'da_ms' if measure.startswith('ack') else 'gap_ms'
                        value -= evaluator.levels_attack.nearest(value, dlevels[level_key])
                    all_values.append(value)
            if all_values:
                q995 = float(np.percentile(all_values, 99.5))
                low = float(np.percentile(all_values, .5))
                pad = max((q995-low)*.04, .01)
                ax.set_xlim(low-pad, q995+pad)
            ax.set_ylim(0, 1.02)
            ax.grid(axis='y', color='.88', linewidth=.5)
            ax.spines[['top', 'right']].set_visible(False)
            ax.set_title(f'$D_A={da}$ ms', fontsize=8)
            if row == 3:
                ax.set_xlabel(label)
            if row == 0 and col == 1:
                ax.legend(frameon=False, fontsize=7, ncol=3, loc='lower right')
    fig.suptitle('Held-out packet-timing distributions by operation' + (' (after subtracting the nearest configured D_A/D_R choice)' if residual else ''), y=.995, fontsize=9)
    fig.text(.012, .5, 'Cumulative fraction (0–1)', va='center', rotation='vertical', fontsize=8)
    fig.tight_layout(rect=(.045, 0, 1, .98))
    stem = 'adaptive_residual_ecdf' if residual else 'adaptive_raw_ecdf'
    fig.savefig(out / f'{stem}.pdf', bbox_inches='tight')
    fig.savefig(out / f'{stem}.png', dpi=240, bbox_inches='tight')
    plt.close(fig)


def plot_variance(distribution_rows: list[dict], out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.55))
    for ax, measure, title in zip(axes, ('ack_ms', 'clrt_ms'), ('Request-to-ACK', 'CLRT')):
        for op in OPS:
            vals = []
            for da in (5, 10, 15, 20):
                policy = f'da{da}_gap1_joint_amp0p5'
                row = next(x for x in distribution_rows if x['policy'] == policy and x['arm'] == 'obfuscated'
                           and x['operation'] == op and x['measure'] == measure)
                vals.append(row['variance'])
            ax.plot((5, 10, 15, 20), vals, marker='o', markersize=3, color=COLORS[op], linewidth=.9, label=op)
        ax.set_title(title, fontsize=8)
        ax.set_xlabel('Configured $D_A$ center (ms)')
        ax.set_ylabel('Variance (ms$^2$; log scale)')
        ax.set_yscale('log')
        ax.set_xticks((5, 10, 15, 20))
        ax.grid(axis='y', color='.88', linewidth=.5)
        ax.spines[['top', 'right']].set_visible(False)
    axes[1].legend(frameon=False, fontsize=7, ncol=3)
    fig.tight_layout()
    fig.savefig(out / 'adaptive_timing_variance.pdf', bbox_inches='tight')
    fig.savefig(out / 'adaptive_timing_variance.png', dpi=240, bbox_inches='tight')
    plt.close(fig)


def plot_accuracy(inventory: list[dict], gaps: list[dict], out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.8))
    for ax, task, title, threshold in zip(axes, ('three_class', 'read_select'),
        ('READ / SELECT / OPERATE', 'READ / SELECT'), (1/3+.05, .55)):
        for family, feature_set, linestyle in (('ACK/CLRT', PRIMARY_FEATURES, '-'),
                                                ('Includes request gap', {'request_gap', 'ack_clrt_gap'}, '--')):
            source = inventory if family == 'ACK/CLRT' else gaps
            marker = 'o' if family == 'ACK/CLRT' else 's'
            for pool, color in ((1, '#999999'), (5, '#E69F00'), (20, '#0072B2')):
                x, y = [], []
                for da in (5, 10, 15, 20):
                    policy = f'da{da}_gap1_joint_amp0p5'
                    candidates = [r for r in source if r['policy'] == policy and r['task'] == task
                                  and int(r['pool']) == pool and r['feature'] in feature_set]
                    if not candidates:
                        continue
                    best = max(candidates, key=lambda r: float(r['accuracy']))
                    x.append(da); y.append(float(best['accuracy']))
                if x:
                    ax.plot(x, y, marker=marker, color=color, linewidth=.8,
                            linestyle=linestyle, markersize=3,
                            label=f'{family}, pool {pool}')
        ax.axhline(threshold, color='.35', linestyle=':', linewidth=.8)
        ax.set_title(title, fontsize=8)
        ax.set_xlabel('Configured $D_A$ center (ms)')
        ax.set_xticks((5, 10, 15, 20))
        ax.set_ylim(.30, 1.03)
        ax.grid(axis='y', color='.88', linewidth=.5)
        ax.spines[['top', 'right']].set_visible(False)
    axes[0].set_ylabel('Best held-out adaptive balanced accuracy')
    axes[1].legend(frameon=False, fontsize=5.8, ncol=2, loc='lower right')
    fig.tight_layout()
    fig.savefig(out / 'adaptive_accuracy_by_pool.pdf', bbox_inches='tight')
    fig.savefig(out / 'adaptive_accuracy_by_pool.png', dpi=240, bbox_inches='tight')
    plt.close(fig)


def plot_pca(policy_data: dict, winners: dict, out: Path) -> list[dict]:
    summaries = []
    for pool in (1, 5, 20):
        fig, axes = plt.subplots(4, 2, figsize=(7.16, 6.2), sharex=False, sharey=False)
        for row_index, da in enumerate((5, 10, 15, 20)):
            policy = f'da{da}_gap1_joint_amp0p5'
            for col, task in enumerate(('three_class', 'read_select')):
                ax = axes[row_index, col]
                rows, protocol, levels, result = policy_data[(policy, task, pool)]
                winner = winners[(policy, task, pool)]
                predictions = read_predictions(winner)
                train = evaluator.split_rows(rows, protocol, 'training')
                test = evaluator.split_rows(rows, protocol, 'test')
                spec = dict(classes=winner['class_order'], representation=winner['representation'],
                            pool=winner['pool'], feature=winner['feature'])
                train_pooled = evaluator.pooled(train, spec, levels, 'obfuscated')
                joined, test_matrix, feature_names = exact_test_vectors(test, winner, levels, predictions)
                train_matrix = evaluator.base.a._pooled_feature_matrix(train_pooled, winner['feature'])
                imputer = SimpleImputer(strategy='median')
                scaler = StandardScaler()
                train_scaled = scaler.fit_transform(imputer.fit_transform(train_matrix))
                test_scaled = scaler.transform(imputer.transform(test_matrix))
                pca = PCA(n_components=2, svd_solver='full')
                train_xy = pca.fit_transform(train_scaled)
                test_xy = pca.transform(test_scaled)
                if train_xy.shape[1] != 2:
                    raise ValueError('PCA did not produce two dimensions')
                for operation in winner['class_order']:
                    for correct in (True, False):
                        ids = [i for i, x in enumerate(joined)
                               if x['txn_class'] == operation and x['correct'] is correct]
                        if not ids:
                            continue
                        xy = test_xy[ids]
                        ax.scatter(xy[:, 0], xy[:, 1], s=5, alpha=.33 if pool == 1 else .55,
                            c=COLORS[operation], marker=MARKERS['correct' if correct else 'incorrect'],
                            linewidths=.35, label=operation if correct and row_index == 0 else None)
                acc = float(winner['mean_accuracy'])
                ax.set_title(f'$D_A={da}$ ms; {task.replace("_", " ")}\n{winner["model"]}/{winner["representation"]}; BA={acc:.3f}', fontsize=6.6)
                ax.set_xlabel(f'PC1 ({100*pca.explained_variance_ratio_[0]:.1f}%)', fontsize=6.2)
                ax.set_ylabel(f'PC2 ({100*pca.explained_variance_ratio_[1]:.1f}%)', fontsize=6.2)
                ax.tick_params(labelsize=5.8)
                ax.grid(color='.9', linewidth=.4)
                summaries.append(dict(policy=policy, da_ms=da, task=task, pool=pool,
                    model=winner['model'], representation=winner['representation'], feature=winner['feature'],
                    accuracy=acc, class_order=winner['class_order'], confusion=winner['confusion_matrix'],
                    feature_names=feature_names, explained_variance=pca.explained_variance_ratio_.tolist(),
                    training_n=len(train_pooled), heldout_n=len(joined),
                    pca_training_rows_sha256=hashlib.sha256(train_scaled.tobytes()).hexdigest()))
        # One class legend per figure; correctness is encoded by circle versus x.
        handles, labels = axes[0, 0].get_legend_handles_labels()
        if handles:
            fig.legend(handles, labels, frameon=False, fontsize=7, loc='upper center', bbox_to_anchor=(.5, .945), ncol=3)
        fig.suptitle(f'Adaptive attacker feature clusters; pool size {pool}', y=.995, fontsize=8)
        fig.text(.5, .966, 'Color = true operation; circle = correct, x = incorrect', ha='center', fontsize=7)
        fig.tight_layout(rect=(0, 0, 1, .935))
        fig.savefig(out / f'adaptive_clusters_pool{pool}.pdf', bbox_inches='tight')
        fig.savefig(out / f'adaptive_clusters_pool{pool}.png', dpi=240, bbox_inches='tight')
        plt.close(fig)
    return summaries


def plot_confusions(policy_results: dict, out: Path) -> None:
    fig, axes = plt.subplots(2, 4, figsize=(7.16, 3.6))
    for row, task in enumerate(('three_class', 'read_select')):
        for col, da in enumerate((5, 10, 15, 20)):
            policy = f'da{da}_gap1_joint_amp0p5'
            rec = policy_results[(policy, task, 20)]
            cm = np.asarray(rec['confusion_matrix'])
            labels = rec['class_order']
            ax = axes[row, col]
            ax.imshow(cm, cmap='Blues', interpolation='nearest')
            for i in range(len(labels)):
                for j in range(len(labels)):
                    ax.text(j, i, str(int(cm[i, j])), ha='center', va='center', fontsize=6,
                            color='white' if cm[i, j] > cm.max() * .55 else '#222222')
            ax.set_xticks(range(len(labels)), labels, rotation=35, ha='right', fontsize=5.5)
            ax.set_yticks(range(len(labels)), labels, fontsize=5.5)
            ax.set_xlabel('Predicted', fontsize=6)
            ax.set_ylabel('Actual', fontsize=6)
            ax.set_title(f'$D_A={da}$ ms; BA={rec["mean_accuracy"]:.3f}', fontsize=7)
    fig.suptitle('Confusion matrices: strongest post-only ACK/CLRT attack, pool 20', y=.995, fontsize=8)
    fig.tight_layout(rect=(0, 0, 1, .96))
    fig.savefig(out / 'adaptive_confusions_pool20.pdf', bbox_inches='tight')
    fig.savefig(out / 'adaptive_confusions_pool20.png', dpi=240, bbox_inches='tight')
    plt.close(fig)


def make_report(out: Path, inventory: list[dict], gaps: list[dict],
                distribution_rows: list[dict], winners: dict) -> str:
    lines = [
        '# Adaptive classifier diagnostics', '',
        'This bundle is a read-only analysis of held-out rounds 40–99 from the matched delay grid. '
        'It reads the frozen transaction rows, trained-model score records, and prediction ledgers. '
        'It does not train or modify attack models, P4, acquisition scripts, or the manuscript.', '',
        '## What the classifier is recovering', '',
        'The ACK/CLRT adaptive classifiers are trained only on Obfuscated (protected) traffic from rounds 0–39. '
        'Their held-out inputs are rounds 40–99. One attacker uses the measured times directly. A second '
        'attacker is assumed to know the configured timing settings, estimates the nearest delay step, '
        'and subtracts it; it still does not know the random choice for an individual packet. For pool '
        'sizes above one, the classifier summarizes multiple samples from the same operation using their '
        'mean, standard deviation, minimum, and maximum.', '',
        'The strongest pool-20 post-only ACK/CLRT models and their per-class recalls are listed in '
        '`adaptive_attack_inventory.csv`; `adaptive_confusions_pool20.pdf` shows their prediction errors. '
        'The PCA panels use those models’ exact feature representation, with the projection fit on '
        'training rounds only. PCA is a descriptive view; classifier scores remain those in the frozen ledgers.', '',
        'The ECDF figures compare held-out protected ACK/CLRT distributions by true operation and '
        'show the times after the nearest configured delay step has been subtracted. `timing_distributions.csv` includes standard deviations, '
        'variances, quantiles, and tails for both Obfuscated and paired Timing OFF traffic. '
        '`pooled_feature_distributions.csv` conditions the exact winning model inputs on actual label, '
        'predicted label, and correctness.', '',
        '## Main held-out results', '',
        'For pool 20, the strongest three-class ACK/CLRT balanced accuracies at $D_A=5,10,15,20$ ms '
        'are 0.553, 0.654, 0.423, and 0.429. The corresponding READ/SELECT balanced accuracies '
        'are 0.562, 0.588, 0.562, and 0.555. At 10 ms, the three-class model has recalls '
        '0.463 (READ), 0.600 (SELECT), and 0.900 (OPERATE): the aggregate score hides a strong '
        'OPERATE result and substantial READ/SELECT confusion. At 15 ms, the binary model recalls '
        'only 0.140 of READ but 0.983 of SELECT; its 0.562 balanced accuracy should not be read '
        'as balanced success on both classes.', '',
        'The request-gap diagnostic is much stronger with pooling (three-class balanced accuracy '
        'approaches 0.99 at pool 20), but the acquisition schedule itself groups READs with 400 ms '
        'waits and runs SELECT→OPERATE immediately. That result indicates schedule leakage in this '
        'trace and is not evidence that ACK/CLRT timing alone supports that accuracy.', '',
        'Raw ACK variance is about 0.135–0.141 ms² across settings (SD about 0.367–0.376 ms). '
        'Raw CLRT variance is larger at smaller $D_A$ because it includes the randomized delay-level '
        'spread; it must not be interpreted as within-step noise. The after-subtraction ECDFs '
        'and corresponding rows in `timing_distributions.csv` show the remaining timing variation. '
        'Variance alone does not establish attacker resistance; the held-out confusion matrices and '
        'balanced accuracies show what these frozen classifiers recovered.', '',
        '## Separate request-gap channel', '',
        'Request-gap classifiers are post-only adaptive diagnostics and are not part of the primary '
        'ACK/CLRT criterion. Their scores and per-class recalls are in `request_gap_attack_inventory.csv`. '
        'The observed gap distributions are in `timing_distributions.csv`. Interpret these scores '
        'against the campaign’s grouped READ sequence, 400 ms waits, and immediate SELECT→OPERATE '
        'procedure; this is evidence about the recorded workload, not proof of identical leakage under '
        'every field workload.', '',
        '## How to read the cluster plots', '',
        'Each point is a held-out pooled signature. Color is the true operation; circles were classified '
        'correctly and x marks were misclassified. PCA is trained on the corresponding Obfuscated training '
        'rounds and then applied to held-out points. Different panels can use different screened model '
        'families/representations, as noted in each panel title. The first two PCs may omit signal used '
        'by the original higher-dimensional classifier, so visible overlap or separation is not itself '
        'a test of attacker success.', '',
        '## Limits', '',
        '- The experiment uses one SEL-751A and predicts operation labels; it does not test cross-device identity classification.',
        '- Same-operation pooling uses the visible operation labels to form groups. Pool-20 results assume the attacker can collect and group 20 samples of a known operation.',
        '- Held-out feature distributions describe the tested workload. They do not identify switch-arrival deadline misses or prove that late replies caused the classification scores.',
        '- Best-per-pool rows are descriptive maxima over the frozen screened attack inventory. The preregistered simultaneous bounds, not these descriptive plots, determine the original pass/fail result.',
        '', '## Artifacts', '',
        '- `adaptive_attack_inventory.csv`: all post-only adaptive ACK/CLRT records.',
        '- `adaptive_best_by_pool.csv`: strongest frozen adaptive ACK/CLRT record for each policy, task, and pool size.',
        '- `request_gap_attack_inventory.csv`: adaptive request-gap and combined-feature diagnostics.',
        '- `timing_distributions.csv`: held-out class-conditional feature statistics.',
        '- `pooled_feature_distributions.csv`: feature summaries conditioned on true/predicted class and correctness.',
        '- `adaptive_timing_variance.pdf`: held-out ACK and CLRT variance by operation and delay; SD is included in the CSV.',
        '- `adaptive_clusters_pool{1,5,20}.pdf`: train-fitted PCA of the exact held-out adaptive model inputs.',
        '- `adaptive_confusions_pool20.pdf`: held-out confusion matrices for the strongest ACK/CLRT adaptive model per policy/task.',
        '- `provenance.json`: source hashes and audit status.', ''
    ]
    return '\n'.join(lines)


def run(run_dir: Path, results: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    audit_path = results / 'independent_audit.json'
    audit = json.loads(audit_path.read_text())
    if audit.get('status') != 'passed':
        raise ValueError('Independent source audit has not passed')
    measurement = results / 'final/measurements.json'
    transactions = results / 'final/primarytransactions.csv'
    grid_doc = json.loads((results / 'grid_attacks.json').read_text())
    if sha(measurement) != grid_doc['measurements_sha256'] or sha(transactions) != grid_doc['transactions_sha256']:
        raise ValueError('Frozen grid inputs do not match score records')
    protocol, subsets = grid_analysis.load(run_dir, measurement, transactions, complete=True)
    results_by_policy, plans, policy_data = {}, {}, {}
    for policy, (rows, policy_protocol, levels) in subsets.items():
        result_path = results / policy / 'final/attacks_heldout.json'
        result = json.loads(result_path.read_text())
        expected_hash = grid_doc['policy_results_sha256'][policy]
        if sha(result_path) != expected_hash:
            raise ValueError(f'Frozen policy score hash mismatch: {policy}')
        results_by_policy[policy] = result
        plans[policy] = json.loads((run_dir / 'plans' / f'{policy}.json').read_text())
        for task in ('three_class', 'read_select'):
            for pool in (1, 5, 20):
                policy_data[(policy, task, pool)] = (rows, policy_protocol, levels, result)

    inventory, winners = pool_inventory_rows(results_by_policy)
    gap_inventory = gap_inventory_rows(results_by_policy)
    timing_rows = timing_distribution_rows(subsets, plans)
    feature_rows = pooled_distribution_rows(policy_data, winners)
    write_csv(out / 'adaptive_attack_inventory.csv', inventory)
    best_rows = []
    winner_records = {}
    for (policy, task, pool), winner in winners.items():
        best_rows.append(dict(policy=policy, da_ms=plans[policy]['center_da_ms'], task=task, pool=pool,
            scenario=winner['scenario'], model=winner['model'], representation=winner['representation'],
            feature=winner['feature'], mean_accuracy=winner['mean_accuracy'],
            per_class_recall=json.dumps(dict(zip(winner['class_order'], winner['per_class_recall']))),
            confusion_matrix=json.dumps(winner['confusion_matrix']),
            fold_scores=json.dumps(winner['fold_scores']), predictions_sha256=winner['predictions_sha256']))
        winner_records[(policy, task, pool)] = winner
    write_csv(out / 'adaptive_best_by_pool.csv', best_rows)
    write_csv(out / 'request_gap_attack_inventory.csv', gap_inventory)
    write_csv(out / 'timing_distributions.csv', timing_rows)
    write_csv(out / 'pooled_feature_distributions.csv', feature_rows)
    plot_ecdfs(timing_rows, out, subsets, residual=False)
    plot_ecdfs(timing_rows, out, subsets, residual=True)
    plot_variance(timing_rows, out)
    plot_accuracy(inventory, gap_inventory, out)
    pca_summaries = plot_pca(policy_data, winners, out)
    (out / 'adaptive_pca_summary.json').write_text(json.dumps(pca_summaries, indent=2) + '\n')
    plot_confusions(winner_records, out)
    source_paths = [Path(__file__), measurement, transactions, results / 'grid_attacks.json',
        audit_path, Path(grid_analysis.__file__), Path(evaluator.__file__),
        Path(evaluator.base.a.__file__), Path(evaluator.levels_attack.__file__)]
    for policy in protocol['policy_names']:
        source_paths.extend([results / policy / 'final/attacks_heldout.json',
                             results / policy / 'models/models.json',
                             run_dir / 'plans' / f'{policy}.json'])
    # Hash only ledgers used by the selected visualizations and summary inventories.
    for policy, result in results_by_policy.items():
        for task in ('three_class', 'read_select'):
            for record in attack_records(result, task):
                if record['scenario'] in PRIMARY_SCENARIOS or (record['scenario'] == 'adaptive_on_obfuscated'
                    and record['feature'] in {'request_gap', 'ack_clrt_gap'}):
                    source_paths.append(Path(record['predictions']))
    provenance = dict(status='complete', audit_status=audit['status'],
        measurements_sha256=sha(measurement), transactions_sha256=sha(transactions),
        grid_attacks_sha256=sha(results / 'grid_attacks.json'),
        sources={str(p.resolve()): sha(p) for p in sorted(set(source_paths))},
        train_rounds=protocol['training_rounds'], heldout_rounds=protocol['test_rounds'],
        note='Read-only diagnostics; frozen prediction outputs are re-used. PCA imputer, scaler and components fit only on each attack’s training rounds. PCA is descriptive, not a classifier or a significance test.')
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (out / 'README.md').write_text(make_report(out, inventory, gap_inventory, timing_rows, winner_records))
    generated = sorted(p for p in out.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    (out / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in generated))
    print(json.dumps(dict(status='complete', outputs=len(generated), adaptive_records=len(inventory),
        gap_records=len(gap_inventory), timing_summaries=len(timing_rows), pooled_feature_summaries=len(feature_rows),
        pca_panels=len(pca_summaries)), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    run(args.run.resolve(), args.results.resolve(), args.out.resolve())
