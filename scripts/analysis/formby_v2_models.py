#!/usr/bin/env python3
"""Classifier fits for formby_eval_v2: declared tie rule, per-fit convergence state and fold-local H for the FF-ANN.

The estimators are the v1 ones (scripts/analysis/formby_eval.py, imported unchanged): Formby Eq. 1 histograms with
MultinomialNB (alpha 1), a 3-component full-covariance GMM on window [mean, variance] with Hungarian label matching,
and a one-hidden-layer MLP on K-normalised histograms. What v2 adds:
  * every fit returns per-class scores in CLASSES order (NB: joint log-likelihood; GMM and FF-ANN: probability) and
    the prediction comes from decide(), not from scikit-learn's predict();
  * convergence is recorded per fit (n_iter_, max_iter and any ConvergenceWarning raised inside that fit);
  * FF-ANN hidden size is chosen by GroupKFold over the training blocks only, with H refitted inside every fold.
"""
import hashlib
import warnings

import numpy as np
from scipy.optimize import linear_sum_assignment
from sklearn.exceptions import ConvergenceWarning
from sklearn.mixture import GaussianMixture
from sklearn.model_selection import GroupKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier

from formby_eval import CLASSES, HIDDEN_SIZES, histogram, moments

TIE_TOLERANCE = 1e-9
ANN_MAX_ITER = 2000
TIE_RULE = ('classes whose score is within %g of the row maximum are tied; the tie goes to the first of them in the '
            'fixed order READ, SELECT, OPERATE; a window whose top-two margin is below %g counts as a near-tie'
            % (TIE_TOLERANCE, TIE_TOLERANCE))


def decide(scores):
    """Predicted class per row of an (n, 3) score array in CLASSES order, and the top-two margin per row."""
    scores = np.asarray(scores, dtype=float)
    top = scores.max(axis=1, keepdims=True)
    choice = (scores > top - TIE_TOLERANCE).argmax(axis=1)
    ordered = np.sort(scores, axis=1)
    return [CLASSES[i] for i in choice], ordered[:, -1] - ordered[:, -2]


def reorder(model_classes, scores):
    """Columns of a scikit-learn score array (classes_ in sorted order) rearranged into CLASSES order."""
    model_classes = list(model_classes)
    return np.asarray(scores, dtype=float)[:, [model_classes.index(c) for c in CLASSES]]


def array_sha256(*arrays):
    digest = hashlib.sha256()
    for array in arrays:
        digest.update(np.ascontiguousarray(array, dtype=float).tobytes())
    return digest.hexdigest()


def captured(fit):
    """Run fit() and return its result with the ConvergenceWarning messages raised inside it; other warnings pass."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        result = fit()
    messages = []
    for item in caught:
        if issubclass(item.category, ConvergenceWarning):
            messages.append(str(item.message))
        else:
            warnings.warn_explicit(item.message, item.category, item.filename, item.lineno)
    return result, messages


def labels(windows):
    return [w['operation'] for w in windows]


def windows_high(windows, fields):
    """H per field: 1.05 x the largest value in these (training) windows."""
    return {f: max(1e-3, 1.05 * max(max(w['values'][f]) for w in windows)) for f in fields}


def signatures(windows, fields, highs):
    """Formby Eq. 1 count vector per window; a two-field feature concatenates its two histograms (v1 joint)."""
    return np.array([np.concatenate([histogram(w['values'][f], highs[f]) for f in fields]) for w in windows])


def fit_nb(train, fields, highs):
    model = MultinomialNB(alpha=1.0).fit(signatures(train, fields, highs), labels(train))
    log_prob = reorder(model.classes_, model.feature_log_prob_.T).T
    params = dict(alpha=1.0, high=highs, score='joint log-likelihood',
                  class_count=dict(zip(CLASSES, reorder(model.classes_, [model.class_count_])[0].tolist())),
                  class_log_prior=dict(zip(CLASSES, reorder(model.classes_, [model.class_log_prior_])[0].tolist())),
                  feature_log_prob_sha256=array_sha256(log_prob))
    state = dict(converged=True, iterative=False, n_iter=None, max_iter=None, warnings=[])

    def score(test):
        return reorder(model.classes_, model.predict_joint_log_proba(signatures(test, fields, highs)))
    return score, params, state


def fit_gmm(train, seed):
    """Formby's unsupervised GMM on raw window [mean, variance]; component-to-class map from training labels."""
    x = moments(train, None)
    model = GaussianMixture(3, covariance_type='full', random_state=seed, reg_covar=1e-6, n_init=10)
    model, messages = captured(lambda: model.fit(x))
    cost = np.zeros((3, 3))
    for component, window in zip(model.predict(x), train):
        cost[component, CLASSES.index(window['operation'])] -= 1
    rows, cols = linear_sum_assignment(cost)
    column = [int(r) for _, r in sorted(zip(cols, rows))]    # component carrying CLASSES[i]
    params = dict(score='posterior probability of the mapped component',
                  component_for_class=dict(zip(CLASSES, column)), weights=model.weights_.tolist(),
                  means=model.means_.tolist(), covariances_sha256=array_sha256(model.covariances_),
                  lower_bound=float(model.lower_bound_))
    state = dict(converged=bool(model.converged_) and not messages, sklearn_converged=bool(model.converged_),
                 n_iter=int(model.n_iter_), max_iter=int(model.max_iter), warnings=messages, n_init=10)

    def score(test):
        return model.predict_proba(moments(test, None))[:, column]
    return score, params, state


def ann_inputs(windows, fields, highs, k):
    return signatures(windows, fields, highs) / float(k)


def ann_fit_once(x, y, hidden, seed, max_iter=ANN_MAX_ITER):
    """One MLP fit; converged means n_iter_ < max_iter and no ConvergenceWarning inside this fit."""
    model = MLPClassifier(hidden_layer_sizes=(hidden,), max_iter=max_iter, random_state=seed)
    model, messages = captured(lambda: model.fit(x, y))
    state = dict(converged=bool(model.n_iter_ < max_iter and not messages), n_iter=int(model.n_iter_),
                 max_iter=int(max_iter), warnings=messages)
    return model, state


def class_mean_recall(truth, prediction):
    truth, prediction = np.asarray(truth), np.asarray(prediction)
    return float(np.mean([np.mean(prediction[truth == c] == c) for c in CLASSES if (truth == c).any()]))


def fit_ann(train, fields, k, seed):
    """Hidden size by GroupKFold over training blocks (H refitted per inner fold); final fit on all training windows."""
    y = np.array(labels(train))
    groups = np.array([w['block_id'] for w in train])
    splitter = GroupKFold(n_splits=min(5, len(set(groups))))
    cv = []
    for hidden in HIDDEN_SIZES:
        for fold, (fit_i, val_i) in enumerate(splitter.split(np.zeros((len(train), 1)), y, groups)):
            fit_w, val_w = [train[i] for i in fit_i], [train[i] for i in val_i]
            highs = windows_high(fit_w, fields)
            model, state = ann_fit_once(ann_inputs(fit_w, fields, highs, k), y[fit_i], hidden, seed)
            prediction, _ = decide(reorder(model.classes_, model.predict_proba(ann_inputs(val_w, fields, highs, k))))
            cv.append(dict(hidden=hidden, fold=fold, fit_blocks=sorted(set(groups[fit_i])),
                           validation_blocks=sorted(set(groups[val_i])), high=highs,
                           validation_ba=class_mean_recall(y[val_i], prediction), **state))
    mean_ba = {h: float(np.mean([c['validation_ba'] for c in cv if c['hidden'] == h])) for h in HIDDEN_SIZES}
    best = HIDDEN_SIZES[0]
    for hidden in HIDDEN_SIZES[1:]:
        if mean_ba[hidden] > mean_ba[best]:     # a tie keeps the earlier (smaller) size
            best = hidden
    highs = windows_high(train, fields)
    model, state = ann_fit_once(ann_inputs(train, fields, highs, k), y, best, seed)
    state.update(inner_fits=len(cv), inner_converged=sum(c['converged'] for c in cv))
    params = dict(score='predicted probability', hidden=best, high=highs, loss=float(model.loss_),
                  validation_ba_by_hidden={str(h): v for h, v in mean_ba.items()}, input_scale='histogram counts / K',
                  weights_sha256=array_sha256(*model.coefs_, *model.intercepts_), cv=cv)

    def score(test):
        return reorder(model.classes_, model.predict_proba(ann_inputs(test, fields, highs, k)))
    return score, params, state
