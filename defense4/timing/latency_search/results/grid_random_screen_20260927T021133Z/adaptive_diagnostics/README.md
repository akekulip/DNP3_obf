# Adaptive classifier diagnostics

This bundle is a read-only analysis of held-out rounds 40–99 from the matched delay grid. It reads the frozen transaction rows, trained-model score records, and prediction ledgers. It does not train or modify attack models, P4, acquisition scripts, or the manuscript.

## What the classifier is recovering

The ACK/CLRT adaptive classifiers are trained only on Obfuscated (protected) traffic from rounds 0–39. Their held-out inputs are rounds 40–99. One attacker uses the measured times directly. A second attacker is assumed to know the configured timing settings, estimates the nearest delay step, and subtracts it; it still does not know the random choice for an individual packet. For pool sizes above one, the classifier summarizes multiple samples from the same operation using their mean, standard deviation, minimum, and maximum.

The strongest pool-20 post-only ACK/CLRT models and their per-class recalls are listed in `adaptive_attack_inventory.csv`; `adaptive_confusions_pool20.pdf` shows their prediction errors. The PCA panels use those models’ exact feature representation, with the projection fit on training rounds only. PCA is a descriptive view; classifier scores remain those in the frozen ledgers.

The ECDF figures compare held-out protected ACK/CLRT distributions by true operation and show the times after the nearest configured delay step has been subtracted. `timing_distributions.csv` includes standard deviations, variances, quantiles, and tails for both Obfuscated and paired Timing OFF traffic. `pooled_feature_distributions.csv` conditions the exact winning model inputs on actual label, predicted label, and correctness.

## Main held-out results

For pool 20, the strongest three-class ACK/CLRT balanced accuracies at $D_A=5,10,15,20$ ms are 0.553, 0.654, 0.423, and 0.429. The corresponding READ/SELECT balanced accuracies are 0.562, 0.588, 0.562, and 0.555. At 10 ms, the three-class model has recalls 0.463 (READ), 0.600 (SELECT), and 0.900 (OPERATE): the aggregate score hides a strong OPERATE result and substantial READ/SELECT confusion. At 15 ms, the binary model recalls only 0.140 of READ but 0.983 of SELECT; its 0.562 balanced accuracy should not be read as balanced success on both classes.

The request-gap diagnostic is much stronger with pooling (three-class balanced accuracy approaches 0.99 at pool 20), but the acquisition schedule itself groups READs with 400 ms waits and runs SELECT→OPERATE immediately. That result indicates schedule leakage in this trace and is not evidence that ACK/CLRT timing alone supports that accuracy.

Raw ACK variance is about 0.135–0.141 ms² across settings (SD about 0.367–0.376 ms). Raw CLRT variance is larger at smaller $D_A$ because it includes the randomized delay-level spread; it must not be interpreted as within-step noise. The after-subtraction ECDFs and corresponding rows in `timing_distributions.csv` show the remaining timing variation. Variance alone does not establish attacker resistance; the held-out confusion matrices and balanced accuracies show what these frozen classifiers recovered.

## Separate request-gap channel

Request-gap classifiers are post-only adaptive diagnostics and are not part of the primary ACK/CLRT criterion. Their scores and per-class recalls are in `request_gap_attack_inventory.csv`. The observed gap distributions are in `timing_distributions.csv`. Interpret these scores against the campaign’s grouped READ sequence, 400 ms waits, and immediate SELECT→OPERATE procedure; this is evidence about the recorded workload, not proof of identical leakage under every field workload.

## How to read the cluster plots

Each point is a held-out pooled signature. Color is the true operation; circles were classified correctly and x marks were misclassified. PCA is trained on the corresponding Obfuscated training rounds and then applied to held-out points. Different panels can use different screened model families/representations, as noted in each panel title. The first two PCs may omit signal used by the original higher-dimensional classifier, so visible overlap or separation is not itself a test of attacker success.

## Limits

- The experiment uses one SEL-751A and predicts operation labels; it does not test cross-device identity classification.
- Same-operation pooling uses the visible operation labels to form groups. Pool-20 results assume the attacker can collect and group 20 samples of a known operation.
- Held-out feature distributions describe the tested workload. They do not identify switch-arrival deadline misses or prove that late replies caused the classification scores.
- Best-per-pool rows are descriptive maxima over the frozen screened attack inventory. The preregistered simultaneous bounds, not these descriptive plots, determine the original pass/fail result.

## Artifacts

- `adaptive_attack_inventory.csv`: all post-only adaptive ACK/CLRT records.
- `adaptive_best_by_pool.csv`: strongest frozen adaptive ACK/CLRT record for each policy, task, and pool size.
- `request_gap_attack_inventory.csv`: adaptive request-gap and combined-feature diagnostics.
- `timing_distributions.csv`: held-out class-conditional feature statistics.
- `pooled_feature_distributions.csv`: feature summaries conditioned on true/predicted class and correctness.
- `adaptive_timing_variance.pdf`: held-out ACK and CLRT variance by operation and delay; SD is included in the CSV.
- `adaptive_clusters_pool{1,5,20}.pdf`: train-fitted PCA of the exact held-out adaptive model inputs.
- `adaptive_confusions_pool20.pdf`: held-out confusion matrices for the strongest ACK/CLRT adaptive model per policy/task.
- `provenance.json`: source hashes and audit status.
