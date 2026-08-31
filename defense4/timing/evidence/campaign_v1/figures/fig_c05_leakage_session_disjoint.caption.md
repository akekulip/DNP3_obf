> **Historical.** First-pass campaign_v1 figure, superseded by `paper/rewrite/figures/ndss/`. Predates the read/control lane separation and the withdrawal of the jackknife and fold-bootstrap intervals. Do not quote as current.

### fig_c05_leakage_session_disjoint

**Transaction-class leakage under session-disjoint evaluation:** (a) balanced accuracy, (b) mutual information, over 22 leave-one-session-out folds.

**Statistics.** Leave-one-session-out cross-validation over 22 sessions; random forest, 120 trees, min_samples_leaf 5. Mutual information estimated per held-out session and summed over features. Three-class chance balanced accuracy is 1/3.
