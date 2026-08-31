> **Historical.** Figure from the retired `final_read_sbo` dataset (six captures, one session, size shaping active in both arms). Superseded by `paper/rewrite/figures/ndss/`. Do not quote as current.

### fig03_timing_feature_overlap_before_after

Timing-feature overlap with the in-network timing mechanism disabled and enabled. Each point is one transaction, placed by the two latencies a passive observer can measure master-facing: request-to-ACK on the horizontal axis and ACK-to-response (CLRT) on the vertical. Left, timing mode off: READ and the SELECT phase of SBO occupy visibly different regions. Right, timing mode on: both classes collapse onto a single point and are no longer separable by these features; the inset magnifies that point. This is a display of feature overlap between two transaction classes on one relay, not a clustering result and not device identification; no unsupervised algorithm is fitted.

**Statistics.** Raw per-transaction features: no scaling, no projection, no subsampling, every analysed transaction plotted. Cold-start transactions excluded as in Figure 1. Axis limits are shared between panels so the collapse is a like-for-like comparison; the horizontal limit is the 99.9th percentile of the pooled feature, which keeps a few extreme points from compressing both panels.
