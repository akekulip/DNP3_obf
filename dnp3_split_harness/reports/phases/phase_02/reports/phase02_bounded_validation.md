# Phase 02 — Bounded-Target Numerical Validation

Numerical check of the corrected bounded sampling. Expected Uniform(20,30) standard deviation: **2.8868 ms**. Uniformity is not claimed from the histogram alone -- the correlations with size and position (both ~0) and the per-position/per-size summaries are the evidence that the target is class-independent.

## bounded20-30/full

- n=250, unique targets=250, min=20.01, max=29.99
- mean=24.8575, median=24.6996, std=2.7347 (expected 2.8868)
- p5=20.57, p25=22.69, p75=27.16, p95=29.36
- **corr(target, response_size) = 0.0174**, **corr(target, transaction_position) = 0.0517** (both ~0 -> target independent of size and position)

Per transaction position (target mean / std / n):

- txn1_17B: mean=24.367 std=2.854 n=50 unique=50
- txn2_17B: mean=24.951 std=2.437 n=50 unique=50
- txn3_17B: mean=25.151 std=2.788 n=50 unique=50
- txn4_2407B: mean=24.953 std=2.718 n=50 unique=50
- txn5_1657B: mean=24.866 std=2.793 n=50 unique=50

Per response size (target mean / std / n):

- 17B: mean=24.823 std=2.720 n=150
- 1657B: mean=24.866 std=2.793 n=50
- 2407B: mean=24.953 std=2.718 n=50

## bounded20-30/crc-split

- n=250, unique targets=249, min=20.06, max=29.99
- mean=24.9237, median=24.8573, std=2.8370 (expected 2.8868)
- p5=20.48, p25=22.54, p75=27.53, p95=29.23
- **corr(target, response_size) = 0.0254**, **corr(target, transaction_position) = 0.0003** (both ~0 -> target independent of size and position)

Per transaction position (target mean / std / n):

- txn1_17B: mean=25.042 std=2.902 n=50 unique=50
- txn2_17B: mean=24.751 std=2.937 n=50 unique=50
- txn3_17B: mean=24.845 std=2.907 n=50 unique=50
- txn4_2407B: mean=25.120 std=2.983 n=50 unique=50
- txn5_1657B: mean=24.861 std=2.399 n=50 unique=50

Per response size (target mean / std / n):

- 17B: mean=24.879 std=2.918 n=150
- 1657B: mean=24.861 std=2.399 n=50
- 2407B: mean=25.120 std=2.983 n=50

