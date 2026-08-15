# S3 Offline Claim Matrix

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Fixed public wire length | PASS | observer_outer_cells.csv has one 256-byte wire size for in-policy epochs |
| Fixed cell count and schedule | PASS | 22 cells per epoch with fixed slot offsets |
| No public length/type/count signal | PASS | observer_stats.json MI and classifier gate |
| Primary RN-L classifier bound | PASS | chance=0.2; models=dummy_most_frequent,logistic_regression,random_forest |
| Adversarial codec faults | PASS | loss, duplicate, reorder, replay, tag, public metadata, private metadata, overflow, nonce restart |
| OpenDNP3 overflow honesty | PASS | full pcapng transaction retained as fail-closed overflow; response-only projection is separately labeled |
| Hardware claim | NOT CLAIMED | S3 is offline evidence only; no SSH/testbed action |
