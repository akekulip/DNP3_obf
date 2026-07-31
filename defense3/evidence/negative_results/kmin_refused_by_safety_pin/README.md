# K-minimization runs REFUSED by the K=64 safety pin — NOT experimental data

These three Gate-2 directories (K=32, K=16, K=8) are **harness-refusal records, not
K-minimization measurements**. The setup's `offline_checks` deliberately pins `K == 64` for
hold-armed trials (it opens only for READ-only fail-open trials), so a reduced-K Gate-2 config
was **refused before any transaction ran**. Every mechanism quantity is therefore `None` /
`INDETERMINATE` and the verdict is FAIL — the record of a *refusal*, not a *result*.

They are kept here (rather than deleted) only to document that the K=64 safety pin does its
job. They must **not** be mixed with valid Gate-2 evidence or read as a continuity/scalability
finding. A real K-continuity sweep is a deliberate post-freeze experiment that requires
explicitly relaxing that safety pin (see `../../final_silicon/*/remaining_10B_assessment.md`).
