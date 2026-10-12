# T outcome elision experiment

This isolated experiment starts from `combined_nt_01` and removes only T's
final outcome-counter sink. The semantic verdict actions still call
`count(code)`, but `count()` is a no-op and the `outcomes` register plus
`outcome_count` table are absent. N and E are byte-identical to the combined
N/T experiment.

Local SDK 9.13.1 compile passes. BFA placement is **N11/E12/T10**:

- Source: `evidence/full_01/response_only.p4`
- Source SHA-256: `b5bd2a395baa1ee1299ff6f33a2b2d8b5e2d328a96921e6fe2f0d11454b1ce28`
- Compiler: `p4c 9.13.1 (SHA: e558d01)`
- Stage evidence: `evidence/full_01/bfa_stage_counts.json`

Filtered source behavior checks pass 33/33 after excluding the nine inherited
assertions that read the removed T `outcomes` register. The excluded checks are
observability assertions; the retained checks cover N residue rejection,
same-tuple lifecycle, old packets/tokens that do not rely on outcome-counter
reads, READ/SBO packet behavior, stale RESET, Work ownership, and T lifetime
bounds.

This is not a candidate55 integration. It trades away T outcome-counter
observability for one additional T stage reduction, so it needs an explicit
review before any hardware candidate uses it.
