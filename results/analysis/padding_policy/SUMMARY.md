# Padding-policy study (offline; no P4 or profile change)

Schema `c72-padding-policy-v1`. Rows `/home/philip/Projects/DNP3/results/analysis/evaluation/final/rows/rows.csv` (sha256 `29b028228c69245e`). Every statement below holds under the enumerated targets, framing rules and limits cited here; the files were checked at run time for the cited text.

## Rules and limits (file:line)

- `results/builds/c72/supported_profile.json:52-59`: native response octets: READ 91 (mixed) / 134 (integrity), SBO 49
- `results/builds/c72/supported_profile.json:60-60`: one SELECT/OPERATE image length (60) shared by both operations
- `results/builds/c72/supported_profile.json:62-75`: two READ targets: 91->141, 134->158
- `results/builds/c72/supported_profile.json:67-70`: SBO reframed as transport 15+17 application octets
- `results/builds/c72/supported_profile.json:77-80`: SBO image link frames [28, 32]
- `p4/profile_template.json:118-161`: READ images: prefix frame + unchanged native frame
- `p4/profile_template.json:162-168`: output lengths READ 141/158, SBO 60
- `scripts/model/dnp3_std.py:27-34`: one-octet LEN = 5 + user (<= 250)
- `scripts/model/dnp3_std.py:59-61`: frame length = 10 + u + 2*ceil(u/16)
- `scripts/model/dnp3_std.py:70-73`: G12V1 responses echo the request qualifiers
- `scripts/model/dnp3_std.py:196-203`: Rule 8: response objects equal the request objects
- `scripts/model/dnp3_std.py:252-254`: transport segment: 1..249 app octets
- `tests/fixtures/vectors/constants_two_read_relay.json:7-10`: reserved padding indices 1024..4095
- `tests/fixtures/vectors/constants_two_read_relay.json:15-15`: smallest prefix frame: 24 octets
- `tests/fixtures/vectors/constants_two_read_relay.json:42-56`: mixed: 26 points, 34 prefix user octets, 50-octet prefix
- `tests/fixtures/vectors/constants_two_read_relay.json:90-104`: integrity: 4 points, 12 prefix user octets, 24-octet prefix
- `scripts/model/read_policy_expect.py:264-277`: prefix = transport+app header/IIN+padobj_head; continuation = 4 zero points + native objects
- `scripts/model/relay_sbo_vectors.py:30-36`: SBO 15+17 reframing
- `scripts/model/model_relay_sbo.py:23-37`: SBO image keeps all 32 application octets
- `p4/response_only.p4:2125-2127`: P4 emits fixed 50-B/24-B prefix headers

## Reachable response totals (octets)

- Mixed READ (native 91), one prefix frame of u = 12..250 user octets (u - 8 <= 242 reserved points, inside 1024..4095): 91 or 115-119, 122-137, 140-155, 158-173, 176-191, 194-209, 212-227, 230-245, 248-263, 266-281, 284-299, 302-317, 320-335, 338-353, 356-371, 374-383.
- Integrity READ (native 134): 134 or 158-162, 165-180, 183-198, 201-216, 219-234, 237-252, 255-270, 273-288, 291-306, 309-324, 327-342, 345-360, 363-378, 381-396, 399-414, 417-426; the 24-octet prefix floor makes 158 the smallest padded total.
- SELECT/OPERATE (native 49), reframing of the 32 application octets only (witness partitions in the JSON; 60 is the implemented 15+17): 60, 62, 71, 73, 84, 86, 97, 99, 110, 112, 123, 125, 136, 138, 149, 151, 162, 164, 175, 177, 188, 190, 201, 203, 214, 216, 227, 229, 240, 242, 253, 255, 266, 279, 292, 305, 318, 331, 344, 357, 370, 383, 396, 409, 422, 435, 448.
- Mixed READ -> 158: attainable under the enumerated targets, framing rules and limits with a 67-octet prefix frame (u = 49 user octets, 41 reserved points).
- Alternatives other than (i) need new P4 prefix headers and constants (p4/response_only.p4:2125-2127 emits fixed 50-B/24-B prefixes); none was compiled or resource-checked here.

## Assignments and added bytes (d)

Ideal ceiling: if READ sizes remain separate from SBO and SELECT/OPERATE have identical size distributions, the ideal size-only three-class BA ceiling is 2/3. In general the bound is (classes with distinct size distributions) / (classes). Added bytes are response payload octets relative to native, over the 12352 retained off-arm exchanges.

| assignment | mixed | integrity | SELECT/OPERATE | attainable | ceiling 3-class | ceiling workload | added B/txn | req+resp % | resp % |
|---|---|---|---|---|---|---|---|---|---|
| native | 91 (+0) | 134 (+0) | 49 (+0) | True | 0.6667 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |
| current | 141 (+50) | 158 (+24) | 60 (+11) | True | 0.6667 | 1.0000 | 19.8238 | 18.2086 | 28.2091 |
| merged_read | 158 (+67) | 158 (+24) | 60 (+11) | True | 0.6667 | 0.5000 | 22.7306 | 20.8785 | 32.3454 |
| full_merge | 162 (+71) | 162 (+28) | 162 (+113) | True | 0.3333 | 0.5000 | 91.7254 | 84.2519 | 130.5242 |
| mixed_sbo_overlap | 123 (+32) | 158 (+24) | 123 (+74) | True | 0.6667 | 1.0000 | 58.5285 | 53.7598 | 83.2854 |

Reading the costs:
- merged_read adds 22.73 − 19.82 = +2.91 B per transaction, averaged over all 12,352 retained exchanges.
- Each affected mixed READ response grows by 17 B (141 to 158; +67 B over native 91 instead of +50).
- Integrity READ (158 B) and SELECT/OPERATE (60 B) stay unchanged.
- full_merge sets every response to 162 B (+91.73 B per transaction, +84.25% payload). It is listed for comparison
  and is not proposed.
- Every classifier figure here is balanced accuracy (BA), not plain accuracy. These are offline estimates; no P4 or
  profile change was made.

## Size-only NB on the off arm with mapped sizes (retrained, test reps 9-16)

BA [block-bootstrap 95% interval over test blocks]; n/a = unavailable.

operation classifier:

| assignment | D ms | K=8 | K=32 | K=64 |
|---|---|---|---|---|
| native | 5 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| native | 10 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| native | 15 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| native | 20 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| current | 5 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| current | 10 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| current | 15 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| current | 20 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| merged_read | 5 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| merged_read | 10 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| merged_read | 15 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| merged_read | 20 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| full_merge | 5 | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] |
| full_merge | 10 | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] |
| full_merge | 15 | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] |
| full_merge | 20 | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] | 0.333 [0.333, 0.333] |
| mixed_sbo_overlap | 5 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| mixed_sbo_overlap | 10 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| mixed_sbo_overlap | 15 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |
| mixed_sbo_overlap | 20 | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] | 0.667 [0.667, 0.667] |

workload classifier:

| assignment | D ms | K=8 | K=16 | K=32 | K=64 |
|---|---|---|---|---|---|
| native | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| merged_read | 5 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| merged_read | 10 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| merged_read | 15 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| merged_read | 20 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| full_merge | 5 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| full_merge | 10 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| full_merge | 15 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| full_merge | 20 | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | 0.500 [0.500, 0.500] | n/a |
| mixed_sbo_overlap | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |


## Joint CLRT+size on the combined arm: OFFLINE POLICY ESTIMATE ASSUMING UNCHANGED TIMING, NOT A HARDWARE RESULT

BA [block-bootstrap 95% interval over test blocks]; n/a = unavailable.

operation classifier:

| assignment | D ms | K=8 | K=32 | K=64 |
|---|---|---|---|---|
| native | 5 | 0.729 [0.667, 0.792] | 0.771 [0.667, 0.876] | 0.667 [0.500, 0.833] |
| native | 10 | 0.682 [0.646, 0.724] | 0.688 [0.604, 0.792] | 0.833 [0.708, 0.958] |
| native | 15 | 0.734 [0.667, 0.792] | 0.812 [0.729, 0.896] | 0.833 [0.708, 0.958] |
| native | 20 | 0.672 [0.641, 0.698] | 0.792 [0.729, 0.833] | 0.875 [0.750, 1.000] |
| current | 5 | 0.729 [0.667, 0.792] | 0.771 [0.667, 0.876] | 0.667 [0.500, 0.833] |
| current | 10 | 0.682 [0.646, 0.724] | 0.688 [0.604, 0.792] | 0.833 [0.708, 0.958] |
| current | 15 | 0.734 [0.667, 0.792] | 0.812 [0.729, 0.896] | 0.833 [0.708, 0.958] |
| current | 20 | 0.672 [0.641, 0.698] | 0.792 [0.729, 0.833] | 0.875 [0.750, 1.000] |
| merged_read | 5 | 0.729 [0.667, 0.792] | 0.771 [0.667, 0.876] | 0.667 [0.500, 0.833] |
| merged_read | 10 | 0.682 [0.646, 0.724] | 0.688 [0.604, 0.792] | 0.833 [0.708, 0.958] |
| merged_read | 15 | 0.734 [0.667, 0.792] | 0.812 [0.729, 0.896] | 0.833 [0.708, 0.958] |
| merged_read | 20 | 0.672 [0.641, 0.698] | 0.792 [0.729, 0.833] | 0.875 [0.750, 1.000] |
| full_merge | 5 | 0.385 [0.333, 0.443] | 0.354 [0.229, 0.521] | 0.375 [0.167, 0.583] |
| full_merge | 10 | 0.385 [0.344, 0.427] | 0.375 [0.292, 0.438] | 0.458 [0.333, 0.583] |
| full_merge | 15 | 0.391 [0.339, 0.448] | 0.417 [0.333, 0.500] | 0.458 [0.375, 0.583] |
| full_merge | 20 | 0.328 [0.286, 0.370] | 0.229 [0.145, 0.333] | 0.250 [0.125, 0.417] |
| mixed_sbo_overlap | 5 | 0.729 [0.667, 0.792] | 0.771 [0.667, 0.876] | 0.667 [0.500, 0.833] |
| mixed_sbo_overlap | 10 | 0.682 [0.646, 0.724] | 0.688 [0.604, 0.792] | 0.833 [0.708, 0.958] |
| mixed_sbo_overlap | 15 | 0.734 [0.667, 0.792] | 0.812 [0.729, 0.896] | 0.833 [0.708, 0.958] |
| mixed_sbo_overlap | 20 | 0.672 [0.641, 0.698] | 0.792 [0.729, 0.833] | 0.875 [0.750, 1.000] |

workload classifier:

| assignment | D ms | K=8 | K=16 | K=32 | K=64 |
|---|---|---|---|---|---|
| native | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| native | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| current | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| merged_read | 5 | 0.422 [0.359, 0.500] | 0.469 [0.312, 0.625] | 0.500 [0.312, 0.688] | n/a |
| merged_read | 10 | 0.547 [0.469, 0.625] | 0.562 [0.500, 0.688] | 0.562 [0.500, 0.688] | n/a |
| merged_read | 15 | 0.641 [0.516, 0.750] | 0.719 [0.625, 0.812] | 0.688 [0.562, 0.875] | n/a |
| merged_read | 20 | 0.547 [0.484, 0.594] | 0.531 [0.438, 0.625] | 0.562 [0.500, 0.688] | n/a |
| full_merge | 5 | 0.422 [0.359, 0.500] | 0.469 [0.312, 0.625] | 0.500 [0.312, 0.688] | n/a |
| full_merge | 10 | 0.547 [0.469, 0.625] | 0.562 [0.500, 0.688] | 0.562 [0.500, 0.688] | n/a |
| full_merge | 15 | 0.641 [0.516, 0.750] | 0.719 [0.625, 0.812] | 0.688 [0.562, 0.875] | n/a |
| full_merge | 20 | 0.547 [0.484, 0.594] | 0.531 [0.438, 0.625] | 0.562 [0.500, 0.688] | n/a |
| mixed_sbo_overlap | 5 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 10 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 15 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |
| mixed_sbo_overlap | 20 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | n/a |

## Cross-check against formby_results.json

36 of 36 recorded cells reproduced exactly (native size = off, current size = size_only, current joint = combined; retrained NB).

Workload K=64 is unavailable: each block holds 33 mixed and 32 integrity READs, and windows never cross blocks. SELECT and OPERATE windows have identical size signatures; MultinomialNB then returns the first class in its sorted order (OPERATE), which the confusion matrices in the JSON show. Intervals of zero width reflect deterministic per-class sizes, not measurement precision.

## Findings (under the enumerated targets, framing rules and limits)

| assignment | size operation BA range over D, K | size workload BA range over D, K | joint operation BA range over D, K | joint workload BA range over D, K | added B/txn |
|---|---|---|---|---|---|
| native: reference: unpadded native sizes | 0.667-0.667 | 1.000-1.000 | 0.667-0.875 | 1.000-1.000 | 0.0000 |
| current: (i) current c72 targets | 0.667-0.667 | 1.000-1.000 | 0.667-0.875 | 1.000-1.000 | 19.8238 |
| merged_read: (ii) both READ workloads at the integrity target | 0.667-0.667 | 0.500-0.500 | 0.667-0.875 | 0.422-0.719 | 22.7306 |
| full_merge: (iii) smallest size reachable by all four classes | 0.333-0.333 | 0.500-0.500 | 0.229-0.458 | 0.422-0.719 | 91.7254 |
| mixed_sbo_overlap: (iii) smallest size shared by mixed READ and SBO; integrity unchanged | 0.667-0.667 | 1.000-1.000 | 0.667-0.875 | 1.000-1.000 | 58.5285 |

Joint columns are offline policy estimate assuming unchanged timing, not a hardware result. Construction on the retained rows: combined 12352/12352, size_only 12352/12352 responses at their current target (padded arms). Size-only scores of `current` equal the native ones in every D/K cell: the mapping relabels the native size classes without merging them, so the size leakage measured by these classifiers remains.
