# Gate S3 Independent Code and Evidence Review

Reviewer lane: Codex native `code-reviewer`

Date: 2026-08-14

Verdict: **APPROVE**

Open issues: **0**

## Scope

The review covered the S3 specification, codec, corpus and capture parser, observer analysis, evidence driver, reproduction wrapper, adversarial tests, generated PCAP/CSV/JSON evidence, claim matrix, and result statement.

## Findings and resolution

The first review found three medium issues:

1. the decoder did not repeat the encoder's 14..1518-byte inner Ethernet frame bounds;
2. observer public-metadata invariants omitted visible outer MAC addresses;
3. replay protection covered accepted nonces in process but not decreasing encrypted epochs per direction and slot.

All three were fixed and regression-tested. The decoder now rejects AEAD-valid invalid inner frame lengths, the observer gate includes outer MAC roles, and the receiver persists a monotonic accepted-epoch map or requires a fresh key epoch after restart.

The final comprehensive review found one low-severity polish issue: a module-only driver had a direct-execution shebang despite package-relative imports. Removing that shebang closed the final finding.

## Independent validation

- `python3 -m py_compile ...` passed for the S3 Python modules.
- `python3 -m pytest -q defense4/size/real_size_normalization/offline/test_s3_offline.py` passed: 69 tests.
- `sha256sum -c defense4/size/real_size_normalization/evidence/s3_offline/manifest.sha256` passed for every entry.
- The final evidence manifest file hash is `64a43ac1d814a428f10593d6810df68c997d5b49934390dc9924e22f3eb9810c`.
- A temporary-directory regeneration passed; payload artifacts were byte-identical, while path-bearing metadata correctly reflected the different output path.
- Weak statistical settings and a broad `/tmp` output target were rejected.

## Claim review

The review approved only the offline S3 claim. It did not approve a live testbed, Tofino CPU-path, RN-T, multi-device, latency, performance, or production-key claim.
