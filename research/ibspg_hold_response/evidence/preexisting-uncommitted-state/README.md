# Pre-existing uncommitted working-tree state — UNRELATED to Part 12

Forensic snapshot only. Captured 2026-07-25 while working Part 12.

These changes were **already present in the working tree** when the Part 12 session began. Their
intent is unknown — deliberate cleanup and accidental deletion are indistinguishable from here — so
they were deliberately **not restored, not committed, not stashed, and not modified**, and no Part 12
commit includes them. `dnp3_split_harness/split_server.py` was not used by any Part 12 work.

| file | contents |
|---|---|
| `status.txt` | `git status --short` |
| `name-status.txt` | `git diff --name-status` |
| `uncommitted.patch` | `git diff --binary` (full recoverable patch) |
| `deleted-files.txt` | `git ls-files --deleted` |
| `split_server.patch` | `git diff -- dnp3_split_harness/split_server.py` |
| `split_server.sha256` | hash of the modified working-tree file |

Summary: 15 deleted tracked root documents plus one modified file. All are recoverable from git
history (`git restore <path>`); nothing here is lost. Disposition is Philip's call.
