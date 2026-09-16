# Removing the Claude co-author trailers from history

Five commits carry a `Co-Authored-By: Claude …` trailer in their message, which is what GitHub
renders as a second author on those commits. Every commit in this repository is authored and
committed by Philip Akekudaga; the trailer is the only place any other name appears, and the
paper's own author block names Philip Akekudaga and Hui Lin and no one else.

| commit | message |
|---|---|
| `99f03fa` | feat(dnp3-obfuscation): rig-validate ACK/latency-delay timing defense |
| `29c3ad5` | docs(resume): record git checkpoint + ACK-delay resume state |
| `9f7717d` | record the Vision DNP3 file reorganisation |
| `f10f788` | render the delay note to PDF, and add the script that does it |
| `9bda4b5` | explain the retransmission limit an administrator has to respect |

## What this costs

A commit message is part of the commit, so changing it changes the hash, and changing a hash
changes every descendant. The oldest affected commit is `99f03fa` of 2026-07-15, so **883 commits
are rewritten** and every one of them gets a new hash.

That breaks **83 commit references quoted in this repository's own documents**, including:

* `8278346`, which every frozen-tree and raw-capture integrity check compares against;
* `f6dd821`, `f573eec` and `6e2eff2`, the `git show` commands that recover the root documents
  removed in the 2026-09-15 prune;
* `6fbf351` and `5ce71ba`, the reviewed commits;
* the build and provenance chains in `defense4/timing/audit_current/`.

Step 2 below repairs all of them automatically from the map the rewrite produces.

Anyone with an existing clone must re-clone. The branch bundles in
`/home/philip/Archives/DNP3_branch_bundles_20260915/` were made from the old history and keep the
old hashes; they stay valid as archives but no longer share commits with the rewritten `main`.

A full backup of the pre-rewrite history is at
`/home/philip/Archives/DNP3_pre_rewrite_20260916/DNP3_full_pre_rewrite.bundle`, verified complete,
with the prior `HEAD` and all 924 commit hashes recorded beside it. To abandon the rewrite, clone
from that bundle.

## Why it is not automated here

The assistant's risk guard denies history rewriting and force-pushing outright, and this
repository's own `CLAUDE.md` says "No history rewriting, no force push." Both commands below are
therefore yours to run.

## Step 1: rewrite

From the repository root, with a clean working tree:

```bash
git filter-repo --force --message-callback "$(cat tools/history_rewrite/strip_claude_trailer.py)"
```

The callback removes only the trailer lines. Tree, author, committer and dates are untouched.

`git filter-repo` removes the `origin` remote as a safety measure, so put it back:

```bash
git remote add origin https://github.com/akekulip/DNP3_obf.git
```

## Step 2: repair the quoted hashes

```bash
python3 tools/history_rewrite/update_hash_references.py            # see what it would change
python3 tools/history_rewrite/update_hash_references.py --apply
git add -A && git commit -m "repoint the documented commit hashes at the rewritten history"
```

## Step 3: verify before publishing

Every gate should pass exactly as before, because no file content changed:

```bash
python3 -m pytest defense4/timing/active_control/tests defense4/timing/active_harness/tests \
                  defense4/timing/active_probe/tests defense4/timing/tests -q
bash paper/rewrite/pipeline/build.sh
python3 paper/rewrite/pipeline/check_lin_intro_verbatim.py
git log --all --format=%B | grep -ci claude          # expect 0
```

Confirm the frozen-tree check still resolves with its new hash, substituting the value the
updater wrote into `CORRECTION_REPORT_20260916.md`:

```bash
git diff --name-only <new-8278346> HEAD -- defense4/timing/implementation | wc -l   # expect 0
```

## Step 4: publish

```bash
git push --force-with-lease origin main
```

`--force-with-lease` rather than `--force`: it refuses if the remote moved since your last fetch,
which is the check worth keeping on an operation like this.
