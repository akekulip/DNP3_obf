# DNP3 timing-obfuscation research

This repository contains the timing-obfuscation evidence, the active paper, and separate
implementation and delay-search work. Start with [REPOSITORY_MAP.md](REPOSITORY_MAP.md) for the
authoritative path for each.

The approved publication evidence is the request-anchored `campaign_v2` dataset: 22 grouped runs,
132 captures, and 63,360 DNP3 exchanges. The size carve was disabled in both arms. Later delay-search and
stage-reduction results are separate evidence and must not be attributed to the paper unless the
manuscript and its claim ledger are deliberately updated.

**September 29 freeze:** Philip has deferred paper changes until Dr. Lin accepts the approach.
Existing delay-search text in Evaluation is an unresolved authority conflict; do not treat its
presence as approval. The [verification ledger](defense4/timing/audit_current/verification_20260929/README.md)
records offline corrections and deferred paper findings. No testbed operations are authorized.

## Main entry points

- [Timing evidence and notation](defense4/timing/README.md)
- [Seven-stage candidate and hardware smoke evidence](defense4/timing/stage_reduction/README.md)
- [Delay-search protocol and results](defense4/timing/latency_search/README.md)
- [Active manuscript and build instructions](paper/rewrite/README.md)
- [Repository instructions](CLAUDE.md)

## Reproduce the paper evidence

```sh
cd defense4/timing
./reproduce.sh
```

The script verifies the manifests before rebuilding tables, statistics, and publication figures.
Use the explicit historical option only for retired datasets.

## Build the manuscript

```sh
cd paper/rewrite
./pipeline/build.sh
```

## Hardware work

Read the Tofino runbook and current connectivity map before each hardware operation. The loaded
program can differ from both the published campaign build and the seven-stage smoke-test build.
Inspect live state; do not infer it from a dated report. Preserve the experiment captures, logs,
source hashes, and rollback bundle.

The repository retains sizing-related candidates and historical results for engineering context.
The active manuscript makes no size-obfuscation claim.

No repository license is present; verify redistribution terms before a public release.
