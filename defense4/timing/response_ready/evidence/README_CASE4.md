# Case 4 compiler evidence packaging

The source-current recovery snapshot is `case4_recovery_build_04`: source
`3f759d06e6c610814def05ce9c83d3688b1bf8397f04000ddf546181674d2f09`,
local compiler p4c 9.13.1 revision `e558d01`, 10 ingress / 0 egress stages.
Its manifest binds schemas, context, binary and resource reports. Earlier
snapshots retain intermediate failures and successes; their results do not
transfer to modified source.

Sources, raw compiler logs, manifests, compressed BFRT/context and text resource
reports are versioned. SDK output trees, binary and assembler products remain
local and ignored. The retained `verify_case4.json` proves the local invocation
with those artifacts present. A clean checkout does **not** have all inputs for
that invocation; the verifier correctly refuses missing binaries or assembly.
Do not remove these checks to make an archive appear deployable.

To reproduce from a clean checkout, first use an installed licensed SDE compiler
and an unused output directory, then verify that fresh source-bound build:

```sh
python3 defense4/timing/stage_reduction/build.py defense4/timing/response_ready/src/defense4_response_ready.p4 /tmp/case4_recovery_rebuild --compiler /home/philip/bf-sde-9.13.1/install/bin/bf-p4c --max-ingress 12
python3 defense4/timing/response_ready/verify_build.py defense4/timing/response_ready/src/defense4_response_ready.p4 /tmp/case4_recovery_rebuild --profile case4
```

Compiler run identities and resulting artifact hashes may differ; use the new
manifest, not copied old hashes. Exact-source SDE 9.13.2 compilation remains a
deployment prerequisite, followed by complete transport integration, measured
admission and actual authorization. An offline compile never authorizes loading.
