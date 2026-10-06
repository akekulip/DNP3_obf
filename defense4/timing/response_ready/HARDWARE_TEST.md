# READ candidate hardware procedure

Status: preparation only. No candidate has been loaded or measured.

## Prerequisites

The candidate must pass release, ownership, timeout, stale-return and busy-request
tests before any pipeline or testbed mutation. The final compiler allocation and
`context.json` must agree on at most seven ingress stages and zero egress stages.
Keep `-DU_BOR`; do not remove another datapath to meet this limit.

Local SDE 9.13.1 compilation is an offline check. Build deployment artifacts with
the switch's SDE 9.13.2 and bind the source, compiler, command, BFRT schema,
configuration, context and binary by SHA-256. Diagnostic builds have their own
identity and cannot stand in for the final build.

## Preflight and restoration

Use read-only checks to identify the actual running process, program, launch
command, artifacts and relevant configuration. Do not assume that MVM is loaded.
Preserve a working restoration procedure for that exact state before replacing it.

The historical `bfrt_snapshot.py` tolerates read errors and does not capture all
traffic-manager and PRE state. Its JSON alone is not a restoration procedure.
The September 25 `restore_mvm.sh` is specific to the old MVM deployment.

Recheck the live port map: historical records place Vision at dp9, SEL-751 at
dp64, and internal loops at dp8 and dp10. Older records also assign a host to
dp10; do not assume that host link is free. Confirm the strict queue ladder,
port rate, disabled size shaping and candidate configuration before traffic.

## Controlled tests

Run early response, response just before/after the ACK deadline, late response,
duplicate ACK return, duplicate response, missing response, pending-state loss,
stale return and next-request recovery. Include timestamp wrap and overlapping
requests in offline tests. Distinguish watchdog release from normal release.

The inherited `D3_SYNTH_EVENTS` parser changes the permitted packet source. Its
build is diagnostic. `D3_INJECT` only injects blockers, not application events.
The archived event driver and production setup both use pktgen app 2, so they
cannot be combined unchanged. No current candidate-compatible replay runner is
claimed here.

Intel's installed SDE example `tna_pktgen/tna_pktgen.p4` documents a 24-bit key
copied from the triggering recirculation packet into every generated packet.
Its `test.py` checks this against `recirc_tag & 0x00FFFFFF`. The candidate can
use the lower 16 bits as an immutable request cookie while preserving the
existing profile byte. Generated blockers must use that cookie, not the
current request's identity at their arrival time.

The bounded candidate must not reuse cookies during a trial. Cookie exhaustion
must stop protected admission and be reported as fallback. Reset only after
traffic has stopped and a drained state is verified. This is a test-candidate
limit, not a claim of continuous protection across arbitrary cookie reuse.

## Final-build READ collection

Use DA = 5, 10, 15 and 20 ms, request anchoring, no random overrides, and a
configured 1 ms gap (999936 ns after quantization). Stop traffic and drain state
before changing parameters; retain successful readbacks for every trial.

1. Collect 100 READs per DA as a smoke test.
2. Only after smoke success, collect 6000 candidate READs per DA.
3. Collect 1000 legacy-mechanism READs per DA and 1000 Timing OFF READs.
4. Use 400 ms spacing and a 500 ms application budget.

The existing `latency_search/run_block.py` supports `--sbo 0`, but also performs
ancillary status READs. Record those separately from trial IDs. Never run its
SBO path for this task. Preserve planned IDs, application records, captures,
readbacks and failures, including requests without responses.

Master-side capture measures visible ACK-to-response CLRT. It cannot establish
when a response reached switch ingress or prove relay-facing byte identity.
Do not label an arrival early/late using master RTT alone. The old `reg_ts_*`
declarations have no writer calls and provide no arrival evidence. Establish
executed, source-bound observations before claiming verified arrival groups.

## Acceptance and cleanup

Report CLRT mean, sample variance, SD, quantiles and absolute gap error, plus
request-to-ACK and request-to-response latency. Separate normal, watchdog,
bypass, missing, malformed and retransmitted outcomes. Report unknown evidence.

Normal timing acceptance is median absolute error <=10 us and >=99.9% within
+/-50 us, checked for all normal records and independently verified early/late
groups. The full run requires all four DAs and sufficient group coverage.
A 100-READ smoke pass is not full acceptance.

Restore the pre-test program and configuration even if collection fails. Verify
the restored identity and readbacks; record any restoration failure explicitly.
Update the engineering report only. The manuscript and published evidence stay
frozen.
