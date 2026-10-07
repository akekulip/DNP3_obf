# model_27: native_11 on the local Tofino-1 model (summary of model_24 .. model_26)

Program: `evidence/native_11/out`, source sha256 `c235257214a5873c9005cf4dd73ebb0596aab0706dc0546fd8556a2130e3c019`,
tofino.bin sha256 `94e8d89b5669625e2c660520cfd0e0c32ad66e97a082d80f48e4870f804afa0e`, 12 ingress stages.
Harness pinned to `native_11/source/native_binding.p4` (identical to the working tree at run time).

## (1) Load
`python3 core/scan_static_entries.py evidence/native_11/out` -> no offenders (exit 0). The model loads it with zero `ERROR` lines in switchd.out
(model_24/switchd.out), gRPC up, all 5 ports (1 2 9 66 68) enabled without errors (68 as the internal recirculation port).

## (2)+(3) Differential corpus (model_24): 71 steps, 68 MATCH, 3 mismatches, none a program or interpreter bug
Command: `cd integration && ./core/launch_model.sh -p evidence/native_11/out -o evidence/model_24 -P "1 2 9 66 68" -d core/cases/diff_native.py`
Per step: same frame + same preset registers (all registers incl. read_app written over bfrt), compare emitted frames (port+bytes), pass count, every register.
The handoff frame on port 66 is compared byte for byte except `t0q` (hardware timestamp): checked separately (low 8 bits zero in every case; values recorded in cases.json).
All earlier cases (witnesses, SELECT/OPERATE/response, handshake chain, FIN/RST, bad checksum/CRC/tuple/ethertype/unrouted/dup/wrong ack, truncations) still MATCH: no regression from native_04.
READ cases (all MATCH on frames, passes, registers, work record free afterwards):
request (kind 9), server ACK (10), response (11), full request/ACK/response exchange, request replay, response replay, wrong app seq (response app 4 vs stored 3: refused),
request at owner outstanding, response at owner idle, ACK at idle (forwarded as ordinary ACK), wrong seq, wrong ack, foreign tuple, foreign link dst/src (request and response),
bad CRC (request header/body; response header/first/second/tail) with TCP checksum repaired, bad IP / TCP checksum.
A passing READ packet takes 4 passes and leaves port 66 as `tev(16 B) + original`: e.g. request 90 bytes, response 119 bytes (model and harness equal); ACK 70 vs 76 only because the model pads the 54-byte original to 60.
Mismatches (all test/model artifacts, same class as before):
* `artifact_sub60_truncated_tcp`: model pads frames <60 B (so no truncation exists). Test artifact.
* `neg_truncated_in_tail` (cut 3 bytes from the end) and `read_truncated_request` (cut 4 bytes from the end of a 74-byte request): the model's ingress length includes a 4-byte FCS, so a cut within
  the last 4 bytes is not a parser error and the frame is forwarded; harness assumes drop. Model artifact (hardware behavior unconfirmed). Cuts deeper than 4 bytes MATCH.
Observation (harness AND model agree, so not a mismatch): `read_request_from_server_side` - a client-tuple READ request injected on the SERVER-side port 2 is accepted and handed off (kind 9, 4 passes).
Direction comes from the tuple, not the ingress port. Probably a design decision to confirm.

## (4) H1 re-verified (model_25, one fresh model per case): epoch 0 is bounded
SYNACK first, ACK first, SYN with ACK!=0, SELECT first at a free connection (epoch 0): model and harness both 4 passes, deny at pass 4, nothing emitted, WorkRecord back to phase 4 (free),
generation counter +1; FIN first / RST first: forwarded in 1 pass, work free; SYNACK first at epoch 17 and duplicate SYN: MATCH. No endless recirculation (native_04 looped at 317-327 passes in 1.5 s).

## H2 re-verified (model_26): 120 race trials over gRPC
The model cannot be paused, so one table entry is deleted `delay` after the frame is sent (delays 0..40 ms, 12 values x 2 repeats x 5 cases), landing in different passes.
Result: ZERO leaks: in no trial did any front-port frame differ from the original or carry the private envelope; every removal ended in deny (nothing) or normal completion.
* `data_connection` removed (SELECT): 18 dropped + 6 completed; WorkRecord free every time. `read_connection` removed (READ request): 10 dropped + 14 handoff; work free every time.
* `connection` (flow) removed: SELECT 17 dropped + 7 completed, ACK 6 dropped + 18 completed, READ 10 dropped + 14 handoff: in the 33 DROPPED trials of these three cases the WorkRecord was left PINNED at phase 2 or 3
  (never freed). The source harness, driven deterministically (`ReadPipeline.mutate`, remove `connection` before pass 2/3/4), gives the same: drop at that pass, work phase 1/2/3 left pinned.
  This is program behavior both agree on: deny works and nothing leaks, but removing the flow entry mid-flight pins the single work record until the controller resets it. Needs an explicit recovery step
  (controller must clear/advance the work register, or the program must release on a flow miss). Classified: program behavior (design gap), not an interpreter bug.

## Sizes (keep out of git; `.gitignore` in model_24/25/26 excludes model.out, bf_drivers.log, model_*.log, switchd.out, zlog-cfg-cur)
model_24 25 MB, model_25 20 MB, model_26 69 MB on disk; the ignored raw logs are ~46 MB of model.out alone. cases.json files (the evidence) are small.
