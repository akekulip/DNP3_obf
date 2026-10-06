# Retained Case 4 BMv2 evidence, 2026-10-06

This is one source-bound, actual P4 joint SELECT/OPERATE run in an isolated
user/network namespace. Endpoints are Python codec emulators. It is neither
OpenDNP3 endpoint evidence nor physical-switch acceptance.

`config.json` records the exact run arguments; `source_bmv2_rr.p4`,
`bmv2_rr.json`, compiler command/log and `lab_source/` retain the executed
artifacts. Both switch-side pcaps, CLI/switch logs, endpoint status records,
`result.json` and `evidence_summary.json` record the actual packets and timing.
`SOURCE.sha256` and `EVIDENCE.sha256` provide integrity checks. A reproducing
run should use a fresh work directory with the same config, rather than
overwrite this evidence.

Both operations completed with real/decoy statuses [0,0]. Actual P4 expanded
both native 35-byte requests to 55 bytes and carved both 57-byte echoes into
[28,29], with contiguous reassembly and correct CRC/TCP/IP checksums. Software
oracles validate captured output; they do not transform the forwarding path.
Captured post-ACK gaps were 1230.951 and 1122.448 us for configured 1000 us.
The requested software heartbeat was 1 ms; observed maximum spacing was
1216 us. This differs deliberately from the Tofino candidate's 100 us request.

`verification.json` retains the final test result: all 13 Case4 tests pass,
8/9 historical tests pass, total 21/22. The historical D_A=0, gap=200 us case
observed a 609.886 us gap, exceeding the unchanged 400 us deviation tolerance
by 9.886 us. `retained_failures/` preserves that final failure and five earlier
failure/stimulus cases. Earlier artifacts have compiled JSON and hashes where
available; they do not have a reconstructed old source tree. The current
source snapshot is included only for the final legacy failure.

The first final-suite timeout case overlapped a size compiler. The unittest
runner was then paused during raw probes and resumed after the size compilers
finished. Later timed tests and this retained canonical run had no root/size
compiler running. No tolerance was widened or failing result concealed.

Initial segmented controls, conflicting/out-of-cache overlaps, general ledger
recovery and old-epoch same-tuple FIN/RST rejection remain unestablished.
These limits block a general transport or joint physical candidate claim.
The historical 120-transaction software population was not modified.

A later root regression found an additional metadata error in the historical
generated-ACK loss case: a valid zero-response timeout had no response evidence
file. `retained_failures/generated_ack_zero_response_evidence_error/` retains
the original artifacts and traceback, pre-fix driver snapshots, fixed driver
snapshots and the one-test passing rerun. The fix initializes empty evidence
before READY and checks endpoint process health; it changes no P4 behavior or
tolerances. The canonical capture and its `lab_source/` snapshots above remain
byte-for-byte intact. `verification.json` records the current driver hashes
separately; the prior 21/22 result and its timing failure remain unchanged.
