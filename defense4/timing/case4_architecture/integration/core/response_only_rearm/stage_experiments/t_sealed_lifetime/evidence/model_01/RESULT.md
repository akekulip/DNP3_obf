# Independent sealed-T compiled-model result

The corrected private model run in `retry_01` passes **491/491 checks** and
exits 0. It executes the immutable repaired T full-composite source
`400caaad2407a1afe1274135acf21846ec10738395583862e4f1a8fcfa86a7bd`,
compiled with local SDK 9.13.1. N and E are byte-identical to checkpoint 55;
the actual BFA placement is N/E/T 12/12/11. The combined N/T experiment is
excluded because its independent N residue binary failed model validation.

The copied driver preserves the checkpoint 55 extended checks and adds
sealed-lifetime checks. Actual raw T register values are compared; there is
no synthetic quarantine value in authority snapshots. The accepted sequence
is N owner phase 5 → 0x101 after the first FIN → 0x10b after server FIN/ACK →
0x10f after the final qualified ACK. T seals on the first qualified FIN,
matching the unchanged checkpoint 55 source oracle, while N retires only at
0x10f. Each allocator advances once on that first CLOSE, then stays fixed for
server FIN, final and duplicate final ACK, and explicit duplicate CLOSE.
Increasing OPEN unseals and advances the preserved allocators once.

The run verifies both apps' old raw tokens on physical return port 196 before
and after OPEN, IDs 0..3, with no departure, exact stale-counter increments,
and unchanged private banks. It also checks all six old ladder roles under
OFF, current-owner OFF flush for ACK/READ response/OPERATE, old Work phases,
old external packets and RESET, fresh READ/SBO padding, OPERATE hold/release,
and the extended inverse ACK/window/checksum cases.

The final isolated T fixture reaches epoch `0x7ffffffe` through OPEN, then
sets only the two private-model allocator cells to `0xfffe` to exercise the
real saturation boundary. Admissions return the `0xffff` sentinel, do not
arm anchors, and drop. Raw `0xfffe` and `0xffff` tokens drop without changing
banks. CLOSE seals the raw epoch to `0xfffffffe`; duplicate CLOSE and all
invalid or nonincreasing OPEN attempts preserve all banks. No owner, Work,
or epoch register is overridden, and no CPU rearm is used.

The initial run is retained with **441/444 passing**. Two added allocator
assertions used a snapshot taken after the first CLOSE and incorrectly
expected a second bump. Its final fixture also passed BFRT `action_name`
metadata to a register write and raised a schema error. The unchanged source
oracle and both driver versions are retained. The retry changes only those
driver boundaries and field filtering; the P4, schema, and binaries remain
identical.

`model_qualification.json` pins the source, binary/BFA/schema artifacts,
driver, helpers, port map, source oracle, initial failure, and successful
result. All processes ran in the supported launcher’s private user/network/
PID namespace using ports 9, 48, 68, 180, 181, 182, and 196. The namespace
exited and returned its hugepages. These results establish compiled-model
behavior; SDK 9.13.2, silicon behavior, and hardware timing remain separate
validation requirements.
