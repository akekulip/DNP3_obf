# model_23: native_04 candidate, model-vs-source differential (summary of model_18 .. model_22)

## (1) Load check
* `native_04` AS RETAINED does NOT load (model_18): `BF_PIPE ERROR - Error Not enough space adding static entry 8 in dev 0 pipe ffff table Ingress.sequence_diff`,
  `bf_device_add failed(9)`. Table `Ingress.sequence_diff` is declared `size=8` and has 9 const entries (context.json: size 8, static_entries 9).
  The only offender (`core/scan_static_entries.py evidence/native_04/out` prints it; exit 1). The generator line is
  `connection/binding/generate.py` / `native_binding.p4` line 152-153 (`diff_reset_forward;...NoAction;}size=8;`). Generator NOT edited.
* To continue I compiled a COPY with only that table's size changed 8 -> 16 (model_19: `patched_source/` + `compile/`, 11 ingress stages, same as native_04):
  source sha256 `0372a14b3b2874fbd224869ee94376888312c68d1a8db2f52454a4477bb6b486`, tofino.bin `f8cd350e...d34d`.
  Retained native_04: source `4ee923b9...e757`, tofino.bin `12278b5b...e332`. It loads with zero driver errors (model_20/22 session logs).
  The launcher now fails fast (exit 4) when device add fails.

## (2) Differential
Command: `cd integration && ./core/launch_model.sh -p evidence/model_19/compile/out -o evidence/model_22 -P "1 2 9 68" -d core/cases/diff_native.py`
(isolated cases: `ONLY=<name> EXACT=1` per directory, model_21; harness is pinned to the native_04 source SNAPSHOT because the working-tree
native_binding.p4 is being changed by another agent, sha now 0bf677d7...; override with NATIVE_SRC=<path>).
Per step the same frame and the same preset (all registers written over bfrt: owner, client, server, epoch, counter, application, decoy_off, six pair registers, work)
go to the harness and the model; compared: emitted frames (port + bytes, Ethernet-padding tolerant), passes (count of "Ingress Pkt" lines in model.out), every register.

model_22: 40 steps, 38 MATCH, 2 mismatches, both harness/test artifacts (below). model_21 (isolated, each in a fresh model): 10 cases.
MATCH on frames, passes and ALL registers (bit for bit): 4 step-1 witnesses (4 passes each, owner unchanged), SELECT first contact at owner phase 4 and 5,
SELECT replay (dropped, 4 passes, generation burned, record freed), SELECT then OPERATE then OPERATE replay, OPERATE first contact, SELECT then 57-byte response
(1 pass, forwarded) and response replay, full SYN/SYNACK/ACK/SELECT chain from a free connection, FIN, RST, bad IP/TCP checksum, wrong tuple, wrong ethertype,
unrouted port 9, out-of-sequence duplicate, wrong ACK number, bad DNP3 header/block/tail CRC, bad data byte, wrong function, ttl 0, truncation inside dl / first block / 70-byte select,
FIN first, RST first, SYNACK first with epoch 17, duplicate SYN. After EVERY one of these the WorkRecord is back to phase 4 (free).

### Mismatches
1. `order_synack_first`, `order_ack_first`, `order_syn_ack_nonzero`, `order_select_first` at a free connection (epoch register 0): PROGRAM BUG, harness agrees.
   Harness stops at 8 passes ("recirculation limit"), the model never stops (317-327 passes in the 1.5 s observation window, ~200/s in the model; the packet is still looping when the
   driver exits). Registers equal the harness bit for bit: WorkRecord generation 1, phase 1 (pinned, never freed), counter 1. Mechanism: snapshot copies epoch 0 into the envelope,
   the envelope parser accepts early on epoch 0, nothing denies, ports.route sends it back to port 68 each pass (harness test `Recirculation.test_epoch_zero_envelope_never_terminates` documents the same path).
   Consequence on a pristine connection slot: one stray SYNACK / ACK / SELECT / SYN-with-ACK!=0 (right tuple, valid checksums) starts an endless recirculating packet and pins the work record.
   With epoch != 0 (`order_synack_first_epoch17`) the pass-4 deny drops it and the record is freed: MATCH. This is the same wedge as handshake finding 2, now worse (endless, not a leak).
   The earlier handshake `tbl_deny_2` no-drop question does not arise here: native_04 simply never reaches a deny with epoch 0.
2. `neg_truncated_in_tail` (select cut at 86 of 89 bytes): the model forwards, harness drops (parser error). MODEL ARTIFACT / unverified, not a program bug: the model prepends no error but
   its ingress packet length includes a 4-byte FCS ("Ingress Pkt from port 1 (90 bytes)" for an 86-byte frame), so a truncation of up to 4 bytes is hidden. Real-hardware behavior must be confirmed;
   harness `drop` policy is only right when the cut is deeper than the FCS.
3. `artifact_sub60_truncated_tcp` (ack cut to 40 bytes): TEST ARTIFACT. The model pads frames below 60 bytes (and adds FCS), so the TCP header parses from zero padding and the frame is forwarded;
   a sub-60-byte frame cannot exist on a real wire. Replaced by truncations at 60/75 bytes (inside dl / first block): MATCH (parser error, dropped, no state change).
No mismatch is a harness interpreter bug. The harness's documented assumptions held: Checksum.subtract accumulation, 0xffeb, parser-error drop (except inside the FCS window).

### Harness vs hardware caveats found
* harness `on_parser_error='drop'` equals the model for truncations deeper than 4 bytes; 'continue' is never what the model does there.
* The model has no recirculation limit; any program path that can loop needs an explicit bound (see 1).

## (3) Passes per exchange (model == harness for every step; model_22/cases.json has the full table)
SYN, SYNACK, final ACK, established ACK, SELECT, OPERATE, replays that reach owner compare, out-of-sequence duplicate, wrong ACK: 4 passes (1 original + 3 on port 68).
FIN, RST (established): 2 passes. 57-byte response: 1 pass. Everything refused at stage 0 (bad csum/CRC/tuple/ethertype/ttl/truncation/unrouted port): 1 pass.
Recirculated bytes per 4-pass exchange = 3 x (frame + 16-byte private prefix + 4 FCS): e.g. SELECT 3 x 109 = 327 bytes on port 68 (model log: "Ingress Pkt from port 68 (109 bytes)"); SYN 3 x 80.
A refused out-of-order packet still costs 4 passes and burns a generation (counter+1) before the owner compare drops it.

## native_05 (READ kinds)
Not yet compiled here. When it exists: `python3 core/scan_static_entries.py evidence/native_05/out` first, then
`NATIVE_SRC=evidence/native_05/source/native_binding.p4 ./core/launch_model.sh -p evidence/native_05/out -o evidence/model_NN -P "1 2 9 68" -d core/cases/diff_native.py`
and the isolated `order_*` cases as in model_21 (a new differential list for READ kinds must be added; registers new in native_05, e.g. read_app, are covered if the harness cells name them).
