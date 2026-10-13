# realrelay_native_01: option-bearing connections stay native; only the clean handshake maps

## What and why

`realrelay_01` showed on the local model that the strict candidate rearm_57s
(`dup_hold_01/evidence/full_02_strict/response_only.p4`, sha256 `2ad71761…7c`) cannot carry the
SEL-751 / Linux-master connection. That connection negotiates MSS, SACK, timestamps and window scaling.
N admitted the TS SYN and opened its owner, offset-8 timestamp segments met E's `drop_odd`, E had no
native pass on a configured tuple, and the relay's FIN|PSH|ACK (0x19) was refused.

This build gives the minimal safe profile, which is not TS, WS or SACK support:

- **A.** Only the clean profile (SYN and SYN-ACK at offset 6 with the MSS template) opens or arms a
  connection. Every option-bearing segment (data offset 7 to 15, or offset 6 on a non-SYN) on a
  configured tuple that has no live clean connection leaves unchanged, in its own direction. It
  touches no N, E or T register.
- **B.** Because nothing is written, the tuple cannot wedge. After a native connection closes or
  resets, a clean connection opens, arms, pads and closes as before, under the same rearm frontier
  rules.
- **C.** A pure FIN|PSH|ACK (0x19, offset 5, no payload) on a mapped flow is admitted as a close,
  exactly like FIN|ACK.

`generate.py` edits N and E of the pinned input. It checks the input hash, requires every anchor to
match exactly once (and the two masked tables to hold an exact count of matches), refuses any new value
that is already in use, and asserts that T is byte-identical and that only N and E differ. The output is
`evidence/full_01/response_only.p4` with `.inputs.json`. The JSON records the input and output segment
hashes and the chosen values.

```
python3 generate.py evidence/full_01
cd C4 && python3 -B build.py <src> <dir>/compile_local --timeout 900
```

## Design

**How N marks a native segment.** No new Register is used. The owner phase N already keeps tells
whether the tuple has a live clean connection.

| site | change |
|---|---|
| N parser | The `ts_*` states (TS SYN at offset 10, TS SYN-ACK at offset 11, TS ACK and FIN at offset 8, TS READ request and response) are removed. Every IHL-5 TCP length now extracts the TCP header (`option_ip_flags` → `option_tcp`). In every TCP-extracting state, an unparsed segment with offset 5 is accepted unparsed as before; any other offset goes to the new state `foreign` (packet_kind 20, network_valid 1). The offset test sits in each state's own select, because a separate state ran out of parser match registers (`evidence/compile_failed_01`). |
| N parser | `(4w5,16w40,8w25):close` is added, so 0x19 parses as a close. |
| N `network`, `sequence_diff`, `close_phase_t` (48 rows), `first_event` (46 rows) | Every `hdr.tcp.flags == 8w17` entry becomes `8w17&&&8w0xf7`, which ignores PSH. All four are ternary on flags, so the entry counts do not change. |
| N `guard` | Two rows are added: `(stage 0, packet_kind 20, dir 1 or 2) → go_native` (sets `go` only: no work claim, no generation). This makes 44 entries in a table of size 48. On the go path every table is then a read: work read, epoch load, client and server load, and owner read. `owner_command` has no stage-0 row. |
| N `option_native_t` (new, 3 of 3) | This table is applied only in the stage-0 branch for packet_kind 20, which is exclusive with `first_event` and `busy_t`. If the owner phase is 0x0000, 0x010f or 0x0200, it runs `native_pass` (event 0xe800 on the route that `ports` chose). Any other phase hits NoAction, which is today's path, where E drops the segment. |
| E | In the rejected-lifetime branch for a configured TCP segment, provenance kind 0xe8 now runs `pass_native()` (strip provenance, outcome 16) instead of `drop_lifetime()`. `lifecycle_access` already rejected 0xe8 through its catch-all, so 0xe8 never enters the mapper. |
| E `settle_t` | Key `m.normalize` is added (it is 1 only on N's 0xe0 master lap), with the row `(dir 2, SH_ODD, mode 1, normalize 1) → NoAction`. This makes 6 entries in a table of size 8. The row stops a stale mode 1, left by an earlier mapped connection, from dropping an option-bearing master segment on the lap. Departures keep `drop_odd`. |

The three new values were checked against N, E and T and were unused: packet_kind 20, event or provenance
kind 0xe8, and E outcome index 16.

## Results

**Compile** (`evidence/full_01/compile_local`, local bf-p4c 9.13.1). Exit 0. Stages are p0 ingress 12,
p0 egress 12 and p1 ingress 11, the same as the input. `scan_static_entries.py` passes. The `.bfa`
`epoch_t` action bus is still one 32-bit slot, `112..115 : epoch_t_0$salu.n_Ingress.epoch(0..31)`. The
compile log has 55 warnings, the same count as the input's, and its one target-error warning (T's
`parse_tev`) is in the input's log too.

**New driver** (`model_drive_native.py`, run through `read_reencode_01/model_drive_oracle.py` with
`CASE4_STRICT_CONTROLS=1`): `evidence/native_model_04` gives **99/99**. In order, the run covers:

- A clean connection that opens, pads a READ to 58 and closes with the relay's 0x19 answer (C), reaching
  phase 0x10f.
- A TS connection with option bytes from the SEL-751 capture: the TS handshake, three TS READ exchanges
  (request, the relay's separate ACK, the 49-octet native response), a SACK ACK, the relay's 0x19 with
  TS, the master's final ACK, the master's FIN|ACK and the relay's last ACK.
- A second TS connection that a TS RST|ACK ends.
- A fresh clean connection (4000/7000). It arms (phase 5, mode 1, front 7001) and pads a READ to 58
  against the re-encoding oracle. While it is live it still drops TS segments with no state change. It
  closes relay-first with 0x19 and reaches phase 0x10f.

Every frame of the two TS connections left once, byte-identical, in its own direction. Every N, E and T
register equalled the snapshot taken before the first TS SYN after each step: N owner, epoch, client,
server, counter, work, application and read_app; E mode, front, acct, img, epoch and master_isn; T
cur_epoch, generations, t0, done and child registers, and all 25 outcome cells. E's outcome delta was
`{16: 1}` for each relay frame and `{0: 1, 16: 1}` for each master frame, whose 0xe0 lap counts 0.

**Regression** (same wrapper and settings; references from `dup_hold_01/evidence/*_strict`):

| suite | this build | reference |
|---|---|---|
| `read_reencode_01/model_drive_diag_strict.py` | 519/519 (`diag_strict_01`) | 519/519 |
| `read_reencode_01/model_drive_retx_strict.py` | 37/37 (`retx_strict_01`) | 37/37 |
| `dup_hold_01/model_drive_dup.py` | 88/89 (`dup_01`), failure `C_read_dup_no_early_READ_copy` | 88/89, same failure |

**Other evidence directories.** `compile_failed_01` is the first parser layout, which ran out of parser
match registers. `full_01_wrong_e_branch` placed the E edit in the outer `else` (configured but no TCP),
which TCP segments never reach. Its run `native_model_02` shows every TS frame dropped with registers
unchanged; `native_model_01_driver_crash` read a T register that does not exist. `native_model_03` is
the corrected build with a driver that expected `{16: 1}` for master frames as well (88/99); the code
was unchanged for `native_model_04`.

## Limits (not done, by design or not reached)

- **Offset-5 segments of a native connection are not passed native.** One example is an option-less
  RST. When a connection negotiated TS, Linux puts TS on every segment of the established connection.
  An offset-5 segment on an idle tuple keeps today's handling. The driver's INFO step shows that an
  offset-5 RST|ACK on the idle tuple is dropped with every register unchanged. Passing it native would
  be unsafe, because E's master lap still reverse-translates an offset-5 ACK when a stale mode 1 is
  present.
- **An offset-6 SYN or SYN-ACK whose option fails the MSS template stays unparsed and is dropped as
  before.** `mss_syn` has already set packet_kind, and Tofino's parser cannot re-assign it (the
  `compile_failed_01` warning). The spec's native range is offset 7 to 15.
- **A clean SYN answered by an option-bearing SYN-ACK** leaves N in phase 2. The SYN-ACK then hits
  `option_native_t`'s NoAction and E drops it. This mixed profile is not native, and this build did not
  test it.
- **An option-bearing master segment on a live mapped flow now reaches N.** N drops it at the relay
  departure (`drop_lifetime`) rather than on the lap (`drop_odd`). Outcome 8 no longer counts it.
- TS, WS and SACK are not supported on mapped flows. The bounded P1 profile is the follow-up. This run
  used the model only: it is not a hardware or timing result.

## Note on realrelay_01 (reported, not edited)

In `realrelay_01/model_drive_ts.py`, the `ts` and `variants` modes build the relay's TS SYN-ACK as
`build(18, s, c + 1, OPT_SYNACK)`, without `reverse=True`. The frame therefore carries the master's
addresses and ports. In the retained map both endpoints share dev port 9, and N's `ports` table
qualifies them by source address, so N treated that frame as a master packet (`normalize_ack` lap).
`ts_model_01` and `variants_model_01` therefore do not show what N does with a relay TS SYN-ACK, and
STATUS's statement that "N drops the relay's TS SYN-ACK (offset 11) itself… MSS + NOP padding at offset
11 is dropped too" rests on mis-addressed frames. The `established` mode and this experiment's driver
address relay frames correctly. This finding does not affect the result here, because the TS SYN-ACK no
longer reaches N's handshake path at all.

## Cold review (2026-10-13): BLOCKED before any hardware step

- **HIGH: the tuple can still wedge.** Native pass and a new clean SYN both need owner phase 0x0000, 0x010f or 0x0200.
  A phase left with nothing to close it blocks every later connection on the tuple. Cases: phase 2 after a clean SYN
  answered by an option-bearing SYN-ACK; an unanswered SYN; quarantine phase 6.
- **MEDIUM: `foreign` sets `network_valid=1` in the parser.** That skips N's `network` checks (IP checksum, TTL,
  reserved/urgent), so TTL-0 or bad-IP-checksum frames are forwarded native.
- **MEDIUM: an MSS + WS + SACK profile without timestamps sends offset-5 segments after its handshake.** These
  reach `go_new` and `allocate`, which bumps the generation counter, and are then dropped. That breaks requirement A
  for that profile. It does not affect the SEL-751, which uses TS.
- **WARNING: `model_drive_real_profile.py` (commit 0c5e3673c) tests the removed TS parser states.** It is retired by
  design and not re-run.
- **Bound on any claim:** with this build, no real-relay (TS) traffic is ever defended; it is passed native.

Status: model-stage candidate only. Not compiled for the switch, not pinned, not run on silicon.
