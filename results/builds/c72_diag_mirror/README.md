# c72_diag_mirror: diagnostic relay-leg mirror build

**This is a diagnostic build, not c72.** Nothing measured with it establishes anything about the exact c72
binary (`results/builds/c72`, source SHA-256 `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`).
Label every result taken with it `c72_diag_mirror`, with source SHA-256
`a46cc55a73a77dfa5691e292451d18d4ec663a04fb5f07b39c6e91915010d437`.

## What it adds

`scripts/build_diag_mirror.py` derives `response_only.p4` from `p4/response_only.p4` by 13 insertions and no
deletions (`diag_mirror.diff`, `diag_mirror.json`). It touches only pipe 0:

- **Frames arriving from the relay (dev64):** n_Ingress names session 101 for every frame received on dev64, and
  n_IgDeparser requests an ingress mirror. The TNA header (`tofino1_base.p4`) says the ingress deparser copies the
  original ingress packet. The 16-byte prefix that N's parser adds to every front-panel frame is therefore not in
  the copy. The model confirms it.
- **Frames leaving toward the relay (dev64):** at the end of r_Egress, a frame leaving on dev64 names session 102
  unless `drop_ctl` bit 0 is set, and r_EgDeparser requests an egress mirror. The copy is the constructed output
  packet, padding and sequence rewriting included. A frame dropped in egress names no session, because bit 0 alone
  does not stop an egress mirror copy.
- **Copy port dev10:** both sessions send to dev10. r_EgParser dispatches only on ports 9, 48 and 64, so a copy on
  dev10 is not parsed. It crosses pipe-0 egress unchanged, touches no register, and names session 0 (no copy). dev10
  is not a loop, recirculation or forwarding port.
- **Mirror-type-0 trap:** each gress writes `mirror_type = 1` on every pass, and the session field defaults to 0
  (no copy). This is the same guard c72's T uses for its session 7.

T and x (pipe 1), session 7 and `scripts/hardware/t_config.py` are unchanged. The T source segment hash is
identical to c72's.

## Sessions

`scripts/hardware/diag_mirror_sessions.py OUT --plan on|off` prints the two `$mirror.cfg` entries:
101 INGRESS and 102 EGRESS, both to dev10, `max_pkt_len` 16384, no truncation. `--apply on|off|absent` writes them
through `switch.Switch`. `off` keeps both entries with `$session_enable` False; `absent` deletes them. All three
states run on the same binary. Applying is a switch write and needs the usual ownership controls. Nothing here has
been applied to hardware.

## Compile (SDK 9.13.2, c72's command, no defines)

| | c72 | c72_diag_mirror | delta |
|---|---|---|---|
| p0 ingress / egress stages | 10 / 10 | 10 / 10 | 0 / 0 |
| p1 ingress / egress stages | 8 / 4 | 8 / 4 | 0 / 0 |
| p0 PHV containers / bits used | 174 / 3381 | 177 / 3404 | +3 / +23 (10 ingress, 13 egress) |
| p0 logical tables, gateways, VLIW | | | +4, +2, +2 |
| p1 MAU and PHV | | | none |

Details: `resource_comparison.json` (`scripts/analysis/resource_compare.py`, baseline c72). Static checks are in
`diag_mirror_checks.json` (`scripts/diag_mirror_checks.py`):

- The pipe-0 mirror tables of both deparsers pass the type-0 guard. The session and select containers are
  solitary, and the session containers are zeroed by the parser.
- The unchanged pipe-1 guard (`check_mirror_select`) passes on both builds.
- Pipe 1's `.bfa` equals c72's once compiler-generated names are mapped. One exact-match hash seed line remains;
  recompiling the unmodified c72 source reproduces c72 byte for byte.

## Model evidence (results/models/c72_diag_mirror/)

All of it is SDK tofino-model functional output. It is not hardware and not timing.

- `diag_mirror_fidelity_01.json`, passed. The smoke exchange set ran with sessions on, off and absent.
  - On: 13 of 13 relay-leg frames were copied byte-exact to dev10. That covers 5 frames received on dev64,
    including the native READ, SELECT and OPERATE responses before padding, and 8 frames emitted on dev64, including
    the SELECT/OPERATE requests and ACKs whose acknowledgement numbers E rewrote.
  - Off and absent: no copies.
  - dev9 and dev64 outputs, ingress passes, recirculations and loop reflections are identical across the three
    states.
  - An LLDP frame entering dev10 goes nowhere.
- `diag_mirror_companion_01.json` and `_02.json`: six unmodified c72 drivers (smoke, relay_sbo, packets,
  select_lifecycle, two_read_robust, response_ready), each run with the sessions absent and on, while dev64, dev9 and
  dev10 were recorded.
  - With the sessions on, every copy matched one frame injected on or emitted from dev64, and every such frame had
    its copy: 2,148 copies in attempt 01 and 591 in attempt 02.
  - select_lifecycle and two_read_robust drop 2 and 6 frames in dev64 egress. None of them was copied.
  - With the sessions absent, there were no copies.
  - Driver verdicts and the dev9/dev64 frame sequences were identical in both states, with two exceptions, both
    outside the P4.
  - Exception 1: in attempt 01, the absent run of packets stopped at `read_seq_37_mapped_ack`. The model took in
    the injected frame 6.3 s late, after the driver's 3 s window, then forwarded it correctly. Its rerun (attempt 02)
    passed 763/763 in both states.
  - Exception 2: in attempt 02, the "on" run of packets has one extra frame at the start. It is a 127.0.0.1:8001
    switchd-model frame, which the driver's port-48 reflector picked up before its socket was bound. The program
    forwarded it to dev64 and copied it.
  - The summary files therefore read `passed: false`. response_ready is flagged only because a T timestamp register
    and the T re-wait count (23 vs 24; c72's own run has 25) differ between runs. Its 838 verdicts match.
- `gate_vs_c72_01.json`: the 17 c72 model drivers on this build with the sessions absent, through `run_model.py`.
  - All 17 exit 0, and their case names and verdicts are identical to c72's runs.
  - abort failed once (attempt 01). Its held-SELECT `+50` case raced the model clock, as that driver documents. It
    passed 84/84 on attempt 02.
  - The only observed differences from c72 are T's `ack_commit_at_reg` timestamps and the T re-wait count.
- The runs used a scratch copy of `scripts/` taken at commit 7cec084b4. The copy differs only in
  `action_observations.json`, whose `source_sha256` names this build. The 61 action bodies it pins are unchanged.
  `gate_vs_c72_01.json` records the file-by-file comparison.

## Not established

- dev10's cabling to Vision `enp59s0f1np1` is an inference from D1. The first hardware step must confirm it.
- The model shows ingress copies are pristine and egress copies equal the emitted bytes. Silicon is not tested.
- Mirror timing and copy loss under load are uncharacterized (plan D3).
- `freeze_gate` refuses a non-canonical candidate. A hardware run of this build needs a diagnostic path that is
  not built yet.
