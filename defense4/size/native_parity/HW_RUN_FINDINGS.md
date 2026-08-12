# Native-parity hardware run — findings (2026-08-12)

Execution engineer run on the physical Tofino testbed from `aaa95c6`. Evidence:
`defense4/size/native_parity/evidence/hw_20260812T170405Z/`.

## Gate results

- **Gate P1 — SEL native READ measurement: PASS.** The physical SEL-751 natively produces a **stable
  49-byte** TCP response to the intended **23-point Group 10 V2** binary-output-status READ (`0A 02 00 00 16`):
  11/11 polls = 49 B, group 10 var 2, count 23, one link frame, not fragmented, not coalesced. This closes
  the previously software-only gap — the READ cover is now **physically confirmed** to match the 49 B SBO.
- **Gate P2 — Tofino synthetic `[28,21]`: BLOCKED.** Not reached: transparent forwarding *through* the
  loaded splitter is broken on silicon (see blocker), so the split could not be exercised. The split logic
  itself was confirmed correctly gated (see below) and never fired.
- **Gates P3–P6 (stress / OpenDNP3-through-Tofino / SEL READ through splitter / SEL SELECT): NOT RUN** —
  blocked by P2.
- **Physical OPERATE: NOT RUN.**
- **Rollback: PASS.** `defense4_caseA` reloaded, `configure --mode OFF` RESULT PASS (0 failures), relay
  READ verified stable at 49 B. Testbed left in the working transparent-forwarding state.

## The concrete blocker (diagnosed, not guessed)

Loading sequence: splitter compiled on the switch (BF-SDE 9.13.2, **0 errors**, `tofino.bin`, source sha
`b9164bed…` matching local); loaded via `swap_generic.sh`; ports + ingress brought up with the caseA setup
bound to the splitter program (`--program defense4_crc_split_kernel --mode OFF`).

Observed: ports came up and the relay was **TCP-reachable** (SYN/ICMP forward both directions), but a DNP3
READ returned **0 bytes** — the relay's 49 B response was lost.

Root cause: the splitter reuses the **frozen caseA (timing) ingress verbatim**, whose response-direction
path routes the packet through the internal **hold-ring loopback** (`$ucast_egress_port = 68`, PORT_PGEN /
PORT_L). In caseA that loop is completed and released by the **timing EGRESS**. The splitter **replaced**
the timing egress with the split egress, which has no hold-ring release, so the looped-back response is
never returned to the master → dropped. The caseA setup's `RESULT: FAIL (17 failures)` is the same fact
from the other side: those 17 are the caseA egress-timing tables the splitter does not contain.

The split egress is **not** at fault: `t_eligible`'s only match requires `POL_SPLIT` from `t_policy`, which
was never installed, so `do_split = 0`, no mirror, no `drop_ctl` — the split correctly did not fire. The
emulator validated the split egress **in isolation** and never modeled the ingress→loopback→egress path,
which is why this surfaced only on silicon.

## Next action (single)

Correct this specific blocker: **compose the split with the caseA timing egress instead of replacing it** —
the egress must first perform the timing hold-ring release (forward the response to the master), and apply
the CRC-boundary split on that released response. i.e. sibling kernel = frozen caseA ingress **+ caseA
timing egress (release path) + the split stage layered after it**, not the split egress alone. Recompile
(BF-SDE 9.13.1 local / 9.13.2 switch), re-run the emulator with an ingress-loopback fixture, then reload and
retry P2.

## What remains software/compile-only (unchanged, honest)
Gates N/E/S/O/C all PASS in software/compile (native intersections, OpenDNP3 SBO semantics, byte-preserving
split, bf-p4c clean, observer). The claim remains `O_count+segmentation` size parity, not DPI. Only Gate P1
(the 49 B native READ) is now additionally **physically proven on the SEL-751**; the on-switch split is
blocked pending the egress-composition fix above.
