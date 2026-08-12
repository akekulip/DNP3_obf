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

## Second hardware run (joint kernel `defense4_joint_size_time_kernel.p4`, commit 8640b89)

> **Architectural correction (see `RRC_DESIGN.md`):** this joint kernel is NOT literally one native
> primitive — `do_shape` is egress-only, the caseA ingress arms timing on READ `0x01` only (SELECT `0x03`
> / OPERATE `0x04` do not arm it), and a global `read_len=18` predicts the ACK. A packet-local egress bit
> cannot admit the earlier request. The "one primitive drives both timing and size" claim is withdrawn and
> replaced by the Release–Replicate–Carve (RRC) design. What this run DID prove on silicon stands: caseA
> ingress forwarding + timing compose correctly and a 49 B READ forwards intact.

- **Forwarding + timing composition FIX VALIDATED on silicon.** The joint kernel (caseA ingress verbatim
  + split on caseA's egress under one `do_shape` predicate) loads, the caseA timing config binds with
  **RESULT: PASS (0 failures)** (the 17-failure mismatch is gone — every caseA table is present), and a
  49 B READ **forwards intact** (stable [49,49,49]) where the split kernel dropped it. The previous run's
  P2 blocker (the composition breaking the timing hold-ring) is resolved.
- **Gate P2 (split → [28,21]) still FAIL, now precisely diagnosed to two concrete causes:**
  1. **The `size49` eligibility predicate is `ip.total_len == 89`, which assumes a 20-byte TCP header.**
     Real DNP3-over-TCP on this testbed carries **TCP timestamp options** (`nop,nop,TS` = 12 B → 32-byte
     TCP header), so a 49 B payload has `ip.total_len == 101`. `size49` never matches → `do_shape = 0` →
     the split never fires; the response is delivered native (single 49 B packet, confirmed by capture,
     NOT dropped — `drop_ctl` never fired). The predicate must key on the **TCP payload length (== 49)**,
     computed from `ip.total_len − ip.ihl*4 − tcp.data_offset*4`, not a hardcoded IP total length.
  2. **The composed setup has a gRPC client-id conflict.** `defense4_joint_size_time_setup.py --mode SPLIT`
     installs `t_policy set_split(cut=28)` (PASS) but then its delegated caseA-timing sub-step fails to
     subscribe to `localhost:50052` (a second gRPC client id collides), aborting before the mirror/
     multicast install. Timing is configured separately anyway, so the split-install should not re-invoke
     the caseA setup in the same process.
  3. The mirror→multicast replication **runtime remains UNPROVEN** (couldn't be reached this run).
- **Rollback: PASS** — `defense4_caseA` restored, `--mode OFF` RESULT PASS, 49 B READ verified.

**Next action (single):** fix the `size49` predicate to match TCP **payload** length == 49 (account for TCP
options via `tcp.data_offset`), and make the split setup install `t_policy` + mirror without re-subscribing
gRPC for the caseA timing (configured separately). Recompile, re-run the emulator with a TCP-timestamp-option
fixture (so this is caught in software), reload, retry P2.

## What remains software/compile-only (unchanged, honest)
Gates N/E/S/O/C all PASS in software/compile (native intersections, OpenDNP3 SBO semantics, byte-preserving
split, bf-p4c clean, observer). The claim remains `O_count+segmentation` size parity, not DPI. Only Gate P1
(the 49 B native READ) is now additionally **physically proven on the SEL-751**; the on-switch split is
blocked pending the egress-composition fix above.
