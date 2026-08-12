# READ vs SBO normalization on the physical SEL-751 — pcap-examined result

Goal: prove that, to a passive observer master-side of the outstation-edge Tofino, a **READ** and an
**SBO** transaction on the SEL-751 look the same in **size** and **timing**. Test driven from Vision,
captured on the observer vantage `enp59s0f0np0` (192.168.10.1), examined at the packet level.
Evidence: `evidence/hw_rrc_readsbo_20260812T212234Z/` (size-only) and
`evidence/hw_rrc_joint_20260812T223342Z/` (joint D4 + size). Switch left in the **joint** state
(`shape_enable=1, mode=4` D4, da_dr=22 ms, PRE RID1/RID2 → dp9); restore with
`configure-timing --mode OFF` (size-only) or `+ rollback-rrc` (transparent).

## Test design

| | Trial A (READ) | Trial B (SBO) |
|---|---|---|
| Request | 23-point G10V2 READ (`0A 02 00 00 16`) | 2-CROB SELECT, real pt0 + decoy pt1 (**non-actuating**, no OPERATE) |
| Count | 30 over one persistent conn, src 192.168.10.1:40000 | 30 over one persistent conn, src 192.168.10.1:40000 |
| Native response | 49 B TCP payload | 49 B TCP payload (32 B G12 echo + link framing + block CRCs) |
| Safety | READ-only | SELECT-only; pt0/pt1 read OPEN before **and** after — nothing actuated |

## SIZE — normalized, identical (PASS)

Packet-level, from the pcaps (socket layer reassembles TCP, so segmentation only lives in the capture):

| Observable | READ | SBO | Same? |
|---|---|---|---|
| Response segment histogram | 30×**28** + 30×**21** | 30×**28** + 30×**21** (+ 2×58 state-reads, correctly **unsplit**) | **yes** |
| Reassembled units | 30 × exactly 49 B | 30 × exactly 49 B | yes |
| Segmentation vector | `[28, 21]` | `[28, 21]` | **identical** |

The 2 all-points state-reads in the SBO trial return 58 B and stay **unsplit** — proof the RRC
eligibility is **size-specific** (keys on the 49 B TCP payload), not "split everything." An
`O_count+segmentation` observer cannot tell a READ response from an SBO response: same count, same
sizes, same segment boundaries.

## TIMING — normalized under the D4 hold (PROVEN, joint bundle)

Two states were captured. **(1) Size-only** (`mode=0`, `evidence/hw_rrc_readsbo_.../`): the response
is at the SEL's **native** timing — READ 2.84 ms / SBO 2.57 ms median, but the READ trial carries a
22 ms cold-poll tail (std 4.31 vs 1.33), so timing is *not* enforced there. **(2) Joint D4 + size**
(`evidence/hw_rrc_joint_.../`): with the D4 hold active (D_A=2 ms, D_R=20 ms, deadline da_dr=22 ms,
under the 30.8 ms fail-open horizon), every response is clamped to the deadline and both trials
collapse to the same value:

| carved-response latency | READ | SBO (SELECT echoes) |
|---|---|---|
| median | **22.665 ms** | **22.639 ms** |
| std | **0.368 ms** | 1.299 ms (one 29.9 ms near-horizon outlier) |
| n | 30 | 31 |

Medians are **0.026 ms apart** and the native ~10 ms spread collapses to sub-ms — response timing is
now *enforced*-identical for READ and SBO, not merely native-similar. (The SBO trial's 2 all-points
state-reads use an 18 B request that does not match the arming profile, so they release native ~2 ms
and are excluded from the carved statistic; they also stay unsplit at 58 B.)

**How the D4 hold was armed (control-plane only — see `switch/CONFIG_PROVENANCE.txt`):** the earlier
`configure-all --mode D4` disabled the pktgen blocker reservoir because the frozen caseA
`config_params_d4` checks `tbl_params.read_len == 18`, which the RRC kernel (read_len **retired** for
multi-function admission → dead field, reads back 0) fails — cascading to a defensive pktgen-disable.
A cold restart does not change a dead binary field. Fix: call caseA directly with **`--read-len 0`**,
which matches the dead-field readback → no failure → pktgen arms. No kernel rebuild, no switchd
restart. The `0x8000` DA/DR default is a placeholder (0.033 ms, ns-scale); the normalizing hold needs
a ms-scale deadline (here 22 ms), set via `--d-a-ms/--d-r-ms`.

## Verdict against the observer

- **O_count+segmentation, response direction:** READ **==** SBO in **size/segmentation** (proven, pcaps).
  **Timing** is native-similar but not yet enforced-identical (needs the D4 hold; mechanism proven).
- **Honest residuals (unchanged claim boundary):**
  - **Request direction differs:** READ request = 20 B, SELECT request = 45 B — the transaction type
    still leaks on the *forward* channel (this defense shapes the outstation's *response*, the device
    fingerprint; the request is the master's).
  - **Parser (DPI) observer** still separates G10 (READ) from G12 CROB (SBO). Claim is
    size+segmentation parity, **not** DPI equality, and **no device-anonymity claim**.
