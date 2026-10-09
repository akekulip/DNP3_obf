# [28,30] carve of the Option B′ 58-byte pad: status (2026-10-08)

**Status: candidate, tested on the local Tofino-1 model only.** Nothing here ran on hardware or
reached the testbed. The current response-only, no-split baseline is still `[58]`
(`../../case4_pad58b_wire.p4`, evidence `../pad58b_wire_02/`).

## What the historical evidence does and does not cover

Commit `9ffa9102` showed that the RRC replicate/carve/checksum mechanism works: a 49-byte frame
was carved into `[28,21]`, the two replicas arrived in reverse order (`[21,28]`), and the real
stack reassembled them. That shows the mechanism works in general. It says nothing about this
composition, where B′'s padded 58-byte frame is carved into `[28,30]`. Everything below that
claims `[28,30]` works comes from the runs in this directory, not from `9ffa9102`.

## What was built

`../../case4_pad58b_carve28_30.p4` is `case4_pad58b_wire.p4` with three changes. Run
`diff ../../case4_pad58b_wire.p4 ../../case4_pad58b_carve28_30.p4` to see them all.

1. **Ingress** now parses IP/TCP. A `connection` table, keyed on the 4-tuple plus the native IP
   length (89 = READ, 77 = CONTROL) plus TCP flags, sets `mcast_grp_a` *instead of* the unicast
   route. The control plane installs only ACK and PSH|ACK, so a FIN is never split onto the prefix.
2. **Egress**: `read_pad_t` and `ctl_pad_t` are now keyed on `egress_rid`. Their default action is
   still the unchanged whole-frame pad (rid 0, the unicast `[58]` path). rid 1 renders bytes 0..27
   of the padded image: the link header with the padded length 0x2f and a fresh header CRC, then
   native block 0. rid 2 renders bytes 28..57: block 1 (READ) or control tail 1 with its fresh CRC
   (CONTROL), then the padded tail, with `seq + 28`. The prefix clears PSH.
3. **Egress, refused frames**: the native-CRC gate is unchanged. When it refuses a frame, rid 2 is
   dropped (`drop_ctl`) and rid 1 carries the original once, unmodified.

**Why the carve is fused into the pad action instead of running as a separate later table.** The
first draft used a separate later table. It invalidated, per rid, the headers the pad action had
just made valid (`rtp`, `ctp1`, `ctp2`), and bf-p4c 9.13.1 failed with `1 error generated` and no
error text, followed by `Internal compiler error`. Bisected on 2026-10-08: invalidating `rb1`, a
header the parser made valid, compiles. Invalidating `rtp` alone, which the pad action made valid,
triggers the error. Both variants are in `ice_repro/` (`only_rtp.p4` fails, `only_rb1.p4` compiles,
each with its `compile.log`).

## Where things happen on the TNA pipeline (observed in the model log, `model_0*/pre_order.txt`)

- **Replication comes before padding.** The PRE sits between ingress and egress, so every replica
  arrives at egress as the *native* frame: 107 B (READ, 103 + FCS) or 95 B (CONTROL). That held for
  all 106 replicas in each run. Neither replica receives a padded frame. Each one runs the
  eligibility/native-CRC gate itself and renders only its own slice of the padded image.
- **The PRE emits the last-listed node first.** With the group's node list `[1, 2]`, the model
  copied RID 2 (suffix) before RID 1 (prefix) for 53/53 multicast frames in each of `model_01`,
  `model_02` and `model_04`. Egress and the wire then preserved that order: arrival was
  `suffix,prefix` in 21/21 trials per role. With the list reversed to `[2, 1]` (`model_03_node_order_21`),
  the model copied RID 1 first 53/53 times and arrival was `prefix,suffix` 21/21. On the model the
  order is deterministic and follows the reverse of the node list. This is consistent with the
  `9ffa9102` reversal, but the hardware PRE order was not measured here.

## Correctness checks (all on the model, `model_04/cases.json`: 729/729 pass; `model_01`, `model_02`: 728/728)

Expected bytes come from two software sources, never hand-copied: the padded image from
`framework/size/case4_pad58b.py` and the segments from `framework/size/rrc.py`'s own segment
builder. Each received frame is also re-checked from its own bytes. For READ and for CONTROL, each
of 23 split cases (PSH|ACK, ACK only, seq wrap at 0xfffffff0, 20 order trials) checks:

| property | result |
|---|---|
| exactly 2 frames out, each byte-identical to rrc's expected prefix/suffix, no stray frame | pass, 46/46 cases |
| `prefix ‖ suffix == padded 58-byte image`, byte for byte | pass |
| payload sizes `[28, 30]`; IP total length `[68, 70]` | pass |
| IPv4 header checksum valid on both; TCP checksum valid on both | pass |
| seq: prefix = original, suffix = original + 28 (including 32-bit wrap) | pass |
| flags: prefix = flags & ~(PSH\|FIN), suffix = original; ack and IP id unchanged | pass |
| DNP3 CRCs: the cut falls at the end of block 0 in both roles (header 8+2, block 16+2 = 28), so no CRC spans it; the prefix's 2 CRC blocks and the suffix's 2 CRC blocks each check on their own; the reassembled 58 B passes `rrc.dnp3_frame_ok` | pass |
| FIN\|PSH\|ACK on the split connection is not split; it leaves as one `[58]` frame | pass |
| an unselected connection leaves as one `[58]` frame (the baseline path is intact) | pass, READ and CONTROL |
| 7 frames with one native CRC/header byte corrupted leave **once**, byte-identical to the input | pass |

**Test discrimination** (`mutant_control/`): with the suffix seq changed to +27 and the refused-rid-2
drop removed, the same driver fails 76 checks. All READ split cases fail, and all 7 refused frames
come out twice. CONTROL, which the mutation did not touch, still passes.

## TCP reassembly by a real stack (`kernel_02/reassembly.json`: 184/184; `kernel_01`: 184/184 from `model_01`)

`../../reassemble_kernel_pad58b_carve28_30.py` writes the **exact frames the model emitted** to a
veth inside a private user+network namespace. A real Linux 5.15 TCP socket receives them. TCP_REPAIR
places the socket directly in ESTABLISHED with `rcv_nxt` equal to the prefix seq; after that the
kernel's normal receive path runs. For each of the 46 split cases:

- in the model's arrival order (`suffix, prefix`), the socket delivered exactly the 58-byte padded image;
- in the reversed order it delivered the same 58 bytes;
- control: the suffix alone delivered 0 bytes, because the kernel holds it out of order behind the 28-byte hole;
- control: a prefix with one TCP-checksum bit flipped, followed by the suffix, delivered 0 bytes, which shows the kernel validates the checksums the deparser wrote.

So on this kernel, arrival order does not affect reassembly. This test did not cover the DNP3
master application (OpenDNP3) reading these bytes, and it did not cover the master host's own
kernel.

## Measured cost: `[28,30]` against `[58]`, same compiler (bf-p4c 9.13.1), standalone compile

Both builds come from the same per-stage logs (`resource_compare.txt`; `out/` is gitignored, and
`manifest.json` hashes the logs).

| | `[58]` (`pad58b_wire_02`) | `[28,30]` (this dir) |
|---|---|---|
| egress stages | 8 | 8 |
| ingress stages | 1 | 1 |
| critical path | 6 | **7** |
| tables | 26 | 32 (+`Ingress.connection`, +`drop_replica_t`, +4 compiler-inserted `egress_reset_invalidated_checksum_fields_*`) |
| SRAM blocks | 8 | **30** (per stage 0/2/3/7: 3→8, 1→8, 2→12, 1→2) |
| hash bits / gateways / VLIW | 175 / 17 / 18 | 295 / 22 / 24 |
| exact xbar bytes / TCAM | 139 / 6 | 164 / 6 |
| PHV containers, bits used (ingress + egress) | 77, 1159 (26 + 1133) | 80, 1369 (173 + 1196) |
| egress pipeline passes per response | 1 | 2 (each carrying the full native frame) |
| frame bytes per response (eth+ip+tcp+payload) | 112 | 82 + 84 = 166 (+54, +48%) |
| wire bytes incl. FCS, preamble, IFG | 136 | 214 (+78, +57%) |
| ingress work | none (the pad is egress-only) | a multicast decision table, so the PRE can only be reached from ingress |

The SRAM increase sits in stages 0, 2 and 3. Those stages hold `Ingress.connection`, `read_pad_t`
and `ctl_pad_t`, which are now exact-keyed on `egress_rid` instead of keyless default-only tables.
That attribution comes from placement and was not isolated per table.

## Recommendation (mine, not a decision)

**Keep `[58]` as the baseline. Do not adopt `[28,30]` now.** On the model it works: it is
byte-exact, the CRCs stay intact, the checksums are valid, it fails closed, and a real TCP stack
reassembles it in either order. But it costs more on every axis measured above: +1 critical path,
3.75x the SRAM, two egress passes and +57% wire bytes per response. Its biggest cost is
integration. It needs a table in pipe 0's ingress, which the `[58]` design avoided because that
ingress is already full (12/12). It also buys nothing that `[58]` lacks among the padded responses:
READ and CONTROL are already the same 58 bytes in one segment. `[28,30]` becomes worth its cost
only if the threat model needs these responses to match some other traffic's segmentation. That
requirement should be stated before any hardware work.

## Not done / open

- No hardware run, no hardware PRE order measurement, and no combined pipe-0 fit with the
  installed ingress.
- The DNP3 master application did not consume the reassembled bytes in this test.
- Runs `model_01` and `model_02` used the driver before the `NODE_ORDER` probe and its record row
  were added (728 checks). `model_03`/`model_04` used the final driver (729 checks). The P4 binary
  was the same throughout (source sha256 `0e05b5df…`, `manifest.json`).

## Reproduce

```bash
cd defense4/timing/case4_architecture
python3 build.py protocol/case4_pad58b_carve28_30.p4 <new_dir>
integration/core/launch_model.sh -p <new_dir>/out -o <new_dir>/model_01 -P "1 2" -d protocol/model_drive_pad58b_carve28_30.py
NODE_ORDER=2,1 integration/core/launch_model.sh ...      # PRE order probe
unshare -Urn python3 protocol/reassemble_kernel_pad58b_carve28_30.py <new_dir>/model_01/cases.json <new_dir>/kernel_01
```
