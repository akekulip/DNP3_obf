# N+T+E composite on silicon: timing and padding on one connection (2026-10-11)

**Result.** The full composite (N admission in pipe 0, E padding in pipe 0 egress, T timing in pipe 1)
loaded and installed on the real switch and carried a live DNP3 connection between the two software
endpoints. On the bound connection the packet generator ran, blockers lapped, the hold queues held real
cells, and all ten READ responses reached the master padded to 58 bytes with valid CRCs. The SBO OPERATE
was lost on that connection, and a second connection on the same tuple did not bind. Both of those trace to
known limits, below. This is the first time timing and padding have run together through the ASIC.

## Setup

- Switch program `response_only`, build `route_ab_01/loopback_ports_01/shared_compile_switch_9132`
  (`--relay-port=9 --n-ack-return=48 --t-in=180 --hb-return=181 --held-return=182`), hashes bfrt.json
  `d1ac5cf6…`, p0/tofino.bin `4a322a75…`, p1/tofino.bin `bb58c2cb…`. Loaded with pipe_scope `[0]`/`[1]`.
- Installed by `hw/bringup_composite.py --apply --enable-pktgen`: 35 writes, read back; the four
  front-panel ports 48, 180, 181, 182 put in `BF_LPBK_MAC_NEAR` first (dev 68 and 196 are the only
  pipe-local recirculating ports on this chip, `evidence/recirc_ports_01`).
- Endpoints: `SocketGatePad58B` master 192.168.10.61:54410 and outstation 192.168.10.62:20000, both on
  dev_port 9 (VEPA, `disable-source-pruning on`), clean TCP profile, separate-ACK emulation on
  (`run.py casea on`, 25 ms). READ sent in the 20-byte 8-bit-range form.

## The bound connection (`loop_first_10`, master port 54410)

- Endpoint: 10/10 READs completed and matched the seed; SELECT accepted (1 real, 0 decoy); **OPERATE never
  completed** (`operate_real` 0); master `success` false.
- Wire: all ten READ responses 49 -> 58 bytes, CRCs valid, 0 checksum errors; the SELECT response came back
  at 37 (native); 5 of 31 master->outstation frames did not reach the outstation.
- Switch counters (snap_before -> snap_after): the READ generator app fired 3,887 triggers / 15,548 packets;
  `OUT_HELD_REWAIT` 0 -> 149,833 (blockers lapping the loopback); `OUT_ACK_FALLBACK` 0 -> 10 and
  `OUT_RESP_FALLBACK` 0 -> 10 (every READ released by the fallback timer, not the clean commit path);
  queue watermarks moved on ACK_HOLD and RESP_HOLD (real queue residence). No OPERATE outcome counter moved.

So on silicon the generator, the blocker lap, the hold queues and the release all work, but through the
fallback path, and the OPERATE path produced nothing.

## The two limits this exposes

1. **OPERATE lost, and READs release by fallback not commit.** The clean ACK-commit path and the OPERATE
   ladder both depend on internal frames crossing the front-panel MAC loopback (ports 180/181/182). Several
   of those frames do not begin with an Ethernet header — their bytes 12-13 land in the MAC's
   type/length field (`loopback_ports_01/RESULT.md`), and the direct OPERATE blocker carries the IP id
   there. A MAC that drops on a length mismatch would lose exactly these, which matches the fallback-only
   releases and the lost OPERATE. The proposed smallest fix (keep the Ethernet header on the OPERATE
   blocker, `read_queue_timing.p4:506`) is not yet applied or tested.

2. **N does not re-arm.** A second connection on the same tuple (`loop_54410_b`, port 54410) did not bind:
   5 SYNs out, 0 back. A new connection needs a fresh cold bring-up until N re-arm exists. A run on an
   unbound port (54411) passes natively with no padding and proves nothing; use the port the bring-up bound.

## What is proven, and what is next

Proven on hardware for the first time: the composite loads on the 2-pipe chip with the loopback port map,
the installer brings it up and tears it down, the pipe-1 packet generator runs, blockers lap through
front-panel MAC loopback, the hold queues hold cells, and READ responses are padded to 58 while T is active.

Next, before a clean paired OFF/ON comparison: apply and test the OPERATE-header fix; confirm whether the
MAC drops the header-less internal frames (the per-frame loopback check in `loopback_ports_01/RESULT.md`);
and either add N re-arm or script a cold bring-up per connection so each arm is a fresh bind.

## Files

`loop_first_10/` (the bound run: master/outstation JSON, result, state) and `loop_first_10_{out,in}.pcap`;
`loop_54410_b/` (the failed rebind); `snap_before.json` / `snap_after.json` (switch counters around the
bound run). The rig was restored to baseline afterward (relay slot, ping .1 -> .7, NIC flag off).
