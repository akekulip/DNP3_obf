# model_02: local Tofino-1 model + bf_switchd, packets in and out (no root, no hardware)

Date 2026-10-06. SDE 9.13.1 `tofino-model` (chip type 2 = TofinoB0) and `bf_switchd` run inside
`unshare -Urn --pid --fork --kill-child --mount-proc`. Program under test: `egress_wire_06/out` (compiled, untouched).

## Result: WORKS. A frame entered the model and left it.
    TX 60 bytes on veth19 (dev port 9 ingress): 0200000000020200000000010800450000280000400040060000 0a0000010a00000204d24e20...
    RX 60 bytes on veth3  (dev port 1 egress) : identical bytes
    RESULT FORWARDED identical
Negative control (run8, role dispatch not matched, no ingress-port-9 frame): model.out shows
`Table tbl_egress_wire1014 is miss ... ----- Drop`, nothing on the output veth. So the compiled parser, role dispatch,
`Ingress.forward.forwarding` table (programmed over BF Runtime gRPC) and deparser really executed.
Reproduce: `./launch_model.sh ../egress_wire_06/out runNN` (new dir each time). Logs: run10/{model.out,switchd.out,bf_drivers.log,session.log}.

## What blocked, in order, and the fix
1. `tofino-model` rejects `--no-port-monitor` (model_probe.py passes it; run_tofino_model.sh also does) with
   `unrecognized option '--no-port-monitor'`. Drop it, use `--no-cli`. Also needs LD_LIBRARY_PATH=$SDE/install/lib.
   The CAP_NET_RAW blocker (`Unable to drop privileges to purely CAP_NET_RAW`, capset EPERM) disappears in a user namespace
   (root-in-userns holds the caps; model prints `PRIVS: Eff=0 Perm=0x2006`). veth pairs can be created there.
2. bf_switchd with the compiled conf: `BF_PLTFM ERROR - Error unable to find cdc_ethernet port` then
   `Error Getting the Board info from BMC. Hence exiting`. Cause: `"agent0": "lib/libpltfm_mgr.so"` loads the real-board
   platform manager. Fix: use a COPY of the conf with agent0 removed (`noagent.conf`). bf_switchd then says
   `Operational mode set to default: MODEL`, connects dru_sim to the model on :8001.
3. The wall previously seen: `BF_PIPE ERROR - pipe_mgr_lrt_buf_load Error pushing stats free memory to device 0 rc -1 addr 0x0 size 512`,
   `failed to setup async dma buffers`, `ilist_push ... fails -1`. Root cause (strace, run4): the DMA pool mmaps hugetlb
   memory fine (hugepages exist, 196 free) and then reads `/proc/self/pagemap`; without real CAP_SYS_ADMIN the PFN field
   reads 0 (`read(15,"\0\0\0\0\0\0\200\241",8)`), so every DMA physical address is 0. A user namespace cannot fix that.
   Fix: `shim/pagemap_shim.so` (LD_PRELOAD, built from pagemap_shim.c) rewrites pagemap entries to
   PFN = vpn + 0x100000 (present bit kept). In model mode the address only needs to be nonzero and unique.
4. Leaked hugepages: killing `unshare` with `timeout` left tofino-model/bf_switchd alive and exhausted hugepages
   (`mmap ... = -1 ENOMEM`, bf_sys_dma_pool_create failed(-1)). `--pid --fork --kill-child` fixes it; after runs
   `HugePages_Free: 196` and no leftover processes.

Result with fixes: switchd listens on 9090/9999/50052(gRPC)/7777, zero `ERROR` lines in switchd.out.
Harmless noise in bf_drivers.log: `tcu_wrack ... 0xbad0bad`, SDS/SBus errors (no real SerDes).

## Facts needed to drive it
* Model maps dev port N to interface `veth(2N)`; the test side uses the peer `veth(2N+1)`. launcher creates pairs 0..9
  (extend the loop in inner.sh for dev port 64 etc: veth128/129; the model only attached ports it found at start).
* Ports must be enabled through the `$PORT` table (drive.py does it with `$SPEED BF_SPEED_10G`, `$FEC BF_FEC_TYP_NONE`);
  before that the model logs `Packet DROPPED: channel disabled in IPB`.
* Python: system python3 is 3.8 and SDE ships `install/lib/python3.8/site-packages`; use
  `sys.path += [P, P/tofino, P/tofino/bfrt_grpc]` then `bfrt_grpc.client` (drive.py shows bind, entry_add, $PORT).
* egress_wire role dispatch needs `(ingress_port 9, IP total length 40/75/41/60)` or `(port 64, len 40/97/89)`; drive.py
  uses port 9, IP length 40 (forward role) and programs `pipe.Ingress.forward.forwarding` 9 -> 1.

## Not done / next
* Only the forward role plain passthrough was exercised. Next: build frames for the `cache`/`carving` paths (DNP3 with valid
  CRCs, TCP checksum 0xFFEB sum), program `connection`/`profile` tables, and compare output bytes with the Python reference.
  model.out logs every PHV/parser/table step, which is the debugging tool for that.
* Registers (image_*) are readable/writable through bfrt gRPC the same way; replay path needs a descriptor frame first.
* Model timing is not hardware timing; this is functional verification only. Does not verify stage fit (compiler does) or silicon behavior.

Note: the committed copy omits run*/switchd.strace, bf_drivers.log and the model_*.log duplicates (local only, 160 MB); *.out logs are git-ignored and stay local too; run10/session.log is kept.
