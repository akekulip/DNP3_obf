# H0 (Tofino CPU punt/reinject path) — IN PROGRESS, not yet proven

Date: 2026-08-18. Authorization: Philip "full go: build + load H0".

H0 is the go/no-go gate for the whole hardware line: prove the Tofino CPU
punt/reinject path (`dp9 -> P4 -> CPU (ens1/bf_kpkt) -> reinject -> dp64`, and
reverse) is endpoint-transparent and bounded. Status: prerequisites proven,
blocked on one authoritative fact needed before writing P4.

## Proven (verified, no mutations)

- `decps` SSH to Vision (`192.168.10.1` on `enp59s0f0np0`) and the switch
  (`ufispace`, `10.10.54.81`, SDE 9.13.2).
- **`ens1` driver is `bf_kpkt`** (bus `0000:04:00.0`) — genuinely the Tofino CPU
  packet netdev, i.e. the second-boundary hook the design needs. `bf_kpkt` is
  loaded, `kpkt_mode=1`, kernel processing enabled for dev 0.
- Switch runs `defense4_rrc_kernel` (the sibling a swap displaces).
- Port map dp8/dp9/dp64/dp68; **dp64 is the relay** (so the CPU port is a
  different internal dev_port, not 64).
- Deploy/rollback: `swap_generic.sh` / `swap_to_d3.sh`; env is
  `export SDE=/home/decps/Downloads/bf-sde-9.13.2; SDE_INSTALL=$SDE/install`.
- The loaded RRC program uses pktgen (dp68), **not** the PCIe CPU port — so the
  CPU punt/reinject path is genuinely unexercised, as S1 said.

## The blocker (open, must not be guessed)

The P4 needs the **CPU-port dev_port** that `bf_kpkt`/`ens1` injects and receives
on (the port a P4 sets as egress to reach the CPU, and the ingress port of
CPU-originated frames). On this platform dp64 is the relay, so the CPU port is a
different internal dev_port and must be read from the live switch, not assumed.

Attempts so far hit non-interactive friction: `run_bfshell.sh` connects to the
status port but the piped `ucli`/`pm show -a` does not advance to a port table;
`bf-sde-env.sh` does not set `$SDE` (the swap scripts export it directly). The
reliable next step is a careful **interactive** `bfshell`/`bfrt` session (or the
bfrt gRPC on `localhost:50052`) to dump the port table and identify the CPU/PCIe
port, then map it to `ens1`.

## Next actions (H0)

1. Resolve the CPU-port dev_port authoritatively (interactive bfrt port dump).
2. Write a minimal TNA cell-gate: punt a test EtherType from dp9 to the CPU port,
   send CPU-port frames out dp9 (and dp64), forward everything else unchanged.
   Apply the tofino-p4 constraint workarounds preemptively.
3. Compile on the switch (`p4studio` cmake/make/install) — non-disruptive.
4. Snapshot; swap the RRC program for the cell-gate (`swap_generic.sh`,
   rollback `swap_to_d3.sh` ready); enable ports.
5. CPU echo shim on `ens1` + a Vision-side test driver; measure round-trip
   latency, loss, ordering at the dp9 observation point.
6. **Go/no-go:** transparent + loss 0 + latency well under one epoch -> proceed
   to H1. Otherwise record the honest negative (length hiding infeasible on this
   testbed) and roll back.

No P4 was loaded and the SEL-751 was not contacted. The switch remains on the
`defense4_rrc_kernel` baseline, unchanged.
