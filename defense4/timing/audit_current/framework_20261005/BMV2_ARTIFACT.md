# BMv2 artifact — what it is, how to run it, what it shows, what it does not (2026-10-06)

Everything runs unprivileged: `framework/bmv2/lab/run_lab.py` re-executes itself under `unshare -Urnm`, so every interface, namespace and
process exists only inside a private user+network namespace and vanishes with the run. No host network is touched.

## Run it

```
python3 -B -m unittest discover -s defense4/timing/framework/tests -p "test_bmv2_artifact.py"      # 9 cases, about 1 minute
python3 -B defense4/timing/framework/bmv2/lab/run_lab.py step5 /tmp/run '{"mode":4,"da_us":10000,"gap_us":1000,"budget":1000,"loop_pps":20000,"shape":1}'
```
Needs `simple_switch` (1.15.0), `p4c-bm2-ss`, `ip`, `ethtool`, scapy-free Python 3.8. Steps: `step1` forwarder, `step3` parser + roles, `exp_priority*`
queue experiments, `step5` the full policy (modes 0, 2, 3, 4; `shape`; `dropreq`; `combined`; `force_points`).

## Incremental build, in the meeting's order

| step | program | shows |
|---|---|---|
| 1 | `step1_forward.p4` | valid DNP3 READs master → BMv2 → outstation, 49-byte responses at both capture points |
| 2 | `step3_roles.p4` | parse and re-emit every header; TCP frames byte-identical in both directions |
| 3 | `step3_roles.p4` | role counters: READ request, READ response, control response, pure ACK, unsupported (SYN/SYN-ACK carry 40-byte option blocks, forwarded untouched) |
| 4 | `bmv2_rr.p4` | blocker tokens and held packets make real trips through the egress queue of a veth loop (ports 2 → 3) |
| 5 | `bmv2_rr.p4` | dual, ACK-focused (D_A = 0), response-focused and generated-ACK policies; watchdog fallback; next transaction |
| 6 | `bmv2_rr.p4` | size split via a two-node multicast group and an RID-driven egress carve; size-only, joint, shaping off, unsupported size |

## BMv2 semantics measured, not assumed

- **Priority queues do not gate.** `--priority-queues` gives each queue its own rate limiter; with both limited the two priorities
  interleave frame by frame, with only one limited the other drains at once. A high-priority queue never starves a lower one, so the Tofino
  idea of holding packets in a low-priority queue behind blockers does not carry over. **Emulation used:** a live-token count per slot; a held
  packet makes real passes through the same loop and leaves only when its slot has no live token. Release granularity is the held packet's own
  loop time, not one blocker slot. This is a different mechanism with different timing and is labelled as such.
- **Timestamps** (`ingress_global_timestamp`) are microseconds: the switch recorded a response 4,025 µs after the request, the wire 4.05 ms.
- **Per-packet trace logging** (`--log-console`) is far too slow for timing runs (it added 1–3 ms of release error); it is off.
- A table may be applied at one call site only; `truncate`, `clone` to a multicast group and `update_checksum` over conditional field lists
  behave as the program expects. `tcpdump` cannot drop privileges inside the namespace, so captures use a raw `AF_PACKET` socket with
  kernel timestamps.
- BMv2 has no packet generator: the blockers are clones of the request.

## Measured accuracy (software timing, not Tofino evidence)

| quantity | configured | observed |
|---|---|---|
| ACK release, D_A = 20 ms | 20 ms | +0.6 to +0.7 ms |
| ACK release, D_A = 5 ms (response arrives at about 4 ms) | 5 ms | +0.8 to +1.5 ms |
| response gap, dual | 1.0 ms | 0.94 to 1.10 ms |
| generated ACK after the request | — | 0.9 to 1.1 ms |
| watchdog horizon | budget × loop time | ACK leaves within 20 % of it |

Tolerances in the tests (ACK +2.0 ms, gap ±0.4 ms) are these measurements with margin, not requirements.

## Not covered

No BMv2 comparison with hardware exists yet: **no hardware run of this candidate has been made**, so "matched application workloads and
policies" is prepared (same declaration, same analysis) but not performed. Endpoints are the repository's Python codec and a small
labelled outstation emulator, **not** opendnp3 or pydnp3. One flow, one outstanding READ. SELECT and OPERATE are not implemented in
the artifact. The response-ready P4 for Tofino is a different program with a different gating mechanism.
