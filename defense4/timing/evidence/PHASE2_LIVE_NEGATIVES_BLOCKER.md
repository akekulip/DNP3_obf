# Live controlled negatives: the exact blocker (topology), and how to unblock it

I investigated finishing the live controlled negatives (missing ACK, missing RESPONSE, FIN/RST,
combined response, multi-segment, SELECT/OPERATE) through the switch. They require the software
outstation on a switch port that the P4 shapes. This records why that cannot be done remotely right
now, with the evidence, and the exact steps that would unblock it.

## The topology, from the P4 itself and live probes

- The P4 shapes exactly one flow, gated on `ingress_port == PORT_RELAY` = **dp64**, where the physical
  SEL-751 is cabled (`defense4_caseA.p4:326`, and the CONSENSUS §8.1 comment). Traffic from other ports
  is not shaped.
- The P4 has an outstation path: `PORT_HULK : from_outstation` maps **dp11** (Hulk) to DIR_OUT
  (`defense4_caseA.p4:977, 321`). But DIR_OUT is **not** shaped. The P4's own comment (lines ~972-978):
  "dp11 is NOT configured on the switch and the live topology reaches the SEL-751 through dp64. Compile
  with `-DD3_REPLAY_ON_HULK` to let a Hulk-side injector stand in for the relay during synthetic gates;
  **the live campaign build must NOT define it**." So the deployed build classifies dp11 as
  from_outstation and does not shape it, by design.
- Live probe: Hulk (`decps@10.10.54.158`) is reachable, but its DNP3-side interfaces are DOWN and its
  only UP interface is on `192.168.100.2/24`, a different subnet, not the `192.168.10.x` DNP3 segment.
  Vision's spare interface (`enp59s0f1np1`) has no carrier. The DNP3 segment's ARP shows only the relay.

## Why it cannot be done remotely

To shape the software outstation, the switch must be running the `-DD3_REPLAY_ON_HULK` build (so dp11 is
classified as from_relay and gets shaped), dp11 must be configured and cabled to Hulk, and Hulk must
have an interface up on the `192.168.10.x` DNP3 subnet running the outstation. None of that is in place:
dp11 is unconfigured, Hulk is not on the DNP3 subnet, and I have no passwordless sudo on Hulk to bring
up and address an interface. Doing it also swaps the switch off the verified live-relay D4 build onto a
different (replay) binary. This is on-site testbed provisioning, not a software task.

## The classification study is also physically blocked

A cross-device fingerprint claim needs at least two comparable separate-acknowledgment (Case-A)
devices. We have one (the SEL-751). The other lab devices (AB1400, ION7550) are combined-acknowledgment
(Case B), out of scope for the CLRT observable. So classification cannot be finished with the available
hardware; with one device the honest result is timing normalization for that device.

## What is ready, and the exact unblock (about 15 minutes on-site)

Ready now: the controlled software outstation scenario engine (`control/outstation/`, 58/58 offline),
the fail-closed pipeline with the paired byte comparator (78/78), and the P4's outstation path
(compiles under `-DD3_REPLAY_ON_HULK`). The remaining steps, which need someone at the bench:

1. Cable Hulk to switch dp11 and bring up a Hulk interface on `192.168.10.x` (e.g. `.8`).
2. Configure dp11 on the switch and deploy the `-DD3_REPLAY_ON_HULK` build (behind the snapshot +
   watchdog + D3 rollback), so the outstation flow is shaped like the relay.
3. Run the outstation on Hulk emitting the 21 controlled cases; capture both sides; score with the
   fail-closed scorer and the paired byte comparator; restore the live-relay D4 build.

Only the outstation's live wire realizer (a scapy TCP endpoint owning the flow) remains to be written;
its deterministic scenario logic is already built and tested.

## What WAS achievable and is done on the physical relay

The lifecycle cases the physical relay can exercise are done and PASS: response-survives-ACK-release
(RESP_HOLD_LATE, D2 held all 240 after-release responses), C0..CF rollover on one connection, and
fail-open bounded release + re-arm. See `final_run/TARGETED_CASES.md`.
