# Phase 7 — switch-generated ACK (Case 3): software feasibility result, 2026-10-06

Status: **software-only prototype; NOT acceptable as a paper case.** Nothing was sent to any physical relay.
Evidence: `framework/tests/test_generated_ack.py` (3 tests), BMv2 mode 3 in `framework/bmv2/p4/bmv2_rr.p4`.

## What was asked, and the earlier objection

Dr. Lin proposed changing delayed-ACK behaviour with a switch-generated ACK. The earlier review
(`dnp3_split_harness/reports/phases/phase_04/ack_control_feasibility.md`, §3a, archive revision `9ffa9102d`) held that independent
ACK/response control exists only when a separate pure ACK is already on the wire, and that making one for a combined-ACK device needs
synthesis, TCP splitting, termination or endpoint control. It excluded synthesis by design and measured nothing about it. This phase
measures what synthesis costs.

## Transport responsibility, stated

A switch that observes a request has not established that the outstation received it. Acknowledging the request bytes makes the switch
the party that vouches for delivery. If a proxy owns reliability it must (1) retain the request until the outstation confirms it,
(2) retransmit on its own timer, (3) reconcile the outstation's later ACK or response against its own, and (4) answer window and option
negotiation consistently. None of (1)–(4) exists in the prototype. That is an architectural change, not a transparent switch.

## Prototype

BMv2 mode 3 clones the READ request, rewrites the clone in egress into a pure ACK toward the master (MAC, IP and port swap; sequence
number from the request's ACK field; acknowledgment = request sequence + payload length; ACK flag only; TSval/TSecr swapped when the
timestamp option is present; checksums recomputed), and arms the response deadline from the generated ACK. The window (16,384) is the
switch's own invention and a known limitation. Endpoints are real Linux TCP stacks; the outstation is `--combined` (delayed ACK).

## Results

| question | result |
|---|---|
| Does a real TCP master accept the generated ACK? | Yes. Every transaction completed `OK`; all packets, generated ones included, have valid checksums; exactly one separate ACK per request, about 0.9–1.1 ms after it, before the response. |
| Is there a spurious second ACK? | Only in the first transaction on a connection (Linux quick-ack at connection start, an endpoint artifact). None afterwards. |
| Request lost on the switch → outstation link after the ACK | **Unrecoverable.** Control (transparent switch): master retransmits after about 206 ms and the READ completes in 209 ms. With generation: the master never retransmits (the request was acknowledged), the outstation never sees it, and the transaction times out at 3,003 ms. |
| What does the new ACK do to CLRT? | It creates a channel that did not exist. A combined-ACK device has no separate ACK, so CLRT_original is **undefined**, not zero. With the generated ACK alone, CLRT_new tracks the device's response latency one for one: 3.2, 7.1, 12.7 ms for latencies of 2, 6 and 12 ms. |
| Can scheduling the response remove that spread? | For responses that arrive inside the window. Scheduled to a 15 ms ACK-relative deadline, CLRT_new is 14.5–14.9 ms for all three latencies. A response later than the deadline is not delayed. |

## Verdict

- Software feasibility of generating the ACK: **shown**.
- Transparent end-to-end delivery with the ACK generated: **refuted** by the loss case; it is the earlier objection, now measured.
- Normalising a channel the ACK itself created is not normalising an existing one; the paper must not call it that.
- Hardware fit: **not assessed.** A retaining, retransmitting proxy on Tofino-1 is not designed here.
- Status for the paper: proposed capability, software-only, transport requirement unresolved. Do not present a third physical case.
