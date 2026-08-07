# Defense 4, explained simply: what we built, what went wrong, and what is now true

This report tells the whole story of the Defense 4 timing work in plain English. It is written so
anyone can follow it, not just someone who watched the work. It is honest about what is proven and
what is not.

## 1. The problem

A DNP3 outstation is a field device, like the SEL-751 protective relay in our lab. A master polls it
with a READ, and the device answers. On the wire, the answer comes in two parts: first a plain TCP
acknowledgment, then a little later the actual DNP3 response with the data.

The gap between that acknowledgment and the response is called the CLRT, the cross-layer response
time. Every device has its own habit for this gap. An attacker who just watches the traffic, without
decoding anything, can measure the gap over many polls and use it as a fingerprint that says "this is
an SEL-751" or "this is that vendor's relay." That fingerprint is reconnaissance. It helps an attacker
pick targets.

We cannot change the relay (it is vendor firmware) and we cannot change DNP3 (it is a deployed
protocol). So the defense has to live in the network, on a switch between the master and the device,
and it has to stay invisible to both ends: same endpoints, same protocol exchange, same bytes.

## 2. What Defense 4 does

Defense 4 runs on one Intel Tofino switch sitting between the master and the relay. It does not change
any packet. Instead it controls WHEN the relay's acknowledgment and response become visible to the
master. It holds the real packets inside the switch's queues and lets small internal marker packets
circulate to hold their place, then the switch's traffic manager releases the held packets on a
schedule the control plane sets.

There are four internal queues in a strict priority order:

- Q_ACK_BLOCK (highest), Q_ACK_HOLD, Q_RESP_BLOCK, Q_RESP_HOLD (lowest).

The original acknowledgment and response wait in the hold queues. The higher-priority blocker tokens
circulate until it is time to release. Because the acknowledgment queues outrank the response queues,
the acknowledgment is never released after the response.

There are five behaviors, called modes:

- OFF: pass everything through unchanged (the native fingerprint).
- D1, event: hold the acknowledgment until the matching response actually shows up.
- D2, response deadline: hold the response to a fixed deadline after the acknowledgment.
- D3, acknowledgment deadline: hold the acknowledgment to a fixed deadline, forward the response after.
- D4, dual deadline: hold both, on two deadlines.

The point of D2 and D4 is to make the CLRT the same every time, a fixed value, instead of the device's
natural, telltale spread.

## 3. What went wrong before this work

Three things had gone wrong, and they are worth stating plainly because they shaped everything after.

First, there was a real bug in the switch program. On D2 and D4 the code retired a transaction when
the acknowledgment was released, before the response had arrived. So the later response found a dead
transaction and slipped through unshaped. On the broken binary this happened to every D2 response and
to a third of D4 responses. That is a real defect, not a limitation of the device.

Second, the earlier reports claimed success that the evidence did not support. A test suite was green,
but the tests never fed bad data through the checks. When bad data was fed in, the tools still said
"clean." A scorer printed a warning and then exited as if nothing was wrong. The campaign script
swallowed failures. A manifest failed its own checksum. So "done" did not mean done.

Third, some numbers were described in a flattering way. "Normalizes the CLRT to a fixed value" was
said over a distribution that actually had a tail of late responses. A median was quoted over a
mixture. A defect was described as a boundary.

## 4. First we made the evidence trustworthy (Phase 1)

Before running any more experiments, we rebuilt the whole measurement pipeline so it fails closed,
meaning it refuses bad data loudly instead of passing it quietly.

- The scorer now exits with an error on a missing, empty, or malformed file; on a duplicate
  acknowledgment, a retransmission, a stale tag left behind, a counter that does not add up, an
  internal token leaking to the wire, a queue drop, or a response that bypassed a hold. It passes only
  a fully clean block. It also checks that a declared negative test actually happened, so you cannot
  label a normal run as a missing-acknowledgment test and get a pass.
- The campaign runner no longer hides failures. It refuses to reuse an old output folder, validates
  every capture file, and builds the checksum manifest only after everything is final, then verifies
  it.
- A new paired byte comparator matches the same frame on the way in and on the way out and compares
  the actual bytes, so we can prove the switch released exactly what it received. It catches a single
  changed byte, a dropped acknowledgment, an injected frame, or a changed MAC address.
- The statistics tool refuses to skip a broken block and reports full distributions with their tails,
  not just a median.

All of this is proven by a test suite that feeds each tool the exact bad input it must reject and
checks the exit code. It reports every test by name with the expected and actual result. It passes 78
of 78.

## 5. A controlled software outstation for the hard cases (Phase 2)

The real relay is READ-only and we never send it control commands. But we still need to test what the
switch does when an acknowledgment is missing, a response never comes, a connection resets in the
middle, a response is split into two packets, or a SELECT/OPERATE command appears. The relay cannot be
told to do those on command.

So we built a software outstation that can, deterministically. It uses a real captured SEL-751
response as its template, and it can emit any of 21 controlled cases exactly. The logic that decides
which frames each case sends is unit tested offline, with 58 checks, all passing. Every response it
builds is a valid DNP3 frame. SELECT and OPERATE only ever go to this software outstation, never to the
physical relay.

## 6. The switch is running the fixed program (Phase 3)

While checking the live switch, I first made a mistake worth admitting: I claimed the switch was
running the old broken binary. That was wrong. I had checked the wrong file path. When I read the
configuration the running switch actually loads, it points at the corrected binary (its checksum is
`97175e7d`, built from the fixed source). So the fix is deployed and running. I retracted the false
claim in the record and fixed the check so it can never be fooled that way again: it now reads the
binary the pipeline actually loaded, not a file that happens to sit on disk.

The switch is healthy: the corrected program, the four queues in the right priority order, the mirror,
the packet generator, and the D4 policy of a 4 ms acknowledgment deadline and a 10 ms response
deadline.

## 7. The result: the timing obfuscation works (Phase 4, Campaign A)

We ran a fresh campaign on the corrected binary against the physical relay, READ-only, and scored
every block with the fail-closed pipeline. Five modes, two connections each, 60 polls each, 120 clean
transactions per mode, 600 in total. All ten blocks passed.

The headline: the bug is gone on the real hardware. On D2 and D4 the switch held every single response
(zero bypass) across 120 transactions each. On the old broken binary D2 leaked every response and D4
leaked a third.

The timing itself, measured as the CLRT in milliseconds:

- OFF is the wide native fingerprint: the middle 90 percent of responses spread from about 1.8 ms to
  7.6 ms, with a tail to 15.6 ms.
- D2 and D4 pull that middle 90 percent into a narrow band around 10 ms (about 9.96 to 10.09 for D2,
  9.98 to 10.03 for D4). That is roughly a fifty-fold reduction in the spread. The wide, telltale
  shape becomes a near-vertical line.
- D3 collapses the CLRT to about zero (the acknowledgment and response come out together).
- D1 shapes it to about 11 ms.

The honest caveat, stated plainly: D2 and D4 do not put every response at exactly 10 ms. A small
number arrive late and are released late but safely (D2 up to 16.6 ms, D4 up to 16.7 ms). The bulk is
normalized; there is a late tail. We report the whole distribution, never a single number pretending
to be the truth. The figure `fig_clrt_ecdf` shows this: OFF is a long slanted curve, D2 and D4 are
steps at 10 ms with a short tail.

## 8. What is proven, and what is not

Proven, on the corrected binary, with the fail-closed pipeline:

- The lifecycle fix holds on silicon. D2 and D4 hold every response, zero bypass, with the counters
  reconciling exactly.
- D2 and D4 normalize the bulk of the CLRT to a fixed 10 ms and shrink the native spread by about
  fifty times, on the physical SEL-751.
- D1 and D3 shape as designed.

Not yet done, and not claimed:

- The controlled negative tests (missing acknowledgment, missing response, reset, combined response,
  split response, SELECT/OPERATE) are built and unit tested offline, but not yet run live through the
  switch against the software outstation.
- Paired byte identity is proven for crafted captures in the test suite, but not yet on a live dual
  capture, because the physical relay has no capture point on its side of the switch. That is a
  software-outstation experiment.
- The before-and-after device-classification study is not done. With only one physical relay, we can
  show timing normalization for that device, not cross-device fingerprint defeat. A real
  classification claim needs several comparable devices or a clearly labeled software-profile study.
- The final acceptance gate is not closed, so there is no final PASS verdict yet.

## 9. The honest bottom line

The timing obfuscation works: on the corrected switch program, the two normalizing modes turn the
relay's variable response-time fingerprint into a fixed 10 ms value and hold every response, verified
by a pipeline that is built to catch its own mistakes. There is a small late tail, reported as such.
The remaining work is the controlled negative lab, the byte-identity dual capture, the multi-device
classification study, and the final independent sign-off. None of those are claimed as done.
