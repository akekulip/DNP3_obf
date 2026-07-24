# Phase-1 GATE-1 on silicon — dp9/dp11 topology (2026-07-24)

First **bidirectional** silicon run of the DNP3 shadow classifier, on the remapped topology after lane
15/0 (dp8) was isolated as faulty. Two findings that matter, plus the core validation.

## Measured topology correction (definitive)

The authorized decision assumed **Vision=dp11, Hulk=dp9**. The per-port RX-counter test (inject from one
host, see which dev_port's `$FramesReceivedOK` moves) proves the **opposite**:

| Inject from | dev_port whose RX moved | ⇒ mapping |
|---|---|---|
| Vision (`10.10.54.19`) | **dp9** (+606) | **Vision = dp9** |
| Hulk (`10.10.54.158`) | **dp11** (+605) | **Hulk = dp11** |

So the cable swap put **Vision(master) on dp9** and **Hulk(outstation) on dp11**. The role contract is
unchanged (master ingress = dir 0, outstation ingress = dir 1); the variant binds the roles to the
**measured** ports: `PORT_VISION=9w9`, `PORT_HULK=9w11` (`dnp3_shadow_dp9_dp11.p4`). The initial
`dp11/dp9` variant (built for the assumed mapping) was removed.

## Core validation — PASS, reproducible over 3 reps

| rep | DNP3_READ (dir0) | DNP3_RESP (dir1) | PURE_ACK | forwarded byte-identity |
|---|---|---|---|---|
| 1 | 300 | 300 | 605 | TRUE (all forwarded frames) |
| 2 | 300 | 300 | 605 | TRUE |
| 3 | 300 | 300 | 605 | TRUE |

- The **physical-direction gate works on silicon in BOTH directions** — READs classify only from the
  master port (dp9=dir0), RESPs only from the outstation port (dp11=dir1). Previously only dir-1 was
  silicon-validated (session 1); dir-0 was blocked by dp8. **This closes that gap.**
- 0 MALFORMED; every forwarded frame is **byte-identical** to its injected original.
- dp11/dp9 link held **5 min, 0 flaps, 0 errors** (`link_stability_20260724.log`).

## The caveat — a reproducible parser drop of DNP3 link-only frames (NEW, explained)

Per direction, exactly **1 frame of the injected half is not forwarded** (dp8 half: 605/606; dp9 half:
604/605), reproducibly. Traced to the parser, not the link or the capture:

- Vision **transmits** the frame (Vision TX capture: 606/606, frame present).
- The switch **receives** it: dp9 `$FramesReceivedOK` **+606**, 0 `FrameswithanyError`, 0 buffer drops.
- The shadow **class counter only advances 605** ⇒ the frame reached the switch but was **dropped by the
  parser before classification/forwarding**.

The dropped frame is a **DNP3 link-only frame**: 10-byte payload `0564058b00000100ce91` (start `0x0564`,
link-length **5** = link header only, no transport/application layer), carried with 12 B of TCP options
(`dataofs=8`). The shadow parser extracts a DNP3 header past the end of such a short link-only payload and
rejects the packet. This is **pre-existing frozen-shadow behavior** (the variant only changed the two
port constants) that was never exercised before, because the master (dir-0) half never ran on silicon
until now (dp8 was blocked).

**Consequence:** the classifier and direction gate are validated, and all DNP3 READ/RESPONSE/ACK **session**
frames forward byte-identically — but the shadow is **not perfectly transparent**: it drops DNP3
link-layer control frames of this shape. For a live inline deployment this would break the DNP3 data-link
layer. This is a genuine transparency defect in the frozen parser, flagged for a fix decision (it requires
editing the frozen `dnp3_shadow.p4` parser and re-validating — not done autonomously).

## Honest status

- **PASS (silicon):** bidirectional direction gate + classification (300 READ/300 RESP/605 ACK, 0 malformed),
  byte-identity of all forwarded frames, over 3 reproducible reps.
- **NOT clean:** strict count-identity is off by 1 frame/direction due to the **explained** parser drop of a
  DNP3 link-only frame. Not an unexplained loss; not a classification or byte-preservation error on session
  frames.
- Evidence: `rep1..3/` (captures, before/after counters), `link_stability_20260724.log`.
