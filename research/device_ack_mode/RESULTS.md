# ION7550 on the testbed: Case B natively, and inducible to Case A

**2026-08-03. Physical Schneider/Power-Measurement ION7550 at `192.168.10.8`
(MAC `00:60:78:02:24:45`, OUI = Power Measurement Ltd), reached from Vision
`192.168.10.1` through the Tofino. Read-only throughout: nothing but Class 0 integrity
polls (group 60 variation 1, qualifier 0x06); no control command of any kind, and no
change to the device's configuration.**

## Question

Does a Class 0 read of this device return a **separate** TCP acknowledgement followed by
the response (Case A, which has a CLRT to conceal), or a response that **carries** the
acknowledgement (Case B, no CLRT)?

## Answer

**Case B — combined.** 40/40 transactions across two runs showed no pure ACK between the
read and the response. Then, separately: **the device can be driven into Case A behaviour
from the master side alone**, without touching its configuration (below).

| device | link addr | mode | n | CLRT (ms) | read→response (ms) |
|---|---|---|---|---|---|
| SEL-751 `.7` (control) | 0 | **SEPARATE (Case A)** | 20/20 | 2.758 med (1.72–5.89) | 3.23 med |
| ION7550 `.8` as-is | 10 | **COMBINED (Case B)** | 20/20 | — none exists — | 2.99 med (2.75–3.41) |
| ION7550 `.8`, split read | 10 | **SEPARATE (Case A)** | 20/20 | 1.979 med (1.34–13.25) | 3.02 med |

The SEL-751 arm is a **positive control run in the same session over the same switch
path**: it proves the method detects a separate ACK when one exists, and that the switch
(on the frozen Defense 2 baseline, blocker generator disabled) is not itself altering
acknowledgement timing.

### Wire evidence — as-is (combined)

```
4  0.601542  192.168.10.1 → .8  len 18  seq 1   ack 1     the Class 0 READ
5  0.604603  192.168.10.8 → .1  len 90  seq 1   ack 19    the RESPONSE, and ack=19
                                                          (= 1+18) acknowledges the READ
6  0.604645  192.168.10.1 → .8  len 0           ack 91    the master's own ACK
```
One frame from the device per transaction. Across 20 transactions the capture holds
exactly one zero-length frame from the ION, and it is a **RST at teardown** (the device
resets rather than closing gracefully), not a transaction acknowledgement.

### Wire evidence — split read (separate)

```
4  0.601519  192.168.10.1 → .8  len 9   seq 1    segment 1 of the SAME 18 read bytes
5  0.603751  192.168.10.1 → .8  len 9   seq 10   segment 2
6  0.605275  192.168.10.8 → .1  len 0   ack 19   a STANDALONE pure ACK  <-- Case A
7  0.606892  192.168.10.8 → .1  len 90  ack 19   the RESPONSE, 1.616 ms later = CLRT
```

## Why it is combined, and what actually controls it

The acknowledgement mode is a property of the outstation's **TCP stack**, not of DNP3.
Two quantities decide it: the stack's delayed-ACK timer, and how fast the application
answers. Whichever comes first carries the acknowledgement.

Both were measured here:

- **The ION's delayed-ACK timer is ≈ 40 ms.** This fell out of a failed probe: before the
  link address was known, reads were sent to address 100, which the device ignored at the
  link layer. With no response to piggyback on, its stack acknowledged on the timer, at
  **39.8–40.8 ms across 10 probes** — a textbook 40 ms delayed ACK.
- **The ION answers Class 0 in ≈ 3.0 ms**, far inside that timer. So the acknowledgement
  is always still pending when the response is ready, and always rides on it.
- The SEL-751, by contrast, acknowledges in 0.4–2.3 ms — *before* its own response — so
  its stack does not wait for a delayed-ACK timer at all.

This also explains the taxonomy without any appeal to vendor intent: Case A and Case B are
not device categories so much as the two sides of the inequality
`response latency  vs  delayed-ACK timer`.

## Can the device be configured to emit separate ACKs?

**Not through device configuration — but it does not need to be.**

- **No DNP3 or device setting exposes this.** The behaviour lives in the embedded TCP
  stack (delayed-ACK timer), which the DNP3 profile does not cover and which the device's
  management surfaces do not expose. The device's open ports are 80 (HTTP config server,
  responds `HTTP/1.0 200`), 20000 (DNP3), 502 (Modbus) and 23 (telnet) — all of which
  configure protocol and metering behaviour, not stack ACK policy. **No configuration
  change was attempted**; this is an assessment of the surface, not a test of it.
- **The master-side lever works and needs no device change.** Delivering the *same 18
  read bytes* as **two TCP segments** obliges the receiver to acknowledge immediately —
  RFC 1122 §4.2.3.2 requires an acknowledgement at least every second full-sized segment
  — so the ACK is emitted before the application answers. Result: 20/20 separate, with a
  real, observable CLRT of 1.979 ms median. The DNP3 bytes are byte-identical; only the
  segmentation changed.
- **A second, untested lever** follows from the same inequality: any read whose processing
  exceeds ~40 ms would also force a standalone ACK. Not attempted here — the segmentation
  lever is simpler and does not depend on finding a slow request.

### What this does and does not license

- It **does** give the project a second device that presents a Case A observable, which is
  what report open item #3 ("a second separate-ACK device", previously "not available")
  was blocked on. Defense 3 holds *acknowledgements*, so a device that emits a separate
  acknowledgement is testable against it.
- It **does not** mean the ION7550 leaks a CLRT in normal operation. The separate ACK here
  is induced by *our own master's* segmentation. A real deployment's master is a third
  party, and with an ordinary single-segment poll this device is Case B and has no CLRT to
  observe. Any use of this in an evaluation must say plainly that the Case A observable
  was induced, and by what.
- The induced CLRT (1.98 ms median) is a genuine measurement of *this device's*
  read-to-response latency minus the acknowledgement delay; it is not an artifact of the
  measurement path (the SEL-751 control rules that out).

## Reproduce

```bash
# on Vision (master side, 192.168.10.1, capture group required)
python3 probe_ack_mode.py --self-test                                   # frame builder
python3 probe_ack_mode.py --relay 192.168.10.8 --scan                   # find link addr
sg wireshark -c "python3 probe_ack_mode.py --relay 192.168.10.8 --dest 10 --n 20"
sg wireshark -c "python3 probe_ack_mode.py --relay 192.168.10.8 --dest 10 --n 20 --split-read"
sg wireshark -c "python3 probe_ack_mode.py --relay 192.168.10.7 --dest 0  --n 20"  # control
```

`--self-test` builds the 16 Class 0 frames the D-sweep campaign sent to the SEL-751 and
checks them byte-for-byte against the recorded originals, so a frame-construction error
cannot masquerade as a device finding.

## Corrections to prior notes

- The physical ION7550's DNP3 link address is **10**, not the 100 used in the
  `Traffic Trace/ION7550.pcap` corpus — corpus addresses do not transfer to this unit.
- Project memory recorded the corpus ION7550 at `10.0.0.2`; the capture actually shows
  **`10.0.0.11`** (master `10.0.0.3`). Corrected.

## Evidence

`evidence/20260803_ion7550/` — `ackmode_sel751.json` (control), `ackmode_ion7550.json`
(as-is), `ackmode_ion7550_split.json` (induced), and the matching pcaps.
