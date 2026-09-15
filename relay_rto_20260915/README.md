# SEL-751A TCP retransmission timeout — measured 2026-09-15

Two nanosecond-resolution captures taken on the master-facing link, one per arm, with the
matching probe script and checksums. These are the first recorded measurements of the relay's
TCP retransmission timeout; `TIMEOUT_AND_RETRANSMISSION_AUDIT.md` previously recorded it as
never measured.

## Files

| file | what it is |
|---|---|
| `relay_rto_timing_off.pcap` | Timing OFF arm (`--mode OFF`), nanosecond timestamps |
| `relay_rto_obfuscated.pcap` | Obfuscated arm (`--mode D4`), nanosecond timestamps |
| `rto_probe.py` | the probe, exactly as it ran on Vision |
| `SHA256SUMS` | checksums of everything above |

## Method

The probe opens a DNP3 session from Vision (192.168.10.1) to the SEL-751A (192.168.10.7:20000),
waits for the handshake to complete, then installs one `iptables` OUTPUT rule that drops **only
pure ACKs** toward the relay:

```
--tcp-flags SYN,RST,PSH,ACK ACK -j DROP
```

Because the mask includes PSH, the DNP3 READ that follows still leaves Vision, but the kernel's
acknowledgement of the relay's response never does. The relay therefore retransmits its
unacknowledged response on its own retransmission timer, and the capture on Vision's relay-side
NIC (`enp59s0f0np0`) timestamps each attempt. The rule is removed in a `finally` block, and a
detached watchdog removes it again after the hold expires, so a crash cannot strand it. Both
runs confirmed zero leftover rules afterwards.

The READ is the exact 20-byte request replayed from the frozen campaign captures:
`05640dc400000100f387c0c0010a020000165a2c`.

## Result

The relay retransmits its unacknowledged response four times, with binary exponential backoff:

| arm | original | retransmissions (s after connect) | intervals (s) |
|---|---|---|---|
| Timing OFF | 0.522 | 3.516, 9.517, 21.517 | 2.9943, 6.0004, 12.0001 |
| Obfuscated | 0.530 | 3.490, 9.491, 21.491 | 2.9598, 6.0004, 12.0000 |

**The SEL-751A's initial RTO is 3 s, doubling on each retry: 3 s, 6 s, 12 s.** The first interval
reads slightly under 3 s because the relay's timer starts when it queued the segment, marginally
before the capture timestamp of the original.

The two arms agree to within 35 ms on the first interval and to within 0.4 ms on the later ones,
which is itself a result: the obfuscation does **not** acknowledge on the master's behalf toward
the relay. If it did, the relay would never have retransmitted.

Both captures also show relay-originated pure ACKs at roughly 10 s spacing (10.506, 20.526,
30.547, 40.567 s in the Timing OFF run), consistent with the previously observed ~10 s keepalive.

## Why it matters

The control plane's guard band assumes `--tcp-rto-ms 200.0`. The measured value is **3000 ms**, a
factor of 15 larger, so the real headroom between the release budget and a retransmission is far
wider than the configuration assumes. Nothing in the campaign is invalidated by this — the
campaign recorded zero retransmissions, and this measurement explains why the margin was never
close.

## Provenance

Switch `ufispace` 10.10.54.81, SDE 9.13.2, program `defense4_rrc_bor_unified12` loaded from
`/home/decps/Philip_repo/dnp3-defense4/rrc_bor_build_v2/out/`, control plane configured by
`defense4_rrc_bor_unified12_setup.py configure-all` (PASS, 0 fail / 0 warn) with D_A = 20 ms and
D_R = 4 ms. Master host Vision 10.10.54.166. Relay MAC `00:30:a7:02:4c:a2`.

These captures are **not** part of `campaign_v1` and no paper claim rests on them.
