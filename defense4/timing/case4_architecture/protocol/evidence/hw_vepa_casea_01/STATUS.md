# Software outstation presenting a separate ACK and a late response (2026-10-11)

**Why.** The OpenDNP3 outstation answers a READ in about 0.3 ms and the kernel puts the request's ACK on the
response segment (299 of 300 exchanges in `../hw_vepa_padding_01`, measured with `hw_vepa/clrt_check.py`). There
is then no separate request ACK, so the interval the timing mechanism acts on (response arrival minus request-ACK
arrival at the master) does not exist. The SEL-751 sends the ACK at once and the response about 25 ms later.

**What was changed, inside `ns_vepa_b` only** (`vision_run.py casea on --delay-ms 25`, undone by `casea off` and
by `restore`): the connected route carries `quickack 1`, so the kernel ACKs every request immediately, and a
netem qdisc on `mvB` delays by 25 ms only the outstation's own DNP3 response segments (IP total length 89 or 77).
This **emulates relay processing time**. It is fixed, without the relay's natural spread, and it is not a
measurement of any device.

**Run `casea_pad_on_30`** (program `case4_response_path`, padding policy on, master port 54405, 30 READs sent in
the 20-byte one-octet-range form with a 20 ms gap, then SELECT/OPERATE; endpoint binary sha256 f66ad08c...,
built from commit 3d6869c04):

| | READ (n = 30) | SELECT | OPERATE |
|---|---|---|---|
| request ACK after request | median 154.5 us | 156.9 us | 66.0 us |
| response after ACK (`clrt_us`) | median 25,312.9 us, IQR 16.9, p95 25,353.0, sd 43.3 | 25,363.2 us | 25,330.1 us |
| response after request (`rt_us`) | median 25,468.0 us | 25,520.1 us | 25,396.1 us |
| ACK carried on the response | 0 of 30 | no | no |

Endpoint: 30/30 READs match the seed, SBO success, 1 real SELECT, 1 real OPERATE, 0 decoy. Switch: COMMIT +32,
growth 312 B = 30x9 + 42, unacknowledged 0. Wire: requests 20 and 35 B unchanged, every response 58 B, CRCs
valid, 0 checksum errors. Times are at the parent NIC's capture point: requests as sent, ACKs and responses as
returned by the switch. They are the measured `m_R - m_A`, not `D_R`.

This run is the size-only reference with a separate ACK on the simpler program. It contains no timing mechanism.
