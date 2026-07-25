# The trailer-padding size mechanism works, and does not close the size channel

**Measured on silicon 2026-07-25.** `[OBS]` This is a negative result, established by measurement
rather than argument, and it is more valuable than the positive one it replaces.

## Two facts, both measured

**1. After correcting the `pkt_length` keying (+4 for the FCS), the mechanism fires exactly as
designed.** All 30 frames of a defended real-DNP3 campaign left the switch at **128 bytes**, a single
size, with IP and TCP checksums both verified GOOD by tshark and the DNP3 dissector still decoding
function 129. Timing stayed normalized in the same run (CLRT p50 25.000 ms, sd 0.0069 ms).

**2. It normalizes the wrong field.** From the same captures:

| observer feature | padding OFF | padding ON |
|---|---:|---:|
| `frame.len` | 1.000 bits (2 distinct) | **0.000 bits (1 distinct)** |
| `ip.len` | 1.000 bits (2) | **1.000 bits (2)** |
| `tcp.len` | 1.000 bits (2) | **1.000 bits (2)** |

The padding sits **below IP**, so `ipv4.total_len` is untouched **by design** — that is simultaneously
the correctness argument for byte-preservation and the refutation of the mechanism. An observer
reading `ip.len` recovers the original size distribution exactly. Zeek, which this project already
uses, reports `orig_bytes`/`resp_bytes` from TCP sequence numbers and `orig_ip_bytes` from IP bytes —
never frame bytes. **The project's own analysis pipeline would be completely unaffected by the
defense.**

## The general result worth stating

**Any padding that is protocol-transparent — that a receiver can strip without cooperating — is by
construction strippable by the observer, who applies the same rule.** This kills the Ethernet-trailer
mechanism, and it also kills IPv4/TCP options padding for a better reason than the one previously
recorded: options padding changes `total_len`, but it also changes `data_offset`, and the observer
recovers `payload_len = total_len − 20 − 4·data_offset` exactly. The 40+40 B ceiling was never the
binding objection.

Closing the size channel therefore **requires byte modification the receiver cannot undo** — growing
`total_len` with DNP3-legal filler inside the payload, with checksum correction and per-flow TCP
sequence translation. That is the construction already scoped in
`research/inline_dnp3_size_normalization/research_design.md`, and it is a different, larger piece of
work.

## ⚠ Latent corruption hazard in the current program — DO NOT deploy as-is `[OPEN]`

The `size_norm` table keys **only** on `pkt_length`; the egress parser requires `data_offset == 5`.
Nothing couples them. For a `data_offset = 8` frame — **2,102 of 2,104 packets in the real corpus** —
the parser falls through leaving the options and payload in the residual, while the table still
matches on length alone, so the pad is emitted **between the fixed TCP header and the options**,
corrupting the frame and breaking both checksums.

This did not bite here only because the replay frames were deliberately built at `data_offset = 5`;
tshark confirms every checksum GOOD in the run above. **Correcting the `pkt_length` offset does not
fix that hazard — it arms it**, because previously nothing matched at all.

The fix, if this code is ever revived: key the table on a **parser-produced `pad_class`** written as a
constant in each `pl_*` state, so "table matched" ⟺ "parser consumed the whole payload" by
construction, with a fall-through of `pad_class = 0 → pad_none`. That is strictly cheaper than the
current 16-bit key and removes the entire bug class.

## Recommendation

Report the size axis as a **characterized negative** with this evidence, and ship the timing result on
its own. Framed correctly this is a contribution rather than a gap: *on a switch ASIC, the padding
mechanisms that are protocol-transparent are exactly the ones a passive L3 observer strips for free.*
It explains why in-network size normalization for cleartext ICS traffic has not been done, and it
motivates the prepend-with-sequence-translation follow-on.
