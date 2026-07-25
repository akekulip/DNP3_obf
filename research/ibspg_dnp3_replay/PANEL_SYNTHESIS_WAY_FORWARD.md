# Panel synthesis — the way forward

Three independent workstreams examined the size axis after it failed on silicon: an implementation
engineer (root cause + fix), an SDN/programmable-networks review (mechanism), and a power-systems/ICS
review (protocol validity and threat model). **All three converged on the same verdict from different
evidence.** This records the agreed way forward.

## The verdict

**Ship the timing result. Report the size axis as a characterized negative. Do not take trailer
padding near the relay.**

## Why — four independent disqualifications, each measured

**1. It normalizes a field no adversary uses.** (my silicon measurement, confirmed by both reviewers)
After the FCS key fix the mechanism works perfectly — every frame leaves at 128 B — and closes
nothing: `frame.len` 1.000 → 0.000 bits, while `ip.len` and `tcp.len` stay at 1.000 bits. The pad sits
below IP so `ipv4.total_len` is untouched *by design*. Zeek, tcpdump, Wireshark and this project's own
classifiers all read IP/TCP lengths, never frame length.

**2. It never fires on the target device at all.** (ICS review, measured over the corpus)
The SEL-751 negotiates RFC 7323 TCP timestamps, so every one of its frames is `data_offset = 8` while
the construction gates on `data_offset = 5`:

| capture / endpoint | frames | would normalize |
|---|---:|---:|
| SEL751 · relay | 600 | **0.0 %** |
| SEL751L · relay | 8,001 | **0.0 %** |
| SEL751L · master→relay | 16,004 | **0.0 %** |
| AB1400L / ION7550L | 2,002 / 4,047 | 99.9 % |

**3. It defends the weakest channel while perfect ones sit untouched.** (ICS review, measured)

| channel | balanced accuracy (3 devices, chance 0.333) |
|---|---:|
| TCP stack fingerprint (TTL, MSS, initial window, options) | **1.000** |
| ACK mode (separate vs combined) | **1.000** |
| size | 0.493 |

AB1400 uses TTL 128 / MSS 1478 / window 2048; ION7550 TTL 64 / MSS 1460 / window 4380; SEL-751 TTL 64
with timestamps + SACK. A p0f-style classifier separates all three perfectly. Spending 46–68 B per
frame to move device-ID from 0.493 to 0.333 while a 1.000 channel is untouched will not survive
review.

**4. The general rule that kills the whole family.** (SDN review)
*Any padding that is protocol-transparent — strippable by a receiver without cooperation — is by
construction strippable by the observer applying the same rule.* This kills the trailer, and kills
IPv4/TCP options padding for a better reason than previously recorded: options change `data_offset`,
so the observer recovers `payload_len = total_len − 20 − 4·data_offset` exactly.

## Two hazards found, neither deployed

- **Mid-frame corruption.** The table keys only on `pkt_length` while the parser requires
  `data_offset == 5`, and nothing couples them. On a `data_offset = 8` frame the pad lands *between*
  the TCP header and its options, destroying the frame and both checksums. **Fixing the `pkt_length`
  offset does not fix this — it arms it.** Safe re-keying: key on a parser-produced `pad_class`
  constant written in each `pl_*` state, so "matched" implies "parser consumed the payload" by
  construction.
- **PRP/HSR.** The SEL-751 is PRP/HSR-capable, and IEC 62439-3 puts a Redundancy Check Trailer in
  exactly the space our padding occupies. **Never apply trailer padding on a PRP or HSR segment** —
  it breaks LSDU size accounting and silently degrades duplicate discard.

## What replaces it

**For the paper:** the timing result stands alone and is complete — CLRT sd 1.85 ms → 0.0068 ms,
observer entropy 4.707 → 0.211 bits at 50 µs and exactly 0 bits at 1 ms, on real DNP3, on silicon.
The size axis becomes a contribution rather than a gap when framed as: *on a switch ASIC, the padding
mechanisms that are protocol-transparent are exactly the ones a passive L3 observer strips for free;
closing the size channel requires byte modification the receiver cannot undo.* That explains why
in-network size normalization for cleartext ICS traffic has not been done.

**For the size channel, if it is pursued:** both reviewers independently pointed away from the READ
path and away from the network.

- **Re-aim at the CONTROL path.** Size leaks weakly on READ (0.493) and decisively on CROB control —
  N-recovery 1.000, MI 4.0 bits, a size↔count bijection at ~14.6 B per point, which is structural in
  IEEE 1815 g12v1 encoding rather than an artifact.
- **Do it at the master, not in the network.** Composing a fixed-N CROB set with valid-but-unwired
  decoy points fixes the request size, and because the response echoes one status object per point it
  fixes the response size too — closing both directions with no middlebox, no byte trickery, no
  sequence translation and no receiver-tolerance question. Use SBO rather than DIRECT_OPERATE so a
  mis-composed set fails at SELECT. Consistent with this project's earlier decoy-index findings.
- **The only in-network construction that would actually close it** is the one already scoped in
  `research/inline_dnp3_size_normalization/research_design.md`: prepend DNP3-legal filler inside the
  payload, grow `total_len`, correct checksums, and translate TCP sequence space per flow. The SDN
  review notes prepending is *native* to the TNA deparser (`[headers][residual]` is a prepend), which
  removes the `pay*` chunk set and the parser state explosion; the hard part remains the seq/ack
  translator under retransmission and SACK.

## Threat-model correction the manuscript needs

With DNP3 in cleartext, an observer reads function codes and point counts directly, so size
fingerprinting is strictly weaker than just parsing DNP3. The threat model only becomes coherent
under DNP3-over-TLS (IEC 62351-3) — where `total_len` still leaks the record size, so trailer padding
still does nothing. Either adopt the TLS framing (and then normalize `total_len`, not frame length),
or present size as characterization rather than defense.

## Operational items for any relay-facing deployment

An inline byte-modifying device inside the ESP is itself a Cyber Asset (CIP-002 categorization, then
CIP-005/007/010 obligations), and unlike a pure timing delay it changes what the utility's own
monitoring sees a frame to *be* — which matters for CIP-005 R1.5 detection and CIP-008 event
reconstruction. Constructive mitigation: export true per-frame metadata out-of-band to the defender's
IDS, which the existing telemetry/digest path already supports. And because this relay's DNP3 path
carries DIRECT_OPERATE, any relay-facing deployment needs a written, tested no-drop / no-duplicate /
no-reorder argument for the control path including the fail-open — a duplicated CROB pulse is not
idempotent. *(Clause numbers recalled by the reviewer and flagged for verification before citation.)*

## Status of the recommendations

Items 1–4 above are measured. The re-aiming recommendation is a design judgement from two independent
reviewers. The SEL-751's tolerance of trailer octets remains **unverified and now moot** for this
mechanism; if it ever matters, the cheapest safe test is a host-side ICMP → SYN → DNP3-READ ladder
with the relay's own error counters read at each step, and PRP/HSR confirmed disabled first.
