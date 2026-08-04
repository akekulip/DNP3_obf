# Ditto (NDSS'22) vs Defense 3 — what transfers, what is impossible, and what to build

**2026-08-04. Four-specialist study (principal-investigator, sdn-networks-expert,
p4-dataplane-engineer, power-systems-expert) plus a full read of the paper and its code.
No hardware was touched. Philip's framing: "we have made the assumption that is impossible
which is not good" — so every prior negative claim of ours was re-examined against the
paper rather than defended.**

Paper: `2022_NDSS_ditto WAN Traffic Obfuscation at Line Rate.pdf`. Code:
`github.com/nsg-ethz/ditto` (SDE 8.9; a Python generator emits the per-pattern P4).

---

## 0. Correcting the premise first

**Ditto does not split packets.** Stated three ways in the paper — "ditto can only make
packets larger"; Eq. 3 selects the next-*larger* pattern state; fragmentation "is often not
available on switches or routers for performance reasons", so the largest pattern state must
be ≥ MTU. Table II lists its techniques as **P (padding), C (chaff), D (delay)**, with no
splitting column anywhere. The repository contains no fragmentation code.

So our standing conclusion "on-switch DNP3 response splitting is infeasible" is **corroborated
by Ditto, not refuted by it**. Splitting is also strategically moot: it changes segmentation,
not total bytes, and any observer that reassembles the TCP stream recovers the size.

---

## 1. What Ditto actually is

A repeating **pattern** `P = [P_0 … P_{L-1}]` of packet *sizes* (L = 3–6), emitted at a
**fixed rate**, computed offline from the expected size distribution. Three data-plane ops:
pad, delay, insert chaff.

The mechanism that makes it exact: per pattern state, a **pair** of priority queues — high =
real packets, low = flooded with chaff — so the pair is **never empty**; then round-robin
across the L pairs yields the pattern. The chaff flood exists precisely because round-robin
*skips empty queues*, which would otherwise break the pattern. TF1 has no hierarchical
scheduler, so every packet traverses the switch **twice via loopback ports**.

**Verified independently from the local SDE** (`~/bf-sde-9.13.1`): TF1 genuinely lacks the
L1-node scheduling tier — `bf_rt_tm_tf1.json` has no `l1_node.*` table while
`bf_rt_tm_tf2.json` does; `tm_tofino_hw_intf.h` contains zero `l1_` symbols against 16 in the
TF2 header. The C API exists but dispatches through a table TF1 never populates. Ditto's
two-pass trick is therefore genuinely necessary **for them**.

---

## 2. The size axis is closed — three independent arguments

This is the headline, and it is a *result*, not a disappointment.

**(P1) Strippability.** Any filler an unmodified receiver correctly ignores must be
self-identifying at the same protocol layer the observer parses. **The receiver's ignore-rule
is the observer's strip-rule.** This kills the prepended black-hole DNP3 link frame (the
master discards it by destination-address filtering; so does Zeek) and it generalises our own
2026-07-25 silicon falsification, where sub-IP padding drove `frame.len` to 0 bits while
`ip.len`/`tcp.len` stayed at 1.000.

**(P2) Redundancy — no escape.** The response length is a *deterministic function of the
visible object headers*. The relay's Class-0 response decodes to

```
01 02 00 00 0f   g1v2  Binary Input w/flags        idx 0..15   16 x 1 B
0a 02 00 00 1f   g10v2 Binary Output Status        idx 0..31   32 x 1 B
1e 04 00 00 14   g30v4 Analog Input 16-bit no flag idx 0..20   21 x 2 B
```

from which the length 134 is computable with certainty. Hence `H(len | structure) = 0` and
`I(len ; device | structure) = 0`. **Normalising the length reduces leakage by exactly zero
bits, by any mechanism** — including the Group 110 octet-string filler, which P1 alone would
have survived. The object structure is a far higher-entropy fingerprint than the scalar
length, and it cannot be altered without breaking semantics.

**(P3) Empirically there is nothing to shape, and padding is counterproductive.** The physical
SEL-751 emits **one response size, every time** (200 B wire / 134 B TCP payload, n = 300,
1 distinct value). Class 0 is static data only. Within-device size entropy is already zero.
Padding *only* this relay to a common target would make it the sole device on the network
emitting that constant — an anonymity set of **k = 1** and a *negative* privacy gain.

**Platform corollary.** Tofino-1 **structurally cannot encrypt the payload**: the DNP3 bytes
are the unparsed deparser residual and never enter the PHV. Any size defense therefore needs
crypto from the link layer or an external device. This is a platform fact, not a design choice.

**Why Ditto escapes all three:** its switch is an *endpoint of an encrypted tunnel*. Padding
is inserted where the observer's parse stops, and a **peer switch** removes it. We have
neither the envelope nor the peer.

---

## 3. Chaff is disqualified on safety, before effectiveness

Source-verified in `opendnp3-community` (file:line in the specialist record):

| chaff | what the master actually does | verdict |
|---|---|---|
| injected unsolicited response | measurements enter the SOE/data model with **no request correlation and no sequence validation** | forbidden |
| any injected application frame | `ProcessIIN` runs **unconditionally, even for rejected frames**: `NEED_TIME` → a g50 **time-sync WRITE to the live relay**; `DEVICE_RESTART` → a clear-restart **WRITE**; class bits → extra READs | forbidden |
| fabricated application CONFIRM | the relay **permanently deletes SOE records** the real master never received | categorically forbidden |
| extra polls / second TCP session | doubles relay load; can displace the operational master's session | forbidden |
| link-layer keepalive chaff | drives `OnLinkStatus`/`OnRequestLinkStatus`, mutates link state, may reply toward the relay | reject |
| **prepended black-hole link frame** | discarded before transport; no measurement delivery, no IIN, no keep-alive restart, stream stays in frame sync | **the only provably inert filler** — but strippable per P1 |

Ditto's chaff is opaque ciphertext inside a tunnel. Ours would be semantically live DNP3
aimed at a protection relay. **Any defense that can cause the master to write to the relay is
disqualified regardless of its privacy benefit.**

---

## 4. The real finding: the grid and the deadline are substitutes

Two specialists reached this independently, from different directions.

**Defense 3 anchors its release on a device-generated arrival** (`t_ACK + D`). That is exactly
why the relay's ACK latency `a` passes through with its spread intact, and why REPORT §12.4
measures READ→ACK separability of 1.000 at every `D ≥ 4 ms`. Defense 3 **relocates** the leak
rather than erasing it. Ditto never has this problem because its output is a fixed pattern,
independent of its input.

**But grafting Ditto's grid downstream of our hold is incoherent.** Either the grid is coarse,
and the observable becomes the grid — making the K=64 reservoir, the deadline register and the
fail-open budget (most of our 10 ingress stages) dead weight; or the grid is fine enough to
preserve the hold's measured 1.72 µs release tail, which needs `1/R ≲ 1.72 µs`, i.e.
**R ≳ 580 kpps of chaff (~297 Mbps at 64 B)**. You get one mechanism or the other.

**So the correct move is not "Defense 3 + Ditto". It is to change what Defense 3 anchors on.**

### Defense 4 — slotted release ("the grid")

Release on **switch-clock edges** `t_k = t_0 + kT`, phase-locked to the master's poll timer,
instead of on a computed per-transaction deadline. Every observable becomes `⌈t/T⌉·T` — a
function of the switch clock and the master's schedule, both adversary-known. No
device-produced interval enters any observable, so §12.4's relocation becomes *structurally*
impossible rather than merely reduced.

**The non-obvious requirement: the master→relay READ must be gridded too.** With READ phase
`φ` uniform, the ACK crosses an extra slot boundary with probability exactly `a/T`, so the
adversary estimates `a = T·P(obs > T)`. At `T = 20 ms` a 5 ms-ACK device crosses at 0.25
against 0.023 for the SEL-751 — separable in tens of samples. Gridding the READ pins `φ = 0`
and the leak vanishes. **Defense 3 never touches that direction, so this is new work.**

What it deletes: the per-transaction deadline arithmetic (and with it the §8.1 large-immediate
SALU hazard), and most of the response-authorisation table — today the single largest stage
contributor. Predicted 7–8 ingress stages against today's 10; only `bf-p4c` settles it.

Residual leak: if `a + c > N·T` the response slips a slot, and the slip *rate* leaks `c` at
granularity `T`. The security claim reduces to a measurable slip probability. **Known
constraint:** the connection-cold first poll runs ~21–25 ms, exceeding any `N·T` that fits the
current fail-open budget — either raise `B` and re-derive `H`, or accept one slipped slot per
TCP connection open (a per-connection tell, not a per-poll one).

---

## 5. Two framings worth keeping for the paper

**The polarity inversion.** Ditto manufactures packets to *fill* a queue so round-robin will
not skip it; we manufacture tokens to *starve* a queue so the scheduler will not serve it.
Same primitive, opposite sign. **Ditto pays for its metronome in wire bandwidth; we pay in
loopback bandwidth**, and ours never egresses. We also do not need their two-pass loopback:
that exists because TF1 has no hierarchical scheduler, but our schedule has one level (gate
open or closed), and a two-stage release order is obtainable in one pass with nested strict
priorities already proven on this silicon (IBSPG Part 11, 100/100).

**The cost-model inversion.** BuFLO, CS-BuFLO, Pacer, NetShaper and Ditto all trade privacy
against overhead because their traffic is bursty and high-rate. At **5 pps and 200 B**, the
provably optimal defense — emission on a content-independent schedule — costs ~10 kbit/s.
**We can afford the ideal instead of a heuristic.** The paper's job then becomes quantifying
exactly what still leaks: the slip rate, intra-burst ordering, and the size axis we prove is
not closable without crypto.

---

## 6. Corrections to our own record

| prior claim | ruling |
|---|---|
| "on-switch splitting is infeasible" | **stands**, and Ditto corroborates it |
| "no byte-preserving DNP3 padding" | true but trivial (padding adds bytes); superseded by the far stronger P1+P2 |
| sub-IP padding is observer-strippable | **stands**, and generalises into the headline result |
| size normalization is "BUILDABLE" (2026-07-18) | mechanically true, **securely void** under P2 |
| "TM shaper starves below ~1200 pps" | **refined**: it is cadence *clumping*, not throughput loss — correct average at 100–2000 pps but ~4.4 s-period clumps at R ≤ 200, smooth above ~600. It is a rate **cap**, not an up-pacer, so it can never manufacture cadence for a sparse flow. pktgen remains the metronome (measured 100 pps ±1) |
| mis-translated ACK causes "challenge-ACK/RST" | **wrong**: RFC 9293 §3.10.7.4 specifies a challenge ACK and drop, **not** a RST. The practical failure is a retransmission stall and session timeout — loss of SCADA visibility on a protection relay |
| "PHV 42% used" (my own report earlier today) | **wrong reading**: 864/2048 is the *tagalong* total. Normal PHV is 45 containers / 793 bits. The binding figures are per-MAU-group: **B0-15 and W0-15 are fully exhausted (16/16)**; new 32-bit SALU operands must land in W32-47 (14 free) |

---

## 7. What to do next, in order

**Gate first (hours, no hardware, data we already hold).** Compute per-observable mutual
information / classifier accuracy for (i) CLRT, (ii) response size, (iii) inter-arrival
pattern, **after** Defense 3, over the 400 defended transactions behind REPORT §12 plus the
native baselines. If size and pattern are already near zero bits for this device, Ditto's size
and pattern machinery has no target here and §2 is confirmed empirically as well as
analytically. **This decision precedes everything else.**

**Then, if the gate justifies it:** design Defense 4 (grid) formally — every observable as a
formula in {lattice, poll schedule, device terms}, showing device terms appear only in the
slip indicator; predict the slip rate from the existing native distribution with a block
bootstrap over connections; re-derive `(T, N, K, B)` against `parameter_policy.py`.

**The falsifying experiment for Defense 4** is a **synthetic device-population run**: drive the
grid with switch-generated READ/ACK/RESPONSE triples at three programmed `(a, c)` profiles —
SEL-751-like (0.45, 2.85 ms), slow-ACK (5, 0.5 ms), slow-response (0.4, 12 ms) — capture at
the master port, and run the §12.4 classifier *between profiles*. The claim is
device-independence; it survives only if every pairwise score sits at the ~0.51 drift floor on
every feature. **This is the experiment Defense 3 structurally could not run** (open item #3,
"a second separate-ACK device — not available"), because under a grid, device-independence is
a property of the release rule rather than of the device. It is a *sufficient falsifier, not a
sufficient confirmation*: the headline anonymity claim still needs a real second device.

**Do not build:** in-band padding of any kind, wire chaff of any kind, or a Ditto graft onto
the existing deadline hold.

**If link crypto ever exists** (a second switch at the far edge — note this is *not* endpoint
cooperation, since the operator owns both edges while the relay and master stay untouched),
the tunnel variant returns and it is *simpler on-chip*: encapsulation makes the inner packet
opaque payload, which deletes the per-flow TCP sequence-space translator, the runtime-Δ
checksum and the MSS re-segmentation — our two highest-risk items — while restoring the entire
size axis.
