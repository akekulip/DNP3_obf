# Native-parity size defense — specification

**Endpoint-assisted native cover generation, not transparent switch-only padding.** This is the
honest framing: the endpoints (master + SEL-751) are configured with real/decoy points so a READ
and an SBO produce the *same native response size*; the switch inserts NO bytes.

## Why this sidesteps the wall

The prior insertion design (`0b6fdba`, `defense4_padnorm_kernel.p4`) grew responses at the switch.
On a persistent DNP3 connection that requires a **multi-boundary transport ledger** — inverting the
running cumulative sum of variable per-response deltas in the reverse-ACK translation — which a single
Tofino-1 SALU cannot maintain (single stateful access per register per packet, no unbounded ledger
loop). See [[dnp3-size-normalization-tf1-multiboundary-wall]].

Native parity removes the cause: **the switch never changes byte counts**, so there is **no sequence
or acknowledgment translation and no ledger**. If segmentation equality is also required, the switch
**splits at existing DNP3 CRC-block boundaries** — byte-preserving (`concat(segments) == payload`,
first segment seq = original seq, subsequent = original + byte offset), which needs no seq-space
translation. That is the only switch action, and it is stateless per packet.

## Mechanism

- **Points:** even indices are REAL, odd indices are DECOYS, configured at both endpoints.
- **SBO:** the master issues a multi-CROB `CommandSet` — one even real CROB + configured odd decoy
  CROBs — via SELECT then an exact-repeat OPERATE. The relay's echo is natively larger by the decoys.
- **READ:** the master requests a configured collection of real/decoy measurement/status objects so
  the relay's native response equals the target SBO size. No opaque filler; only legal DNP3 objects.
- **Switch:** applies the same byte-preserving CRC-boundary segment vector to both classes. No insertion.
- **Timing:** Defense-4 timing normalization remains the (silicon-proven) timing mechanism, unchanged.

## Confirmed native-size intersections (PI arithmetic, verified against measured anchors)

`link_size(u) = 10 + u + 2*ceil(u/16)`; `u_SBO(K) = 9 + 12K` (K CROBs). Measured on the real relay:
1-CROB echo 35 B, 2-CROB echo 49 B.

| Target size | SBO | READ (native, configured) | Status |
|---|---|---|---|
| **49 B** | 2-CROB (real + 1 odd decoy) | **23-point G10V2** binary-output-status | intersection confirmed |
| 61 B | 3-CROB (real + 2 odd decoy) | **7-point G30V1** analog | intersection confirmed |
| 35/75/89 B | 1/4/5-CROB | (solver enumerates G10/G30/G1/G20 matches) | see `candidates.*` |

The full solver + Pareto table are in `length_synth.py` / `candidates.{json,csv}` / `CANDIDATE_REPORT.md`.

**CRITICAL deployment requirement (Gate E finding, from real opendnp3 bytes).** The multi-CROB SBO
serializes as ONE shared G12V1 header whose qualifier width is set by `MasterParams::controlQualifierMode`:
- `allow_one_byte` (qualifier `0x17`, indices ≤255): `u_SBO(K)=9+12K` → 35/49/61 B — **matches the relay
  anchors and the READ intersections.**
- `always_two_bytes` (opendnp3 **default**, `0x28`): `u_SBO(K)=10+13K` → 37/52/67 B — **breaks parity.**

So the master MUST be configured `allow_one_byte` and all decoy CROB indices kept ≤255, or the intersection
does not hold. The qualifier width is itself a parser-visible residual. (Intersection generality, from bytes:
G10V2 matches every SBO K at N=12K−1; G30V1 at N=(12K−1)/5, integer iff K≡3 mod 5.)

## Observer claim (from real bytes — see `offline/observer.py`)

| Observer | READ vs SBO | Basis |
|---|---|---|
| **O_count+segmentation** | **EQUAL** | both 49 B native, identical `[28,21]` CRC-split → same payload-length vector; no insertion |
| O_parse_link | distinct | func/IIN/block layout differ (and request direction: READ `0x01` vs SELECT `0x03`+OPERATE `0x04`) |
| **O_parse_app** | **distinct (residual)** | SBO objects = G12V1 CROB; READ objects = G10V2 status — a parser separates them |
| O_profile/config-known | distinct | knows the point map |

**The claim is O_count+segmentation equality, NOT full-DPI/parser equality.** A parser-aware observer
still distinguishes READ from SBO; that residual is reported honestly and never collapsed into a DPI claim.
No device-anonymity claim; scoped to the tested relay/model.

## Acceptance gates

- **N** native equality — a real serialized common native size / declared common segment vector via legal configured objects.
- **E** endpoint semantics — full SELECT-before-OPERATE, exact even/odd parity, per-object statuses, inert decoys, decoy-failure fails the parity op.
- **S** stream-safe segmentation — byte-identical reassembly, no seq/ack translation, survives the transport adversary.
- **O** observer — pass/fail independently per observer; size success is not DPI success.
- **C** compiler — recorded reproducible clean `bf-p4c` result.
- **P** hardware — **explicitly blocked** this run. Software / OpenDNP3 / emulation / `bf-p4c` only.

## Safety invariants (non-negotiable)

Even = real, odd = decoy; every referenced point exists at both endpoints; SELECT and OPERATE use the
identical SBO command set; the real callback occurs exactly once; odd callbacks are inert in the test
outstation; a failed decoy status fails the parity operation; no direct-OPERATE shortcut; **no physical
command transmission this run**; no proxy / paired gateway / opaque filler / fixed-K fallback disguised
as the result. **Mandatory hardware prerequisite (future, not performed here): odd output points must be
proven physically disconnected / unmapped from breaker control before any physical experiment.**
