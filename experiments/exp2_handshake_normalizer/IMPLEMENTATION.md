# Experiment 2B — implementation

How `p4src/handshake_normalizer.p4` realizes the reviewed Experiment 2A design on Tofino-1 (TNA).
Standalone: it imports no Defense-4 source and borrows only the frozen program's fixed-width,
`data_offset`-keyed option idiom as a pattern (no runtime TLV loop).

## Parser (`IgParser`)

Ethernet → IPv4 → TCP. IPv4 proceeds to TCP only for `(protocol, ihl, frag_off) = (6, 5, 0)` — TCP,
no IP options, first/only fragment. `total_len` is copied to `md.tlen` here (a metadata copy, so
later arithmetic never touches the deparsed field). The TCP option region is decomposed into
**non-overlapping sequential 4-byte pieces**: `o0` is the first option (MSS, `k0/l0/mss`), and
`e1..e5` are successive 4-byte extras, extracted **cumulatively** by `data_offset` (6→`o0` only,
7→`o0,e1`, …, 11→`o0..e5`). Each state stops when `data_offset` matches. `data_offset` 5 (no
options) and any value > 11 fall straight through to `accept`. There is no runtime `advance` and no
kind/length decode — the frozen program documents that "the TNA parser cannot advance by a runtime
amount," so option handling is fixed-width and `data_offset`-keyed, supporting `data_offset` 5–11
(0–24 option bytes).

## Ingress (`Ingress`)

**Classification (all in cheap, shallow gateways).** `syn`/`synack` from the SYN/ACK flag bits;
`md.pl` (payload present) from `md.tlen == md.exp`, where `md.exp` is the expected header-only length
looked up from `data_offset` by the const-entry table `t_exp` (no arithmetic on deparsed fields).
The MSS clamp flag `md.clampf` comes from the **range-match** table `t_clamp` (`orig_mss` >
1460). Every remaining predicate — MSS-is-first (`k0==2 && l0==4`), `data_offset==6`, second-option
safety `k1_safe` — is precomputed into a **1-bit flag** in its own gateway. This keeps each gateway
under the PHV-input limit (see `COMPILE_RESULTS.md`).

**Outcome (one index, counted once).** A single `bit<4> outc` captures the packet's one
mutually-exclusive outcome, and `ctr.count(outc)` fires exactly once:

| outc | meaning | action |
|---|---|---|
| 1 | eligible SYN normalized | `canon` |
| 2 | eligible SYN normalized + MSS clamped | `canon` |
| 3 | eligible SYN-ACK normalized | `canon` |
| 4 | eligible SYN-ACK normalized + MSS clamped | `canon` |
| 5 | SYN-ACK non-minimal (has extra options) | fail open |
| 6 | SYN not eligible (no options / MSS not first) | fail open |
| 7 | established segment carrying options | fail open (leak counted) |
| 9 | SYN with unsafe 2nd option (MD5/AO/unknown) | fail open |
| 10 | SYN/handshake carrying payload (TFO/data) | fail open |
| 0 | anything else (non-handshake, established no-opt) | forward |

Eligibility (`md.eligible = 1`) is set only for outcomes 1–4, and drives `t_norm`.

**Normalization (`canon`, a table action).** `t_norm` keys on `md.eligible`; the `1 → canon()`
const entry rewrites the packet: `o0` is set to the canonical `[MSS=md.outmss]` option, `e1..e5` are
`setInvalid` (dropping the extra option bytes), `data_offset := 6`, `total_len := 44`, a non-emitted
`norm` marker is set so the deparser recomputes the TCP checksum, and `tcp_pseudo_len := 24`. The
MSS written is `md.outmss = min(orig_mss, 1460)` (never raised — PMTU-safe), computed from
`md.clampf`. Doing the header-validity edits inside a **table action** (not an inline `if`) is what
the backend lowers cleanly.

**L3 scrub.** `ttl := 64` on every IPv4 packet; `id := 0` only for atomic datagrams
(`flags == 010`, `frag_off == 0`, i.e. DF set / MF clear), per RFC 6864. DF itself is preserved.

## Deparser (`IgDeparser`)

Unconditional IPv4 header checksum. TCP checksum recomputed with a full `Checksum.update()` only
when the `norm` marker is valid (the rewritten no-payload handshake, whose entire covered region is
in PHV). Emits `eth, ipv4, tcp, o0, e1..e5`; the `norm` marker is never emitted. Egress is a
pass-through that emits `hdr` unchanged.

## Fail-open discipline

Every path that is not a recognized, safe, eligible handshake **forwards the packet unchanged** and
only increments a counter. Nothing is dropped; no sequence/ack/TSval is ever touched. MD5/AO/unknown
second options, SYN payload/TFO, non-minimal SYN-ACKs, and established segments all fail open — the
normalizer can only ever *remove a fingerprint on a handshake it fully understands*, never corrupt a
connection it does not.

## Deliberate simplifications vs. the 2A design (documented, not hidden)

- **Supported `data_offset` is 5–11 (≤24 option bytes), not 5–15.** A standard SYN option set
  (MSS+SACK+TS+WScale+NOPs) is ≤ `data_offset` 11; `data_offset` 12–15 fall through to fail-open
  rather than being normalized. Extending to 15 is two more cumulative parser states (`e6`,`e7`) and
  two more `t_exp` entries — mechanical, deferred to keep the compile artifact minimal.
- The `norm` marker is a 1-byte non-emitted header used purely as the deparser checksum condition
  (user metadata cannot gate a deparser condition on this target).
