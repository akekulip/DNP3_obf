# Experiment 2B — adversarial review of the implementation

Two read-only adversarial passes over `p4src/handshake_normalizer.p4` and the compile evidence,
each trying to break the artifact. Both **pass the compile gate**; both surface real, bounded caveats
that the functional model run must close.

## Review A — Tofino / bf-p4c correctness

**Verdict: the program is a valid, stateless TNA pipeline that compiles to a loadable binary; its
functional behavior is unproven until the model run.**

Confirmed:
- Compiles `0 errors` to `tofino.bin` on 9.13.1; **stateless** (0 registers/meters declared, 0
  stateful ALUs allocated; the one `Counter` is packet telemetry, not connection state).
- The option region is fixed-width, `data_offset`-keyed (no runtime `advance`), matching the frozen
  program's proven idiom. Header-validity edits live in a table action (`canon`), the shape the
  backend lowers cleanly.
- Table ordering is sound: `t_exp`/`t_clamp` read `data_offset`/`orig_mss` **before** `t_norm`
  (`canon`) rewrites `data_offset` — no read-after-write hazard on the classification.

Caveats it raised (all model-checkable):
1. **Checksum correctness is asserted by construction, not yet observed.** The deparser TCP-checksum
   field list is 16-bit aligned (`data_offset(4)+res(4)+flags(8)` = one word; `o0.k0+o0.l0` = one
   word) and `tcp_pseudo_len = 24` matches the shrunk 20+4 header, but only PTF's byte compare
   against a scapy-recomputed packet proves the checksums land correct. **This is the single most
   important thing the model run validates.**
2. **The `-g` build and the 9.13.1↔9.13.2 seam.** The lab switch is 9.13.2; a 9.13.1 clean compile
   is strong evidence but not a guarantee on 9.13.2. Recompiling on the switch's SDE before any
   (separately authorized) hardware step is required.
3. **Two benign `min_parse_depth` warnings** — bf-p4c padding shallow parse paths; not a defect.

## Review B — TCP / endpoint safety of the realized logic

**Verdict: the realized fail-open discipline is sound and conservative; two semantic points must be
stated precisely so they are not mis-read as "byte-identical passthrough."**

Confirmed:
- MSS is **clamped, never raised** (`min(orig,1460)` via the range table); DF is preserved; sequence
  and ack numbers are never touched; MD5/AO/unknown second options, SYN payload/TFO, non-minimal
  SYN-ACKs, and established segments with options all **fail open** (no normalization).
- Established data segments are re-emitted with their options and **payload byte-preserved** (the
  parser never extracts the payload, so trailing bytes pass through untouched).

Points that must be documented (and are, in `IMPLEMENTATION.md`):
1. **"Fail open" means "do not touch the TCP options," not "touch nothing."** The L3 scrub
   (`ttl := 64`; `id := 0` for atomic datagrams) and the IPv4 header-checksum recompute are
   **unconditional** on every IPv4 packet, including fail-open ones. This is intended — TTL and
   IP-ID are themselves device fingerprints and the scrub is always safe — but it means a fail-open
   SYN leaves with a normalized L3 header and its original L4 options. The TCP checksum of a
   fail-open packet is **not** recomputed (correctly, since no L4 field changed), so it stays valid.
2. **Supported `data_offset` is 5–11, not 5–15.** A SYN with more than 24 option bytes falls through
   to fail-open rather than being normalized. Standard SYNs fit; the bound is a deliberate
   minimal-artifact choice (extend with two more cumulative parser states + `t_exp` entries).
3. **The endpoint-safety claim is still Experiment 3's, not this one's.** Whether real SEL751 /
   ION7550 / AB1400 stacks honor the RFC 7323/2018 negotiation fallback (emit no options on
   established segments after a stripped SYN) is unproven here and unprovable by compile or model —
   it needs the isolated-OpenDNP3 and read-only-relay tests of Experiment 3.

## Net

The implementation **survives both reviews at the compile gate**. Nothing found is a
target-feasibility or safety blocker; the open items are (a) functional/checksum validation by the
model run and (b) the standing Experiment-3 endpoint-safety question. No fabricated passthrough
claim, no dropped requirement, no hidden state.
