# m12 — integrated READ+SBO timing-and-size obfuscation: implementation design + status

Branches from **m11_09** (on `main`, preserved on branch `baseline-m11_09-20261019`). Replaces the old
size path (READ re-encode + SBO fixed-61) with two mechanisms sharing one target policy, keeping N/E/T,
timing and OPERATE hold J. Offline; hardware lock intact.

## Status (2026-10-19)
- **M0 done, committed** (`623a78f77`): software READ measurement-object padding (`full_read_01/`),
  9/9 Case A/B runs verified, report corrected, baseline branch created.
- **Gating risk cleared, committed** (`2b923ef63`): `classify_rev` regenerated to a 282-byte image (566
  entries) compiles under SDE 9.13.1 at **egress 12 / ingress 11** stages, exit 0
  (`probe/evidence/classify_rev282_manifest.json`). The reverse-ACK withhold window — the one piece that
  could not collapse to a range — is **not** the blocker.
- **Remaining (this document):** the padding-action rewrite (READ + SBO), the forward mapper constants,
  and the N lane. Designed below to the exact site; not yet compiled as an integrated whole.

## Size policy (confirmed with Philip)
Equalize the **master-facing TCP payload**, shared across READ/SELECT/OPERATE, computed from attainable
encodings. SBO is quantized at **22 + 13k** (k transport segments); READ reaches native + an appended
frame (min +19). 292 is the READ max-frame reference, not a mandatory target. **Single shared target
first:** the smallest size attainable by all three that holds the 247-byte full READ. READ floor =
247+19 = 266; smallest SBO 22+13k ≥ 266 is **269 (k=19)**; READ reaches 269 (247+22, range 49+220, both
≤ one frame of 250 user octets). So **T = 269** for the single-target demonstration. Multi-target (e.g.
a smaller shared size for the short ops) follows the same `pad_oracle`/`encode61` enumeration; no forced
sizes, report op→target and residual distinctions, no indistinguishability claim.

## E changes (pipe-0 egress), by exact site in m11_09 `response_only.p4`

### Remove (old size logic)
- READ re-encode: `read_profile` (787-789), `read_eligible`/`read_pad_t` (1047-1048), `crc_read_tail_t`/
  `crc_read_b_t` (1051-1055), parser `read_b0` (737-738), deparser `if(hdr.ra.isValid())` (1381-1393),
  emits (1412-1414), headers `ra/ca/rbh/rc/cb/c2` (599-601), meta `rtcrc/rtcrc_b/read_shape`.
- SBO fixed-61 is **adapted, not removed** (the append-frame split is the reused technique).

### READ append-padder (replaces the re-encode) — mechanism verified in software (`pad_oracle.py`)
- Parser: a state for the full-READ response (`dl.len = 0xD6` = 214 → one 247-B frame) and the range
  READ (`dl.len = 0x26`) that extracts only the first 16-B user block (`rh` + first object header +
  first points) + its CRC (~28 B parsed, << the 160-B egress-parser budget); the rest of the native
  frame stays unparsed and is re-emitted.
- Action: clear FIN on the parsed block's transport octet (affine CRC XOR on that 16-B block, via the
  existing Hash-0x3D65 unit); append ONE link frame = link header + continuation transport segment
  (FIR=0, FIN=1, seq+1) + g1v2 object header + N synthetic padding points (value 0, flags 0x00) + block
  CRCs, sized so the TCP payload reaches **T=269**; set `m.len_delta` accordingly.
- Deparser: one new TCP-checksum branch over the appended frame's fields (parity-ordered, like the
  existing `tcp_read`/`tcp_ctl` branches), plus `pkt.emit` of the new headers.

### SBO reframer (adapts `ctl_eligible`/`ctl_sequences_t`) — application bytes preserved
- Split the 22-B control fragment into **k=19** transport segments (TCP payload 22+13k = 269), each a
  link frame (8-B header + 1-B transport + data + 2-B link CRC + 2-B data CRC), FIR on the first, FIN on
  the last, transport sequence s..s+18. Reuse the `ctl_sequences_t` sequence-assignment pattern extended
  from 2 appended frames to 18; reuse the affine-CRC-XOR + Hash pattern. **No measurement objects, no
  fabricated control results** — only the native control bytes, reframed. Preserve SELECT match and
  exactly-once OPERATE (unchanged N/T lifecycle).
- Attainability: 269 is a legal 22+13k size; if a chosen shared target is not 22+13k, pick the nearest
  attainable and record it — never pad SBO with arbitrary bytes.

### Forward mapper → single image length T (compile constant)
- `const bit<32> r_IMAGE_LEN = 61;` → `= 269;` (feeds `acct_try` 936 and `fwd_prep` `m.t` 1001).
- `start_arm` (978): `seq + 32w0xFFFFFFC4` (= −60 = −(61−1)) → `−(269−1)` = `32w0xFFFFFEF4`.
- `fwd_prep` (1001): `m.pm = m.p + 32w0xFFFFFFC3` (= −61) → `−269` = `32w0xFFFFFEF3`.
- `acct_t` (924): add a `do_acct_try` row for `m.leff = 247` (full READ, read_shape) beside the existing
  49/37 rows; `m.leff` stays the native length (acct_t key), `r_IMAGE_LEN` is the output advance.
- `classify_fwd` (1021): add `out_reset_front_247` beside 49/37 for an RST exactly one full-READ ahead
  (RST-at-frontier handling; lower-priority correctness row).
- `classify_rev`: regenerate to a 269-byte image (540 entries) — proven to place at 282 (566).

## N changes (pipe-0 ingress) — carry the new shapes through the SAME timing lanes
- Parser `ip.len` dispatch (123): add the full-READ response length (247-B frame → ip.len 287) to
  `read_response_ip_flags`, and a read-response parse of its first block; add padded-size rows as needed.
- `read_response_profile` (420-421): add the full-READ `dl.len` entry beside `8w38`.
- `next_seq_t` (277-278): `next_read_response` must use the native response length per shape (49 or 247),
  not a fixed +49 — generalize via the shape, retaining complete CRC + length validation.
- Boundary check: a response failing E's link-CRC verdict must not advance N connection/timing state
  (verify in the model's `control_timing`/`contention` drivers).

## Generator
A new generator under `m12_fullsize/` branching BASE = m11_09 (`f1de2b30…`), applying the above as
`once()`/`block()` transforms (mirroring `ctl_timing_01/generate.py:transform_e_m8` and
`efficiency_candidates.py`). Record `source_sha256`, segment SHAs, `successor_of = m11_09`. The
`classify_rev` regeneration reuses `probe/make_classify_rev_probe.py:rev_entries`.

## Validation (unchanged workflow)
- `model_packets.py --validate-vectors` (READ 49/247→T, SBO 37→T framing/CRC/reassembly/checksums).
- `run_model.py` ×9 drivers + `model_summary.py --v3 --enforce` == `model_gate_passed`.
- Commit-gate pytest set (HANDOVER 265-272; baseline 873) exit 0 + `full_read_01/tests`.
- `build.py` (9.13.1) + `compile_switch_orchestrator.py` (9.13.2); `resource_review.py` table vs m11_09.
- Software demo: `proxy_demo.py`/`verify_demo.py` for READ and SBO at T (and multi-target).

## Hardware
Lock intact (`unsafe_restoration: true`). The restore failure of `dev_m11_09_20261019_01` is a
**volatile-counter false positive** — `restore_verify.json` mismatch is entirely counter/outcome tables
(`tm.counter.*`, `ig_port/eg_port/pool/dpg`, `Egress.outcome`), and `reverify_20261019/restore_verify.json`
already shows `ok:true` after manual re-restoration. No loading without explicit authority + an
independently verified restore.

## Remaining bounded work (overnight continuation)
1. Write the m12 generator with the E remove+padder+reframer+mapper transforms and the N lane transforms.
2. Compile locally (9.13.1); at most two corrective attempts per placement constraint, then record it.
3. `model_packets.py` size vectors → fix until READ+SBO pass.
4. Full 9-driver model gate + pytest.
5. Remote 9.13.2 compile + resource table.
6. Multi-target policy via the oracle; decoded examples; per-response frame-count + added-byte report.

## Design advances (2026-10-20) — construction resolved to the byte

Verified by compilation this session (all SDE 9.13.1, egress 12 / ingress 11, exit 0):
`baseline` rebuild; `classify_rev`@282 (566 entries); +220 egress bytes; **integrated mapper T=269**
(`r_IMAGE_LEN=269`, `classify_rev`@269 = 540 entries, `acct_t` +247 row, `classify_fwd`
+`out_reset_front_247`). Generator `make_m12.py` (transform `mapper`) committed (`3e91e8bb6`).

Four advances that make the remaining padder tractable and correct-by-construction:

1. **Full-READ parser budget is resolved by first-block-only parse.** The 247-B full READ has ~14
   link-user blocks, over the ~160-B egress-parser budget. The padder parses/validates/modifies **only
   the first 16-B block** (where the transport FIN bit lives) and re-emits the remaining native blocks
   **unparsed**. Those blocks are untouched, so their original CRCs stay valid and the **master still
   validates every block** — no weakening of what reaches the master; the switch simply does not
   re-validate bytes it does not alter (the same way E already re-emits merged-retransmission tails).

2. **Range READ reuses the existing full parse.** `read_b0` already extracts the whole 49-B response;
   the padder keeps `robj/c0/c1`/points **live** (unlike the re-encode, which invalidated them), clears
   FIN on `rh.tpctrl` (`&0x7f`), and appends the padding frame — no new parser state for the range READ.

3. **Clearing FIN is an affine CRC delta (constant).** Flipping the one FIN bit (0x80) at byte 0 of the
   first user block changes that block's CRC by a fixed constant, so `c0_new = c0 ^ FIN_DELTA` — derived
   from the live `c0`, with a proven-invariant delta (same class as the existing `^0x6222`).

4. **The appended padding frame's checksum contribution is a single constant.** Its content is synthetic
   (g1 points, value 0, flags 0x00) so its one's-complement sum is a compile constant folded into the TCP
   checksum — no byte-by-byte summing of ~220 added bytes in the deparser. The appended frame's **link
   header is derived** (copy `dl.ctrl/dst/src`, const `len`, CRC `= dl.crc ^ delta`, the `ctl_eligible`
   pattern); its **first user block's transport octet is derived** (native seq+1 via a `ctl_sequences`-
   style table) so that block's CRC is Hash-derived, while the remaining all-zero blocks have constant
   CRCs.

## Honest status (2026-10-20)
- **Done + committed:** M0 software milestone (`623a78f77`); two placement probes (`2b923ef63`,
  `6685b6bb1`); generator + integrated mapper T=269 (`3e91e8bb6`). Baseline preserved on
  `baseline-m11_09-20261019`.
- **Feasibility: proven.** Every placement unknown compiles within the 12-stage egress budget.
- **Remaining (NOT blocked; large byte-exact coding):** the READ append-padder (range 49→269 reuses
  parse, +220 B / 12 blocks; full 247→269 needs the first-block parser path, +22 B / 1 block), the SBO
  reframer (37→269, k=19 segments), the N-lane recognition of the full READ (ip.len 287, first-block
  classify, seq delta 247), then `model_packets` vectors + the 9-driver model gate + both-SDK builds +
  the P4 multi-target extension + the hardware demonstration. The mapper, the affine/derived-CRC
  patterns, the constant-checksum folding and the parser-budget resolution above remove the uncertainty;
  what is left is careful generation of the per-shape append blocks and their derived CRCs, compiled and
  model-checked shape by shape.
- **Restore lock:** volatile-counter false positive; `reverify_20261019` `ok:true`. The lock-reconcile
  (extend `restore_verify`'s volatile-ignore set to the counter/outcome tables, without touching
  config/operational checks, then clear via the ownership mechanism) is specified in the plan's M0b and
  pending before any hardware load.
