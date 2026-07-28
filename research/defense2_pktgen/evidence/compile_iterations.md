# Request-Triggered Pktgen — local bf-p4c 9.13.1 compile iterations

Running record of every local compile attempt for the compile gate. Negative evidence
is preserved here (what failed, why, the fix). This is NON-DESTRUCTIVE: local compile only,
no switch, no bf_switchd.

Command shape (log captured OUTSIDE the -o dir because bf-p4c WIPES its -o dir):

    PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g \
      -o research/defense2_pktgen/p4/build_local_9.13.1/ \
      research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4 \
      2>&1 | tee research/defense2_pktgen/p4/build_local_9.13.1_compile.log

---

## Design summary (what the additive changes are)

- Parser: `PORT_PGEN` (dp68) -> `from_pgen`; `value_set<bit<8>> pgen_recirc` on the leading
  byte splits a generated blocker token (-> `parse_pktgen_token`, `advance(48)` past the 6B
  pktgen_recirc header, then the existing parse_eth/parse_token forces ROLE_BLOCK) from a
  recirculated clone (-> accept, port_ok=0, dropped).
- reg_tag: new read-only RegisterAction `tag_read` (rv = v) to lift the CURRENT generation for
  a pktgen token; `tag_read` vs the existing `tag_rmw` are mutually exclusive per packet (one
  access), 0 extra PHV inputs (within the 2-input budget).
- `tbl_pktgen_active`: ternary on cur_gen, `(0xC0 &&& 0xF0) -> active` (generation domain 0xCn).
- fresh ROLE_BLOCK branch: if is_pktgen, stamp gen+budget + to_block() when active, else drop.
- ROLE_ARM branch: on fresh arm only (tag_diff != 0) call `arm_clone()` -> set I2E mirror to
  CLONE_SESSION_ID + build 4B tag (marker byte0 | gen in low byte).
- ingress deparser: `Mirror() clone_mirror;` emits the 4B recirc tag on the clone (0 egress
  stages). Egress unchanged (byte-preserving).

---

## Iterations

### Iteration 1 — bf-p4c 9.13.1, `-g` — PASS (clean, first compile)

Command exit 0. Compiler tail:

    0 errors, 3 warnings generated.

**No negative evidence to preserve** — the construction compiled on the first attempt.
The 3 warnings are benign and pre-existing in kind:
- `uninitialized_out_param 'meta'` — the baseline's deliberate zero-init-default pattern
  (fields assigned once-per-path, zeroed elsewhere by the parser). VERIFIED SAFE: `is_pktgen`
  is container `H12`, and `H12` is in the parser `init_zero` set (`.bfa` line 255) alongside
  `B6` = `meta.role` — the exact known-good baseline mechanism. So the pktgen admission branch
  (`is_pktgen == 1`) can never fire on ordinary traffic.
- two `min_parse_depth_accept_loop will be unrolled up to 3 times` — bf-p4c padding the parse
  graph to the minimum parse depth; benign.

#### Resource table (from `pipe/logs/mau.resources.log` Totals row + `table_summary.log`)

| Metric                         | This build (pktgen) | Frozen inline baseline | Delta |
|--------------------------------|---------------------|------------------------|-------|
| Ingress stages                 | **10 / 12**         | 10 / 12                | +0    |
| Egress stages                  | **0**               | 0                      | +0    |
| Critical path (table dep graph)| 8                   | —                      | —     |
| Logical tables                 | 70                  | 60                     | +10   |
| SRAM blocks                    | 61                  | 55                     | +6    |
| Map RAM                        | 60                  | —                      | —     |
| TCAM                           | 1                   | 1                      | +0    |
| Stateful ALUs (Meter ALU col)  | 9                   | 9                      | +0    |
| Stats ALUs                     | 21                  | —                      | —     |
| Gateways                       | 36                  | —                      | —     |
| PHV containers used            | 41 (18.3%)          | —                      | —     |
| PHV bits used (ing / egr)      | 580 / 13            | —                      | —     |

Authoritative stage counts (`pipe/logs/table_summary.log` lines 2-6):
`Number of stages for ingress table allocation: 10` / `... egress table allocation: 0`.

#### Structural evidence (`pipe/dnp3_timing_normalizer_pktgen.bfa`)
- `is_pktgen` zero-init: `H12` in `init_zero` set (line 255), same list as `B6`=`meta.role`.
- Deparser mirror (0 egress stages): `mirror:` block in the ingress deparser section
  (lines 1224-1231) selects on `ig_intr_md_for_dprsr.mirror_type` and emits `meta.clone_ses`
  (H2) + `meta.clone_tag` (H5,H7).
- `arm_clone` action (lines 2699-2705): `set mirror_type,1; set clone_ses,7;
  set clone_tag.16-31, 57600 (0xE100); deposit-field H5(8..15),0,H4` (gen_in into the low byte).
- `reg_tag` reuse: ONE stateful block `...reg_tag` carries BOTH `tag_rmw_0` (line 1746) and
  `tag_read_0` (line 1767) — the raw-read added no new stateful ALU (Meter ALU stays 9).
- Parser: `from_pgen` state (line 1136) with `value_set IgParser.pgen_recirc` (line 1138),
  reached from the port select (`next: from_pgen`, line 299).

#### Forwarding invariants (by construction — file line refs in dnp3_timing_normalizer_pktgen.p4)
1. READ byte-identical to dp64: ROLE_ARM branch `to_fwd()` (PORT_RELAY, bypass_egress=0);
   deparser emits original headers in extraction order; `clone_mirror.emit` shapes only the
   mirror copy.
2. Clone to dp68 only on fresh arm: `if (meta.tag_diff != 8w0) { arm_clone(); }` in the
   ROLE_ARM branch (reuses baseline reg_tag idempotency → no second trigger on retransmit).
3. Token admission: parser forces ROLE_BLOCK (`parse_token`); `is_pktgen` fresh ROLE_BLOCK
   branch checks `txn_active` (tag_read + tbl_pktgen_active), stamps gen+budget, `to_block()`
   (dp8/Q_BLOCK qid7); drops if inactive.
4. Never to dp9/dp11/dp64: role forced ROLE_BLOCK in parser; every ROLE_BLOCK branch reaches
   only `to_block()`/`drop_pkt()`; recirc clone re-entering dp68 → `from_pgen` default → accept
   → port_ok=0 → dropped.

**Gate result: PASS.** Ingress 10/12, egress 0.
