> **SUPERSEDED (2026-08-12).** This record describes the PRE-REPAIR cover kernel
> (source sha256 `570abb57…`), which used **placeholder DNP3 CRCs**, **byte-reversed link
> addresses**, and a **scalar `reg_delta`/`reg_last_resp_seq`/`reg_dlast`** epoch that did NOT
> implement the offline oracle. Those defects are fixed in the repaired kernel. The current
> record is **`defense4/size/evidence/cover_kernel_repair/`** and the decision is
> **`defense4/size/REPAIR_DECISION.md`**. Read those first; the claims below (real CRC-valid
> cover, "models the offline oracle") are HISTORICAL and no longer describe the source.

# Cover-kernel compile probe — evidence record (PRE-REPAIR, historical)

DNP3 size cover-framing mechanism, Tofino-1 / TNA compile probe. **COMPOSED** probe
(Case-A-derived timing ingress + new cover-prepend size egress). **PASS — 0 errors.**

Source: `defense4/size/p4/defense4_cover_kernel.p4`. Build artifacts were produced in a
scratch dir OUTSIDE the tree; only sanitized text logs are recorded here.

## Build facts

| item | value |
|---|---|
| exact command | `bf-p4c --target tofino --arch tna --std p4-16 -g -o build_cover defense4_cover_kernel.p4` |
| exit code | **0** |
| compiler | bf-p4c / p4c **9.13.1** (SHA e558d01) — local SDE `~/bf-sde-9.13.1` |
| target / arch | tofino (Tofino-1) / tna |
| source sha256 | `570abb571d035c224bc56cdd4d10a6c52a37cc0c1818583bcc499f79cf25235c` |
| compile time | ~7.8 s |

### Errors / warnings (verbatim)
```
0 errors, 3 warnings generated.
defense4_cover_kernel.p4(345): [--Wwarn=unused] warning: tag_clear: unused instance
warning: Parser state min_parse_depth_accept_loop will be unrolled up to 3 times due to @pragma max_loop_depth. (x2)
```
All three warnings are inherited **verbatim** from the timing ingress (they also appear in
`defense4_joint_canon` builds): `tag_clear` is an unused RegisterAction in the timing core, and
the `min_parse_depth` unrolls come from the ingress `@pragma max_loop_depth`. The new egress
(cover-prepend size layer) contributes **zero** warnings. Full log: `compile.log`.

## Resource profile (`metrics.json`, `table_summary.log`, `phv_allocation_summary_0.log`, `mau.resources.log`)

| axis | value |
|---|---|
| **ingress stages** | **12 / 12** (the timing core — unchanged; source copied verbatim from `defense4_joint_canon`) |
| **egress stages** | **10 / 12** (the new cover-prepend size layer) |
| **critical path (table dep graph)** | **12** (ingress-bound) |
| logical tables | **76** |
| MAU SRAM | 41 |
| MAU TCAM | 4 (egress `e_haspay` + `e_mtu` range tables = 2; ingress `tbl_release` = 2) |
| MAU MapRAM | 20 |
| stateful ALUs | ingress 6 registers + 1 Stats/counter ALU; **egress 3 registers** (`reg_last_resp_seq`@st3, `reg_delta`@st4, `reg_dlast`@st6) |
| parser TCAM rows | ingress 60, egress 16 |
| deparser FDE entries | ingress 23, egress 31; POV bits ingress 8, egress 4 |
| MAU latency (cycles) | ingress 252, egress 174 |

### PHV
- Overall normal PHV: **59 containers / 26.3 %** used — ample headroom.
- Ingress-owned normal groups are near-full (as expected for the exhausted timing core):
  **B0-15 = 15/16 (97.7 % bits allocated)**, **W0-15 = 14/16 (109 % bits allocated, overlaid)**.
- Egress-owned normal groups have headroom: B16-31 = 10/16, W16-31 = 10/16, H16-31 = 6/16.
- Tagalong total **46.9 % (8b) / 58.3 % (16b) / 50 % (32b)**; collections 6 and 7 are EMPTY →
  headroom (tagalong is NOT the limiting resource for this probe).

## Checksum / deparser mechanism and limitations

- **IPv4**: whole-header recompute in the egress deparser (`Checksum.update`) with the new
  `total_len` (header fully parsed → always correct).
- **TCP**: residual-preserving (incremental) recompute. The egress parser calls
  `subtract_all_and_deposit(m.residual)` to capture the checksum of the **unparsed real-DNP3
  payload** (never parsed); the deparser `update()` re-sums pseudo-hdr(new len) + tcp hdr(new
  seq/ack) + cover(new constant bytes, POV-gated) + `m.residual`. This is the proven switch.p4
  NAT idiom and offloads the checksum from MAU stages to the parser/deparser checksum engines.
  - **HARD constraint (documented in source):** correct ONLY because the cover is **EVEN**-length
    (16 B), so the residual's 16-bit alignment inside the checksummed region is preserved. An
    odd-length cover would invalidate `m.residual`.
- The two DNP3 cover CRC fields are **compile-time constants** (fixed cover) → **0 CRC ALUs**.
  Their values in the source are illustrative placeholders; the real CRC-valid cover is the
  constant validated offline by the cover-frame gate. The IPv4/TCP checksums are computed over
  whatever cover bytes are emitted, so the emitted packet is self-consistent.

## Ordering (size selected before timing; prepend materialised post-TM in egress)
The size **policy** (which flow is covered, template, target size) is a static per-flow property
logically prior to the timing hold; it is realised in egress by re-deriving the owner/policy from
the immutable flow key (equivalent to bridging a policy bit set in ingress). The physical prepend
is in **egress, after TM dequeue**, because the hold/release is an ingress→TM decision (the
released packet is only materialised in egress) and TNA cannot emit a header after the unparsed
residual. **Consequence:** TM enqueue accounting saw the **pre-cover** length — queue occupancy,
shaping, and any byte-derived deadline reflect the native response size; the cover's extra
bytes/serialisation are added only at dequeue. The padded frame must still fit the MTU (guarded).

## Scope — what this proves and does NOT prove
- **COMPOSED probe, PASS.** The full cover-prepend size mechanism — cover-frame parser/deparser,
  bounded transport epoch (`reg_delta` / `reg_last_resp_seq` / `reg_dlast`), full-5-tuple exact
  owner validation (`t_owner`), MTU-guard range table, committed-vs-inserted retransmit logic,
  and residual-preserving IPv4+TCP checksum recompute — **co-fits with the frozen Case-A timing
  ingress on one Tofino-1 pipe** (ingress 12/12, egress 10/12). The **integration gate is
  demonstrated at the COMPILE level; it is NOT blocked.**
- **A compile is NOT silicon validation.** Nothing here was loaded or run on hardware. Checksum
  arithmetic, the even-cover alignment assumption, byte-identical delivery, and the transport
  translation are validated only OFFLINE (cover-frame gate + `transport_oracle.py`, re-run green:
  oracle demo 5/5, adversarial suite 46/46). This probe does not re-verify them on silicon.
- The timing evidence source `defense4/timing/p4/defense4_caseA.p4` was **NOT** modified.

## Reproduce
```
cd defense4/size/p4
bf-p4c --target tofino --arch tna --std p4-16 -g -o /tmp/build_cover defense4_cover_kernel.p4
```
(Build in `/tmp` or a gitignored dir; do not commit build artifacts.)
