# P5 — timing + parser-produced pad code, NO actual padding

**Architectural variable:** the ingress *decides* to normalize and exports the decision, but pads
nothing. The whole Part-12 HOLD_RESPONSE control block is byte-for-byte the P0 text; the only
change is a 3-byte `padctl_h` header produced entirely in the ingress parser.

**Question:** does merely deciding — a `normalize_size` flag, a target-size code and an
oversize/fail-open flag — cost an ingress MAU stage on a pipeline already at 12/12?

**Answer: no. Zero ingress MAU cost.**

**Build**

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out p5_parser_padcode.p4
```

Log: `compile.log` — **0 errors, 2 warnings** (benign parser-unroll notices).
SHA-256 `a7484e0daf0cd62cac11b26de928b75377da75418cfce98d4f45ef308ac5b33a`.

**Result vs P0 (same compiler run)**

| | P0 | **P5** | Δ |
|---|---|---|---|
| Ingress stages | 12 | **12** | **0** |
| Egress stages | 0 | 0 | 0 |
| Critical path | 12 | **12** | **0** |
| Logical tables | 44 | 44 | 0 |
| Ingress SRAM / map RAM / TCAM | 36 / 36 / 0 | 36 / 36 / 0 | 0 |
| Ingress SALU / Stats ALU | 7 / 11 | 7 / 11 | 0 |
| Ingress gateways | 25 | 25 | 0 |
| Ingress parser states | 2 | **3** | **+1** |
| Ingress parser TCAM rows | 4 | **7** | **+3** |
| PHV bits ingress | 354 | **355** | **+1** |
| Tagalong bits allocated | 560 | 608 | +48 |

The per-gress MAU split (`resources.json` unit ownership joined with `context.json` table
`direction`) is **identical** to P0 in every column, and both place 85 ingress tables at max stage 11.

**Mechanism.** The decision is a parser `select(hdr.ib.role)` with two terminal states
(`padctl_normalize`, `padctl_passthrough`), each assigning every `padctl` field **exactly once**.
Tofino parsers have no clear-on-write, so a second assignment on the same path is a hard error —
hence no init of these fields in `start` and one terminal state per decision. The header is emitted
by the ingress deparser so the fields stay live and are not dead-code-eliminated; a deployment would
strip it at the far edge. It is not a wire-format proposal.

**Reading.** The Part-13 lever generalizes: parser-side classification is essentially free on a
stage-saturated pipeline. It did **not** shorten the critical path here, and that is expected —
Part 13 gained a stage because a stage-0-produced metadata field was pinning a downstream table,
whereas P0's critical path is the serial `reg_gen → reg_active → reg_deadline` register chain, which
the pad code does not touch.

**Superseded by P6.** P5's export turns out to be unnecessary: `eg_intr_md.pkt_length` gives egress
the frame's *measured* length, which is strictly more than the ingress can offer (TF1
`ingress_intrinsic_metadata_t` has no length field at all). P5 remains the clean isolation of
"decision cost = 0" and would be the right building block if a future design needed an
ingress-derived decision that egress cannot recompute.
