# P4 — single-state size primitive ALONE (no timing)

**Architectural variable:** the validated Level-1 size primitive, standalone, in this codebase's
frame format (`ethernet_h` + `ibspg_h`, exactly what `ibspg_hold_response.p4` parses). No timing
state machine, no telemetry.

**Purpose:** establish the primitive's standalone cost *in the same compiler run* as the P0
baseline, so the P4/P5/P6 comparison is not a quote from an older report.

**Build**

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out p4_size_only.p4
```

Log: `compile.log` — **0 errors, 2 warnings** (both the benign `min_parse_depth_accept_loop` unroll
notices that every program in this tree emits).
SHA-256 `f1b09334c3db042ddba2e890fb74fd1e01c8dfd68b718293da1fb3c90930a31e`.

**Result**

| | P4 | (ref) validated primitive, telemetry OFF | (ref) validated primitive as-is |
|---|---|---|---|
| Ingress stages | **2** | 2 | 3 |
| Egress stages | 0 | 0 | 0 |
| Critical path | 2 | 2 | 3 |
| Logical tables | 7 | 11 | 15 |
| SRAM / map RAM / TCAM | 7 / 6 / 0 | 7 / 6 / 0 | 13 / 12 / 0 |
| SALU / Stats ALU | 0 / 3 | 0 / 3 | 2 / 4 |
| Gateways / VLIW | 2 / 15 | 5 / 17 | 6 / 21 |
| Ingress parser states / TCAM rows | 2 / 4 | 4 / 5 | 4 / 5 |
| PHV containers / bits | 9 / 68 | 13 / 117 | 33 / 440 |

**Readings**

* The size primitive proper is **2 ingress stages**. Everything above that in the validated program
  was measurement scaffolding (see `SIZE_PRIMITIVE_REUSE_AUDIT.md` §6).
* Dropping the 19-byte trace-replay encap (no header to strip, no ethertype to restore) buys a
  further 4 logical tables, 3 gateways and 49 PHV bits over the telemetry-OFF ablation.
* The compile-time power-of-2 decode is preserved verbatim: each of the 13 `pad_dNN` actions sets
  its whole pad subset valid inside **one** action, so all pads land in `size_class_pad`'s single
  stage. The runtime `if (delta[i])` form would serialize into 7 stages.

**Scope honesty.** Like the program it reproduces, P4 pads between the last parsed header and the
unparsed residual. That is fine for the synthetic IBSPG/trace frame and **invalid for live
IPv4/TCP/DNP3** — see `SIZE_PRIMITIVE_REUSE_AUDIT.md` §5.4. P4 measures cost, not protocol validity.

**Relevance to co-residency:** 2 ingress stages is still 2 more than P0 has (12/12). P4 is the
*negative* control that motivates P5/P6 — it is exactly the thing that does not fit.
