# On-chip instrumentation audit — the claim is withdrawn

On 2026-09-07 the rerun plan asserted that the loaded program "already latches the switch-side
instants the study lacks", that four of six timestamp registers were already read by the
preserved control plane, and that obtaining `e_r` was therefore "a two-entry control-plane
change, no new P4".

**That claim is withdrawn. It was wrong.** Every part of it fails, and this document records
why, per timestamp, with the evidence.

The headline: **no timestamp write action in the program is ever executed.** The registers are
declared, the write actions are declared, and nothing calls them. bf-p4c said so at compile
time and the source says so on inspection. Four of the ten are additionally excluded from the
build by a preprocessor guard, and even if they all fired, none of them would record an
external wire departure.

---

## 1. The finding, three ways

### From the source: no execute site

Searching the frozen source for every `.execute(` call gives 27 call sites. Not one targets a
timestamp action. The full inventory of `.execute(` targets is `tag_rmw`, `tag_read_or_mark`,
`tresp_rmw`, `tresp_arm_once`, `topj_rmw`, `tag_retire_if_unmarked`, `tag_arm`,
`sess_port_rmw`, `ready_read`, `ready_confirm`, `ready_clear`, `gen_read`, `gen_clear`,
`gen_arm`, `fo_take`, `fo_note`, `exp_seq_w`, `exp_seq_r`, `exp_ack_w`, `exp_ack_r`,
`epoch_retire`, `epoch_read`, `epoch_prepare`, `deadline_rmw`, `deadline_arm_once`,
`ack_rel_rmw` and `ack_rel_r`. Every one of the ten `ts_*_w` actions has **zero** references
outside its own declaration; the only other appearances of their names in the file are inside
comment prose.

The metadata flag the comments describe as the trigger, `meta.ev_first_block`, appears only in
comments at lines 2026 and 2098. **No such field is declared.**

### From the compiler: unused instances

`8a6896e:defense4/size/native_parity/evidence/hw_campaign_20260813T172014Z/switch_compile_9132/compile_9132.log`,
the archived bf-p4c transcript for the campaign build, contains:

```
defense4_rrc_bor_unified12.p4(1982): [--Wwarn=unused] warning: ts_first_block_w: unused instance
defense4_rrc_bor_unified12.p4(1986): [--Wwarn=unused] warning: ts_ack_arm_w: unused instance
defense4_rrc_bor_unified12.p4(1990): [--Wwarn=unused] warning: ts_block_term_w: unused instance
defense4_rrc_bor_unified12.p4(1998): [--Wwarn=unused] warning: ts_ack_release_w: unused instance
defense4_rrc_bor_unified12.p4(2109): [--Wwarn=unused] warning: ctr_fresh: unused instance
defense4_rrc_bor_unified12.p4(2110): [--Wwarn=unused] warning: ctr_deq: unused instance
0 errors, 9 warnings generated.
EXIT=0
```

The compiler itself declares the four unguarded timestamp actions unused. It also declares
`ctr_fresh` and `ctr_deq` unused, which matters separately: see §5.

### From the absent warnings: the guard was not defined

bf-p4c warned about exactly the four **unguarded** timestamp actions. It did not mention
`ts_read_w`, `ts_resp_release_w`, `ts_clone_w`, `ts_resp_bypass_w`, `ts_last_block_w` or
`ts_last_term_w`. Had those been compiled they would have been unused too, and would have
warned too. Their absence from the warning list is therefore compiler-attested evidence that
`D3_SYNTH_EVENTS` and `D3_TS_INTERNAL` were **not defined** in that build.

Two independent records agree: `defense4/timing/PROVENANCE.md` gives the compile as
`bf-p4c --target tofino --arch tna -g -DU_BOR`, and the control plane's own header says
"corrected single-pipe defense4_rrc_bor_unified12.p4 (-DU_BOR)". `U_BOR` is the only `-D`.
`D3_TS_INTERNAL` is not a command-line macro at all: it is derived at source line 586 from
`D3_SYNTH_EVENTS` or `D3_LIVE_FULL_TELEMETRY`, so with neither defined it is off as well.

## 2. Per-timestamp table

Clock, units, width and wrap are common to all ten and are given once in §3.

| register | write action | guard | compiled in the loaded build? | execute site | what it would have recorded |
|---|---|---|---|---|---|
| `reg_ts_first_block` | `ts_first_block_w` | none | yes | **none** | ingress MAC time of the first blocker token re-entering from the loopback |
| `reg_ts_ack_arm` | `ts_ack_arm_w` | none | yes | **none** | ingress MAC time of the relay acknowledgment at dp64 ingress, that is `t_a` |
| `reg_ts_block_term` | `ts_block_term_w` | none | yes | **none** | ingress MAC time of the terminating blocker token, from the loopback |
| `reg_ts_ack_release` | `ts_ack_release_w` | none | yes | **none** | ingress MAC time of the held acknowledgment as it **re-enters ingress** from the dp8 loopback, not its departure at dp9 |
| `reg_ts_last_block` | `ts_last_block_w` | `D3_TS_INTERNAL` | **no** | none | as `first_block`, write-always rather than write-if-zero |
| `reg_ts_last_term` | `ts_last_term_w` | `D3_TS_INTERNAL` | **no** | none | as `block_term`, write-always |
| `reg_ts_read` | `ts_read_w` | `D3_SYNTH_EVENTS` | **no** | none | ingress MAC time of the READ at dp9 ingress, that is `t_0` |
| `reg_ts_resp_release` | `ts_resp_release_w` | `D3_SYNTH_EVENTS` | **no** | none | ingress MAC time of the held response as it **re-enters ingress**, not its departure at dp9 |
| `reg_ts_clone` | `ts_clone_w` | `D3_SYNTH_EVENTS` | **no** | none | ingress MAC time of the returning clone |
| `reg_ts_resp_bypass` | `ts_resp_bypass_w` | `D3_SYNTH_EVENTS` | **no** | none | ingress MAC time of a response taking the bypass path |

Source declarations are at frozen lines 2003, 2007, 2011, 2019, 2030, 2038, 2069, 2073, 2106
and 2124; their actions at the following line in each case.

## 3. Clock, units, width, wrap, and the observation point

* **Clock source.** `ig_intr_md.ingress_mac_tstamp[31:0]`, assigned to `meta.ts32` at frozen
  line 2905, inside `control Ingress`'s `apply` block, on every packet that passes the port
  isolation check. It is the **ingress** MAC timestamp of the packet currently in the ingress
  pipeline.
* **Units and width.** Nanoseconds, low 32 bits. `meta.ts32` is the full-resolution value and
  is what all ten write actions would store; the separate deadline path uses
  `meta.ts_m = ts32 & 0xFFFFFF00`, a 256 ns grid whose low byte is cleared so bit 0 can carry
  an ARMED marker.
* **Wrap.** 2^32 ns is about 4.295 s, so the counter wraps roughly 14 times in a 60 s run. The
  source is explicit that this must be handled by the reader: *"All differences must be
  computed mod 2^32 by the analyzer: the 32-bit ns counter wraps every ~4.3 s (~14x per 60 s
  run) and a signed subtraction FABRICATES the headline number."*
* **What it is, and is not.** Every register is in the ingress control and every write would
  take an **ingress** timestamp. There is no egress-side timestamp register and no egress-side
  write anywhere in the program. So `reg_ts_ack_release` and `reg_ts_resp_release` are, at
  best, **internal loopback re-entry timestamps of the released packet**: between them and the
  wire lie the rest of the ingress pipeline, the traffic manager, the egress pipeline and dp9
  serialization. Calling either one `e_a` or `e_r`, an external wire departure, is not
  justified, and the earlier rerun plan did exactly that.

  The program itself flags the gap, as an untried prediction: *"THE RELEASE INSTANT IS NOT THE
  DEADLINE INSTANT. They differ by a deterministic K-proportional bias, K/rate_dp8 = 1.711 us
  at K=64 / 25G (predicted; Part 12 measured 1.72 us with ~23 ns spread ...)"*.

## 4. Reset behaviour, transaction association, and cross-contamination

* **Reset.** All ten are `Register<bit<32>, bit<1>>(1, 0)`: one slot, `bit<1>` index, init 0.
  Eight write **if-zero** (`if (v == 32w0) { v = meta.ts32; }`), so the first event of a run
  would latch and every later one would be ignored until the control plane cleared the slot.
  Two, `ts_last_block_w` and `ts_last_term_w`, write **always**, so they would hold the most
  recent event instead. Neither of those two is compiled.
* **Clearing.** `implementation/control/defense4_caseA_setup.py` writes 0 to
  `reg_ts_first_block`, `reg_ts_ack_arm`, `reg_ts_block_term` and `reg_ts_ack_release` at lines
  186 and 471, and reads them back at line 473. Because the data plane never writes them, those
  reads return the init value 0 on every call. The clear/read path is real; the data behind it
  is not.
* **Transaction association: none.** There is no transaction identifier in any of these
  registers and no per-transaction index. A single global slot cannot be attributed to a
  transaction except by the control plane clearing it, driving exactly one transaction, and
  reading it back before the next. Nothing in the campaign did that.
* **Cross-contamination.** With write-if-zero and a single slot, a value latched by transaction
  *n* would be silently reported as transaction *n+1*'s if the slot were not cleared in
  between. There is no generation tag, unlike `reg_tag`, and no epoch qualification, unlike
  `reg_bor_epoch`. So a naive per-run readback would mix transactions by construction.

## 5. The counters have the same problem, and one live counter exists

`ctr_fresh` and `ctr_deq` are reported by bf-p4c as unused instances. The frozen control plane's
evidence path reads exactly those two arrays, at `defense4_caseA_setup.py` lines 463 and 464,
across all 18 `CF_*` and 8 `CD_*` slots mapped in `control/counter_map.py`. Those reads return
zero.

This retracts a second statement in the rerun plan. It proposed reading `CF_RESP_DUP_SUPP`
before and after each block as a proxy for whether the relay retransmitted a held response.
`CF_RESP_DUP_SUPP = 8w16` is a slot index into the unused `ctr_fresh`, so that counter is inert.

The suppression itself, however, **is live**, and that is worth separating. `OUT_RESP_DUP_SUPP`
is a real decision outcome: the decide table maps it to `cmt_drop()` at frozen line 2309, and
`cmt_drop` calls `ctr_outcome.count()`. `ctr_outcome` is a `DirectCounter` attached to the
decide table (`counters = ctr_outcome;`, line 2297), one counter per table entry, and bf-p4c did
**not** report it unused. So:

* the claim that a position-matched response retransmission is absorbed inside the switch
  **stands**, now verified in the live decision path rather than inferred from a comment;
* the way to count it is the decide table's own direct counter at the `OUT_RESP_DUP_SUPP` entry,
  not `ctr_fresh`;
* the frozen control plane reads neither `ctr_outcome` nor any decide-table counter, so counting
  it needs new control-plane code as well.

## 6. A provenance limit on all of the above

The archived compile log is from `/home/decps/rrc_bor_build/defense4_rrc_bor_unified12.p4`. The
preservation record `E0_testbed_preservation.md` says the loaded conf was
`/home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel_abs.conf` — a **different
build tree**. No compile log, `context.json` or BFRT schema from `rrc_bor_build_v2` is archived
anywhere in this repository's history, and neither recorded `context_conf` hash
(`3d475d3c…`, `c13cea4e…`) matches any archived `.conf` or `context.json`.

Worse for line-level provenance: the compile log's line numbers do not match the frozen source.
`ts_first_block_w` is at log line 1982 and frozen line 2004, an offset of 22; `parser IgParser`
is at log line 1042 and frozen line 1051, an offset of 9. A non-constant offset means inserted
content, not a header. Hashing every version of the file in history identifies the compiled one:
a **3,484-line** blob, sha256 `5b846064d2b3ebc9…`, first seen at commit `fdb67cf7` under
`defense4/size/native_parity/p4/`, which matches the log on both cross-checks. The frozen
"exact experiment source" is a **3,509-line** file, sha256 `7ce30494…`.

So the frozen source is not byte-identical to the source in the archived compile log, and
neither is provably the source of the loaded binary `33fa3a77…`, whose own compile transcript is
not archived.

**What this does and does not change.** It does not soften the withdrawal: the instrumentation
is inert in the frozen source by exhaustive inspection, and inert in the one compile that is
archived by the compiler's own testimony. Two independent lines agree. What it does mean is that
the statement is **PARTIAL for the loaded binary specifically**: to state it VERIFIED for
`33fa3a77…` one would need that binary's compile transcript or its BFRT schema, and neither
exists here.

## 7. The smallest correction, and what it costs

Obtaining any switch-side release instant requires **editing the P4 and compiling a new
binary**. There is no control-plane-only path. Concretely, the smallest change is:

1. Add an execute call for `ts_read_w` on the admitted READ, and for `ts_ack_arm_w` on the
   qualifying relay acknowledgment. Both actions already exist and are already compiled, so
   this adds two call sites and no new register.
2. For the release side, add an **egress**-side timestamp register and write it from the egress
   pipeline, because an ingress-side write cannot observe a departure. This is new state, not a
   call site, and it must be shown to fit the egress stage budget.
3. Give each register a generation tag qualified by `reg_tag`, or accept that a readback is
   valid only when the control plane clears, drives one transaction, and reads back before the
   next.
4. Extend the control plane to clear and read whatever is added, including the decide table's
   direct counter at `OUT_RESP_DUP_SUPP`.

**This is a new program.** It requires a new compile, produces a **new binary with a new hash**,
and therefore a separately identified build that is not the one the published evidence rests on.
It needs its own approval before deployment, and any campaign run under it must be reported as a
different build, never pooled with `campaign_v1`.

**Do not reach it by defining `D3_SYNTH_EVENTS` for a physical campaign.** The source forbids
it in terms, at frozen line 193:

> COMPILE-TIME SWITCH. Everything guarded by D3_SYNTH_EVENTS exists so that ONE complete
> Defense 3 transaction can be driven end to end with NOTHING outside the chip: no host
> injector, no physical relay, no dp11 (which is unconfigured and dark). **The LIVE CAMPAIGN
> BUILD MUST NOT DEFINE IT.** With the macro undefined the preprocessed source is
> byte-identical to the Gate-1 program that is loaded on the switch — that identity is
> checked, not asserted.

Two things follow. It is a third independent corroboration that the macro was off in the loaded
build, from the author's own design note rather than from a flag list. And enabling it would
materially change the data plane under measurement: it brings in synthetic ACK and response
generation with their own ethertypes (`ETYPE_SYNTH_ACK`, `ETYPE_SYNTH_RESP`,
`ETYPE_SYNTH_RESP_ALT`) and a second packet-generator application on a separate parser path
(frozen lines 295 to 306 and 1077 to 1103). Turning it on to expose registers would replace the
program being measured, and the exposed registers would **still** have no execute sites. It is
the wrong lever twice over.

## 8. What the earlier claim got right

Two small things survive. The registers and their write actions really are declared, so the
author's intent is recoverable from the source. And the control plane really does clear and read
four of them, so the plumbing on that side exists. Neither amounts to working instrumentation.
