# Ordinary control candidate

Follow [PLAN.md](../../../PLAN.md#execution-checklist--2026-10-07) and
[HANDOVER.md](../../../HANDOVER.md). First SELECT is model verified; full SBO,
ACK/window mapping, timing and lifecycle remain open. Existing switch SDK9.13.2
first-SELECT runs now pass6/6 each for normal, zero and wrap coordinates.
[Current verification](evidence/installed_select_verification_01/verification.json)
binds NF `ca695e97…`12/4, baseline M `c8820a1f…`10/0 and E `dae2efee…`1/10 to
saved MODEL packets/configuration/artifacts. Exact109-byte frames,55-byte payload,
independent checksums and genuine N9/M4/E4 completion pass. No proof presets,
SDK updates or chip activation. Fresh source tests71/71 and scanner3/3 pass.

The table below retains the historical local SDK9.13.1 placement. Current builds
use the switch's existing9.13.2. Exact E qualifies1/10
in `installed_e_01`; extended NF now fits12/4 (critical11) in
`installed_nf_05`, with full artifact and per-pipeline static-capacity checks.
Extended M12 (`deceea36…94cd`, next14) fails PHV allocation; its mapper has no
installed-version fit/model claim. It uses a20-byte actual generation/owner/
coordinate snapshot and independent full32 rereads in two visits. Source-only
accounting is7 ingress visits and408/750 private ACK/response bytes.
Latest next15 (`081b4122…fea25`) uses actual scalar full32 coordinate comparisons;
source review passes, but installed M13 still fails table placement. See the plan
for the next diagnostic; baseline SELECT acceptance does not transfer to this mapper.
See the installed-SDK checkpoint in the linked handover for current failures.

`split.py` renders the accepted placement from `n.p4`, `m.p4`, `e.p4` and
`work_record.p4`, preserving the original prerequisite candidates. The coupled
N/E layouts failed at14 stages; the split uses three disjoint program scopes on
one modeled device0:

| Role | Source | Build | Ingress / egress | Critical path | Stateful banks |
| --- | --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `placement/nf.p4` | `nf_02` |12 /4 |11 |20 |
| M, pipe1 | `placement/m3.p4` | `m3_01` |10 /0 |9 |6 |
| E cache + ingress bridge, pipe3 | `placement/e3.p4` | `e3_02` |1 /10 |7 |18 |

N has no spare ingress stage; M has two. Pipe2 is available for the later T join.
Every14-word image store/load and full identity check remains. Ready publication,
N release commit, M geometry/ledger activation, once-only emission and downstream
terminal cleanup are driven by actual packets. Final emission has a full32
current-N-Work-generation receipt; cached producer identity remains separate.
Lost terminals retain pins. Post-M cancellation and later replay are unfinished.

[Source/configuration/artifact verification](evidence/split_verification_01/verification.json)
records52 passing tests and three actual model trials, each6/6. External handshake
and native SELECT35 yield one exact109-byte Ethernet frame (55-byte payload) at
normal100, zero0 and wrapped0xfffffff0 coordinates. The independent codec, IP/TCP
checksums and DNP3 CRCs match. Actual terminal states are N9/M4/E4; BFRT configured
only routing/admission/mirror plumbing, with no ownership/cache proof presets.
This is local SDE9.13.1 functional evidence, not physical timing or a full target.

Observed SELECT path:19 ingress visits and6 service egress visits;18 private TX
records carry2346 Ethernet bytes excluding model trailers, plus an internal24-byte
completion header. See verification for exact port/byte records and exclusions.
Earlier117/133-byte partial-preparation counts are historical subsets.

Run from `case4_architecture`:

```sh
python3 -B -m unittest discover -s integration/core/ordinary/tests -q
```

`split_model_config.py` binds exact `nf_02`, `m3_01` and `e3_02` artifacts to
scopes0,1,3. `split_model_select.py` drives external frames on the private local
model. Successful retained trials use cold-added front ports and omit
`--int-port-loop`; the SYN-only control proves reserved private recirculation still
works. Preserve the failed front-loop attempts rather than treating them as passes.
Source/model commands and raw events remain in each fresh evidence directory.

Next: reverse ACK and both window edges before N association, matching SELECT57
response, then OPERATE padding/carving, both insertion boundaries and tail repair.
The accepted first-SELECT source/artifact hashes must not be transferred to the
next transport candidate. Full timing/lifecycle and complete9.13.2 target qualification remain open.
