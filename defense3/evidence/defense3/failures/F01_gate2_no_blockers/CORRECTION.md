# CORRECTION — the "arm write did not land" diagnosis was WRONG

Written by the PI after re-reading the artifacts. **Supersedes the hypothesis in
`DIAGNOSIS_PROGRESS.md`.** The template is not broken and `reg_tag` was never the fault.

## What I got wrong

I inherited the dying agent's lead — *"the arm write did not land"* — and then built a second wrong
theory on top of it: that the synthetic event template carries no DNP3 layer, so
`meta.gen_in = hdr.dnp3_app.app_control` could not supply a valid generation.

Both are refuted by evidence that was already in the artifacts I had:

1. **The role map installed correctly.** `gate2_txn.json`:
   `role_map["0"] = {action_name: "Ingress.synth_read", gen: 192}` — `0xC0`, a valid generation.
2. **The P4 takes the generation as control-plane action data, precisely because the template is a
   pure ACK.** `synth_read(bit<8> gen) { … meta.gen_in = gen; }` at `.p4:1338-1343`, and the design
   note at `.p4:192-197` says so explicitly: *"Its generation is control-plane action data"*
   — because *"the template is a pure ACK and carries no DNP3 bytes."* I read past it.
3. **The arithmetic confirms the arm executed and wrote.** With `v = 0xFF` and `gen_in = 0xC0`,
   `tag_arm` returns `rv = 0xC0 − 0xFF = 0xC1`, which the decode table maps to "FRESH, armed now"
   — which is exactly why `ARM_FRESH = 1` fired.

## Why `reg_tag = 255` is the CORRECT end state

There are two deliberate retirement sites, both writing `TAG_INACTIVE`:

- `.p4:1581` — fail-open on budget exhaustion.
- `.p4:1591` — **the released RESPONSE path.** The comment states the intent: retiring the
  generation here *"is what stops a later keepalive from finding a live generation."*

The run recorded `RESP_BYPASS = 1`, so the transaction was retired by the response path after the
ACK was rejected. Reading `255` afterwards is expected behaviour, not a lost write.

## The real, still-open state of F01

Three independent faults. **None explains another**, and the two constructions queued earlier
(C1 direct pattern trigger, C2 timer-armed reservoir) are **back on the table** — they were only
disqualified by the wrong theory.

| id | fault | evidence | status |
|---|---|---|---|
| **F01-a** | the K=64 reservoir never fires | `tag_diff = 0xC1 ≠ 0` so the clone *should* have been emitted, yet `trigger_counter = 0` | **open** — the mirror→dp68→pattern→fire path does not fire when the triggering packet is itself a dp68-originated generated packet |
| **F01-b** | the synthetic ACK is rejected | `ACK_REJECT = 1` with a live generation at the time it arrived, so the failing conjunct is a header test | **open** — prime suspect is `tcp.seq` vs `EXP_RELAY_SEQ`: the template's `seq` is fixed while `EXP_RELAY_SEQ` is seeded from the master ACK's `ack_no` |
| **F01-c** | the one-shot fired twice | `app_event.trigger_counter = 2`, 6 packets where 3 were intended | **open** — and it means the counter tallies above **mix two fires** and must be read with that caveat |

## Lesson

A dying agent's last line is a lead, not a finding. It had not verified it either. Two cheap reads
— the installed `role_map` and the two `TAG_INACTIVE` write sites — would have refuted both
theories before I committed to one, and I had both files open.
