# Errata for `case_a_defense3_fixed_ack_delay.p4`

**Added 2026-07-30 after an external audit.** Several comments in the switch program still
describe an earlier state of the work and now contradict both the code below them and
`../REPORT.md`. They are listed here rather than edited **because the archived compiler
artifacts key on source line numbers** — `artifacts/resources/*.table_summary.log` contains
table names like `tbl_case_a_defense3_fixed_ack_delay1871`, so inserting or deleting a
single line renames those tables and breaks the correspondence between the source, the
archived assembly and the binary currently loaded on the switch.

**Rule: where a comment and this file disagree, this file is right.**

| lines | what the comment says | actual state |
|---|---|---|
| 27–29 | "Nothing here has been loaded on the switch, and the switch has not been touched by this work. Defense 2 remains the loaded program." | **False.** The program has been loaded and validated on Tofino-1 against a physical SEL-751 across four synthetic gates and a 480-transaction campaign. The switch is deliberately left running Defense 3 with the reservoir armed. |
| 108–113 | "Nothing here has been loaded or run. This file answers a compile-fit question only." | **False**, same reason. The rest of that block — multi-segment bypass, K = 64 not minimal, one active transaction as measured capacity — is still accurate. |
| 101–105 | "Nothing on a protected session is ever dropped by Defense 3." | **False since the duplicate-suppression repair.** A response retransmission matching the current transaction's identity while a copy is already queued is **dropped**, counted as `RESP_DUP_SUPP`. The mechanism also drops blocker tokens at the deadline, trigger clones, stale tokens and off-topology frames. The accurate claims are *zero queue drops* and *zero unintended host-packet drops*. |
| 1822–1827 | a duplicate response "is FORWARDED as a bypass rather than held or marked again" | **False**, and superseded by the repair described in `REPORT.md` §9.7. A duplicate is **suppressed**, not forwarded, because forwarding it was measured overtaking the held acknowledgement by 1.0014 ms. The surrounding claim — that the distinct-value encoding makes one-shot protection fall out for free — is still correct. |
| 1093–1095 | "INITIAL VALUE IS TAG_INACTIVE, **not 0**" | **Self-contradictory leftover from the `0xFF` era.** `TAG_INACTIVE` *is* `0x00`, as the declaration on the very next line says. Read it as "the initial value is `TAG_INACTIVE`, which since §7.1 is `0x00`". |
| 1342–1359 | `TODO(silicon)` items | Most have since been measured; see `REPORT.md` §6.4 and §10.4. |

## Two defects, not comment problems

Separately from the stale comments, **two confirmed state-ordering defects remain in this
source** and are not marked in it at all: the response marker and the fail-open retire both
commit their register write one pipeline level before the test that authorises them
resolves. Full analysis in [`../AUDIT_RESPONSE.md`](../AUDIT_RESPONSE.md) and
`REPORT.md` §7.5. Anyone modifying this file should read those first.

## When the source is next edited

Fold these corrections into the comments in the same change that repairs the two defects —
that edit renames the line-numbered tables anyway, so the artifacts must be regenerated
regardless, and there is no reason to pay that cost twice.
