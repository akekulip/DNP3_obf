# Rewrite repair audit

Paragraph-by-paragraph audit of the Claude-generated Introduction, Threat Model, Implementation, and
Related Work (archived at `rewrite/archive_claude_generated/`). Per paragraph: intended function;
knowledge assumed without explanation; unsupported/overly-broad claims; terminology introduced too
early; missing citations; contradictions with final code/evidence (see `FACT_CONFLICTS.md`, F#);
disposition (retain / rewrite / move / split / remove). "Reader" = fresh NDSS reviewer, no project
exposure.

## A. Introduction (generated)

| ¶ | function | assumes | overbroad/unsupported | early terms | missing cites | conflicts | disposition |
|---|---|---|---|---|---|---|---|
| 1 reconnaissance/Ukraine/FDIA | set the stakes | — | — | — | ok (ukraine2015, liufdia2009) | — | **retain** (matches author ¶1 arc; keep) |
| 2 Formby + CLRT + segment shape + SEL numbers | name the leak | DNP3 master/outstation, READ, SELECT, ACK, "segment vector", "49-byte" | "separable by timing alone" is fine (measured) | CLRT, segment vector, READ/SELECT, 49-byte all before the transaction is taught | ok | F1 (CLRT packets under-defined) | **split + rewrite**: move device/transaction teaching to a new ¶ (story ¶5–6); define CLRT from the two exact packets |
| 3 desirability First/Second | motivate in-network angle | — | — | — | — | — | **retain** |
| 4 constraints First/Second/Third/Last | prior-art mismatch | padding/morphing/WF-defense mechanics | "encryption alone would not hide…tunneling" ok w/ cite | — | ok | — | **retain, lighten** (dense; one clause per item) |
| 5 gap sentence | name the gap | — | — | — | — | — | **retain** |
| 6 mechanism (hold/release/replicate/carve) | first design sketch | queues, replication, CRC boundary | "master reassembles the identical response" | response shaping introduced before leak fully taught | — | **F3 (identical)**, F4 | **rewrite**: move after Background; remove "identical"; teach concept before naming |
| 7 modes (passthrough/ACK/response/combined) | selectable modes | timing modes | — | mode detail early for an intro | — | — | **move** to Background/Overview or Impl; keep one sentence in intro |
| 8 control-command mode | second mechanism | OPERATE, echo, "hidden delay" | — | OPERATE/echo before taught | — | F8 (secret/hidden), F9 | **rewrite**: introduce after teaching SBO; drop "secret" |
| 9 evaluation preview | strongest results | CLRT, [28,21], classifier | numbers ok (measured) | — | — | check "no unsplit escape" phrasing ok | **retain** (verify each number vs verdict) |
| 10 bounds | honest limits | relay-facing | — | — | — | F9 wording | **retain** (align "single release … verified by model, not observed") |
| 11 first-claim + contributions | contributions | — | "first in-network defense to normalize both…" (scope) | — | — | F11 (bound to eval) | **retain, bound**: contributions map to artifacts; scope "first" to the evaluated setting |

**Section-level:** the generated intro is close to the required arc but **teaches the mechanism (¶6–8)
before teaching the DNP3 transaction/leak**; it must be reordered to story order (concept → DNP3
example → consequence → requirement → mechanism). Add the missing "why ICS/DNP3 is different" and the
running-example paragraphs. Expand to 8–10 developed paragraphs (~1.5–2.5 pp).

## B. Threat Model (generated)

| ¶ | function | assumes | overbroad | early terms | missing cites | conflicts | disposition |
|---|---|---|---|---|---|---|---|
| System and observation model | fix the setup | master/outstation/SEL-751 not re-taught here | — | SEL-751, SBO | — | — | **retain**; ensure Background taught it first |
| Adversary capabilities (passive fingerprinting) | attacker powers | CLRT, segment shape | "features that survive the absence of payload decoding" | — | ok (formby2016) | **F2** (payload availability) | **rewrite** F2; keep passive framing |
| Out-of-scope for the threat | carve-outs | — | — | — | — | — | **retain** |
| TCB and deployment assumptions | trust + no-TS | TCP timestamp option | — | — | — | **F7** (how TS handled) | **rewrite** F7 to implemented behavior |
| Security goals G1–G6 | testable goals | — | — | — | — | G5 relabeled (done) | **retain** |
| Non-goals | bounds | — | — | — | — | F3, F9 wording ok | **retain** |

**Section-level:** ordering is close to prompt §7 but should **lead with the system model + native
transaction** (currently assumes Background), separate adversary objective from capabilities, and
avoid restating mechanism internals. Add "what changes if the observer sees the relay-facing link."

## C. Implementation (generated)

| ¶ | function | assumes | overbroad | early terms | missing cites | conflicts | disposition |
|---|---|---|---|---|---|---|---|
| lead: "six major parts" | overview | Tofino/P4 | — | **six internal components, dp8/dp10/dp68, meta.outcome before any end-to-end transaction** | — | — | **rewrite**: precede with a one-page end-to-end READ + SBO walkthrough (prompt §8); defer parts list |
| topology/port roles | ports | dp9/dp64/dp8/dp10/dp68 | — | port names very early | — | — | **move** port names to the detailed figure; teach paths first |
| one-outcome/one-commit | pipeline structure | meta.outcome, tbl_commit | "default forwards unmodified" | code symbols | — | **F5/F13** (default vs explicit drops) | **rewrite** F13; keep after concept |
| parser/classification | classify | READ/SELECT/OPERATE, value set | — | — | — | — | retain, teach roles first |
| timestamps/deadlines | anchor to T0 | T0/A/R | — | — | — | — | **retain** (accurate; mutant-verified) |
| pktgen/reservoirs | timer | pktgen, K=64 | — | — | ok (pifo/sppifo in RW) | — | retain |
| response shaping (release/replication/carving) | mechanism | PRE, carve | "no DNP3 byte modified … reassembled remains 49" | — | — | F3/F4, F12(ok) | **rewrite** measured-vs-design (F4); keep byte-28 design-choice |
| control commands | SBO lifecycle | epoch/spent marker | "designed to release once at T0+J" ok; "secret codebook" | — | — | F8, F9 | **rewrite** drop "secret"; keep model-verified framing |
| two domains | design constraint | scheduler starvation | — | — | — | — | **retain but reorder**: show the failure first (prompt §8.7) |
| control plane/readback | setup | TM/PRE | — | — | — | F6 (rollback ok) | retain |
| failure behavior | fail-open | — | "never drops on default path" | — | — | **F13** | **rewrite** F13 |
| safety guard | safety | {1,3}, index 6 | — | — | — | ok | retain |
| resource fit/limits | fit | 12 stages | "production-representative" (lead sentence) | — | — | **F14** | **rewrite** F14 |

**Section-level:** strong content, wrong order for a new reader — it **starts from internal components
and code symbols** instead of an end-to-end transaction. Reorder per prompt §8; introduce each symbol
only after its concept; correct F4/F5/F8/F13/F14.

## D. Related Work (generated)

| ¶ | function | assumes | overbroad | missing cites | conflicts | disposition |
|---|---|---|---|---|---|---|
| Device fingerprinting | category a/b | — | — | now has kohno/gu added | — | **retain**; split remote vs ICS/CPS if space |
| Network-timing TA + defenses | category c/d | — | — | pacer/panchenko added | — | retain |
| Padding/morphing/segmentation | category e/f/g | — | — | tamaraw/walkie/apthorpe/netshaper added | — | retain |
| Anti-recon ICS | category j | — | "complements rather than replaces" ok | nethide added; could add cardenas/east/fovino | — | **retain + expand** (DNP3 IDS/attack taxonomy) |
| Programmable-switch shaping | category h/i | — | — | securitas/minos/hulin/sppifo added | — | retain |

**Section-level:** organized by problem with per-category contrasts — good. **Two structural fixes:**
(1) it is currently placed AFTER the Conclusion — **move before Conclusion** (F15); (2) expand per the
gap matrix (DNP3 security/IDS, formal fingerprinting, dependent link padding, process-control attack
model) toward ~40–50 verified sources.

## Disposition summary
- **Retain (with wording fixes):** intro ¶1,3,4,5,9,10,11; threat goals/non-goals; impl
  timestamps/pktgen/safety; all RW categories.
- **Rewrite:** intro ¶2,6,8; threat adversary-capabilities + TCB (F2,F7); impl lead + one-commit +
  response-shaping + control-command + failure + resource (F4,F5,F8,F13,F14).
- **Move:** intro ¶7 (modes) → Background/Impl; port/queue names → detailed figure; Related Work →
  before Conclusion.
- **Add (new):** Background & Design Overview section; intro "why ICS/DNP3 differs" + running-example
  paragraphs; the two-domain failure-first framing; the reader-first figures F1–F6.
- **Remove:** "identical response" everywhere; "secret" J; "production-representative"; any
  general/all-DNP3 determinism claim.
