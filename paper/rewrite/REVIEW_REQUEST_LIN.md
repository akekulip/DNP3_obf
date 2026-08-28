# Review request for Dr. Lin — "Programmable In-Network Timing Obfuscation for DNP3"

Attached: `paper/rewrite/main.pdf` (10 pages, IEEEtran conference template; target NDSS,
13-page limit), built 2026-08-26 from branch `paper/final-timing-rewrite-20260826`
(GitHub `akekulip/DNP3_obf`, draft pull request open, not merged).

The paper is timing-only: one Tofino-1, one physical SEL-751A, one master-facing capture
session. Size shaping was active in both arms of the frozen evidence, the configuration
provenance is partial, and the relay-facing timing and physical breaker motion were not
observed; all of this is stated in Section VI-F.

I would value your review of five points in particular.

1. **The Introduction (Section I).** It is the text you and Philip wrote, verbatim; only citations
   were added (`pipeline/reports/LIN_TEXT_CHANGELOG.md`).
2. **The Stuxnet sentence (¶1, last sentence).** It cites the E-ISAC/SANS Ukraine analysis [1] and
   Langner's Stuxnet analysis [2]; the six-month dwell is documented for Ukraine, not Stuxnet.
   Please confirm the wording you want.
3. **The framework as the main contribution (¶4 and the contribution list).** CLRT normalization
   (READ and the SELECT phase of SBO) and the OPERATE control path are presented as two case
   studies of one framework, following your guidance.
4. **The bounded OPERATE claim (Section VI-D, Figure 7).** We claim only that the master-visible
   OPERATE ACK-to-echo interval stays at R − A = 4 ms across configured holds J = 2, 6, 12 ms;
   J was configured, not observed on the relay-facing wire; breaker motion and exactly-once
   delivery are not claimed.
5. **The title and the contribution list.** Title: "Programmable In-Network Timing Obfuscation
   for DNP3". Four verb-first contributions; no "first" claim is made.

Also open: the two author email addresses in the author block, and the affiliation line
(University of Nevada, Reno), which I ask you to confirm.
