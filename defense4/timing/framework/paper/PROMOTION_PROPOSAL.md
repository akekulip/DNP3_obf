# Working-paper promotion proposal

This is a separate working candidate, not an approved replacement for
`paper/rewrite`. Its three protected Introduction paragraphs are copied
byte-for-byte, including the existing citation mappings. The newer meeting
framework paragraph is available here only as a summary in
`audit_current/MEETING_20261005_DIRECTION.md`. The proposed continuation follows
that positioning but is not presented as Dr. Lin's verbatim newer paragraph.
The exact authored paragraph must be supplied before its verbatim promotion.

The frozen checker and writing guide stay intact. A future promotion needs:

1. Dr. Lin's acceptance and Philip's instruction to change the frozen source.
2. Resolution of the joint Tofino translation/fit, association/CRC, reset and
   drain gates, or explicit acceptance of a narrower demonstrated scope.
3. Per-claim provenance for the proposed size/response-ready results, retaining
   protected text, citation checks and established notation. Size permission
   would apply to evidenced working claims, not remove the old checker globally.
4. Review of the protected Introduction's encrypted-channel breadth and the
   newer paragraph's adversaries being unable to reconnoiter. Neither is
   silently rewritten or supported by invented results.

The draft's design separates infrastructure, operation policies, Case 4
composition, constraints and realization. Platform inventories stay in
Implementation/evidence. Evaluation separates observation points, endpoint
success, software timing/stream behavior, cost and limitations.

Claim locations map to the canonical `CLAIMS_RECONCILIATION.md` and the size
semantic gate manifest. The frozen campaign's timing claims remain separate.
No submission eligibility or author acceptance is implied by a PDF build.

Rebuild locally from this directory:

```sh
python3 working_gate.py
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build main.tex
```
