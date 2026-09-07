# Schematics (Figures 1–3 of the manuscript)

Hand-drawn SVG schematics, authored 2026-08-26 from the verified event model
(`paper/rewrite/pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`); they contain no measured
data. Source of truth is the SVG; PDF (vector, fonts embedded) and 600 dpi PNG are exported with
Inkscape 1.4.2 (`~/.local/bin/inkscape <f>.svg --export-type=pdf|png --export-dpi=600`).
Manuscript copies live in `paper/rewrite/figures/` and are byte-identical to these.

| file | manuscript figure | what it shows |
|---|---|---|
| `fig_ladder` | Fig. 1 (Background) | READ poll and select-before-operate control on the master-facing link: requests blue, TCP acknowledgments grey, application responses green; interval c (CLRT) and O (the OPERATE response-to-acknowledgment interval) in red. The label
text inside the SVG still reads "echo"; correcting it changes Figures 1 and 3 and therefore
`main.pdf`, so it is held in the proposed manuscript patch rather than applied here |
| `fig_observation` | Fig. 2 (Threat model) | master, switch, SEL-751A; the master-facing link (solid red, shaded) is observed, the relay-facing link and the two internal lanes (dashed) are not |
| `fig_design` | Fig. 3 (Design) | ingress; read lane (ACK at t_A + D_A, response + D_R); on-chip generator feeding both blocker reservoirs; control lane (OPERATE to relay at T0 + J; ACK T0 + A, response T0 + R); unmatched traffic forwarded |

Conventions: 3.5 in single-column width at final size (72 SVG units per inch), Times New Roman,
6–8 pt text, the `alessandretti-nature` palette shared with the data figures (blue #2177B5, orange
#FF800E, green #2BA02B, red #D72927), one meaning per colour: red = master-facing / observed,
green = outstation side, orange = blockers and generator, blue = the switch. Arrowheads are SVG
markers; no arrow crosses another.

## A note on re-exporting

`pipeline/export_schematics.sh` re-exports all three schematics whether or not their SVG
changed, and Inkscape stamps a `/CreationDate` into each PDF. So a run always dirties all three
PDFs and PNGs even when only one SVG was edited. On 2026-09-07, `fig_ladder` and `fig_design`
were edited to remove the word "echo" from their label text; `fig_observation.svg` was **not**
touched, and its PDF differs from the previous one only in that timestamp, at identical size and
with an identical `/ID`. Read a `fig_observation` diff that changes nothing else as export noise.
