# Mechanism figure

Suggested caption: **Proposed target and separate executed software size path.**
Panel (a) shows the intended full Case 4 target. Master requests and relay
ACKs/responses enter Ingress. The proposed ingress size path validates and pads
eligible requests; proposed egress carving and forwarding sends requests to the
relay and ACKs/responses to the master. Repeated endpoint boxes distinguish
send/receive roles. Read ACK blockers occupy qid7 above held ACK qid6, and Read
response blockers occupy qid5 above held response qid4 on PORT8. The control
OPERATE domain uses PORT10 with qid3 blockers above held OPERATE qid2. A tagged
request clone triggers packet generation. Initial generated seeds and packets
returning from either loopback pass through Ingress before queue scheduling or
release. The independent PORT68 pulse requests 100 us service for a 30 ms
readiness expiry; requested spacing does not establish achieved service or drain.
The proposal does not establish complete target compilation, physical queue
behavior, activation or achieved timing. Historical compiled component snapshots
do not qualify the edited recovery source.

Panel (b) independently shows the executed BMv2 size path with Python codec
endpoints: SELECT/OPERATE requests expand from 35 to 55 bytes; returning 57-byte
echoes are carved into 28/29-byte segments and reassembled. TCP translation is
part of this bounded software path. It is separate from the production OpenDNP3
software socket evidence and from the target proposal. The historical READ
49→[28,21] profile remains a separate documented capability.

The canonical source is `fig_framework_mechanism.spec.yaml`. From the repository
root, run `python3 -B defense4/timing/framework/figures/gen_mechanism_drawio.py`.
The generator uses the installed offline Draw.io skill with Node >=20, draw.io
Desktop for preview/export evidence, and Inkscape for the final physical-size
vector PDF and 300 DPI PNG. The editable `.drawio`, SVG, PDF and PNG share the
basename. Sidecars, strict diagnostics and Desktop attempts are retained in
`.drawio-tmp/case4-mechanism/`. The exact strict diagnostic log is also packaged
as `strict_validation_20261006.log` and hash-bound in the provenance. Failed Desktop attempts are labeled unavailable;
previous outputs are removed before each attempt. The generator refreshes hashes
and provenance, and explicit visual review is recorded separately.

The original blue `#1f4e9e`, orange `#c25b00` and gray `#555555` palette remains.
Colorblind/grayscale certification is unavailable. Direct labels and solid versus
dashed lines also convey meaning: blue packet paths, orange generated packets,
and dashed configuration/clone triggers.

XML validation passes. Strict validation exits 1 with 13 retained warnings:
11 combinations of explicit connection points and waypoints, one short final
segment, and one concise-label warning covering two labels. There are no label-fit
warnings. Normal rendering reports zero node and edge crossings. Final PNG,
Desktop preview and actual working-paper page 2 were inspected; no clipping or
connectors through unrelated boxes were observed. The 27-node/23-edge figure is
7.16 inches wide, with minimum effective text 8.175 pt in the standalone export
and 8.152 pt at the actual manuscript placement. PDF fonts are embedded without
Type 3 fonts. `figure_provenance.json` binds the source proposal, separate software
evidence, export hashes, diagnostics and manuscript check. No old compiler PASS is
transferred to current edited source.
