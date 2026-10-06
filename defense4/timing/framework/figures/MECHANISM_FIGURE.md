# Mechanism figure

Suggested caption: **Case 4 timing architecture and separate size evidence.**
Master requests and relay ACKs/responses enter Ingress. After release, Egress
sends requests to the relay and ACKs/responses to the master. Endpoint boxes
repeat the same master and relay in their send and receive roles; they do not
depict additional endpoints. Ingress qualifies one active flow and one
outstanding association. Its owner cookie identifies an owner generation,
without establishing connection-epoch quarantine. On PORT8,
ACK blockers occupy qid7 above the held ACK in qid6, and response blockers occupy
qid5 above the held response in qid4. The control OPERATE domain uses PORT10,
with qid3 blockers above the held OPERATE in qid2. A tagged request clone triggers
packet generation that seeds the internal reservoirs. Packets dequeued through
either loopback return to Ingress before further scheduling or external release.
A separate internal PORT68 pulse requests 100 us service for timeout cleanup;
configured service spacing and physical release latency require measurement.
The absolute readiness timeout is 30 ms, followed by the full configured gap
after a normal ACK release. The source and compile candidate do not establish
hardware activation, queue behavior or achieved timing. Size evidence is
reported separately: software verifies the fixed control request expansion
35→55 bytes, echoed response 57→[28,29] split, and two-boundary TCP translation.
The historical READ response 49→[28,21] profile remains explicit. The current
timing-ingress/size-egress coexistence probe compiles at 10/10 stages, but omits
the transport ledger, joint association and size-ingress response guards.
Complete joint implementation and physical validation remain pending.

The canonical source is `fig_framework_mechanism.spec.yaml`. Run
`python defense4/timing/framework/figures/gen_mechanism_drawio.py` from the
repository root. The generator uses the installed offline Draw.io skill with
Node >=20, draw.io Desktop for an independent visual preview and export
evidence, and Inkscape for physical-size vector PDF and 300 DPI PNG exports.
The editable `.drawio` and SVG, vector PDF and PNG retain the same basename.
Work sidecars and visual review records live in
`.drawio-tmp/case4-mechanism/`. No manuscript or frozen paper artifacts are
modified.

The original blue `#1f4e9e`, orange `#c25b00` and gray `#555555` palette is
preserved through explicit YAML overrides. This custom source palette has no
independent colorblind or grayscale certification. Direct labels and solid
versus dashed lines retain meaning in grayscale. The palette selection gate
was superseded by the approved instruction to preserve the source palette.

The CLI XML validation passes. Strict routing validation retains 13 warnings
about combining explicit face positions with routing waypoints, plus one
warning about the intentional shared packet-generator seeding bus. Face
positions and waypoints keep the queue returns and endpoint arrows distinct.
An additional informational message notes long labels. There are no label-fit
warnings, and the layout metrics report zero node crossings. Final PNG and
Desktop preview inspection found complete endpoint directions and no clipping
or connector paths through unrelated boxes. These routing warnings remain
recorded; strict validation exits 1 and is not claimed to pass. Final SVG/PDF
page width is 7.16 inches, with 8.175 pt minimum effective text size, embedded
Times fonts and a 300 DPI PNG. `figure_provenance.json` records the geometry,
source identities and checks.
