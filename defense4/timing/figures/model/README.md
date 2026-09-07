# Model diagrams

Two explanatory diagrams, both **DRAFT** until the manuscript revision that would use them is
authorised. They are schematics of the verified mechanism, not plots of a distribution, and
they are kept out of `paper/rewrite/figures/` deliberately: no manuscript figure changes.

| figure | what it shows |
|---|---|
| `fig_m01_release_timeline` | the read lane's release timeline: `m_0`, `t_0`, `t_a`, `t_r`, both release deadlines, the actual `e_a`, `e_r`, and the master-observed `m_a`, `m_r`, with the on-time case in (a) and the late-response case in (b). Filled circles are instants that were measured; open squares are instants inside the switch that were not. Bars are durations. |
| `fig_m02_timeout_model` | the two timers that could end a held transaction, each drawn from the condition that actually starts it, against what the mechanism consumed. The application receive budget starts when the program enters the receive, immediately after the send; it is **not** drawn starting at the acknowledgment. |

Regenerate with

```sh
../../evidence/campaign_v1/repro/.venv/bin/python \
  ../../audit_current/tools/make_model_figures.py
```

No value is written into the script. Configured offsets come from
`evidence/campaign_v1/PROVENANCE_CONSTANTS.json` and measured values from
`audit_current/outputs/timeout_and_tcp_audit.json`. Each figure emits, through the same
`figstyle_ndss.save` contract the NDSS figures use, a vector PDF at 7.16 in, a 600 dpi PNG, its
exact plotted values as CSV, a caption draft, a method note, a limitations note and a
provenance sidecar naming every input by repository-relative path and SHA-256.

Style, enforced by the shared module and gated on emit: opaque white background, Times
compatible serif with `pdf.fonttype 42`, minimum 8 pt at printed size, Okabe-Ito colours, and
marker or line style varying with colour so both read in greyscale.
