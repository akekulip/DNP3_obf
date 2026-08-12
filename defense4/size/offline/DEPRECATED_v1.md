# DEPRECATED v1 offline scripts — NOT part of the reproducible workflow

The audit (`DEFENSE4_31B630F_INDEPENDENT_AUDIT.md`, hygiene) flagged that several older size-probe
scripts hard-code absolute `~/.../dnp3_split_harness` paths (an external sibling in the
FROZEN `~/Projects/DNP3` repo). They are **superseded v1 artifacts** and are **deprecated**: they are
NOT imported by the current gates and are NOT part of the reproducible workflow. They are retained only
as historical record and must not be cited as reproducible.

| deprecated file | absolute-path dependency | superseded by |
|---|---|---|
| `canonical_response.py` | `~/Projects/DNP3/dnp3_split_harness` | the OpenDNP3 decoy/cover gates + `observer_scoring.py` |
| `p4_egress_emulator.py` | `~/Projects/DNP3/dnp3_split_harness` | `transport_oracle.py` + the P4 conformance corpus |
| `size_transform.py` | `~/Projects/DNP3/dnp3_split_harness` (+ pcap) | the decoy READ gate |
| `joint_transform_oracle.py` | `~/Projects/DNP3-size-probe/dnp3_split_harness` (nonexistent) | `transport_oracle.py` |
| `sbo_oracle.py` | `~/Projects/DNP3/dnp3_split_harness` | the OpenDNP3 SBO round-trip gate |

`../p4/baseline.err` is a **stale stored bf-p4c stderr** from an earlier `size_read_range.p4` build and
contains a home path; it is a historical log, not an active artifact.

**Reproducibility scope:** the audit-repair reproducible workflow is the current set only —
`transport_oracle.py` / `stream_reconstruction.py` / `gate_a.py` (transport), `timing/analysis/`
(timing), the OpenDNP3 cover/decoy gates + `observer_scoring.py` (endpoint/observer), and
`p4/defense4_cover_kernel.p4` (compile). All of those use a `.git`-file-aware repo-root resolver with
**no absolute paths**. The files listed above are outside that scope.
