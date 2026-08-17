# Gate S4 Result — Packet-Preserving Fixed-Cell Software Prototype

Gate: S4
Status: **PASS (software prototype). No hardware. S4 does not open S5.**
Mechanism: M-001, packet-preserving Layer-2 fixed-volume AEAD cell bridge (policy `S3-RNL-256-v1`).
Evidence: `evidence/s4_software/` (manifest `evidence/s4_software/manifest.sha256`, 185 files).

## What this gate proves

Two independent software shims carry complete Ethernet frames between a native
DNP3/TCP master and relay while the link between them shows a passive observer
nothing but fixed 256-byte encrypted cells. The master and relay run real TCP
sockets end to end; the shims never terminate a connection. The observed link
transcript is independent of the inner DNP3 content, and the inner byte stream
is recovered exactly at both trusted boundaries.

This is the software prototype the S3 offline codec was designed for. It runs in
a rootless user + network namespace on this host — no Vision, no Tofino, no
physical relay, no P4/BFRT.

## Topology

```
master ns (10.44.0.1)
  <-> vision shim ns    v_in | v_out
  <-> parent test link  l_left | l_right   (cell link + independent observer)
  <-> ufispace shim ns  u_out | u_in
  <-> relay ns  (10.44.0.2)
```

Both shims phase-lock on one shared `--start-monotonic-ns` epoch grid. The cell
link bridges the observed segment and the observer captures it independently.
Runner: `software/run_s4_namespace.sh`. Campaign: `software/run_s4_campaign.sh`.
Analysis: `software/analyze_s4.py` (per run) and `software/s4_summarize.py`.

## Campaign and results

Six analyzed pipeline runs plus a direct-veth baseline, all PASS. Full matrix in
`evidence/s4_software/CLAIM_MATRIX.md` and `S4_SUMMARY.json`.

**Functional correctness (the real byte-equality oracle).** In every run the
master->relay and relay->master application TCP streams reconstructed at the two
trusted boundaries are byte-equal. In the 100-exchange main run all 200 delivered
DNP3 frames pass link-header and block CRCs and all 209 delivered TCP frames pass
IP/TCP checksums.

**Size security (main run).** The observed link carried only 256-byte cells
(wire-length set `[256]`). Across 120 steady-state epochs (1 partial teardown
epoch trimmed) the per-epoch cell count, size vector, and direction pattern are
constant. Mutual information between the inner response length and every
size/count feature (total outer bytes, cell count, size signature, direction
signature) is 0.0 bits, within a 1000-permutation null. A random-forest attacker
trained on the outer transcript reaches balanced accuracy 0.167 — exactly chance
for the six-class label — with a 2000-bootstrap CI that does not beat the
majority baseline. Inner response lengths `{17,49,56,75,104}` and cover epochs
are indistinguishable on the wire.

**Fault recovery.** Four post-emission link faults were injected and each fired
and recovered: a dropped cell (`link_dropped=1`) was recovered by native TCP
retransmission with the stream still byte-equal; a duplicated cell was deduped by
the receiver (`vision_duplicate_cells=1`); a reordered cell was reassembled; a
replayed cell was rejected as an exact duplicate. Decode-level authentication,
replay-epoch, overflow, and timeout fail-closed paths are covered deterministically
by the offline (`offline/test_s3_offline.py`) and software (`software/test_*.py`)
unit suites.

**Lifecycle.** Three sequential master reconnects against one relay served all
exchanges with byte equality preserved.

**Overhead.** Baseline endpoint round-trip over a direct veth is ~0.33 ms median.
Through the cell layer it is ~210 ms median — one fixed epoch per exchange, the
latency cost of the fixed-slot schedule. Observed outer bytes are ~27.6x the
delivered inner bytes (fixed cover-cell overhead). The vision shim used ~0.64 s
CPU and ~24 MiB RSS over the run, with per-cell emission slip max ~1.2 ms / p99
~1.0 ms.

## Claim labels (mission §7)

- **PASS: real size normalization (software prototype).** Outer size and count
  are independent of inner length within the `S3-RNL-256-v1` policy domain, and
  the inner length and type are not visible on the observed link.
- **NOT DEMONSTRATED: multi-device fingerprint suppression.** A single synthetic
  outstation was used; this is length-independent transcript construction, not
  cross-device classification.

## Not demonstrated (out of S4 scope)

- Hardware, Vision, or the Tofino CPU punt/reinject path — the mandatory,
  still-unproven condition before any hardware use (S6).
- RRC/BOR timing integration — the cell layer's interaction with the ACK/response
  timing policy (S5).
- Byte-identical reproduction — the package is functionally reproducible; cells
  carry fresh AEAD nonces and captures carry fresh timestamps, so hashes differ.
- Wall-clock inter-cell timing constancy is deliberately excluded from the size
  gate; it is a timing-policy property (RRC/BOR), reported here only as overhead.

## Reproduction

```bash
PYTHONPATH=<repo> bash defense4/size/real_size_normalization/evidence/s4_software/reproduce.sh
```

Regenerates the campaign, analysis, summary, claim matrix, and manifest. Gate
outcomes reproduce; file hashes do not, by design.

## Stop condition

S4 is complete as an isolated rootless-namespace software result. It does not
proceed to S5 or any hardware action without a new explicit instruction.
