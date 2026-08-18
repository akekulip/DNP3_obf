# Gate S4 Result — Packet-Preserving Fixed-Cell Software Prototype

Gate: S4
Status: **PASS (software prototype). No hardware. S4 does not open S5.**
Mechanism: M-001, packet-preserving Layer-2 fixed-volume AEAD cell bridge (policy `S3-RNL-256-v1`).
Evidence: `evidence/s4_software/` (manifest `evidence/s4_software/manifest.sha256`).

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

## Results

Seven analyzed pipeline runs plus a direct-veth baseline, all PASS. Full matrix
in `evidence/s4_software/CLAIM_MATRIX.md` and `S4_SUMMARY.json`.

**Functional correctness (the real byte-equality oracle).** In every run the
master->relay and relay->master application TCP streams reconstructed at the two
trusted boundaries are byte-equal, and the delivered side reassembles with no gap
or conflicting overlap. In the 100-exchange main run all delivered DNP3 frames
pass link-header and block CRCs and all delivered TCP frames pass IP/TCP
checksums. (Frame-level counts are reported but not gated: legitimate TCP
re-segmentation on a retransmit changes frame boundaries while preserving bytes.)

**Size security — the decisive test is cross-workload volume.** Over one fixed
40-second wall-clock window, an idle run (zero DNP3 exchanges) and a busy run (40
exchanges) produced the observer an **identical** transcript volume: 3878 cells,
992,768 bytes each — cell delta 0, byte delta 0. A passive observer cannot tell
zero traffic from a full transaction load. Combined with the fact that every
observed cell is exactly 256 bytes (`wire_len` set `[256]`), the observed
size/count transcript is independent of the inner DNP3 content — for loads within
the fixed cell budget, which the 40-exchange busy run fit inside (see the
overload caveat below).

Supporting per-run statistics on the 100-exchange main run: cells binned by
wall-clock time show a modal 22 cells per epoch bin with only small (max 3)
boundary deviation; mutual information between the inner response length and the
per-bin size/count features stays within a 1000-permutation null; and a
random-forest attacker trained on those features (2000-bootstrap CI) does not
beat the majority baseline (RF balanced accuracy 0.142 vs dummy 0.160, chance
0.167).

**Correction from the first S4 pass.** An earlier version of this analysis chunked
the observer cells by the mechanism's own cell counter (`counter // window`),
which re-derives a fixed block structure by arithmetic and therefore cannot
detect a content-dependent cell count — the invariants and the classifier were
tautologies. That was found in independent review and replaced: the analysis now
bins by wall-clock time (which can detect a volume leak; the negative unit test
confirms it fails on a planted count excess), and the load-independence claim
rests on the cross-workload idle-vs-busy identity above, which has no binning
phase. The per-bin count shows a few cells of boundary jitter (fixed 210 ms bins
drift against the true epoch cadence); that is a measurement artifact, not a
leak, as the idle-vs-busy identity establishes. The MI / classifier reuse only
`empirical_categorical_mi` from the frozen S3 `observer_analysis`; the invariants
and classifier are implemented locally, not the frozen S3 gate.

**Fault recovery.** Four post-emission link faults were injected and each fired
and recovered with the application stream still byte-equal: a dropped cell
(`link_dropped=1`) was recovered by native TCP retransmission (which re-segments,
handled by the retransmission-aware reassembler); a duplicated cell was deduped
(`vision_duplicate_cells=1`); a reordered cell was reassembled; a replayed cell
was rejected as an exact duplicate. Decode-level authentication, replay-epoch,
overflow, and timeout fail-closed paths are covered deterministically by the
offline (`offline/test_s3_offline.py`) and software (`software/test_*.py`) unit
suites.

**Lifecycle.** Three sequential master reconnects against one relay served all
exchanges with byte equality preserved.

**Overhead.** Baseline endpoint round-trip over a direct veth is sub-millisecond
median. Through the cell layer it is ~210 ms median — one fixed epoch per
exchange, the latency cost of the fixed-slot schedule. Observed outer bytes are
~28x the delivered inner bytes (fixed cover-cell overhead). Per-run shim CPU,
RSS, and emit slip are in `S4_SUMMARY.json`.

## Claim labels (mission §7)

- **PASS: real size normalization (software prototype).** The observed outer
  size and count are independent of the inner load within the `S3-RNL-256-v1`
  policy domain (idle and busy are identical on the wire), and the inner length
  and type are not visible on the observed link.
- **NOT DEMONSTRATED: multi-device fingerprint suppression.** A single synthetic
  outstation was used; this is length-independent transcript construction, not
  cross-device classification.

## Not demonstrated (out of S4 scope)

- Hardware, Vision, or the Tofino CPU punt/reinject path — the mandatory,
  still-unproven condition before any hardware use (S6).
- RRC/BOR timing integration — the cell layer's interaction with the ACK/response
  timing policy (S5).
- Overload behavior — independence is demonstrated only within the fixed
  `S3-RNL-256-v1` cell budget. The busy run offered 40 exchanges, which fit inside
  the cover budget (cell delta 0); a load that saturates the emission rate would
  force the observed volume to expand and is not tested.
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
