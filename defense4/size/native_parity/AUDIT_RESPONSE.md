# Audit response — ce3392d RRC READ/SBO joint result

Point-by-point response to the independent audit of the pushed state at ce3392d (RRC P4, setup,
emulator, analyzer, result doc, manifests, both raw joint pcaps). Every correction below was
reproduced from the raw pcaps; the corrected analyzer's numbers match the auditor's independent
pairing to the millisecond.

## Confirmed (no change needed)

- **Core RRC mechanism is real and holds** for the tested SEL profile: ADMIT (function-specific
  expected-ACK, READ seq+20 / SELECT·OPERATE seq+45) → HOLD (pure-ACK arms the Case-A deadlines) →
  RELEASE (`do_shape = shape_enable & payload49`, mcast to MGID 0x2849, no unicast source copy) →
  REPLICATE (two same-port PRE nodes, RID 1/RID 2 on dp9) → CARVE (bytes [0:28] and [28:49],
  contiguous TCP seq, recomputed IP/TCP checksums). Byte-exact reassembly; block CRCs and IP/TCP
  checksums valid; no 49 B source copies, resets, or carved retransmissions.
- **Cold-restart conclusion is correct.** `read_len` is dead in the RRC PHV and reads back 0;
  restarting switchd cannot revive a compiler-eliminated field. `--read-len 0` is the correct
  immediate workaround; the direct caseA command in `CONFIG_PROVENANCE.txt` arms pktgen without
  changing the kernel.
- **Both offline RRC conformance suites and the joint evidence manifest verify completely.**

## Fixed — analyzer (`analyze_rrc_pcaps.py`, rewritten)

The old analyzer paired each request with the next 28 B segment by time, with no TCP check — so an
18 B state READ was paired with a later SELECT response, inventing a 29.9 ms outlier and n=31.

- **TCP-semantic pairing:** a relay response/ACK belongs to request R iff `tcp.ack == R.seq + len(R)`,
  bounded by the next request. → SELECT count is **30**, not 31; the 29.9 ms outlier **does not exist**;
  request→response std is **0.334 ms**, not 1.299 ms.
- **DNP3 function classification** (READ / STATE_READ / SELECT / OPERATE) from the request function +
  length; only the admitted 20 B / 45 B profiles are counted.
- **Block CRCs removed before parsing** → the response function is the real **0x81** (the old 0xC0 was
  the application-control byte), group G10 for READ / G12 for SELECT.
- **Both orderings reported:** TCP-sequence order **[28,21]** and capture-arrival order **[21,28]**.
- **Both timing metrics:** request→response *and* pure-ACK→response (the Case-A CLRT the deadline
  clamps), plus request→pure-ACK.
- **Declared equivalence margin** (0.5 ms on the ACK→response median) replaces the arbitrary
  "median within 2 ms = equal".
- Verified against the auditor's independent numbers: ACK→response medians 20.003 / 20.001 ms;
  request→ACK 2.652 / 2.607 ms; request→response 22.655 / 22.606 ms; state-reads native 1.94 / 7.16 ms.

## Fixed — result doc + figures

- `READSBO_NORMALIZATION_RESULT.md` rewritten: scope is **READ-vs-SELECT-echo parity** (not full
  READ-vs-SBO; physical OPERATE not run); "every SEL response" → "every **admitted** 20 B READ / 45 B
  SELECT profile"; timing claim is **deadline-clamped central parity (ACK→response), not statistical
  identity**; both segment orderings named; the primitive is **multi-function, not fully type-agnostic**
  (admission branches on function; only the carve is type-blind); the combined-ACK boundary is stated.
- `figures/` rebuilt from the corrected analyzer (n=30 each, no phantom point), series relabeled
  **SELECT** (not SBO): `fig_size.pdf`, `fig_timing.pdf`, `fig_clrt.pdf`.
- Corrected `analysis.json` regenerated in both evidence bundles; manifests refreshed.

## Fixed — setup (`defense4_rrc_setup.py`, control-plane only)

Per the audit, the one-shot at ce3392d does not pass `--read-len 0`, lacks `--d-a-ms/--d-r-ms`, does
not forward master/relay/budget/poll, accepts a misleading 0x8000 default, and enables shape before
installing the PRE (a short loss-risk window). The corrective patch: always pass `--read-len 0`;
add+forward `--d-a-ms/--d-r-ms` and `--master-ip/--relay-ip/--budget/--poll-ms`; require explicit ms
deadlines for D-modes (no silent 0.065 ms normalization); safe order shape=0 → configure+verify timing
→ install PRE → verify exact MGID/nodes/RIDs/dp9 → shape=1 → read back all → abort (never substitute
defaults); rollback verifies shape is off before deleting the PRE and does not swallow deletion
failures. (See the commit that lands this file.)

## What is NOT banked

- Full physical SBO equality (SELECT **+** OPERATE) — OPERATE not run.
- "Every SEL response" — only admitted 20 B/45 B profiles are shaped.
- Generic Case-B / arbitrary-size support — the carve is hardcoded to 49 B single-fragment, and the
  timing engine needs a separate pure ACK to arm (a Case-B combined response has none).
- Statistical identity beyond the tested ACK→response deadline behavior.

## Verdict

Keep RRC as a real, silicon-proven primitive: release-triggered PRE replication + RID-directed
byte-preserving TCP carving composes Case-A timing normalization with native response-size parity on
one Tofino-1. The corrections tighten the claim; they do not weaken the result.
