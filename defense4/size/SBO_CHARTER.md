# Phase 5 — corpus-relevant SBO size mechanism (charter + oracle design)

The READ-range primitive (`RESULT.md`) is length-preserving, so it needs no TCP sequence
translation. The SBO mechanism is fundamentally harder: padding a SELECT/OPERATE with real + inert
**decoy CROBs** to a public target size `S` **inserts bytes into the request**, which shifts the
TCP sequence space and requires per-flow, bidirectional translation. This charter fixes the design
before implementation. No design-only gate follows — the oracle is the next artifact.

## Mechanism

Expand a DNP3 SELECT (and the paired OPERATE) to a public target size `S` by appending configured
**inert decoy CROBs** (control-relay-output-block objects, Group 12 Var 1) addressed to **reserved
software-only indices that cannot operate a physical output**, alongside the real CROBs. Recompute
the DNP3 block CRC(s), the DNP3 length, and the IP/TCP length + checksums. The larger request makes
the outstation emit a larger response, and the larger response must be delivered toward the master
so the WAN-visible size actually changes. **No DIRECT OPERATE. Software outstation only.**

## Why this needs per-flow TCP state (the hard part)

Inserting `k` bytes into the request at sequence `s` means every subsequent master→outstation byte
is shifted by `+k`. The oracle/data-plane must therefore maintain, per flow:

1. **Request-side cumulative sequence delta** `Δ_req`: after inserting `k` bytes, add `k` to
   `Δ_req`; every later master→outstation segment has `seq += Δ_req` on the WAN side.
2. **Outstation-ACK translation back to the master's original space**: the outstation ACKs the
   *expanded* sequence numbers; translate `ack -= Δ_req` before forwarding to the master, so the
   unmodified master sees ACKs for the bytes **it** actually sent.
3. **Response-side delta** `Δ_resp` (symmetric): if the response is also rewritten/enlarged toward
   the master, track and translate the reverse direction the same way.
4. **Exact transaction + SELECT/OPERATE pairing**: the OPERATE must carry the identical (expanded)
   CROB set as its SELECT, or the outstation rejects it — the decoy set is fixed per transaction.
5. **Retransmission / duplicate / FIN / RST / timeout / tuple-reuse**: a retransmit of a
   pre-insertion segment must get the same `Δ`; deltas reset on connection teardown/reuse.

This is exactly the **per-flow 32-bit sequence-translation state** the READ primitive avoids, and
the reason the upstream `NO_GO` analysis flags size/count closure as needing store-and-forward-like
state. The oracle's job is to determine whether a **bounded, packet-parsable** version is
sufficient (a single per-flow 32-bit delta register + ACK fix-up), or whether it truly needs
reassembly.

## Oracle deliverables (offline, bidirectional)

An offline oracle over a captured/synthesized SELECT→OPERATE exchange that models all of the above
and verifies:
- The master still receives correct confirmation for its real CROBs.
- The outstation accepts the expanded SELECT and the matching OPERATE (exact CROB-set pairing).
- Decoy CROBs address reserved indices and **cannot** operate a physical output.
- `Δ_req`/`Δ_resp` bookkeeping keeps both endpoints' sequence spaces consistent across
  retransmits/dupes/teardown.
- The WAN-visible request and response sizes reach the public target `S`.
- **Whether an unmodified master accepts additional inert CROB status objects** in the response — if
  it rejects them, preserve the exact packet + application evidence and identify the precise
  response-validation rule. **Do not** strip the extra objects before the WAN-visible output (that
  would remove the obfuscation).

Then a standalone Tofino compile probe (per-flow seq-delta register + ACK translation) — begun
without further design authorization once the oracle works.

## Boundary

Software outstations and reserved decoy indices only; no DIRECT OPERATE; no physical control. The
physical SEL-751 stays untouched. The ION7550 (Case-B, connected for testing) is READ-only and is
**not** an SBO target (Case-B has no separate-ACK CLRT and no relay output to exercise here).

## Status

STARTED — design fixed. Oracle implementation is the next artifact.
