# Architecture Review

Owner: `architecture_lane` conceptually, integrated by the coordinator after interruption

Scope: current testbed only, no extra host/SmartNIC/gateway/relay
Status: conditional recommendation

## Bottom line

The only architecture that plausibly satisfies the new size-normalization phase on the existing testbed is fixed-volume AEAD cellization with:

- a trusted master-side shim on Vision;
- a trusted relay-edge shim on the UFISpace control CPU if and only if the `bf_kpkt`/`ens1` path can be proven as a real punt/reinject boundary;
- the existing RRC/BOR timing defense kept separate from the cell layer;
- no P4 cryptography.

If the CPU punt/reinject path cannot be proven, the correct result is not a weaker resegmentation design; it is impossibility under the current constraints.

## Evidence-backed reasoning

- `defense4/README.md:31-41` and the frozen evidence bundle show the current topology is one switch between Vision and the SEL/ION relay leg, with internal loopbacks only.
- `defense4/CLAIMS.md:30-40` explicitly says total DNP3 length is not hidden in the historical result.
- Live read-only checks show Vision and the switch CPU both have Python, OpenSSL, and AEAD-capable crypto libraries, but `wg` is missing on both endpoints.
- Live read-only checks also show the switch CPU has a real `bf_kpkt` packet interface (`ens1`) and a live switch process, but the codebase does not already expose an obvious CPU punt/reinject path.

## Compared architectures

1. **Fixed-volume AEAD cell tunnel**
   - Best security fit.
   - Requires fixed outer cell size/count and encrypted length/type metadata.
   - Can satisfy the observer model only if the relay-edge boundary is real.

2. **Standard secure tunnel with padding shims**
   - Acceptable only as a fallback.
   - `wg` is not installed on either endpoint, so this is not a ready path today.
   - Ordinary tunnels without fixed inner records still leak size.

3. **P4-only shaping or resegmentation**
   - Rejected.
   - The mission directive and the frozen evidence already rule this out as real size hiding.

## Feasibility blocker

The decisive blocker is still the CPU path:

- The switch CPU exists.
- The packet interface exists.
- The proof that it can act as an endpoint-transparent decapsulation boundary does not yet exist.

That is the line between a viable design and an impossible one.
