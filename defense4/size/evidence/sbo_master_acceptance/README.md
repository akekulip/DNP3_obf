# SBO master-acceptance evidence (vendored)

The decisive test for the **SBO size** axis of the joint timing+size anti-fingerprinting defense:
*does an unmodified DNP3 master accept a SELECT/OPERATE echo padded with extra inert decoy CROBs it
never selected?* This gates whether response-side CROB padding is application-feasible at all.

The test was authored and run against the real **OpenDNP3 command stack** (community build 3.1.2)
using the maintainers' `MasterTestFixture`, which drives crafted APDU response bytes directly into
`MasterCore` — no networking, so it isolates the one variable (the decoy encoding). The two cases
are vendored here as a patch against `dnp3/opendnp3` because that upstream repo is third-party and
not ours to push to.

## What the two cases prove

The master selects **only** real index 1; the echo is padded with inert decoy CROBs at valid
indices {2,3}, status SUCCESS. The decisive observable is whether the master emits the OPERATE.

- **Encoding A — decoys in a SEPARATE trailing G12V1 header → ACCEPTED.** The master ignores the
  extra header, emits OPERATE (carrying only the real index), and the real point executes with
  `CommandStatus::SUCCESS`. **→ response-side SBO size padding is feasible.**
- **Encoding B — decoys MERGED into the real header (count grown 1→N) → REJECTED.** No OPERATE is
  emitted; the real point stays in `INIT`. **→ this encoding is a bounded negative.**

## Mechanism (OpenDNP3 source, traced)

- The master positionally matches only its **own** request headers. An extra trailing header yields
  `IINBit::PARAM_ERROR` in `CommandSetOps::ProcessAny`, which is OR-ed into `IAPDUHandler::errors`
  and **never read** — so the real header still selects → OPERATE. (Encoding A accepted.)
- Growing a **matched** header's count trips `TypedCommandHeader::ApplySelectResponse`'s
  `if (commands.Count() > records.size()) return;`, dropping the whole header → `FAIL_SELECT` →
  OPERATE suppressed. (Encoding B rejected.)
- **Decoy index validity is irrelevant to the master** — it ignores extras regardless. Configured
  valid inert indices matter only (a) to avoid the *outstation*-side `OUT_OF_RANGE` that killed the
  request-side path, and (b) to make the fabricated echo byte-realistic.

## Verified result

Filter `*decoy*` on the `unittests` binary:

```
SBO-DECOY[A] ACCEPT: master emitted OPERATE after decoy-padded SELECT echo; real index 1 -> SUCCESS
SBO-DECOY[B] REJECT: no OPERATE emitted; real index 1 state=INIT summary=0
All tests passed (9 assertions in 2 test cases)
```

## The bound this establishes (carried into the paper)

Encoding A emits **two** G12V1 headers, which no native device does. So SBO-size delivers
**device-independence** (all devices normalize to the same padded form; the observer can't tell
which device) but **not covertness** (the padded echo is detectably "defended"). The native-looking
one-header form is exactly the master-rejected one. Making it both master-accepted and native-
indistinguishable would require store-and-forward re-segmentation, which the architecture forbids.
This is asymmetric with READ-size, which *is* native-looking.

## Method trap

The SBO task reports `TaskCompletion::SUCCESS` for **both** encodings (the response is well-formed).
Task-level success coexists with the control never executing in encoding B. The only correct
discriminator is whether OPERATE was emitted and the per-point `CommandPointState`.

## Caveats

- Ran against OpenDNP3 **3.1.2**; pydnp3 embeds the older ChargePoint ~2.x. The traced logic
  (`CommandSetOps` / `TypedCommandHeader` / two-pass `APDUParser`) is materially unchanged across
  2.0–3.1, so the result transfers, but the exact pydnp3 2.x master was not exercised.
- The live pydnp3 loopback session was blocked by the dev environment (SIGSTKFLT on any master↔
  outstation DNP3 link); the offline stack test above is the faithful substitute.
- The physical SEL-751's own SBO echo layout (which qualifier/header form the relay emits) is
  lab-gated and not yet confirmed.

## Files

- `TestMasterCommandRequests_sbo_decoy.patch` — the two test cases as a patch against
  `dnp3/opendnp3` `cpp/tests/unit/TestMasterCommandRequests.cpp`.
