# Objection Ledger — Defense 3

For each load-bearing claim: **who in the literature would push back**, the **objection**, and
**our response**. Citekeys resolve to `references.bib`. This is adversarial pre-review input for a
power/security venue (TDSC, TSG, EuroS&P, NDSS).

---

### Claim 1 — CLRT is a real, exploitable device fingerprint (so a defense is warranted)

- **Who pushes back / basis.** A skeptic drawing on Formby et al. themselves [@formby2016control]
  and on network-timing-variance arguments (e.g., the queuing-delay caveats in
  [@radhakrishnan2014gtid]) could argue CLRT is an artifact of one lightly-loaded substation and
  would wash out under realistic jitter, path changes, or cross-traffic — making the leak, and thus
  the defense, marginal.
- **Response.** Formby explicitly measured CLRT stability across two substations and over a year,
  and showed network architecture has only minor effect because ICS links are over-provisioned and
  polling is periodic, so the ACK and response traverse identical paths with near-constant queuing
  [@formby2016control]. Independent OT-fingerprinting results reach the same conclusion from
  different features [@radhakrishnan2014gtid; @jeon2016passive], and timing-only attacks succeed
  even without size information [@feghhi2016timing]. Our own physical-relay measurements (SEL-751)
  reproduce a tight steady-state CLRT, confirming the channel is real on hardware, not just in the
  original capture corpus.

### Claim 2 — Holding the pure ACK a predetermined delay `D`, released independently of the RESPONSE, hides the CLRT

- **Who pushes back / basis.** A Deep-Fingerprinting-style adversary [@sirinam2018df] and the
  "padding that leaves the feature present is brittle" critique would object: delaying the ACK just
  *shifts* the interval; a CNN or a re-derived feature (e.g., READ→ACK, or ACK→RESPONSE sign/ordering)
  could recover the device from the residual timing, exactly as DF recovered pages under WTF-PAD.
- **Response.** The distinction is between *masking* and *structural removal*. WTF-PAD/BuFLO leave
  the discriminative feature latent under added noise [@juarez2016wtfpad; @dyer2012peekaboo], which
  is what DF exploits [@sirinam2018df]. Here, once the ACK is released at `t_ACK + D` on a
  switch-generated schedule rather than on the device's response, the processing time `c` no longer
  appears in *any* inter-packet interval whenever `D > c`: READ→ACK becomes `a + D` (a constant,
  device-independent), and the response's own arrival carries no ACK-relative timing. This is the
  content-independent-release principle of dependent link padding [@wang2008dependent], applied to a
  single packet. The honest caveat we carry in the paper: `D` must exceed the device's CLRT (a
  mis-set `D < c` degrades to information-preserving masking), and the release tail must not let the
  response overtake the held ACK — both are design constraints we enforce and measure, not
  assumptions.

### Claim 3 — The transform is byte-preserving (no DNP3 field/CRC/length modification, no host change)

- **Who pushes back / basis.** A reviewer familiar with in-network shapers that *add* traffic —
  Ditto's padding/chaff [@meier2022ditto], HORNET's uniform-size padding [@chen2015hornet],
  TARANET's packet splitting [@chen2018taranet], IoT rate-shaping/cover traffic
  [@apthorpe2019stp] — might doubt that a switch can alter timing without touching bytes, or object
  that TCP semantics (seq/ack, retransmission, keepalives) break under a held ACK.
- **Response.** Unlike those systems, Defense 3 neither pads, splits, nor injects: it re-times the
  release of an existing, unmodified packet, so `concatenation == original` holds trivially and no
  CRC recompute or field edit occurs — consistent with the project's byte-preservation invariant and
  with PINOT's demonstration that a targeted, single-field in-switch transform needs no host
  cooperation [@wang2020pinot]. The TCP-semantics objection is real and we address it concretely: a
  held pure ACK within `D` (single-digit ms) is well inside RTO, and the known failure mode — a
  ~10 s TCP keepalive that also qualifies as a pure ACK and can silently disarm the hold — is fixed
  by tightening the ACK classifier (sequence-number match), which we document as a required
  correctness fix.

### Claim 4 — The leak is not merely relocated: the defense *compresses/collapses* the CLRT distribution

- **Who pushes back / basis.** The strongest internal objection (and one our own design study
  raised): an entropy-preserving-bijection argument. If `D` sits below the native CLRT, a delay is
  an invertible shift that moves entropy from ACK→RESPONSE into READ→ACK rather than destroying it —
  i.e., a mutual-information reviewer would demand evidence of *reduced* leakage, not relocation,
  echoing the WF-defense overhead/security trade-off bounds [@cai2014csbuflo; @dyer2012peekaboo].
- **Response.** We report the observable's entropy, not just its mean. For `D` exceeding the
  measured CLRT the ACK-relative interval collapses toward a constant (the switch's deterministic
  release), driving observer mutual information on the CLRT feature toward zero — the deterministic
  analogue of the bounded-leakage guarantee of dependent link padding [@wang2008dependent] and the
  feature-elimination goal that padding-only WF defenses fail to reach [@sirinam2018df]. We state the
  boundary honestly: at small `D` the transform is near-bijective and only *shifts* the leak (this is
  a documented failure region, and the reason `t_READ`-anchoring is explored as the stronger
  variant); the compression claim is made only in the `D > c` regime, with measured entropy as
  evidence rather than asserted.

### Claim 5 — Delaying the ACK beats the naive alternative of delaying the RESPONSE

- **Who pushes back / basis.** A constant-rate purist [@dyer2012peekaboo; @chen2018taranet] would
  argue the clean fix is to normalize the *response* release (or shape the whole flow to a fixed
  schedule), and that ACK-delay is a fragile point solution.
- **Response.** Delaying the response normalizes ACK→RESPONSE but leaves READ→ACK — the second
  cross-layer interval Formby's method can also read — and, more importantly, forces added latency on
  the *data-bearing* packet, degrading control-loop responsiveness. Delaying the pure ACK moves the
  latency onto a non-data packet and, because the ACK is released on a switch-generated deadline,
  makes the device's processing time absent from every observable rather than merely equalized in
  one. This is the same rationale by which targeted, minimal in-network transforms
  [@wang2020pinot; @meier2022ditto] are preferred over whole-flow constant-rate shaping
  [@chen2018taranet], which pays continuous overhead and (per Ditto's own comparison) still needs
  end-host support to shape per flow. The fair caveat: ACK-delay addresses the *CLRT/timing* channel
  only — it does not touch response *size* or ACK-*mode* residuals, which remain out of scope and are
  named as such.

---

**Standing caveats the paper must keep visible (bad news up front).** (i) `D` must exceed the
device's native CLRT or the defense degrades to an invertible shift; (ii) the ACK classifier must
exclude TCP keepalives or the hold silently disarms; (iii) the claim is a *timing/CLRT* defense,
not size, ACK-mode, or anonymity; (iv) evidence is a single physical relay (SEL-751) — multi-device
generalization is future work.
