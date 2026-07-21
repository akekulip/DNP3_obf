# FORMBY_SOURCE_MAP.md — Primary-source map of the device-fingerprinting attack

Source-grounding for the DNP3 timing-defense paper (Part 2). Every claim below is drawn
**only** from the primary PDF, with the section and printed page number and a short quoted
passage or accurate paraphrase. No project memory was used. Where a detail is genuinely
absent, the entry says **"not stated in the paper."**

**Paper (verified from the PDF itself):**
- Title: *Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems*
- Authors: David Formby, Preethi Srinivasan, Andrew Leonard, Jonathan Rogers, Raheem Beyah (Georgia Institute of Technology)
- Venue / year: **NDSS '16** (Network and Distributed System Security Symposium), 21–24 Feb 2016, San Diego, CA. Copyright 2016 Internet Society, ISBN 1-891562-41-X. DOI 10.14722/ndss.2016.23142 (title page, p.1).
- Two methods: **Method 1 = Cross-Layer Response Times (CLRT)** — the attack our Part-2 timing defense targets; **Method 2 = Physical Fingerprinting** (operation times), plus a white/black/gray-box synthetic-fingerprint extension.

Terminology note (locked project terms used below): **Case A** = separate-ACK device (SEL-751), the only case with a defined CLRT; **Case B** = combined-ACK device (AB1400, ION7550), no standalone ACK; **Defense 1/2** = the ACK-hold / response-hold. In Formby's own terms the fingerprinted device is the **IED** (outstation/slave) and the poller is the **RTU / SCADA master**.

---

## 1. Exact CLRT definition (the precise quantity, how computed, and the term used)

**Section IV-A "Method 1: Cross-layer Response Times" + Fig. 3, p.4.** The paper uses the literal
term **verbatim**: "The timing diagram of how this measurement, which **we call the cross-layer
response time (CLRT)**, would be taken in a typical SCADA network is illustrated in Figure 3."
So the label **"cross-layer response time / CLRT" is the paper's own**, not ours.

Precise quantity and computation (Section IV-A, p.4): the method leverages "the interaction between
regular polling of measurement data at the application layer with acknowledgments at the TCP layer
to get an estimate of the time a device takes to process the request." Crucially: "It should be
noted that the CLRT measurement is **based on the time between two consecutive packets from the same
source to the same destination**, it is **independent of the round trip time between the two nodes**."

From **Fig. 3 ("Measurement of cross-layer response time," p.4)**: at a network tap between RTU and
IED, the RTU sends a **SCADA Read**; the IED replies first with a **TCP ACK**, then with a **SCADA
Response**; the label **"IED processing time (m)"** marks the interval. The two "consecutive packets
from the same source to the same destination" are therefore the IED's **TCP ACK** and the IED's
**SCADA Response** (both IED→RTU). **CLRT = t(SCADA Response) − t(TCP ACK)** as observed at the tap
— i.e. the ACK→response gap. "Cross-layer" = it mixes a transport-layer packet (TCP ACK) with an
application-layer packet (SCADA Response).

Fingerprint/signature definition (Section IV-A, p.4, **Equation 1**): "The fingerprint signature is
defined by a vector of bin counts from a histogram of CLRTs where the final bin includes all values
greater than a heuristic threshold." Formally, for a set `M` of CLRT measurements from a device,
`B` bins/features, and heuristic threshold `H` ("an estimate of the global maximum that CLRT
measurements should ever be"), with thresholds `t_i = i·H/(B−1)`, each signature element is
`s_j = |{m : t_{j−1} ≤ m < t_j, m ∈ M}|` for `0 < j < B`, and `s_j = |{m : m > H, m ∈ M}|` for
`j = B`. **The fingerprint is thus a histogram (distribution) of many CLRT samples, not a single
ACK→response measurement.**

## 2. The separate pure-ACK assumption

**Yes — the feature relies on a standalone TCP ACK that arrives before the application response.**
Stated at three points:
- Abstract (p.1): "The first approach ... uses the interaction between the **application layer
  responses and transport layer acknowledgments** ..."
- Fig. 3 (p.4) draws the **TCP ACK as its own packet**, emitted by the IED **before** the SCADA
  Response.
- The assumption is made explicit as a stated requirement in **Section VI-C "Limitations," p.13**:
  "the SCADA protocol must sit on top of a TCP implementation that uses at least a minimum amount of
  **'quick ACKs' (immediately ACKing a packet instead of delaying in the hopes of piggybacking)**.
  ... every vendor in the observed power substation dataset used quick ACKs for every packet,
  presumably to reduce latency. Therefore, the amount of quick ACKs used by a device would determine
  how quickly a fingerprint could be generated."

That is exactly the separate-ACK requirement: the device must send an immediate, standalone TCP ACK
rather than delaying and piggybacking it onto the response. This is the property that defines our
**Case A**.

## 3. Packet-matching rules (how request, ACK, and response are paired)

The paper gives only a **coarse** rule, not a detailed algorithm.
- **Section IV-A, p.4:** the measurement is "the time between **two consecutive packets from the
  same source to the same destination**." The paired packets are the IED's TCP ACK and the IED's
  SCADA Response (same source = IED, same destination = RTU), as drawn in Fig. 3.
- The triggering request is a **polling read**: **Section IV-A-2, p.5** — "CLRT measurements were
  taken from **DNP3 polling requests for event data**."
- Independence from RTT is asserted (Section IV-A, p.4), i.e. matching is done on the intra-source
  inter-packet gap on the return path, not on a request→response round trip.

**Not stated in the paper:** an explicit low-level matching algorithm (e.g. TCP sequence/ack-number
correlation of the Read to its ACK and Response, handling of retransmissions, or how multiple
outstanding requests are disambiguated). The pairing is only illustrated (Fig. 3) and described as
"two consecutive packets from the same source to the same destination."

## 4. Feature extraction (what is computed, over what)

**Section IV-A-2, p.5 and Section IV-A-3, p.6.** Two feature vectors are used:
- "a more complex approach using the **arrays of bin counts as defined in Equation 1**" (the CLRT
  histogram), and
- "a simple approach using arrays containing only the **mean and variance** for each time slice."
(Section IV-A-2, p.5.)

CLRT samples are aggregated over **time slices**: "summarized by dividing all measurements into time
slices (e.g. one hour, or one day) and calculating means, variances, and **200-bin histograms** for
each time slice" (p.5). Grouping is **per device (per IP address)**: e.g. Fig. 6a plots "the mean and
variances of the CLRT measurements for **one IP address** over the course of one day" (p.6). The
unsupervised GMM used "a **signature vector consisting of means and variances** with a time slice of
one day" (Section IV-A-3, p.7).

The **only** feature of Method 1 is the CLRT (and its histogram / mean+variance summaries). No other
timing feature is added in Method 1. (Method 2, physical fingerprinting, separately uses device
**operation times** from SER/unsolicited timestamps, p.8 — a different feature, not CLRT.)

## 5. Classifier design (model, training/testing, thresholds)

**Section IV-A-3, pp.6–7.** Three learners are used on the CLRT features:
- **Feed-forward artificial neural network (FF-ANN), one hidden layer, back-propagation** — "This
  algorithm was chosen due to its popularity and previous use in related work [18]" (p.6). Samples
  "randomly divided using **75% as training data and 25% as testing data**" (p.6).
- **Multinomial naïve Bayes** — "we also attempted supervised learning using one of the simplest
  algorithms ... a multinomial naïve Bayes classifier"; for a real-deployment simulation "the
  **training data was taken from the beginning of the capture and the test data was taken from the
  following 1000 detection time windows**" (p.6).
- **Gaussian Mixture Models (GMM), full covariance, unsupervised** — signature = means and variances,
  one-day time slice; achieved "an accuracy of **92.86%**, a precision of **0.891**, and a recall of
  **0.956**" (p.7).

Metrics: accuracy, precision, recall (**Equations 2, 3, 4, p.6**), reported as average and minimum
across classes. Headline results: FF-ANN reaches "**average accuracy of 93%**" with 5-minute slices
(p.6); overall the CLRT method achieved accuracies "**as high as 99% in some cases**" (Section VI-A,
p.11).

**Thresholds:** the only threshold defined is the **feature-extraction** heuristic `H` in Equation 1
("an estimate of the global maximum that CLRT measurements should ever be," p.4). **A classifier
decision threshold is not stated in the paper** (classification is by the ML models above, not a
hand-set cutoff).

## 6. Measurement window (timing window, packet count, session boundaries)

**Sections IV-A-2/3, pp.5–6.** CLRTs are aggregated into **time slices ranging from one day down to
5 minutes**: "even with time slices as small as **5 minutes** an average accuracy of 93% can be
achieved. Some devices at this substation were being polled only **once every 2 minutes**, so the
5 minute detection time is roughly equivalent to a **decision after only two samples**" (p.6). So the
window is a **time interval**, and the number of CLRT samples it contains depends on the polling rate
(as few as ~2 samples per 5-minute decision).

For the Bayes real-deployment test, "the test data was taken from the following **1000 detection time
windows**" and both training time and detection time were varied (Figs. 8a/8b, p.6).

**Session boundaries:** grouping is by **device (IP address)** and **time slice**; the paper does not
describe TCP-session-boundary handling for CLRT aggregation — **not stated in the paper** beyond
per-IP, per-time-slice grouping.

## 7. Device population (count, types, SEL/DNP3 relevance, dataset size)

**Section III, p.3 and Section IV-A-2, p.5.**
- Utility scope (Section III, p.3): the source utility covers "an area of **2800 square miles with
  35 substations**." Footnote 1 (p.4): "The utility whose network we monitored is small and part of a
  Utility Cooperative, and the control actions are not representative of larger, more modern,
  utilities."
- Primary dataset (Section IV-A-2, p.5): "network traffic (**~20GB**) was captured from a live power
  substation with **roughly 130 devices running the DNP3 protocol** over the span of **five months**"
  (first substation, Fig. 4). "Then over a year later, one month more of data was captured from the
  same substation" after a router/IP change and increased polling.
- Second substation (p.5): "a brief overnight capture was collected from another substation ...
  (**roughly 80 devices using DNP3**, illustrated in Figure 5)."
- Device **types** in the CLRT experiments are **anonymized vendor/type labels**: Vendor A Type 1a,
  Vendor A Type 1b, Vendor A Type 2, Vendor B, Vendor C (Fig. 6a/6b, p.6) — i.e. **5 device-type
  classes**. The company "provided a list of all device IP addresses on the network organized by
  location, device type, and device software configuration" (p.5). Appendix A (p.14–15) further shows
  CLRT can separate **software configurations** of "the same exact IED," using "approximately **700
  CLRT measurements** ... for each of three cases."

**SEL / DNP3 relevance:** the **SEL-751A** appears **only in Method 2 (physical fingerprinting) lab
experiments**, not in the CLRT dataset. Section IV-B-2, p.8: the lab setup used "a DNP3 master from a
C++ open source DNP3 implementation (**OpenDNP3 version 2.0**), an **SEL-751A DNP3 slave** and two
latching relays." Section IV-B-2, p.9: "The **SEL-751A IED is a feeder protection relay supporting
Modbus, DNP3, IEC61850** protocol, time synchronization based on SNTP, and a fast SER protocol which
timestamps events with millisecond resolution." The CLRT (Method 1) large-scale results are on the
anonymized Vendor A/B/C devices, **not** a labeled SEL-751.

## 8. Limitations the paper states

**Section VI-C "Limitations," pp.13–14** (plus VI-A):
- CLRT method "first requires a SCADA protocol using **'Read' and 'Response' messages**" (p.13).
- CLRT requires TCP with **quick ACKs** (separate immediate ACK, not delayed/piggybacked); a device
  that piggybacks would slow or impede fingerprint generation (p.13; quoted in §2 and §9).
- Physical method (Method 2) "requires high resolution timing of when operations take place, so it
  must be used with protocols that include **operation timestamps** in their responses. Not all SCADA
  protocols support this functionality" (p.13).
- Requiring timestamps "is a limitation in the sense that it can make it easier for an adversary to
  ... forge the device fingerprints, but it can also be a defensive strength in another. If the
  network traffic is encrypted, an adversary would have to resort to white box modeling ..." (p.13).
- High accuracies "99% and 92% ... would result in an impractical number of false alarms (1% and 8%)
  if each mis-classification was treated directly as an intrusion," so the method must be paired with
  **IDS alert-correlation** work rather than used as a stand-alone IDS (Section VI-A, p.13).
- White-box synthetic modeling requires detailed mechanical construction data, "may be difficult to
  obtain ... due to intellectual property concerns," and suffers non-parametric/structural modeling
  error (Section VI-C-1, pp.13–14).
- Cross-network generalization is imperfect: fingerprints learned on one substation and tested on a
  different one "seemed to level off around **90%**" accuracy (Section IV-A, p.7).
- Dataset representativeness caveat: the monitored utility is "small ... not representative of larger,
  more modern, utilities" (footnote 1, p.4).

## 9. What happens when the ACK and response are combined (directly relevant to Case B)

**The paper addresses this only briefly, and does not implement or measure the combined-ACK case.**
The single relevant passage is **Section VI-C "Limitations," p.13**:

> "the SCADA protocol must sit on top of a TCP implementation that uses at least a minimum amount of
> 'quick ACKs' (immediately ACKing a packet instead of delaying **in the hopes of piggybacking**).
> For example, modern Linux systems use quick ACKs to accelerate TCP slow start ... but **every
> vendor in the observed power substation dataset used quick ACKs for every packet**, presumably to
> reduce latency. **Therefore, the amount of quick ACKs used by a device would determine how quickly
> a fingerprint could be generated.**"

Interpretation grounded strictly in that text: "delaying in the hopes of piggybacking" is exactly the
combined ACK+response packet of our **Case B** (AB1400/ION7550). The paper acknowledges that such a
device yields fewer (or no) separate ACK→response gaps, which "would determine how quickly a
fingerprint could be generated" — i.e. it degrades or prevents CLRT fingerprinting. But the paper
reports it **never encountered this case in its dataset** ("every vendor ... used quick ACKs for
every packet"), and it **does not define, measure, or evaluate CLRT for a combined-ACK device, and
provides no alternative handling for it.** So for combined-ACK traffic the paper offers **no CLRT
measurement** — consistent with the project's rule that CLRT is undefined for Case B.

---

## Consistency check vs our usage

Our project defines **"CLRT = ACK→response gap, Case-A / separate-ACK only."** Against the primary
source:

- **Definition — MATCH.** Formby's CLRT is "the time between two consecutive packets from the same
  source to the same destination" (Section IV-A, p.4), which per Fig. 3 is the IED's **TCP ACK → SCADA
  Response** gap. That is precisely our ACK→response gap. Our project also fingerprints the
  **outstation/IED** (SEL-751), and in Formby both the ACK and the response originate at the IED — so
  the direction (outstation→master) matches.
- **Term — MATCH.** "Cross-layer response time (CLRT)" is the **paper's own label** (p.4), not ours;
  our usage reuses the original term correctly.
- **Case-A-only restriction — MATCH.** The paper's own quick-ACK requirement (Section VI-C, p.13)
  makes the separate standalone ACK a precondition, and it does not define CLRT for the piggybacked
  (combined) case. Our restriction of CLRT to Case A is faithful to the source; it is **not** a
  strawman.

**Divergences / cautions to carry into the Phase-9 evaluation (so we do not attack a strawman):**

1. **The fingerprint is a distribution, not one gap.** Formby's classifier consumes a **histogram
   (or mean+variance) of many CLRT samples over a time slice** (Equation 1, p.4; Section IV-A-2, p.5),
   grouped per device and evaluated with FF-ANN / naïve Bayes / GMM. A faithful reproduction of "the
   Formby attack" must attack the **CLRT distribution over a window**, not a single ACK→response
   threshold. Attacking a lone-gap threshold would understate the attacker.
2. **Time-window semantics.** Formby's decision is per **time slice** (1 day → 5 min), with the sample
   count set by polling rate (as few as ~2 samples per decision, p.6). Our evaluation window and
   grouped splits should mirror this, not use per-packet random splits.
3. **Metrics differ.** Formby reports **accuracy / precision / recall** (Equations 2–4, p.6), not
   AUROC or balanced accuracy. Our Phase-9 plan adds AUROC/balanced accuracy — that is acceptable and
   stronger, but note the original headline numbers (up to 99%, GMM 92.86%) are ACC-based.
4. **SEL-751 CLRT is our application, not the paper's literal experiment.** Formby's large-scale CLRT
   results are on **anonymized Vendor A/B/C** devices; the **SEL-751A appears only in the physical
   (operation-time) Method 2** (Section IV-B-2, pp.8–9). Applying Formby's Method-1 CLRT
   feature+classifier to the SEL-751 is a **faithful application of the method**, but it is **not** a
   literal replication of a labeled-SEL-751 CLRT experiment from the paper. State this precisely in
   the paper's evaluation framing.
5. **Value context (not a definitional divergence).** Formby describes real-world CLRTs as "on the
   order of **tens or even hundreds of milliseconds**" (Section IV-A-2, p.5; Fig. 6a x-axis spans
   ~0–0.14 s). The project's SEL-751 native median (~12.9 ms, per our terminology file) sits at the
   low end of that range. This is a measured-value difference across device/setup, not a difference in
   how CLRT is defined.
6. **Tap-side, RTT-independent measurement supports in-network defense.** Because CLRT is measured at
   a passive tap as the **intra-source inter-packet gap** and is "independent of the round trip time"
   (Section IV-A, p.4), an in-network switch that reschedules the ACK vs. the response emission times
   (Defense 1 / Defense 2) directly changes the quantity the attacker measures. This is consistent
   with, and motivates, the timing-defense design.

---

## 4-line summary

1. Paper: *Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems*, Formby, Srinivasan, Leonard, Rogers, Beyah — **NDSS 2016** (Internet Society), DOI 10.14722/ndss.2016.23142.
2. It **does** use the literal term **"CLRT"** and "cross-layer response time" verbatim (Section IV-A, Fig. 3, p.4); the label is the paper's own, not ours.
3. CLRT = time between the IED's TCP ACK and its SCADA Response (the ACK→response gap, tap-measured, RTT-independent); the fingerprint is a **histogram/mean-variance distribution** over 5-min-to-1-day windows, classified by FF-ANN / naïve Bayes / GMM (up to 99% accuracy).
4. Our "CLRT = ACK→response gap, Case-A/separate-ACK only" **matches** the source (incl. the quick-ACK / no-piggyback requirement, Section VI-C p.13, which is our Case B); the only cautions are that Phase-9 must attack the CLRT **distribution over a window** (not a single gap) and that the paper's SEL-751 work is physical operation-time, so our SEL-751 CLRT is a faithful **application** of Method 1 rather than a literal replication.
