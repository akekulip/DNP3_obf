# Formby et al., read in full — and what it means for our positioning

Source: David Formby, Preethi Srinivasan, Andrew Leonard, Jonathan Rogers, Raheem Beyah,
"Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems",
NDSS 2016. Read from the publisher's PDF at
`ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf`,
text extracted locally with `pdftotext -layout`. Sections IV-A, IV-B, the Figure 14 timing
definition and the page-9 experimental discussion were read; quotations below are verbatim.

This replaces the abstract-only reading of 2026-09-07, which was flagged as such at the time.

---

## 1. The two methods

**Method 1, cross-layer response times.** Addresses "the data acquisition half of SCADA systems
by leveraging the interaction between regular polling of measurement data". The device "is still
going to go through the same process of parsing the data request, retrieving the measurement from
memory, and sending the response", and because of "limited processing power and fixed CPU load
CLRTs can be leveraged to identify ICS device types". This is a **device-type** fingerprint built
from the response time of a poll. It is the feature our read lane normalizes.

**Method 2, physical fingerprinting.** Addresses "the control half of SCADA systems by
fingerprinting physical devices based on their unique physical properties", using **operation
times** governed by the electromagnetic force in a solenoid coil (their Equation 5). The devices
fingerprinted are two vendors' **latching relays**, driven by an SEL-751A acting as the DNP3
outstation — the same relay model as our testbed, in a different role.

## 2. How Method 2 measures an operation time: Figure 14's two definitions

> When a breaker or relay responds to an operate command from the master, an event change is
> observed at the slave device. With unsolicited responses enabled in the slave device, it
> asynchronously responds back with a message on an event change, which can be observed with a
> network tap to calculate the operation time. The response can also contain a sequence of event
> recorder (SER) timestamp indicating the time that the event occurred. Therefore, operation
> times can be estimated based on two different methods:
>
> 1. **Unsolicited Response Timestamps** — Calculated by the OS at the tap point by taking the
>    difference between the time at which the command was observed and the time at which the
>    response was observed. `m = t3 − t1`
> 2. **SER Response Timestamps** — Calculated from the difference between the time at which the
>    command was observed at the tap point and the application layer event timestamp.
>    `m = t2 − t1`

So definition 1 is a **packet-arrival** difference and definition 2 is a **packet-arrival minus
an application-payload timestamp**. The SEL-751A "supports ... a fast SER protocol which
timestamps events with millisecond resolution".

## 3. The reported result uses SER, because the arrival-time method failed

From the page-9 experimental discussion, verbatim:

> The commands and responses were recorded at the tap point and operation times were calculated
> using both the unsolicited response method and SER based method. **The unsolicited response
> method did not produce any usable results, so the SER method results are described below and
> retained as the physical fingerprint.**

The results that follow are all SER-based: close-operation times of 16 to 38 ms for Vendor 1 and
14 to 33 ms for Vendor 2 (Figure 17a), a feed-forward neural network levelling off near 86 per
cent and a naive Bayes classifier near 92 per cent (Figure 18), and open-operation times that
show "little variation between the two, thus preventing these times from being used for accurate
device fingerprinting" (Figure 17b). Figure 19 distinguishes open from close operations on one
device. 2,500 open and close commands were issued with 20 s idle between operations.

## 4. What this means for our mechanism, stated plainly

**The physical-operation-time fingerprint as reported is out of reach of a timing-only defense.**
It is computed from a timestamp **inside the application payload**, written by the outstation's
own event recorder. Our mechanism moves packets in time and changes no byte, so it cannot alter
an SER timestamp. Delaying the packet that carries it changes `t2 − t1` only through `t1`, the
command observation, which the mechanism does not delay toward the relay in a way the master can
see, and not at all through the SER value.

**The one variant our defense could affect is the one that failed.** Definition 1, `t3 − t1`, is
a packet-arrival difference and is exactly the kind of quantity our release schedule governs.
Formby reports it produced no usable results. So there is no established packet-timing physical
fingerprint for us to suppress, and none to claim credit for suppressing.

**Our traffic does not contain the channel at all.** Measured over all 132 `campaign_v1`
captures: **zero unsolicited responses** (function 0x82; the only functions present are 1, 3, 4
and 129), and the only objects present are Group 10 Variation 2 (binary output status, 105,600
occurrences) and Group 12 Variation 1 (CROB, 21,120). **No time-bearing object of any kind
appears** — no g2v2/v3, no g11v2, no g13v2, no g50 or g51 time-and-date or CTO objects. The IIN
is the constant `0x8000` in all 63,360 responses. So no physical-event timestamp is present in
the evaluated traffic, unsolicited reporting was not enabled, and there is nothing of that kind
for the mechanism to have affected in either direction.

**Their target is a device type; ours is a transaction class.** Formby's methods classify device
types, in Method 2 two vendors' latching relays. Our classifier separates READ, SELECT and
OPERATE on one outstation. We suppress a feature their Method 1 uses, without showing that two
devices become indistinguishable.

**No SELECT-specific result exists in their paper.** Method 1 uses polls; Method 2 uses open and
close commands. Nothing in Section IV, Figure 14, Figures 17 to 19 or the page-9 discussion
reports a select-before-operate result, so none may be attributed to them.

## 5. Three claims that must stay separate

| claim | ours? | basis |
|---|---|---|
| **CLRT normalization.** The master-visible acknowledgment-to-response interval of a poll or a SELECT is replaced by a configured value | yes | the common-anchor schedule plus the measured residual; this is Formby's Method 1 feature |
| **OPERATE protocol-response timing.** The master-visible OPERATE response-to-acknowledgment interval sits at the configured value | yes, as our own observable | request-anchored schedule; **not** a Formby feature, and not a correlate of one |
| **Suppression of physical-operation-time fingerprints** | **no** | the reported fingerprint is SER-payload-based; our mechanism changes no payload; the arrival-time variant produced no usable results; and our traffic carries no such timestamp |

## 6. The manuscript sentence that has to change

`sections/07_related_work.tex` currently reads, of the control path, that we "address the
master-visible correlate of the physical operation-time feature Formby et al. measured on a
physical outstation, i.e., the OPERATE response-to-ACK interval".

**"Correlate" is not defensible.** No correlation was measured, the two quantities are computed
from different information — one from a payload timestamp, the other from packet arrivals — and
the arrival-based variant of their feature is the one they report as unusable. Patch item P7
supplies replacement wording that keeps the three claims of §5 apart.
