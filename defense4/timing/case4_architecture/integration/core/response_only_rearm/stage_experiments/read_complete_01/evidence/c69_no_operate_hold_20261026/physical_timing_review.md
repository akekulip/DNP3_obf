# Fixed J retirement: what SER and unsolicited reporting mean

Source: Formby et al., NDSS 2016, section IV-A/B, Figure 14 and the page9 experiment discussion:
https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf

SER is the device's Sequential Events Recorder: a record of when a configured event occurred. An unsolicited response reports events without waiting for a master poll. A report can contain an event timestamp; event time and report arrival time are different measurements. SEL also exposes proprietary SER reporting; a generic DNP3 unsolicited report is not synonymous with that separate protocol.

Formby defines the arrival-based estimate as notification-arrival time minus observed command time, and the SER estimate as event timestamp minus observed command time. The experiment used synchronized clocks. Their reported physical-fingerprinting results used SER timestamps after their unsolicited-arrival estimate produced no usable results. Ordinary successful CROB replies are not physical actuation timestamps.

For an upstream observer, holding a command shifts when the actual event and its generated timestamp occur. Thus the SER estimate includes actual command hold H plus device/event time, path delay and clock offset. Downstream of the switch the command is observed after that hold, so the prior hold is absent from the interval. Delaying an ACK changes neither endpoint. Delaying a report changes its packet-arrival estimate but not its embedded timestamp.

The c68 configuration has fixed op_j=2400000ns, not the historical per-command random-J proposal. Its constant component shifts distributions without removing their centered shape. A classifier trained on unshifted fixed bins may fail after a shift; that does not establish suppression against a recalibrated classifier. Actual switch scheduling may add variation, but incidental unmeasured jitter is not a demonstrated defense. A timing-only mechanism can affect an SER measurement by delaying the command even while preserving every response byte; the earlier contrary blanket review statement was corrected.

Read-only review of all six retained c68 blocks found22 master records with1852 solicited responses, function0x81, and timestamp-free object groups1v2/30v1/10v2/30v4/12v1. No unsolicited0x82 or timestamped physical-event channel was demonstrated. This evidence cannot establish physical-fingerprint suppression, nor the cause of prior OPERATE TIMEOUT failures.

The user's decision is to remove current fixed J and its dedicated resources, keep common ACK/response timing, preserve Git history/experimental records, and stop at offline compile/model verification. Randomized J, unsolicited/SER support, clock/timestamp rewriting and new physical instrumentation are outside this task.
