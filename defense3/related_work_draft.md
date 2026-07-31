# Related Work (draft)

*Prose Related Work section for the Defense 3 paper. Citations are Pandoc/BibLaTeX
`[@citekey]` keys resolving to `references.bib`. ~620 words.*

---

## Related Work

**ICS device and protocol fingerprinting.** Passive fingerprinting of networked devices from
timing metadata dates to Kohno et al.'s use of microscopic clock skew to identify remote hosts
[@kohno2005remote], and was formalized for protocol implementations by Shu and Lee
[@shu2006fingerprint]. In the embedded and industrial setting, GTID showed that inter-arrival-time
distributions identify both a device and its *type* [@radhakrishnan2014gtid], and Jeon et al.
fingerprinted SCADA roles on real critical-infrastructure captures without deep packet inspection
[@jeon2016passive]. Our threat model is Formby et al.'s cross-layer response time (CLRT): the
interval between an outstation's TCP acknowledgment and its DNP3 response captures the device's
processing time and yields a stable, hard-to-forge fingerprint that classifies substation devices
with 92--99% accuracy [@formby2016control]. Prior work exposes this leak; to our knowledge Defense
3 is the first *defense* against it, releasing the pure ACK at a predetermined offset so the
device's processing time never enters a measurable interval.

**In-network obfuscation on programmable data planes.** Programmable switches (P4/Tofino) now host
non-trivial security functions at line rate [@kfoury2021p4survey], from volumetric-attack
identification [@ding2021inddos] to network-layer anonymity such as HORNET
[@chen2015hornet], TARANET's constant-rate shaping via packet splitting [@chen2018taranet], and
PINOT's in-switch client-address encryption [@wang2020pinot]. The closest system is Ditto, which
shapes WAN traffic to a fixed size/timing pattern entirely in the data plane using padding, chaff
packets, and priority-queue scheduling, at 100 Gb/s and with no end-host changes
[@meier2022ditto]. Defense 3 adopts this line-rate, host-transparent stance and the same
queue/recirculation toolkit, but differs in target and cost: Ditto obfuscates the *aggregate* size,
volume, and timing of a whole link by adding traffic, whereas Defense 3 leaves every DNP3 byte and
packet intact and normalizes exactly one *device-specific* observable — the ACK-to-response cross-layer
interval — at the cost of a single held acknowledgment.

**Website- and flow-fingerprinting defenses.** A large body of work hides encrypted-traffic
patterns from a passive observer. Traffic morphing reshapes packet-size distributions
[@wright2009morphing]; BuFLO and its congestion-sensitive successor show that only rigid
constant-size, constant-rate transmission resists analysis, at substantial overhead
[@dyer2012peekaboo; @cai2014csbuflo]; WTF-PAD injects adaptive dummy packets at zero added latency
[@juarez2016wtfpad]; and Walkie-Talkie molds bursts so distinct pages collide
[@wang2017walkietalkie]. Deep Fingerprinting later defeated padding-only defenses with a CNN,
demonstrating that masking a feature that remains present is brittle [@sirinam2018df]. These
defenses are host- or proxy-based, per-flow, and dominated by packet-size obfuscation; Defense 3
instead runs in-network on one device-timing feature and *structurally removes* it rather than
statistically masking it.

**Timing side channels and timing-only defenses.** Timing alone is a first-class leakage channel:
inter-keystroke timing over SSH recovers typed content [@song2001timing], and Feghhi and Leith
mount a traffic-analysis attack using *only* timing, with no size information [@feghhi2016timing] —
which is precisely why a timing-only countermeasure is a necessary, non-redundant contribution.
Dependent link padding bounds timing leakage by transmitting on a content-independent schedule
[@wang2008dependent], and in the smart-home domain, rate/timing patterns of encrypted device
traffic betray user activity, motivating rate-shaping and stochastic traffic padding
[@apthorpe2017spying; @apthorpe2019stp]. Defense 3 is a timing-channel normalizer in this
tradition, but exploits the specific structure of the CLRT leak — its confinement to one cross-layer
interval — to neutralize it deterministically by scheduling a single packet's release, avoiding the
continuous cost of constant-rate schedules or cover traffic.

**ICS defensive context.** Reconnaissance and fingerprinting are recognized early-stage steps in
DNP3 attack taxonomies [@east2009taxonomy], and existing ICS defenses are largely detective — state-
and specification-based intrusion detection for Modbus/DNP3 [@fovino2010modbus; @lin2013bro] and
broader process-control detection-and-response frameworks [@cardenas2011attacks] — while
cryptographic protection remains infeasible on much legacy field equipment [@sridhar2012cyber].
Defense 3 is complementary and proactive: it denies the attacker a passive fingerprint upstream of
any intrusion, transparently in the network, without modifying the relay, the DNP3 payload, or
introducing key management.
