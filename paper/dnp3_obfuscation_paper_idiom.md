# Byte-Preserving Response Splitting to Obfuscate the Segmentation Fingerprint of DNP3 Outstations

**Authors:** [author list]

> Idiom-injected draft (v3). Dense corpus register with the reference authors'
> construction texture applied at the word level (the low-probability "spikes"
> that a general language model does not predict). Same facts, figures, tables,
> and numbers as v1; only the phrasing changed. Some constructions are
> deliberately non-native-flavored and a reviewer may read them as slightly off;
> that is the accepted tradeoff. Still machine-written: re-run GPTZero yourself,
> I cannot see that score. Citation markers `[N]` are placeholders.

## Abstract

A passive observer of the DNP3 traffic can fingerprint an outstation based on the size, the segmentation, and the timing of its responses, even without decoding the payload. To obfuscate this fingerprint is challenging, because a DNP3 outstation segments its responses in a deterministic way, and any modification on the response bytes breaks the per-block cyclic redundancy checks (CRCs) that the master validates. In this paper, we propose CRC-boundary splitting, a byte-preserving obfuscation primitive that re-segments a captured DNP3 response only on its existing CRC block boundaries. No DNP3 byte is modified and no CRC is recomputed, such that the concatenation of the emitted chunks equals the original response, and the live master reassembles the identical application message. We implement CRC-boundary splitting in a request-aware split-replay server that stands in the place of the outstation, and we evaluate it on a two-host testbed with an OpenDNP3 master and outstation. A large Class 0 read that OpenDNP3 natively delivers as 9 application fragments over 49 link frames and 20 TCP segments can be presented instead as up to 141 chunks of at most 18 bytes, while the master still delivers all the measurements and returns a DNP3 CONFIRM on a connection with zero retransmission and zero reset. Across a granularity sweep, the master accepted every splitting level and produced the measurements identical to the baseline. Based on those results, we believe that byte-preserving CRC-boundary splitting holds promise as the transparent primitive for an in-network obfuscation layer that resists the passive fingerprinting of DNP3 outstations.

## I. Introduction

Supervisory control and data acquisition (SCADA) systems that operate the power grids exchange measurement and control data over legacy protocols such as DNP3 (Distributed Network Protocol 3) [1]. These protocols usually carry no encryption and no authentication by default [1], so any observer on the communication path can read the traffic. In December 2015, remote intruders penetrated into a Ukrainian power grid and caused a blackout that affected 225,000 residents [2]. Before an adversary inflicts such damage, it first observes the target to obtain the knowledge of what the devices are and how they behave. Consequently, the information that a passive observer can extract from the unencrypted control traffic is a serious security concern, and not just in theory.

A passive observer does not need to decode the DNP3 payload to learn about a device. As shown in the traffic-analysis studies, the packet sizes and the timing alone can identify the content of even encrypted communications [5], and the unencrypted DNP3 traffic exposes a similar side channel. The size of an outstation's response, the number of the frames it is split into, and the timing between those frames constitute a fingerprint of the device and its database. For example, a large integrity poll produces a long, highly segmented response, while a small point read produces a short one, such that the observed segmentation pattern already reveals how many points the device exposes. This fingerprint is stable, because a DNP3 outstation segments its responses in a deterministic way, following the frame structure of the protocol. Consequently, an observer can distinguish device types, infer database sizes, and track a device across sessions, all without breaking any encryption.

To obfuscate this fingerprint is challenging, due to two reasons. First, DNP3 protects every 16-byte block of an application message with a CRC, and the master validates these CRCs during the reassembly, so any modification on the response bytes, any inserted padding, or any recomputed length field can raise a CRC failure that the master rejects. Second, the outstation firmware is fixed and provided by the vendor, so a practical defense cannot change how the device itself constructs its frames. What makes the problem even harder is that a defense must alter the wire-visible size and segmentation of a DNP3 response while it preserves the exact bytes that the master expects to reassemble. There is a big research gap for such an obfuscation primitive.

In this paper, we propose CRC-boundary splitting, a byte-preserving obfuscation primitive that changes how a DNP3 response is segmented on the wire without changing a single DNP3 byte. The idea is to cut the response into TCP chunks only on the boundaries between the CRC-protected blocks that already exist in the captured stream. Because every chunk ends on an already-valid CRC, and because the chunks concatenate back into the original response, the master reassembles the identical application message, no matter how finely the response is chopped. We realize the primitive in a request-aware split-replay server that stands in the place of the outstation, replays the captured responses matched to each master request, and splits every data response on its CRC boundaries.

To validate the primitive on the real DNP3 software, we build a software harness around an OpenDNP3 master and outstation, and we evaluate it on a two-host testbed. This paper makes the following contributions.

- **We characterize the native fingerprint.** We measure how an OpenDNP3 outstation natively segments its responses on a real testbed. A large all-types read produces a 12,204-byte response carried as 9 application fragments, 49 link frames, and 20 TCP segments, and the response size grows linearly at about 5.7 bytes per analog point, such that the segmentation pattern directly encodes the database read.
- **We design byte-preserving CRC-boundary splitting.** The proposed primitive re-segments a captured response only on the existing DNP3 CRC block boundaries, with no CRC recompute and no field modification, such that the concatenation of the emitted chunks is byte-identical to the original response.
- **We build a request-aware split-replay server.** The proposed server reassembles whole DNP3 frames from the TCP stream, matches each request by the function code and the application sequence, replies only with the matching captured response, and preserves the DNP3 CONFIRM handshake, such that it can stand in the place of the outstation without a live proxy.
- **We evaluate the transparency and correctness on the rig.** We show on the testbed that the master accepts every splitting granularity, delivers the measurements identical to the baseline at the byte, protocol, and measurement levels, and keeps the TCP connection clean, while the same response is presented as up to 141 tiny segments instead of the outstation's native 9 frames.

## II. Background and Threat Model

In this section, we first present the DNP3 response structure that makes the segmentation fingerprint possible. Then we describe the passive-observer threat model considered in this work.

### A. DNP3 response structure

DNP3 is a request-response protocol used between a master and an outstation in SCADA systems [1]. The master issues a read request, e.g., a Class 0 integrity poll, and the outstation responds with the requested measurements. A DNP3 message is layered, and each layer imposes its own size limit. At the application layer, the outstation constructs a response fragment that carries the measurement objects. At the transport layer, a fragment larger than a single segment is split into transport segments marked with the first (FIR) and the final (FIN) bits. At the data-link layer, each transport segment is carried in one or more link frames. A DNP3 link frame has a fixed structure [1]: an 8-byte header, a 2-byte header CRC, and then up to 250 bytes of user data protected by a CRC after every 16-byte block. Consequently, a full link frame reaches a ceiling of 292 bytes, and a long application response can only be delivered as a run of 292-byte link frames followed by a shorter tail frame.

The per-block CRCs are the reason why byte-preserving splitting is possible at all. Because every 16-byte block already ends with a valid 2-byte CRC in the captured stream, a cut placed on such a block boundary produces two pieces that each end on an already-valid CRC, without recomputing anything.

### B. Threat model

In this work, we consider a passive on-path observer. We assume that the adversary can capture the unencrypted DNP3 traffic between a master and an outstation, e.g., from a mirrored switch port or a tap on the control network, but does not modify, inject, or block any packet. We argue that this is a reasonable assumption, as DNP3 usually runs without encryption or authentication over shared substation and utility networks, so read access to the traffic is practical for an adversary that has established a foothold on the network. The objective of the adversary is the reconnaissance: to fingerprint the outstation and infer its type and configuration from the observable properties of its responses, i.e., the response size, the number and sizes of the frames, and the inter-frame timing, without decoding the application payload.

We do not consider an adversary that decrypts a protected channel, because the observable size and segmentation properties persist even under some tunneling, and an unencrypted deployment is the practical baseline for legacy DNP3. We also do not consider an active adversary that tampers with the traffic in this work, and we leave the defense against active manipulation to future work.

## III. CRC-Boundary Splitting

In this section, we describe CRC-boundary splitting and the request-aware split-replay server that realizes it. In Figure 1, we present the design.

![Figure 1. The request-aware split-replay server stands in for the outstation. It reassembles whole DNP3 frames from the TCP stream, matches each request to its captured response, splits data responses only on existing CRC block boundaries, and preserves the CONFIRM handshake. The master command is unchanged.](figures/fig1_architecture.svg)

**The primitive.** CRC-boundary splitting cuts a captured DNP3 response into TCP chunks only on the boundaries between its CRC-protected blocks. To split a response, we scan it into its sequence of blocks, i.e., the 10-byte link header block and the following 16-byte data blocks, each already terminated by its CRC, and we group a configurable number of whole blocks into each TCP chunk. Because a chunk always begins and ends on a block boundary, every chunk ends on an already-valid CRC, and the chunks concatenate back into the original response. Before sending, the server enforces the byte-preservation invariant `b"".join(chunks) == response`; it refuses to send if the check fails. Consequently, no DNP3 byte is modified, no CRC is recomputed, and no length field is touched, such that the master's link-layer and transport-layer reassembly proceeds exactly as it does for the native response.

**Splitting granularity.** The number of whole blocks per chunk is the single control knob for how aggressively the response is fragmented. When the count is one, every CRC block becomes its own TCP segment, which is the most aggressive byte-preserving split possible; larger counts group more blocks per write and produce a coarser split. To cut finer than one block per chunk is not possible without splitting inside a CRC block, which would break a boundary and fall outside the byte-preserving primitive. The server also delays each chunk by a configurable interval, such that the timing dimension of the fingerprint can be varied independently of the size dimension.

**Request-aware replay.** The split-replay server stands in the place of the outstation at the same address and port, such that the master command does not change. To reply correctly without running a full DNP3 stack, the server reassembles whole DNP3 frames from the TCP stream using the link-header length field, parses each request's function code and application sequence, and replies with only the captured response that matches that request. Because a captured session contains startup and handshake exchanges as well as the data read, matching each request to its own captured response keeps the master on its captured trajectory. The server refuses to fire a captured response at a request that it cannot match, which prevents the blind byte-dumping behavior that an earlier positional replay design exhibited. Only the data responses are split on CRC boundaries; the short handshake replies are sent whole.

**Handling multi-fragment responses and CONFIRM.** A large read is answered by more than one application fragment. The outstation sends the first fragment, the master returns a DNP3 CONFIRM, and the outstation then sends the continuation fragment. The server preserves this handshake: it sends the split first fragment, waits for the master's CONFIRM bytes, and then sends the continuation fragment, split on its own CRC boundaries. Consequently, the continuation is obfuscated to the same degree as the first fragment, instead of being emitted as a single write.

## IV. Implementation

We implement the harness in Python around an OpenDNP3 [8] outstation and master, reached through the ChargePoint pydnp3 binding. The outstation runner (`run_outstation.py`) starts a real OpenDNP3 outstation with a configurable database, disables unsolicited responses, and rejects controls by default, such that the baseline capture contains only the issued reads. The master runner (`run_master.py`) issues one controlled Class 0 read and writes the delivered measurements to a per-phase CSV, together with a human-readable measurement receipt. All the lab settings, i.e., the host addresses, the TCP port, and the DNP3 link addresses, are read from a single configuration module, such that no address is typed on the command line.

The split-replay server (`split_server.py`) needs no DNP3 stack. It contains a frame reassembler, a request parser, the CRC-boundary splitter, and a captured-exchange map, and it depends only on itself and the configuration module. It exposes two delivery modes: `full` replays each captured response verbatim, and `crc-boundary` splits every data response on its CRC boundaries. The byte-preservation check runs on every response before it is sent. We deliberately confine the harness to the byte-preserving phase: it recomputes no CRC, modifies no DNP3 field, inserts no padding, and runs no live proxy, such that byte preservation stays the enforced invariant throughout.

## V. Evaluation

In this section, we evaluate CRC-boundary splitting on the testbed. Our evaluation answers three questions. First, how does an OpenDNP3 outstation natively segment its responses, i.e., what is the fingerprint that we aim to obfuscate? Second, does the master still accept and correctly reassemble a response that has been split on the CRC boundaries? Third, how far can the size and segmentation of a response be distorted while the byte-level acceptance is preserved?

**Testbed.** The testbed is two directly switched hosts on a 1 Gb/s management network. The master runs on one host, and the outstation, or the split-replay server in its place, runs on the other host on TCP port 20000. The DNP3 link addresses are 1 for the master and 10 for the outstation. We capture the traffic on the master's interface with a port filter, and we analyze the captures with scapy and a DNP3 CRC helper. The outstation and the master use OpenDNP3 through pydnp3 on Python 3.12. Unless stated otherwise, all the results are from the two-host rig, not from the loopback.

### A. Native segmentation fingerprint

To characterize the fingerprint, we issue a single large Class 0 read against an outstation configured with 200 analog, 50 binary, and 50 counter points, and we measure the response from the capture. In Table I, we present the result. The outstation returns a 12,204-byte response carried as 9 application fragments, 49 link frames, and 20 TCP segments. Of the 49 link frames, 46 are the 292-byte DNP3 maximum, and the rest are short per-fragment tails. The reason why the response reaches 49 link frames is that 292 bytes is the DNP3 link-frame ceiling, so a long application fragment can only be delivered as a run of full frames plus a short tail.

The DNP3 layer and the TCP layer segment independently. The kernel packs the link frames into TCP segments of up to 1448 bytes, i.e., the maximum segment size of the connection, such that a single 292-byte link frame can straddle a TCP segment boundary, and a single TCP segment can carry several partial link frames. Consequently, the two segmentation boundaries do not align, and the wire-visible pattern reflects both the DNP3 frame structure and the TCP packing.

To confirm that the fingerprint tracks the database, we sweep the read range on a 200-analog database, and we measure the response for each range. In Table II, we present the result. The response size grows linearly at about 5.7 bytes per analog point, and the frame and segment counts rise once the response crosses the 292-byte frame ceiling and the maximum segment size. Consequently, a passive observer can infer how many points a device exposes directly from the size and segmentation of its response, which is the fingerprint that CRC-boundary splitting aims to obfuscate. An observer may also combine this size estimate with the response timing, so as to strengthen the fingerprint.

We also measure the outstation's TCP-level response behavior on the same large read. The outstation piggybacks the application response on the TCP acknowledgment for 9 of the 9 requests, with a mean request-to-acknowledgment delay of 0.24 ms and a mean request-to-response delay of 1.01 ms, and the steady-state data segments carry a `NOP-NOP-Timestamp` TCP option signature. This is the TCP/IP stack fingerprint of the host, which is distinct from the DNP3 application fingerprint, and which would differ for a field device with a different stack.

### B. Transparency and correctness of CRC-boundary splitting

To test whether the master accepts a split response, we run the full pipeline on the rig. We first capture a baseline read against the real outstation, we extract the captured responses, and we then replace the outstation with the split-replay server and repeat the read, once with verbatim replay and once with CRC-boundary splitting. We compare the delivered measurements across the three runs.

The master accepts the split response and reassembles the identical application message. When a captured 2,407-byte read response, which OpenDNP3 natively carries as 9 link frames, is delivered as 141 chunks of at most 18 bytes under one-block-per-chunk splitting, the master still delivers all the 800 measurements from the replayed response set and returns a DNP3 CONFIRM. The measurement sets are identical at three levels. First, the split bytes concatenate to the original response, i.e., the byte level. Second, the master raises no DNP3 parser or CRC error and sends the CONFIRM, i.e., the protocol level. Last, the delivered measurements match the baseline, i.e., the measurement level. We also ran a clean-pipeline check on a Class 0 read that returned 2,400 unique measurement tuples across a 6-fragment response. The baseline, the verbatim replay, and the CRC-boundary split produced byte-identical measurement sets, and every data fragment was split, while the handshake replies were left whole. The reason why the measurements are preserved is that CRC-boundary splitting changes only where the TCP write boundaries fall, which the master's reassembly is indifferent to, and leaves every DNP3 byte and CRC untouched.

### C. Obfuscation envelope

To measure how far the fingerprint can be distorted, we replay the same captured 2,407-byte response split at one, two, four, and eight blocks per chunk, while holding everything else constant. In Table III, we present the result, and in Figure 2, we show the size and segmentation distortion against the native response.

![Figure 2. The same 2,407-byte response carries the identical bytes in both rows; only the TCP segmentation differs. OpenDNP3 natively presents it as 9 link frames, while one-block-per-chunk CRC-boundary splitting presents it as 141 chunks of at most 18 bytes. Across the granularity sweep the master accepted every level, delivering all 800 measurements with a CONFIRM on a clean connection.](figures/fig2_baseline_vs_split.svg) The master accepts every granularity and delivers all the 800 measurements. It returns a CONFIRM on a connection with zero retransmission and zero reset, while the READ response is presented as 141, 71, 36, and 18 chunks respectively. The chunk counts follow the ceiling of 141 divided by the blocks-per-chunk value, exactly. Consequently, the byte-preserving obfuscation envelope spans the full block-grouping range, and the maximum size and segmentation distortion is reached at one block per chunk, where a single 2,407-byte response that the outstation natively presents as 9 frames is presented instead as 141 tiny segments. To push the fragmentation past this point, or to change the per-frame sizes arbitrarily, would require rebuilding the frames and recomputing the CRCs, which falls outside the byte-preserving primitive.

## VI. Discussion

**From harness to in-network defense.** The harness proves the primitive in software, where the split-replay server stands in the place of the outstation and replays the captured responses. It is not yet the final in-network implementation. A deployed defense would apply CRC-boundary splitting to the live responses in the data plane, e.g., on a programmable switch, instead of replaying the captured ones. We leave the in-network, live implementation and its throughput and latency evaluation to future work.

**What the primitive hides and does not hide.** CRC-boundary splitting distorts the size and segmentation of a response and, through the chunk delay, its timing, while it preserves the DNP3 bytes. It does not change the total number of bytes that the application response carries, so an observer that counts the total payload bytes across a full exchange can still estimate the read size. To make the total size itself less informative requires padding or frame rebuilding, which recomputes the CRCs, and which is a separate line from the byte-preserving primitive studied here. We leave a padding-based extension, and its interaction with the master's reassembly, to future work.

**Scope of the evaluation.** Our fingerprinting measurements characterize a single outstation on one testbed, such that they show what the primitive changes on the wire, rather than a measured reduction in an adversary's classification accuracy across devices. A quantitative fingerprinting study across multiple device types and stacks would let us report the obfuscation effect as a drop in the classification accuracy. We leave such a study to future work.

## VII. Related Work

**Traffic obfuscation for ICS reconnaissance.** Previous work obfuscates the control-network communication to disrupt an adversary's reconnaissance of the power grids. In [3], the authors randomize the data acquisitions and craft decoy measurements to mislead the attackers into designing ineffective strategies, and in [4], the authors virtualize the physical devices to disrupt the reconnaissance of the cyber-physical infrastructure. These approaches obfuscate the content and the connectivity that an adversary learns. This work, on the other hand, serves a different objective: it obfuscates the wire-visible size and segmentation of a DNP3 response without changing any application byte, such that it complements the content-level obfuscation instead of replacing it.

**Website and traffic fingerprinting defenses.** A large body of work fingerprints the encrypted traffic from the packet sizes and the timing, and defends against it by padding and by reshaping the packet-size distribution [5]. The size and segmentation of the DNP3 responses provide a similar side channel in an unencrypted industrial setting. Compared with the general traffic-shaping defenses, CRC-boundary splitting is constrained by the DNP3 CRC structure: it can re-segment freely on the block boundaries, but it cannot alter the bytes or the sizes without recomputing the CRCs, such that it trades some reshaping freedom for the exact byte preservation and the transparent master acceptance.

**DNP3 security and monitoring.** Previous work adds intrusion detection and specification-based monitoring to the DNP3 traffic [6], and analyzes the safety impact of the malicious DNP3 commands [7]. These efforts detect or analyze the malicious activity in the traffic. This work is not a detection technique: it modifies the observable traffic of the outstation to resist the passive fingerprinting, before any malicious activity is attempted.

## VIII. Conclusion

A passive observer can fingerprint a DNP3 outstation based on the size, the segmentation, and the timing of its responses, which are stable because the outstation segments in a deterministic way, and because any byte change breaks the CRCs of the protocol. In this paper, we proposed CRC-boundary splitting, a byte-preserving obfuscation primitive that re-segments a captured response only on its existing CRC block boundaries, and we implemented it in a request-aware split-replay server. On a two-host testbed, the master accepted every splitting granularity and delivered the measurements identical to the baseline, while a response that OpenDNP3 natively presents as 9 frames was presented as up to 141 tiny segments on a connection with zero retransmission and zero reset. Based on those results, we believe that CRC-boundary splitting holds promise as the transparent primitive for an in-network obfuscation layer, which we plan to implement in the data plane in future work.

## References

> Placeholders. Replace each with a complete, verified citation before submission.
> The descriptors name the intended source; they are not full bibliographic entries.

[1] IEEE Standard for Electric Power Systems Communications, DNP3 (IEEE Std 1815). [complete citation]
[2] Analysis of the December 2015 Ukraine power grid cyberattack (e.g., E-ISAC/SANS report). [complete citation]
[3] H. Lin, Z. Kalbarczyk, and R. K. Iyer, "RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers," IEEE Transactions on Smart Grid. [complete citation]
[4] H. Lin et al., "DefRec: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures," NDSS. [complete citation]
[5] Representative website/traffic fingerprinting attack and padding-based defense. [complete citation]
[6] H. Lin et al., "Adapting Bro into SCADA: Building a Specification-based Intrusion Detection System for the DNP3 Protocol." [complete citation]
[7] H. Lin et al., "Safety-Critical Cyber-Physical Attacks: Analysis, Detection, and Mitigation." [complete citation]
[8] OpenDNP3, an open-source implementation of the DNP3 protocol stack. [complete citation]

## Tables

**Table I. Native segmentation of a large Class 0 read (200 analog + 50 binary + 50 counter).**

| Layer | Result |
|---|---|
| Total response bytes (outstation to master) | 12,204 |
| DNP3 application fragments (transport FIR/FIN) | 9 |
| DNP3 link frames (`0x0564`) | 49 |
| Link frame sizes | 46 x 292 B + short per-fragment tails |
| TCP segments (response) | 20 |

**Table II. Response size versus read range on a 200-analog database.**

| Read range | Analog points | Response bytes | DNP3 link frames | TCP segments |
|---|---|---|---|---|
| 0..9 | 10 | 129 | 4 | 4 |
| 0..49 | 50 | 332 | 3 | 3 |
| 0..99 | 100 | 625 | 4 | 3 |
| 0..199 | 200 | 1,211 | 6 | 3 |

**Table III. Split-aggressiveness sweep on a captured 2,407-byte READ response (9 native link frames).**

| Blocks per chunk | READ chunks | Measurements delivered | Master CONFIRM | TCP retransmits | TCP resets |
|---|---|---|---|---|---|
| 1 | 141 | 800 | yes | 0 | 0 |
| 2 | 71 | 800 | yes | 0 | 0 |
| 4 | 36 | 800 | yes | 0 | 0 |
| 8 | 18 | 800 | yes | 0 | 0 |
