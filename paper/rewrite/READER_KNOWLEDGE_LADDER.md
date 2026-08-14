# Reader knowledge ladder

The exact order a fresh NDSS reviewer (security + networks background, no exposure to this project,
testbed, or terminology) must learn the concepts. Each project-specific term is introduced in plain
language BEFORE any acronym, symbol, port, queue, register, or code name. Columns:
concept | one-sentence explanation | why it matters | first section it may appear | prerequisite |
supporting citation / repository evidence.

| # | Concept | One-sentence explanation | Why it matters | First section | Prereq | Support |
|---|---|---|---|---|---|---|
| 1 | ICS reconnaissance → damage | An attacker on a grid control network first learns what devices exist and how they behave, then acts. | Establishes that observation is the first, deniable step of an attack. | Intro ¶1 | — | `ukraine2015`; `liufdia2009` |
| 2 | DNP3 | A SCADA protocol a control center uses to poll and command field devices, usually unencrypted. | The traffic under study; unencrypted means the metadata is observable. | Intro ¶5 | 1 | `dnp3std` |
| 3 | Master / outstation | The master is the polling control station; the outstation is the field device (here a protective relay) that answers. | Names the two endpoints every later sentence refers to. | Intro ¶5 / Background | 2 | `dnp3std`; testbed |
| 4 | READ transaction | The master sends a READ request; the outstation returns a response with its measurements. | The simplest running example; the basis for the timing/shape leak. | Background | 3 | `dnp3std` |
| 5 | TCP ACK vs application response | On the wire the outstation first sends a TCP segment acknowledging the request, then later the DNP3 application response. | These are the two packets whose gap defines the timing feature. | Background | 4 | `clrt_extract.py:28-31` |
| 6 | CLRT (cross-layer response time) | The delay between the outstation's first TCP ACK-bearing segment and its DNP3 application response (func 0x81). | The device's internal processing signature; stable across sessions. | Background / Intro ¶6 | 5 | `clrt_extract.py`; `formby2016` |
| 7 | Fingerprinting: identity vs type vs transaction-class | Repeated timing/size lets an observer infer a device's identity, its type, or which transaction it is running. | Separates what prior work does (device id/type) from what we evaluate (READ-vs-SELECT class). | Intro ¶2 | 6 | `formby2016`; `gtid2015`; `kohno2005` |
| 8 | TCP segmentation / segment vector | TCP delivers a byte stream in segments; the vector of segment sizes for a response is observable (e.g. `[49]`). | The size/shape feature, distinct from timing. | Background / Intro ¶6 | 4 | `size_verdict.csv` |
| 9 | The 49-byte eligible response | The SEL-751's READ/control response is a 49-byte DNP3 frame that natively leaves as one 49-byte segment. | The concrete object the size defense reshapes. | Background | 8 | `size_verdict.csv` |
| 10 | DNP3 CRC blocks | A DNP3 frame is a link header plus fixed 16-byte data blocks, each followed by a 2-byte CRC the master validates. | Explains why bytes cannot be edited/padded and where a safe cut exists. | Background | 9 | `dnp3std`; frame layout |
| 11 | Shape vs length (`[49]` vs `[28,21]`) | Splitting the 49 bytes into two segments changes the observed shape while the reassembled length stays 49. | Prevents the reader from thinking the defense hides length; it normalizes shape. | Background / Intro ¶6 | 8,10 | `size_reconstruct.py` |
| 12 | SELECT-before-OPERATE, OPERATE, echo | A control is two steps: SELECT arms a point, OPERATE actuates; the outstation echoes the command back. | The control path that creates a second, operation-timing leak. | Background | 4 | `dnp3std`; `relay_operate_guarded.py` |
| 13 | Operation-timing fingerprint | The delay from an OPERATE to its confirmation reflects the relay's actuation and is itself a signature. | Motivates the second mechanism (control-command hold). | Background / Intro ¶8 | 12,6 | `formby2016`; `sbo_timing.py` |
| 14 | Master-facing vs relay-facing observation | The attacker sees the master-side link; the relay-side link and switch internals are not observed. | Defines the measurement boundary and what is inferred, not measured. | Threat Model | 3 | `VERDICT.json` |
| 15 | In-network enforcement (programmable switch) | A programmable switch on the path can rewrite timing and segmentation without changing the endpoints. | Introduces where the defense runs before any hardware detail. | Intro ¶8 / Overview | 2,3 | `p4ccr2014`; `ditto2022` |
| 16 | Strict-priority queue / blocker reservoir as a timer | A held packet waits behind higher-priority "blocker" packets; when they drain, it is released — a data-plane timer. | The mechanism that realizes a fixed release deadline without a controller. | Overview / Impl | 15 | `pifo2016`; `sppifo2020`; P4 queues |
| 17 | Response shaping (the timing+shape mechanism) | Hold the ACK and response, release them at fixed offsets from the request, replicate the response, and carve it at a CRC boundary. | The first primitive, taught by function before any port/queue name. | Overview | 6,11,16 | P4; `CLAIM_EVIDENCE_LEDGER` CL-24 |
| 18 | Control-command hold (the OPERATE mechanism) | Admit one OPERATE, hold it, release it once at a hidden internal delay, and pin the master-visible ACK/echo to the request time. | The second primitive; explains master-facing J-invariance. | Overview | 12,13,16 | P4; ledger CL-11 |
| 19 | Two scheduling domains | The two mechanisms cannot share one priority ladder without the response reservoirs starving the OPERATE queues; they run on two internal switch schedulers. | Explains a real design constraint, shown as a failure first. | Overview / Impl | 16,17,18 | `RRC_BOR_PRIMITIVE.md` |
| 20 | Programmable-switch internals (Tofino, P4, PRE, pktgen, recirculation) | The switch program, its packet-replication engine, packet generator, and internal loopback ports. | Only needed in detailed Implementation, after the concepts above. | Impl (late) | 15,16,17,18 | P4; setup |
| 21 | One-outcome / one-commit pipeline (`meta.outcome`, `tbl_commit`) | Earlier stages compute one compact decision that a single terminal table applies. | Explains auditability and the 12-stage fit; a late implementation detail. | Impl (late) | 20 | `defense4_rrc_bor_unified12.p4:2309` |
| 22 | Port/queue names (dp8/dp10/dp68, qid7–qid2) | The specific internal ports and queues that carry each held packet class. | Concrete mapping for a reviewer; appears only in the detailed implementation figure. | Impl (last) | 20,21 | P4; setup |

**Rule enforced by the ladder:** a term at row *n* may not appear before its prerequisite rows are
taught. In particular, rows 20–22 (Tofino/PRE/pktgen and dp/qid names) must not appear in the
Introduction or the first architecture figure; they belong to detailed Implementation only.
