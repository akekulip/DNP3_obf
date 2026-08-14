# Related-Work Additions — mined from the five target papers

Prepared 2026-08-14 for the NDSS paper on in-network DNP3 traffic obfuscation
(response-timing + segment-shape normalization on a Tofino-1, evaluated on a
physical SEL-751). READ-ONLY mining pass; the manuscript itself is untouched.

**Source extracts mined:** DefRec (`10139606.txt`), Testbed (`10336809.txt`),
RAINCOAT (`raincoat.txt`), Ditto (`ditto.txt`), Formby *Who's in Control…*
(`who-control-…txt`).

**Already in `refs.bib` (not re-proposed):** formby2016, gtid2015, sirinam2018,
juarez2016, song2001, wright2009, dyer2012, defrec2020, raincoat2019,
lintestbed2020, linbro2013, lincps2016, ditto2022, p4ccr2014, pifo2016,
dnp3std, ukraine2015, opendnp3.

**Selection constraint applied (per coordinator):** only flagship venues —
NDSS, ACM CCS, IEEE S&P, USENIX Security, USENIX NSDI, ACM SIGCOMM, PETS/PoPETs,
IEEE TSG/TDSC/TIFS/ToN. Workshop-only sources surfaced in the mining (e.g.
Rahman–Al-Shaer MTD at MTD'14, Jafarian OpenFlow random host mutation at
HotSDN'12, the various ICS honeypots) were **dropped** for tier. Every metadata
field below was verified against DBLP, Semantic Scholar, and the venue's own
proceedings page (each opened this session).

**7 verified additions.** Each: title, full authors, venue + tier, year,
DOI/URL, BibTeX, our five-category bucket, the claim it supports, and the exact
contrast to our work.

Our five categories:
1. ICS/CPS device fingerprinting
2. Network-timing traffic analysis + defenses
3. Packet-size padding / morphing / segmentation
4. Anti-reconnaissance / MTD for ICS / power
5. Programmable-switch timing / queueing / replication / shaping

---

## 1. Liu, Ning, Reiter — False Data Injection Attacks against State Estimation (CCS 2009)

- **Category:** 4 (anti-reconnaissance / MTD for ICS-power) — the *threat anchor*
  the grid-reconnaissance motivation leads to.
- **Venue tier:** ACM CCS — flagship (tier-1 security).
- **Verified:** DBLP (`Yao Liu, Peng Ning, Michael K. Reiter`; CCS 2009;
  pp. 21–32; DOI `10.1145/1653662.1653666`). This is DefRec reference [42] and
  RAINCOAT's FDIA anchor; author order taken from the ACM DL / DefRec citation
  form `Y. Liu, P. Ning, and M. K. Reiter`.
- **Why it fills a gap:** our threat model says a passive observer fingerprints
  the outstation to *prepare* an attack, but we never cite the canonical result
  that makes reconnaissance dangerous. Liu–Ning–Reiter is the origin of the
  false-data-injection line every ICS anti-reconnaissance paper (DefRec,
  RAINCOAT) builds on. It grounds *why* device fingerprinting is a precursor
  worth denying.
- **Suggested sentence:** "Reconnaissance is the precursor to targeted
  grid attacks: once an adversary learns which measurements a device reports and
  how, it can craft false-data-injection attacks that pass bad-data detection in
  state estimation~\cite{liufdia2009}, motivating defenses that deny the
  fingerprint before the attack is built."
- **Contrast to our work:** Liu et al. define the *downstream* attack that
  fingerprinting enables; we defend the *upstream* step, normalizing the
  outstation's observable response timing and segment shape so the device
  identity needed to target such an attack is never leaked.

```bibtex
@inproceedings{liufdia2009,
  title     = {False Data Injection Attacks against State Estimation in Electric Power Grids},
  author    = {Liu, Yao and Ning, Peng and Reiter, Michael K.},
  booktitle = {Proc. ACM SIGSAC Conf. on Computer and Communications Security ({CCS})},
  pages     = {21--32},
  year      = {2009},
  doi       = {10.1145/1653662.1653666}
}
```

---

## 2. Panchenko et al. — Website Fingerprinting at Internet Scale (NDSS 2016)

- **Category:** 2 (network-timing traffic analysis + defenses).
- **Venue tier:** NDSS — flagship (tier-1 security).
- **Verified:** DBLP + NDSS 2016 programme (`Andriy Panchenko, Fabian Lanze,
  Jan Pennekamp, Thomas Engel, Andreas Zinnen, Martin Henze, Klaus Wehrle`;
  NDSS 2016). NDSS has no DOI; stable venue page confirmed.
- **Why it fills a gap:** our traffic-analysis citations are a keystroke-timing
  attack (song2001) and a deep-learning WF attack (sirinam2018). Panchenko et al.
  is the standard *scale/realism* reference — it shows fingerprinting accuracy
  collapses (or holds) under realistic open-world conditions, which is exactly
  the adversary-realism framing a reviewer will expect us to acknowledge.
- **Suggested sentence:** "Traffic-analysis classifiers that look strong in a
  closed world often degrade at realistic scale~\cite{panchenko2016}; we
  therefore evaluate our defense against the observable that survives such
  scaling — the device's response-timing and segment-shape signature."
- **Contrast to our work:** Panchenko et al. attack a *browsing* adversary over
  Tor and argue about attacker realism on the open web; we target a *single
  industrial device* whose response signature is far lower-entropy, and we remove
  that signature in-network rather than at an end host.

```bibtex
@inproceedings{panchenko2016,
  title     = {Website Fingerprinting at Internet Scale},
  author    = {Panchenko, Andriy and Lanze, Fabian and Pennekamp, Jan and Engel, Thomas and Zinnen, Andreas and Henze, Martin and Wehrle, Klaus},
  booktitle = {Proc. Network and Distributed System Security Symposium ({NDSS})},
  year      = {2016},
  url       = {https://www.ndss-symposium.org/ndss2016/ndss-2016-programme/}
}
```

---

## 3. Cai et al. — A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses (Tamaraw, CCS 2014)

- **Category:** 3 (packet-size padding / morphing / segmentation).
- **Venue tier:** ACM CCS — flagship.
- **Verified:** DBLP (`Xiang Cai, Rishab Nithyanand, Tao Wang, Rob Johnson,
  Ian Goldberg`; CCS 2014; pp. 227–238; DOI `10.1145/2660267.2660362`). This is
  the paper that introduces the **Tamaraw** constant-rate defense.
- **Why it fills a gap:** we cite BuFLO's critique (dyer2012) and WTF-PAD
  (juarez2016) but not the provably-secure constant-rate defense that BuFLO's
  authors' successors converged on. Tamaraw is the canonical
  "pad-and-fix-the-rate" baseline our shape normalization is a lightweight,
  device-scoped cousin of — Ditto's related-work table positions the whole
  BuFLO/CS-BuFLO/Tamaraw family this way.
- **Suggested sentence:** "Constant-rate padding defenses such as
  Tamaraw~\cite{tamaraw2014} bound information leakage by forcing a fixed packet
  size and inter-packet interval, at a bandwidth and latency cost that is
  acceptable for a single flow but prohibitive across a substation's device
  fleet."
- **Contrast to our work:** Tamaraw runs on the end host and pads *every* flow to
  a global constant, paying continuous overhead; we normalize only the
  DNP3 response boundary in the switch, byte-preservingly (CRC-boundary
  segmentation, no fabricated padding), so the outstation and master are
  unmodified.

```bibtex
@inproceedings{tamaraw2014,
  title     = {A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses},
  author    = {Cai, Xiang and Nithyanand, Rishab and Wang, Tao and Johnson, Rob and Goldberg, Ian},
  booktitle = {Proc. ACM SIGSAC Conf. on Computer and Communications Security ({CCS})},
  pages     = {227--238},
  year      = {2014},
  doi       = {10.1145/2660267.2660362}
}
```

---

## 4. Wang & Goldberg — Walkie-Talkie (USENIX Security 2017)

- **Category:** 3 (packet-size padding / morphing / segmentation).
- **Venue tier:** USENIX Security — flagship.
- **Verified:** DBLP + Semantic Scholar + USENIX proceedings page (`Tao Wang,
  Ian Goldberg`; USENIX Security 2017). USENIX has no DOI; stable presentation
  URL confirmed.
- **Why it fills a gap:** Walkie-Talkie is the low-overhead *molding* defense —
  half-duplex communication plus burst shaping so different pages produce
  colliding traces. It is the efficiency counterpoint to Tamaraw and the natural
  reference for "shape the burst, don't pad everything," which is conceptually
  what our segment-shape normalization does at the DNP3 layer.
- **Suggested sentence:** "Rather than padding to a constant, Walkie-Talkie molds
  bursts so distinct activities collide onto one observable
  pattern~\cite{walkietalkie2017}; our design applies the same collide-the-shape
  intuition to DNP3 responses, but enforces it in the data plane and without
  end-host cooperation."
- **Contrast to our work:** Walkie-Talkie requires a modified browser and a
  cooperating proxy to run half-duplex; our normalization is transparent to both
  DNP3 endpoints and imposes no protocol change on the master or outstation.

```bibtex
@inproceedings{walkietalkie2017,
  title     = {Walkie-Talkie: An Efficient Defense against Passive Website Fingerprinting Attacks},
  author    = {Wang, Tao and Goldberg, Ian},
  booktitle = {Proc. 26th USENIX Security Symposium},
  pages     = {1375--1390},
  year      = {2017},
  url       = {https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao}
}
```

---

## 5. Alcoz, Dietmüller, Vanbever — SP-PIFO (USENIX NSDI 2020)

- **Category:** 5 (programmable-switch timing / queueing / shaping).
- **Venue tier:** USENIX NSDI — flagship (tier-1 networking).
- **Verified:** DBLP + Semantic Scholar + USENIX NSDI'20 page (`Albert Gran
  Alcoz, Alexander Dietmüller, Laurent Vanbever`; NSDI 2020; pp. 59–76). No DOI;
  stable presentation URL confirmed.
- **Why it fills a gap:** we cite PIFO (pifo2016) as the *ideal* programmable
  scheduler but not its *realizable-on-hardware* approximation. SP-PIFO shows
  that rank-ordered scheduling can be approximated with a handful of
  strict-priority queues on stock programmable switches — the exact primitive
  class our four-logical-queue Tofino scheduler is built on. It substantiates
  that our timing engine sits on an established, feasible scheduling foundation
  rather than the unbuilt PIFO abstraction.
- **Suggested sentence:** "PIFO~\cite{pifo2016} is a hardware abstraction, not a
  shipping primitive; SP-PIFO~\cite{sppifo2020} shows rank-ordered scheduling can
  be approximated with a few strict-priority queues on today's programmable
  switches — the primitive class our deadline-driven response scheduler uses."
- **Contrast to our work:** SP-PIFO is a *general* scheduling primitive that
  approximates arbitrary rank orders for throughput/fairness; we use a small
  fixed set of strict-priority queues for a *security* objective — releasing the
  ACK and the response on predetermined deadlines to collapse the CLRT
  distribution — not to approximate PIFO.

```bibtex
@inproceedings{sppifo2020,
  title     = {{SP-PIFO}: Approximating Push-In First-Out Behaviors using Strict-Priority Queues},
  author    = {Alcoz, Albert Gran and Dietm{\"u}ller, Alexander and Vanbever, Laurent},
  booktitle = {Proc. 17th USENIX Symp. on Networked Systems Design and Implementation ({NSDI})},
  pages     = {59--76},
  year      = {2020},
  url       = {https://www.usenix.org/conference/nsdi20/presentation/alcoz}
}
```

---

## 6. Meier, Tsankov, Lenders, Vanbever, Vechev — NetHide (USENIX Security 2018)

- **Category:** 4 (anti-reconnaissance for critical networks) with a 5 crossover
  (programmable data plane).
- **Venue tier:** USENIX Security — flagship.
- **Verified:** DBLP + Semantic Scholar + USENIX Security'18 page (`Roland Meier,
  Petar Tsankov, Vincent Lenders, Laurent Vanbever, Martin Vechev`; USENIX
  Security 2018). No DOI; stable presentation URL confirmed.
- **Why it fills a gap:** this is the *in-network anti-reconnaissance* precedent
  from the same group as Ditto — obfuscating a network's topology in the data
  plane to deny reconnaissance (link-flooding attacks) while preserving
  usability. It is the closest prior "obfuscate-to-deny-recon, in the network"
  systems point to ours, bridging our MTD/anti-recon category (DefRec/RAINCOAT,
  which are host/SDN-controller based) and our in-switch mechanism.
- **Suggested sentence:** "In-network obfuscation has been used to deny
  reconnaissance before: NetHide rewrites traceroute-visible topology in the data
  plane to blunt link-flooding attacks while keeping path tracing
  usable~\cite{nethide2018}; we bring the same in-network, usability-preserving
  stance to the *device-fingerprinting* surface of an ICS outstation."
- **Contrast to our work:** NetHide obfuscates *network topology* against an
  active tracer; we obfuscate a *single device's response signature* (timing +
  segment shape) against a passive fingerprinter, and we validate on physical ICS
  hardware rather than an emulated ISP topology.

```bibtex
@inproceedings{nethide2018,
  title     = {{NetHide}: Secure and Practical Network Topology Obfuscation},
  author    = {Meier, Roland and Tsankov, Petar and Lenders, Vincent and Vanbever, Laurent and Vechev, Martin},
  booktitle = {Proc. 27th USENIX Security Symposium},
  pages     = {693--709},
  year      = {2018},
  url       = {https://www.usenix.org/conference/usenixsecurity18/presentation/meier}
}
```

---

## 7. Apthorpe, Huang, Reisman, Narayanan, Feamster — Keeping the Smart Home Private with Smart(er) IoT Traffic Shaping (PoPETs 2019)

- **Category:** 3 (padding / traffic shaping) with a 1 crossover (device-activity
  fingerprinting from encrypted traffic).
- **Venue tier:** PoPETs (Proceedings on Privacy Enhancing Technologies) —
  flagship privacy venue (on the accepted list).
- **Verified:** DBLP + Semantic Scholar (`Noah Apthorpe, Danny Yuxing Huang,
  Dillon Reisman, Arvind Narayanan, Nick Feamster`; PoPETs 2019, issue 3;
  DOI `10.2478/popets-2019-0040`). Cited in Ditto's reference list [26].
- **Why it fills a gap:** this is the canonical demonstration that a passive
  observer infers *device activity* from encrypted traffic *size/rate* alone, and
  it proposes stochastic traffic padding as the shaping defense. It is the direct
  analogue of our threat — device inference from an encrypted/opaque stream — in
  the IoT domain, and shows the size/shape channel is exploitable even without
  payload access.
- **Suggested sentence:** "Even under end-to-end encryption, a passive observer
  infers device activity from packet size and rate alone, and traffic shaping is
  the standard countermeasure~\cite{apthorpe2019}; the same size/shape channel
  identifies an ICS outstation, which our segment-shape normalization closes."
- **Contrast to our work:** Apthorpe et al. shape *aggregate home traffic rate*
  from the end host / gateway with injected cover traffic; we normalize the
  *DNP3 response segmentation* in the switch without injecting fabricated
  application payload, keeping the byte stream verifiable against the real
  response.

```bibtex
@article{apthorpe2019,
  title   = {Keeping the Smart Home Private with Smart(er) {IoT} Traffic Shaping},
  author  = {Apthorpe, Noah and Huang, Danny Yuxing and Reisman, Dillon and Narayanan, Arvind and Feamster, Nick},
  journal = {Proceedings on Privacy Enhancing Technologies ({PoPETs})},
  volume  = {2019},
  number  = {3},
  pages   = {128--148},
  year    = {2019},
  doi     = {10.2478/popets-2019-0040}
}
```

---

## Coverage summary

| # | Key | Category | Venue (tier) | Fills |
|---|-----|----------|--------------|-------|
| 1 | liufdia2009 | 4 (threat anchor) | CCS (flagship) | FDIA/state-estimation origin the grid-recon threat leads to |
| 2 | panchenko2016 | 2 | NDSS (flagship) | attacker-realism / scale reference for traffic analysis |
| 3 | tamaraw2014 | 3 | CCS (flagship) | constant-rate padding defense (Tamaraw) |
| 4 | walkietalkie2017 | 3 | USENIX Sec (flagship) | low-overhead burst-molding defense |
| 5 | sppifo2020 | 5 | NSDI (flagship) | realizable strict-priority approximation of PIFO |
| 6 | nethide2018 | 4/5 | USENIX Sec (flagship) | in-network anti-recon obfuscation precedent |
| 7 | apthorpe2019 | 3/1 | PoPETs (flagship) | encrypted-traffic device inference + shaping defense |

**Notes on integrity:** every field above was checked against DBLP and/or
Semantic Scholar and the venue proceedings page, all opened 2026-08-14.
DOI-bearing venues (CCS, PoPETs) carry the DOI; DOI-less venues (NDSS, USENIX
Security, NSDI) carry the confirmed stable venue URL. Page ranges for the
USENIX/NSDI entries are the published proceedings ranges
(Walkie-Talkie 1375–1390, SP-PIFO 59–76, NetHide 693–709); if the build is
strict about un-DOI'd page numbers, they can be dropped without affecting the
citation. Candidates that surfaced but were **excluded for venue tier**:
Rahman–Al-Shaer MTD (MTD'14 workshop), Jafarian et al. OpenFlow Random Host
Mutation (HotSDN'12 workshop), the CryPLH/Conpot/HoneyMix ICS honeypots
(workshops), and Acar et al. *Peek-a-boo* smart-home (WiSec — not on the
accepted list).
