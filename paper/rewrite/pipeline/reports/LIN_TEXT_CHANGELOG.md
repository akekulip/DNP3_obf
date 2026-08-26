# Changelog of Dr. Lin's protected introduction text

Source of the protected text: the red-boxed paragraphs of the annotated introduction
(`lin.png`, archived at `/home/philip/Archives/DNP3_nonfinal_20260824/unused_code/lin.png` and
at the tag `archive/pre-final-timing-prune-20260824:lin.png`), transcribed verbatim in
`pipeline/samples/lin_intro.txt` and quoted in full in `PRE_REWRITE_RECONCILIATION.md` R10.
Two paragraphs are protected: the opening device-fingerprinting paragraph and the
traffic-obfuscation-trend paragraph. The pivot sentence he discussed in the meeting
("Unfortunately, it is challenging, if not impossible, …") is treated the same way.

Each row gives the original sentence, the sentence now in `sections/01_introduction.tex`, the
reason, the evidence or citation that required the change, and whether the change is editorial
(wording, grammar, citation placement) or scientific (a claim changes). Changes made on
2026-08-19 in `introduction_pipeline_v1.tex` and kept are listed too, so the log covers every
departure from the original.

## Paragraph 1

| # | original | revised | reason | evidence | kind |
|---|---|---|---|---|---|
| 1.1 | "Device fingerprinting has been an essential step in cyber reconnaissance, allowing adversaries to reveal unique features of target networks and design effective, stealthy attack strategies." | "Device fingerprinting is an essential step in cyber reconnaissance, allowing adversaries to reveal unique features of target networks and design effective, stealthy attack strategies." | present tense for a standing fact (2026-08-19 edit, kept) | grammar | editorial |
| 1.2 | "These techniques are becoming increasingly critical in industrial control systems (ICSs) such as power grids, where adversaries often use IP-based control networks and computing devices within as entry points to inflict physical damage." | "… where adversaries often use IP-based control networks and the computing devices within them as entry points to inflict physical damage." | "computing devices within" has no object; "the computing devices within them" completes it | grammar | editorial |
| 1.3 | "Consequently, fingerprinting shifts the focus from visited web sites, user biometric behavior to device models and types of control operations that are critical to ICS attacks." | "Consequently, fingerprinting shifts the focus from visited web sites and user behavior to device models and types of control operations that are critical to ICS attacks." | the list "web sites, user biometric behavior" lacks a conjunction; "biometric" is dropped because website fingerprinting and behavioral fingerprinting are the prior-work targets and no biometric work is cited | grammar; consistency with the cited literature | editorial |
| 1.4 | "In the 2015 attack that disrupted Ukrainian power grids and the Stuxnet attack that disrupted Iranian nuclear power facilities, it is widely believed that adversaries stay in their systems for at least 6 months to perform cyber reconnaissance." | "In the 2015 attack that disrupted the Ukrainian power grid, it is widely believed that the adversaries stayed in the target systems for at least six months to perform cyber reconnaissance [Lee et al. 2016], and the Stuxnet attack that disrupted Iranian nuclear facilities depended on detailed knowledge of the specific controllers it targeted [Langner 2011]." | The six-month reconnaissance dwell is documented for the Ukraine attack by the E-ISAC/SANS analysis (`leeAnalysisCyberAttack2016`); no source in the bibliography supports a six-month dwell for Stuxnet, so the sentence is split and each incident carries the claim its source supports. Langner (`langnerStuxnetDissectingCyberwarfare2011`, IEEE S\&P 9(3), 2011) documents that Stuxnet targeted specific Siemens controller configurations and required detailed knowledge of them. "nuclear power facilities" → "nuclear facilities": the Natanz enrichment plant is not a power plant. "stay in their systems" → "stayed in the target systems": past tense for a past incident, and "their" was ambiguous. | brief §23 ("cite the exact reconnaissance or disruption claim with an authoritative source"); brief §3 (verify facts) | scientific (claim scoped per source); editorial (tense, facility) |

The sentence roles of paragraph 1 are unchanged: topic (fingerprinting as reconnaissance),
narrowing to ICS and physical damage, the "Consequently" pivot to device models and control
operations, the incident example pointed at reconnaissance.

## Paragraph 2 (traffic-obfuscation trend)

| # | original | revised | reason | evidence | kind |
|---|---|---|---|---|---|
| 2.1 | "To disrupt device fingerprinting, many studies present network traffic obfuscation." | same, with citations [Wright 2009; Dyer 2012] | citation added; wording unchanged | citation correctness | editorial |
| 2.2 | "Because device fingerprinting targeting general computing environments generally relies on network-level features such as packet size and/or inter-packet latency observed from communication patterns, traffic obfuscation often focuses on (i) padding and splitting network packets, which hide or change the distribution of network packet sizes, and (ii) delaying network packets and adding dummy ones, which disrupt the inter-packet timing pattern." | same, "and/or" → "and", with citations [Kohno 2005; Sirinam 2018] after "communication patterns", [Wright 2009; Cai 2014] after (i), [Dyer 2012; Juarez 2016] after (ii) | "and/or" is avoided in the guide; citations placed on the clause each supports | citation placement (brief §33: no citation after several unrelated claims) | editorial |
| 2.3 | "Since manipulating communication networks can introduce runtime overhead, recent works have begun to offload traffic obfuscation onto programmable network switches, which change communication patterns at much higher line rates than CPUs." | same, with citations [Ditto 2022; Minos 2025; Securitas 2026] | citation added; wording unchanged (the 2026-08-19 rewording "manipulating traffic at the host" is reverted to his wording) | citation correctness | editorial |
| 2.4 | (none) | appended: "These approaches assume an encrypted payload, so that size and timing are the only features left to hide, and most of them accept a change on the end host or a bandwidth cost as the price of protection." | the brief's paragraph-2 blueprint asks for why general Internet approaches assume encrypted payloads or tolerate host-side overhead; added as a closing sentence after his paragraph, not inserted into it | brief §23 paragraph 2 | editorial (addition, no change to his sentences) |

## Pivot sentence

| # | original | revised | reason | evidence | kind |
|---|---|---|---|---|---|
| 3.1 | "Unfortunately, it is challenging, if not impossible, to apply these methods to device fingerprinting in ICS environments." | "Unfortunately, it is challenging, if not impossible, to apply these methods to device fingerprinting in ICS environments, for three reasons." | opens the enumerated gap paragraph the brief requires | brief §23 paragraph 3 | editorial |

## Not Dr. Lin's text

The paragraph about power grids, plaintext DNP3 and false-data injection in the earlier draft was
Philip's paragraph 2 (`LIN_VS_PHILIP_DIFF.md`; `lin.png`, unboxed). It no longer interrupts the
Introduction: the plaintext-DNP3 point is the first reason of the gap paragraph, and the
false-data-injection point moved to the Threat Model ("What the observer wants"), where it
motivates the reconnaissance target. The duplicate, mis-dated Ukraine sentence it contained
("December 2025") is removed.
