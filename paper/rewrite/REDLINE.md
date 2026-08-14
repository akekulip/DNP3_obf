# Redline: reader-first rewrite vs the author base (`*_desmoothed.tex`)

What each original section became. The author base is the software CRC-splitting paper; the reader-first
rewrite (`dnp3_obfuscation_paper_readerfirst.tex`, sections `rewrite/sec2_*.tex`) transforms it into the
in-network hardware defense while preserving the author's reconnaissance-to-defense narrative. Legend:
**retained** (author phrasing/idea kept), **reorganized** (moved/reordered), **rewritten**
(same role, new content), **removed** (software-specific, superseded), **new**. A mechanical
Introduction diff is in `intro_mechanical.diff`.

## Introduction
| author paragraph (desmoothed) | disposition |
|---|---|
| "The grid runs on old protocols…" + Ukraine 225,000 + "begins with watching" | **retained** (voice and arc preserved; ¶1), extended with the FDIA/process-control precursor cite |
| "Reading the payload is not even necessary…" (size+timing fingerprint; integrity-poll vs point-read) | **rewritten/reorganized** into ¶2–3 (device/type/transaction-class distinction; CLRT + segment shape defined precisely) |
| "Erasing the fingerprint is hard… CRC… fixed firmware… gap" | **retained + reorganized** into ¶5 (why ICS/DNP3 differs) and ¶7 (requirements), kept the CRC-and-fixed-firmware constraint |
| "We fill that gap with CRC-boundary splitting… split-replay server" | **rewritten** into ¶6–8: CRC-boundary splitting becomes the shape-normalization step of the in-network defense; the split-replay server is **removed** |
| software-harness contributions (native fingerprint 12,204 B/9 frags/141 segments; primitive; replay server; rig study) | **removed**; replaced by five contributions mapping to the hardware artifacts |

## Background and Threat Model (author) → Background + Threat Model (rewrite)
| author | disposition |
|---|---|
| "DNP3 response structure" (layers; 292-byte link frame; per-block CRCs) | **retained + reorganized** into the new Background (§II) and the carve explanation; kept the per-block-CRC mechanic |
| "Threat model" (passive on-path observer; unencrypted; recon; active/tunneling out of scope) | **retained + rewritten** into the reordered Threat Model (§III), with the metadata-not-payload-unavailable fix and the relay-facing carve-out added |

## CRC-Boundary Splitting (author mechanism) → folded into Implementation
| author | disposition |
|---|---|
| the primitive; split granularity; request-aware replay; CONFIRM handshake; `fig:arch` | **removed** as a standalone section; the byte-preserving cut is **retained** as the carve step of response shaping in §IV; the software architecture figure is replaced by the reader-first figures |

## Implementation (author software harness) → Implementation (hardware)
| author | disposition |
|---|---|
| Python harness (OpenDNP3, run\_outstation/run\_master/split\_server) | **removed**; **rewritten** as the P4/Tofino implementation (overview → timers → response shaping → control command → two lanes → one-commit → control plane → safety → resource fit), concept-before-symbol |

## Evaluation, Discussion, Conclusion
| author | disposition |
|---|---|
| software testbed evaluation (granularity sweep; 141 segments; measurement identity) | **removed**; **rewritten** as the SEL-751 hardware evaluation from the frozen E\_FINAL numbers, with measured/modeled/unobserved status per result |
| (author had no separate Related Work before Conclusion in the transformed scope) | **new** Related Work (§VI) placed **before** the Conclusion; Conclusion is last |

## Net
- **Retained from the author base:** the reconnaissance→fingerprint→constraint→defense narrative and
  voice; the Ukraine anchor; the size-and-timing fingerprint framing; the per-block-CRC constraint and
  the byte-preserving-cut idea (now the carve).
- **Removed:** the software line in full (split-replay server, OpenDNP3 harness, 12,204-byte /
  141-segment numbers) as superseded and out of scope for the hardware paper.
- **New:** Background & Design Overview; the reader-first figures (native transaction, native-vs-defended
  shape, threat model, scheduler failure/fix); the control-command treatment; the hardware evaluation.
- **Order:** Introduction → Background → Threat Model → Implementation → Evaluation → Discussion →
  Related Work → Conclusion (Related Work before Conclusion).
