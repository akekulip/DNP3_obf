# Lin vs Philip — sentence-level style diff from the annotated Introduction (lin.png)

Ground truth: in the marked-up intro, the RED-boxed paragraphs are Dr. Lin's, the rest is Philip's.
This is the strongest signal we have — the same section, both hands, side by side. It confirms the
transcript + papers profile and pins the concrete gap. Transcribed from the image; quoted text may
carry minor OCR slips. 2026-08-19.

## Who wrote what

- **LIN — Para 1** (the opener): "Device fingerprinting has been an essential step in cyber
  reconnaissance … it is widely believed that adversaries stay in their systems for at least 6
  months to perform cyber reconnaissance."
- **LIN — the obfuscation-trend paragraph** (bottom-left → top-right box): "To disrupt device
  fingerprinting, many studies present network traffic obfuscation. Because … traffic obfuscation
  often focuses on (i) padding and splitting … and (ii) delaying … adding dummy ones … Since
  manipulating communication networks can introduce runtime overhead, recent works have begun to
  offload traffic obfuscation onto programmable network switches, which change communication
  patterns at much higher line rates than CPUs."
- **LIN — the pivot line** (he discussed it in the meeting): "Unfortunately, it is challenging, if
  not impossible, to apply these methods to device fingerprinting in ICS environments."
- **PHILIP — Para 2** (DNP3/observer): "Industrial control systems and grids run on protocols …
  a device, its type, and model can be identified from the traffic leak and behavior."
- **PHILIP — the related-work + DNP3 mechanism paragraphs** ("The standard treatment …", "For DNP3
  traffic …", "This approach to solve the leakage will not directly work …").

## The mechanical difference (this IS "his flows, mine doesn't")

**1. Lin leads sentences with an explicit logical connective; Philip juxtaposes.**
- Lin: "**Consequently,** fingerprinting shifts the focus …"; "**Because** device fingerprinting …
  relies on … features, traffic obfuscation focuses on (i) … (ii) …"; "**Since** manipulating …
  introduces overhead, recent works … offload … onto programmable switches"; "**Unfortunately,** it
  is challenging, if not impossible, to apply …". Each pivotal sentence is *led* by the connective
  that names its relation to the prior one — the "connective spine."
- Philip: sentences sit next to each other and the reader infers the link. This is exactly the
  weakness Lin named ("linking sentences … that's where I'm lacking") and the profile flagged
  (Consequently/For example/Based on = 0).

**2. Lin's sentences each do one job; Philip's overload and tangle.**
- Lin Para 1 = four clean sentences (topic → narrow to ICS → Consequently-pivot → example).
- Philip's Para 2 contains a **grammatically broken sentence**: "By learning which devices are
  communicating on the network and how they behave, **because** a control-related attack, such as a
  false-data injection attack on state estimation, only works if the attacker knows the target
  [3],[4]." — "By learning X …" never resolves to a main clause; the "because" derails it. This
  single sentence is the clearest instance of the flow problem.

**3. Lin's example serves the argument and isn't repeated; Philip re-uses it and mis-dates it.**
- Lin uses Ukraine 2015 + Stuxnet once, pointed at the **6-month reconnaissance dwell** (the paper's
  thesis).
- Philip re-introduces Ukraine in Para 2 ("**In December 2025** remote intruders reached the
  Ukrainian power grid and left 225,000 users in the dark") — **redundant** with Lin's Para 1 and a
  **date error** (the Ukraine grid attack was December **2015**).

**4. Lin uses clean parallel enumeration; Philip's parallels break mid-sentence.**
- Lin: "(i) padding and splitting …, and (ii) delaying … adding dummy ones …" — balanced.
- Philip: "Recent implementations like Ditto … every packet is padded and injects dummy packets **so
  the size, timing, and so have their prior implementations sought to obfuscate** …" — the sentence
  collapses; "so the size, timing, and so have …" is garbled.

**5. Small precision errors in Philip's parts to fix on the pass:**
- "an **overtype** can study and classify" → adversary/observer (typo).
- "padding … will violate this, and the receiver or master **will receive** the exchange" → logic
  inverted; should be **will reject / will not receive** the exchange.
- "traffic leak and behavior", "less security implementation" → tighten wording.

## The rules to carry into the rewrite (from the diff)

1. **Lead pivotal sentences with the connective** that names the logical relation
   (Consequently / Because / Since / However / Unfortunately / For example).
2. **One idea per sentence**; split Philip's overloaded sentences; guarantee every sentence has a
   subject–verb main clause (kill the "By learning …, because …" fragment class).
3. **Use each fact once, pointed at the thesis** (reconnaissance); remove the duplicate Ukraine and
   fix the date.
4. **Keep enumerations balanced** ((i)…, and (ii)…) and finish them.
5. **Plain words, consistent terms** — already mostly fine at the word layer; the work is structure
   and connective tissue, not vocabulary.
6. **Fix the precision/logic slips** listed above.

## What this does NOT change

Lin's own paragraphs are the model and stay as-is. The rewrite applies his method to Philip's
paragraphs (Para 2 and the related-work/DNP3 mechanism block) and then to the rest of the paper,
using the section-order + contribution-grammar contract in `LIN_STYLE_PROFILE.md` and the method in
`LIN_WRITING_GUIDANCE.md`.
