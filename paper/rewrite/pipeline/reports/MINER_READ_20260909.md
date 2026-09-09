# Reviewer read of `main.pdf` - 2026-09-09

**Artifact:** `main.pdf`, 15 pages, NDSS 2027 two-column, built 2026-09-08 21:35.
**Method:** pages rendered with `pdftoppm -r 150/300` and inspected as images; body text from
`pdftotext -layout`; numbers checked against `figures/ndss/MANUSCRIPT_VALUES.json`; voice counted
against the five papers in `~/.claude/skills/paper-voice/corpus/`. Introduction paragraphs 1-3 are
advisor-protected: no edit is proposed for them; observations go to section 7.

Ranks: **BLOCKER** (would sink the submission) / **MAJOR** / **MINOR** / **NIT**.

## 1. Figures

| Fig | Page | First cited | Placement | Verdict |
|---|---|---|---|---|
| 1 | 2, col 2 top | p2 col 1 | same page | keep |
| 2 | 3, col 1 top | p3 col 1 | same page | keep, fix clipped label |
| 3 | 4, col 2 top | p4 col 1 | same page | keep, best figure in the paper |
| 4 | 6, col 2 top | p6 col 2 | same page | keep, fix colour key |
| 5 | 8, col 2 (full column) | p8 col 1 | same page | merge (a)-(c), see below |
| 6 | 9, col 1 (full column) | p8 col 1 | next page | **cited before Fig. 5** |
| 7 | 9, col 2 top | p9 col 2 | same page | cut or shrink panel (b) |
| 8 | 10, col 1 (full column) | p10 col 2 | same page | keep |
| 9 | 12, full width top | p11 col 1 | next page | shrink; panel (b) is 90 % empty |
| 10 | 12, full width bottom | p11 col 2 | next page | keep |

All ten figures are referenced in the body. Panel labelling matches every caption I checked
((a)-(d) in Figs. 3, 5, 6, 7, 8, 9, 10 all agree with what the caption asserts).

### F-1 (MAJOR) Figure 6 is cited before Figure 5 - page 8
Page 8, col 1: *"Figure 6 shows the two READ distributions directly."* is the first figure citation
in Section VI-B. The next sentence-group is *"In Figure 5(d), we show the median CLRT..."*. IEEE and
NDSS style require figures numbered in order of first citation. Either swap the two float
definitions in `06_evaluation.tex`, or move the Figure 6 paragraph after the Figure 5 paragraphs.

### F-2 (MAJOR) Figure 2, page 3: the label "relay-facing" is clipped to "relay-facin"
Confirmed at 300 dpi. The final "g" is overrun by the `SEL-751A outstation` box. This is the first
architectural figure a reviewer sees. Also in the same figure, three dashed stubs hang below the
switch but only two lane labels ("read lane", "control lane") are given, and the white knock-out box
behind "master-facing" partly covers the red arrow.

### F-3 (MAJOR) Figure 4, page 6: the colour key contradicts the figure
The key under the figure reads *"red: master-facing (observed) green: relay side orange: blockers"*.
But the read-lane box is drawn green and titled `read lane (READ, SELECT)` - it is not "relay side" -
and the control-lane box is drawn orange although orange is declared to mean "blockers". A reviewer
reading the key will mis-parse the diagram. Either recolour the two lane boxes to neutral, or extend
the key. Secondary: the strings `release + C_target` and `release at T_0 + R` touch the right border
of their boxes at 300 dpi, and the in-figure math is set in upright text font while the body sets the
same symbols in math italic.

### F-4 (MAJOR) Figure 5, page 8: panels (a), (b), (c) are three near-identical CDFs
Panels (a) READ, (b) SELECT and (c) OPERATE are visually indistinguishable: an orange staircase
rising to ~0.9 by 4 ms and a blue step at the target. The figure spends a whole column making one
point three times. Merge (a)-(c) into one axes with three orange and three blue curves, keep (d).
That recovers about two thirds of a column, which the paper needs (X-2).

### F-5 (MINOR) Figure 5 is discussed out of panel order
Page 8 takes 5(d) first, then 5(a, b), then 5(c, d) on page 9. Reorder the panels so the narrative
runs (a)->(d).

### F-6 (MINOR) Figure 7, page 9: panel (b) carries one bit of information
Panel (b) is a flat line of 22 identical markers at 4.00 ms with the in-panel note *"note: magnified
ordinate, full span 0.20 ms"*. The caption already states the fact ("Panel (b) uses a magnified
ordinate spanning 0.20 ms"), and the body already states it ("The obfuscated median sits at the
scheduled release in every run and for every class"). Either cut panel (b) or fold it into (a) as an
inset. The italicised sentence inside the Fig. 7 caption is also the only italicised caption clause
in the paper (NIT: make it upright for consistency).

### F-7 (MINOR) Figure 9, page 12: panel (b) is ~90 % white space, and the inset floats free
The obfuscated cloud collapses into a single marker at the lower right; the rest of the panel is
empty. The emptiness is the result, so it is defensible, but at column width it reads as a rendering
failure. Two fixes: (i) draw a light rectangle at the cluster location and a leader line to the
inset, so a reader can see what the inset magnifies; (ii) reduce the figure height by ~30 %, which
also relieves page 12.

### F-8 (MINOR) Page 12 is a figure-only page
Page 12 contains Figures 9 and 10 and no body text at all, with a visible vertical gap between them.
Reviewers read this as padding. Shrinking Fig. 9 (F-7) and Fig. 5 (F-4) should let at least one of
the two rejoin its text on page 11.

### F-9 (NIT) Figure 8(c), page 10: the `C_target=4 ms` annotation baseline nearly touches the
x-axis rule between the 0 and 5 ticks. Legible at 300 dpi; raise it a few points.

### Legibility summary
No figure text is illegible at printed size. Panel letters in Figs. 5, 8, 9, 10 are the smallest type
in the paper (top-right inside the axes) but survive at 300 dpi. Figs. 5, 6, 8, 10 encode meaning in
orange/blue plus dash pattern, so they survive greyscale; **Fig. 4 does not** - its key is
colour-only.

## 2. Reading it as a reviewer

### R-1 (BLOCKER) Against the strongest adversary the paper evaluates, the defence buys 0.082
Page 11 reports, for the fixed adversary on Timing OFF, *"0.651 balanced accuracy ... using the CLRT
alone, and 0.733 using both intervals"*, and for the adaptive adversary *"it recovers to 0.651 when
the acknowledgment latency is added."* A reviewer subtracts: **0.733 -> 0.651**, a reduction of 0.082
balanced accuracy on a three-class problem with chance 0.333. The paper never performs that
subtraction, never states it, and never argues why the fixed adversary should carry the weight of the
contribution when the adaptive one is defined two pages earlier as *"the one that limits our claim"*
(page 3). This is the single question every NDSS reviewer will ask first. It is answerable - the
fixed adversary is the reconnaissance model of Formby et al. and is the deployed threat - but the
answer has to be on the page, with the delta stated, not left for the reviewer to compute.

### R-2 (BLOCKER) The conclusion uses 0.651 for two different quantities four sentences apart
Page 14: *"a classifier trained before deployment drops from 0.651 balanced accuracy to three-class
chance"* and then *"An adversary who retrains recovers to 0.651 from a second interval we do not
target."* Both numbers are correct (`clrt.A_fixed_timing_off` = 0.6515 and
`ack_clrt.B_adaptive_obfuscated` = 0.651 in the gate file), but the coincidence is fatal to a fast
read: the conclusion appears to say the defence returns the attacker to exactly where it started.
Disambiguate at every occurrence, e.g. "0.651 from the response interval alone" vs "0.651 from the
acknowledgment interval it introduces". The same collision occurs on page 3 (*"Section VI-F shows an
adversary recovering 0.651 balanced accuracy"*) and page 11 (both values in one column).

### R-3 (MAJOR) The mechanism manufactures the feature the adaptive attacker uses, and the paper
### never says so in numbers
The gate file records `residual_leakage.req_to_ack_only`: **native 0.3792, protected 0.6622**. Under
Timing OFF the request-to-acknowledgment interval is near chance; under the mechanism it becomes the
best single feature in the paper. Neither number appears anywhere in the manuscript (verified by
grep). Page 11 gives the mechanism (*"the read and control paths are timed from different events, so
their acknowledgment latencies differ"*) but not the magnitude. Figure 9(b) shows it graphically -
the horizontal offset - so a reviewer looking at the figure will infer it and then notice it is
unquantified. Report both numbers in Section VI-F; stating the cost yourself is far stronger than
having it found.

### R-4 (MAJOR) "Spread" means two different statistics in the abstract and the conclusion
Abstract, page 1: *"it settles on the configured value with a spread more than two orders of
magnitude smaller."* Conclusion, page 14: *"Its spread falls from 2.61 to 0.63 ms."* 2.61/0.63 is
4.2x - **0.6 orders of magnitude, not two**. The abstract's claim is true of the interquartile range
(2.778 -> 0.006 ms, 463x) and false of the standard deviation; the conclusion quotes the standard
deviation. As printed, the two headline statements of the paper contradict each other. Fix by naming
the statistic in both places.

### R-5 (MINOR) Page 5 is where a reader gets lost
Page 5 runs four independent constraint arguments back to back with no figure and no table: the TCP
retransmission bound, the fail-open horizon, the admissible budget, and the absence of a standard for
the target. Two numbers arrive with no derivation on the page - *"For the configuration we evaluate,
H is 30.8 ms."* and *"...a safety margin leaves an admissible budget of 24.8 ms."* Neither 30.8 nor
24.8 is in the gate file, and neither is computed anywhere the reader can follow. A three-row table
(quantity, source, value: D_A = 20 ms configured, C_target = 4 ms configured, D = 24 ms, H = 30.8 ms
control-plane, admissible 24.8 ms) would fix the page and cost four lines.

### R-6 (MINOR) The threat model retracts before it claims
Page 3 withdraws a claim before the objectives are stated: *"The second interval deserves a careful
statement, because it is easy to claim more for it than we can support."* The care is right, but the
reader meets the limitations before the goals. Move it after the RO list.

## 3. Numbers

Everything checkable against `MANUSCRIPT_VALUES.json` agrees except the items below. Verified
correct: all corpus counts (pages 8, 10); all six medians and IQRs (pages 8, 9, 11); the ACK medians
(page 11); coverage 99.900 % and 29 of 29,040 (pages 5, 10); the eight sweep targets, their measured
medians and the 25.30-25.34 ms band (page 10); added latency 22.7 / 22.6 / 21.2 ms; variance ratios
0.058 and 0.0001 with both CIs (page 8); every classifier and mutual-information number (page 11).

### N-1 (MAJOR) Page 2: *"each with a tail reaching 83 ms"* is true of READ only
Page 2, col 2: *"the median CLRT on an SEL-751A is 2.116 ms for a READ, 2.050 ms for a SELECT and
2.937 ms for an OPERATE, each with a tail reaching 83 ms."* Gate file maxima: READ 83.4579,
**SELECT 24.8311, OPERATE 24.2031**. "Each" is wrong by a factor of 3.4 for two of the three classes.

### N-2 (MAJOR) Page 9: *"one to four orders of magnitude"* is asserted of standard deviations
Page 9, col 1: *"...retains a standard deviation of 2.609 and 2.267 ms, one to four orders of
magnitude above what we measure."* Against the protected standard deviations (0.628 and 0.024) the
ratios are 4.2x and 93.5x, i.e. **0.6 to 2.0 orders**. "One to four orders" is the correct range for
the *variance* ratios (17x and 8,700x). Either say variance or fix the range.

### N-3 (MINOR) Page 3 rounds 0.821 ms to 0.9, page 2 and page 3 round it to 0.8
Page 3, col 2: *"the first interval's median differs by 0.9 ms between a poll and a control"*, but
page 2 says *"a control command takes 0.8 ms longer to answer than a poll, 2.937 ms against 2.116
ms"* and page 3 later says *"the control lane answers 0.8 ms slower than the read lane"*. 2.937 -
2.116 = 0.821. The 0.9 is the outlier; make all three 0.8.

### N-4 (MINOR) Page 10: *"all 5,280 SELECT and OPERATE exchanges returned a success status"*
The gate file has `select_total` 5,280 **and** `operate_total` 5,280, so the union is 10,560. As
written the sentence either halves the count or means "5,280 SELECT-and-OPERATE pairs", which is a
third reading. Say "all 5,280 SELECT and all 5,280 OPERATE exchanges" or "all 10,560".

### N-5 (MINOR) Page 5: *"about 23 ms per exchange"* covers the read lane, not OPERATE
Added latency is 22.66 / 22.62 ms for READ and SELECT but **21.18 ms** for OPERATE. Page 10 states
all three correctly; page 5 and the RO5 summary on page 10 (*"a measured cost of about 23 ms per
exchange"*) generalise the read-lane figure to every exchange.

### N-6 (MINOR) Body numbers the gate file does not carry
Not defects, but unsourced if a reviewer asks: 30.8 and 24.8 ms (pages 5, 7, 13); 13.5 % and the
"99.9 % within 0.10 ms of target" of Fig. 6(c, d) (page 8 - distinct from the gated 99.900 %
coverage); 24 of 26,400 (pages 9, 13); 30.571 / 31.07 / 5.503 / 7.498 / 9.507 ms (page 10); 1,560
lines of P4, 890 of Python, 12 stages, 112 tables (page 7); 29.2, 77.7, 0.19 ms (page 11). Either add
them to the gate or record in the README that the gate is not exhaustive.

## 4. Self-defeating passages

### S-1 (MAJOR) Page 7 concedes that two of the three declared modes do not work
*"The loaded build realizes the dual-deadline schedule only: its arming table admits that mode alone,
so the acknowledgment-only and response-only limits of the model are properties of the design and not
settings of this build. Configuring them left both packets unheld, and the measured interval was the
outstation's own."* Honest, and it belongs in the paper. But it is placed mid-Section V with no
framing, so it reads as "we tried the other two modes and they silently failed open." Reframe: the
model has three limits, the build implements the one that satisfies (4), and the other two are stated
as design limits rather than as configurations that were attempted and produced nothing.

### S-2 (MAJOR) Page 13 discloses that the program's timestamp registers are dead code
*"the timestamp registers it declares are never written, and every write it does declare would take
an ingress rather than an egress timestamp."* A reviewer who has just read that the artifact is 1,560
lines of P4 occupying all twelve stages will read this as unexercised code in the evaluated binary,
and will ask what else is declared and unused. Say instead what is true and bounded: the build has no
egress-timestamp write site, therefore switch-side release instants are unmeasurable with this
binary, therefore the residual is a difference between two releases.

### S-3 (MAJOR) Page 11 claims zero retransmissions; page 13 says the claim cannot be made
Page 11: *"There was no retransmission, no reset and no duplicate acknowledgment in either arm."*
Page 13: *"because the program suppresses a response retransmission that matches an already-seen
transport position, a relay-side retransmission of a held response would be absorbed inside the
switch and would not reach a master-facing capture."* The second sentence removes the evidentiary
force of the first for exactly the direction that matters (relay-side). Attach a one-clause caveat at
the page-11 claim ("master-side; relay-side retransmissions are invisible to these captures, see
Section VI-G") rather than leaving the reader to find it two pages later.

### S-4 (MINOR) The abstract concedes the residual before the result has landed
*"However, an adversary who retrains recovers much of what it lost from a second interval we do not
target, and that residual bounds what the framework achieves."* As the last substantive line of the
abstract this is the sentence a reviewer quotes back. Keep the disclosure, bound it ("recovers 0.651
of a possible 0.733"), then close on what the framework owns: the fixed reconnaissance adversary of
the threat model is left at chance.

## 5. Voice against the corpus (5 papers, `~/.claude/skills/paper-voice/corpus/`)

Measured on the extracted body text (paper: 10,503 words, 565 sentences).

| Feature | This paper | Corpus range | Verdict |
|---|---|---|---|
| Mean sentence length | 20.0 words | 19.0 - 22.9 | in range |
| "Consequently" /10k words | 16.2 (17 uses) | 10.3 - 16.8 | at the ceiling |
| "However" /10k | 3.8 (4 uses) | 3.4 - 15.9 | at the floor |
| "Note that" /10k | 4.8 (5 uses) | 0.7 - 6.7 | in range |
| "Moreover"/"Furthermore"/"Thus"/"Hence" | 0 | 0 - 6.0 | in range |
| "significantly", "novel", "state-of-the-art" | 0 | 0 - 13.7 | cleaner than corpus |
| Median caption length | 46 words (range 26 - 67) | ~7 words | **7x the corpus** |

- **V-1 (MINOR)** The "Consequently" / "However" ratio is 17:4. The corpus group runs closer to 1:1
  (RAINCOAT 14:15, 2898375 7:10). Every one of the paper's connectives pushes the argument forward;
  almost none turns it. Converting four or five "Consequently"s to "However"/plain juxtaposition
  would match the corpus and would also make the honest concessions (S-1 to S-4) read as deliberate
  turns rather than as interruptions.
- **V-2 (MINOR, judgement call)** Captions are 26-67 words where the corpus writes 2-11 ("Raincoat
  approach."). Self-contained captions are better modern NDSS practice, so do not shorten to corpus
  length; but Fig. 3's 67-word caption restates the body and can drop to ~45.
- **V-3 (in range)** Contribution grammar is verb-first and matches the house style: "Designs a
  timing-obfuscation framework...", "Realizes the framework on an Intel Tofino-1...", "Evaluates the
  realization against a physical SEL-751A relay..." (page 2). No firstness claim anywhere, per repo
  policy. No em dashes found.
- **V-4 (NIT)** "Since" is used twice as a causal connective (page 1); the corpus uses it zero times
  across all five papers. Both occurrences are inside the protected introduction.

## 6. What an NDSS / CCS reviewer expects and does not find

- **X-1 (BLOCKER, verify against the CfP)** No **Ethics Considerations** section and no **Open
  Science / artifact availability** statement. NDSS has required both as mandatory sections since the
  2024 cycle. Neither string appears in the PDF. Desk-reject risk. What would settle it: the NDSS
  2027 call for papers.
- **X-2 (BLOCKER, verify against the CfP)** **Length.** Body text runs to page 14 (Conclusion ends
  mid-page 14); references occupy page 15. NDSS's limit has been 13 pages excluding references. If
  that holds for 2027 the paper is one page over. F-4 (merge Fig. 5 panels) and F-7 (shrink Fig. 9)
  recover roughly that much.
- **X-3 (MAJOR)** **No baseline comparison.** The paper measures itself against "Timing OFF" only.
  A reviewer will ask why not a constant-rate release, a uniform random delay, or the switch-based
  obfuscators cited in Section VII (Ditto, Minos). Even a one-paragraph analytical comparison of what
  a random delay does to the same three-class classifier would blunt this.
- **X-4 (MAJOR)** **No load or scale evaluation.** One relay, one master, 480 exchanges per capture.
  Nothing shows what happens with N outstations sharing the pipeline, whether 64 recirculating
  blockers per lane scale, or what recirculation costs in bandwidth. Section V-D gives resource
  counts in prose; a reviewer expects a table and a concurrent-transaction limit.
- **X-5 (MINOR)** **No table anywhere in the paper.** Ten figures, zero tables. Resource usage,
  the parameter set, and the classifier results are all natural tables and would read faster.
- **X-6 (MINOR)** The adaptive attacker is one Random Forest on two hand-chosen features. The paper
  says so (page 11), but a reviewer will want a sequence-aware attacker before accepting 0.651 as the
  residual bound.

## 7. Author review notes - protected introduction (paragraphs 1-3, page 1). No edits proposed.

Three items a reviewer will see; forwarding them to the advisor rather than editing:

1. `sections/01_introduction.tex:46` - *"exposing the the underlying traffic pattern"*: doubled "the".
2. `sections/01_introduction.tex:41` - *"Since each vendors may choose different materials..."*:
   "each vendors" is a number disagreement.
3. `sections/01_introduction.tex:45` - *"despite ICS network protocols may provide security
   features"*: "despite" does not take a finite clause.

## 8. Ranked summary

**BLOCKER** - R-1 (0.733 -> 0.651 delta never stated), R-2 (0.651 used for two quantities in the
conclusion), X-1 (no ethics / open-science section), X-2 (one page over the likely limit).

**MAJOR** - R-3 (defence creates the 0.379 -> 0.662 feature, unreported), R-4 ("spread" contradicts
itself between abstract and conclusion), N-1 (83 ms tail claimed for all three classes), N-2 ("one to
four orders of magnitude" of standard deviations), S-1, S-2, S-3, F-1 (Fig. 6 cited before Fig. 5),
F-2 (clipped label in Fig. 2), F-3 (Fig. 4 colour key contradicts the figure), F-4 (three redundant
CDF panels), X-3, X-4.

**MINOR / NIT** - N-3, N-4, N-5, N-6, R-5, R-6, S-4, F-5 to F-9, V-1, V-2, V-4, X-5, X-6.
