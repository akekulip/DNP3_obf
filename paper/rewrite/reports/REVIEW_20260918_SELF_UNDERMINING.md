<!--
Rescued from the Claude session store on 2026-09-19: a second adversarial pass over the
campaign_v1 manuscript, recorded here because it existed only in a session transcript.
-->

Worst first. Section numbers follow the source order: §2 Background, §3 Threat Model, §4 Design, §5 Implementation, §6 Evaluation, §7 Related Work, §8 Conclusion.

**Damage-ordered findings**

1. **Abstract, last two sentences** ("that residual bounds what the design achieves"; "for a single device at a single configuration"). Categories 6 and 4. The abstract ends on a concession. "Much of that" sounds worse than the actual number, 0.782. "Single configuration" is also false by the paper's own account: §6.4 sweeps 16 policies and the tail sweep covers 18 budgets. Reviewers repeat what the abstract says about itself. Fix: give 0.782 and its source once as a number, add the 1 to 22 ms result at a fixed 25.3 ms response time, limit "one configuration" to the classifier, and end on the programmable-policy result.

2. **§6.5 RO3** ("The mechanism leaves that feature in place, and it creates it"; "That margin stays small, and we report it as measured"). Categories 1 and 4. This gives Reviewer 2 a ready line: "net benefit 0.038." Your own confusion shape points to a different reading: OPERATE is separable while SELECT stays confused with READ. So the retrained model is picking up which lane anchored the transaction, and the plaintext function code already names that. Fix: one paragraph. The CLRT is suppressed under both conditions (0.333 and 0.347). The retrained model reaches 0.782 from the gap between the request anchor and the acknowledgment anchor. A common anchor removes that gap. Drop the "net effect 0.820 to 0.782" arithmetic and the "We state the cost" opener.

3. **0.782 is stated about eight times**: the abstract, §3 twice ("the second limits our claim"), §6.5 twice, §6.6 "What RO3 Establishes", §8 "Three bounds", and Ethics. Category 2. Keep it in three places only: the abstract, RO3, and one line in the limitations. In §3 it gives away a result before the design has been presented.

4. **Ethics** ("One effect works against the defender."). Categories 4 and 2. Placed in Ethics, it reads like a disclosed flaw. Fix: delete it. RO3 already carries the fact.

5. **§8 Conclusion** ("Three bounds limit the result."). Categories 6 and 2. The paper ends on "Attributing the residual would take…", and this section also brings in new tail detail ("does not follow the budget smoothly"). Fix: end on what the operator can set. If you keep the limits, give them one clause.

6. **§2** ("what timing adds is a second, device-derived signature of that operation"). Categories 4 and 6. This concedes that the class RO3 predicts is already in plaintext, which invites "RO3 defends a moot channel." Fix: present the class-conditioned timing as the device's per-operation timing profile, which is what a fingerprinter builds. RO3 then tests whether that profile survives.

7. **§6.1** ("Configuration provenance is partial."). Categories 3 and 2. It sits ahead of the Dataset paragraph, so the evaluation opens on a caveat. Fix: move it to Limitations as one sentence. Also note that the tail sweep read back the installed policy for every block (line 174), so the gap covers campaign_v1 and the policy sweep only. That makes it smaller than it now sounds.

8. **§6.2 RO1** ("A tail remains, and it falls on one side only"). Category 1. Three lines later the paper says "Below the configured value the distribution keeps mass as well", which contradicts it. Two more defensive asides sit nearby: "Low spread at the wrong interval would not be normalization" opens a paragraph with a negative, and "we do not present it as a measured arm". Fix: open with "99.9% within 0.10 ms". Give the tail one sentence with its numbers, and drop the counterfactual disclaimer, since "translated" already says it is analytic.

9. **The admission horizon H is disclaimed six times**: §4.2 ("names no release deadline the hardware guarantees"), §5.3, §5.5 ("without enforcing it"), §6.4 ("yet it remains no evidence that the data plane enforces H") and §6.6. Category 2. Fix: say it once in §5.5 and once in the limitations.

10. **§6.6** ("The control lane has a second and worse case"), plus three paragraphs on a probe that "does not show that duplicate suppression preserves loss recovery". Categories 2 and 4. The same problem is stated again in §5.3, whose title "Failing open" promises a property and then turns: "One path behaves differently". Fix: write one limitation paragraph. Exactly-once delivery is not provided. A retransmitted OPERATE with a spent generation is dropped, which comes from reading the source and was not exercised in the campaign. Remove "worse" and move the probe to the artifact.

11. **"Transaction class, not device" is stated five times**: the abstract, §3, §6.6, §7 ("we do not demonstrate that two devices become indistinguishable") and §8. Categories 2 and 3. §3 opens this point with a negative: "Our testbed holds one outstation, so no second device exists". Fix: open §3 positively with the three-class problem, keep one limitation line, and drop it from Related Work.

12. **§6.4 RO5, costs** ("a real operational cost to weigh against"; "so it belongs to the cost"; "would have to be rechecked"). Categories 5 and 1. Fix: frame the costs as headroom. The median rises by 21 to 23 ms, below the release budget D. The longest acknowledgment wait is 29.2 ms against the 201 ms repeat threshold. No select went stale, and no frame or byte is added.

13. **§3 and Introduction, defensive asides** ("we report it as measured"; "The narrower interval still merits defending"; "These are two case studies of one mechanism, not two systems"). Category 1. Each answers an objection nobody has raised yet. Fix: delete them.

14. **§6.5, mutual information** ("Failing to reject falls short of evidence for zero…"). Category 1. Fix: "p = 0.084, within the permutation null" is enough.

15. **§4.1** ("keeps the identity honest"; "full D_R remains unmeasured"). Categories 2 and 3. These are measurement caveats sitting inside the Design section. Fix: move them to §6 or the limitations.

16. **Structure.** Category 6. The contributions carry no numbers ("what the policy can and cannot cover"), and the first one has no label. The evaluation runs RO1, RO2, RO4, RO5, RO3, while §3 lists them in order RO1 to RO5, so the security result comes last and ends on a concession.

**Where each required boundary should appear once**
- Arms and timing-only scope: §6.1.
- Transaction class only, SEL-751A and Tofino-1, Random-Forest attacker: §3, plus one limitation line.
- 0.782: abstract and RO3.
- J and the relay-facing release unobserved: the "What RO2 Rests On" limitation.
- Exactly-once not provided: one limitation paragraph.
- Provenance partial: one limitation sentence.

**The argument's overall shape**

The paper's one-sentence claim should be something like this: a switch that releases the outstation's own acknowledgment and response against one shared anchor turns the cross-layer response time into a value the operator sets (median 4.000 ms, interquartile range 0.006 ms, any value from 1 to 22 ms at a constant 25.3 ms response time), without changing a byte or an endpoint, and leaves a fixed timing classifier at chance.

The current structure works against that claim in four places:
- **The abstract and conclusion close on limits** rather than on the result.
- **The strongest result is buried.** Separating the observed interval from the added cost (§6.4 Figure 5b) appears in neither the abstract nor the conclusion.
- **The security result is placed last** and framed as a net loss.
- **The limitations section outweighs several results sections**, while its content is also spread across the Threat Model, Design, Implementation, Related Work, Conclusion and Ethics.

Each boundary should be stated once, with its number, in the section it belongs to. Every other mention costs credibility without adding honesty.

Files reviewed (sections 00 to 09): `/home/philip/Projects/DNP3/paper/rewrite/sections/`. I read the `.tex` sources, not the compiled `main.pdf`.