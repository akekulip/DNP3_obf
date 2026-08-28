# Draft: contribution list and the multi-mode framing

Written to the rules in `paper/rewrite/pipeline/DR_LIN_WRITING_GUIDE.md`: verb-first
contribution headlines, plain language, active voice, no em dashes, calibrated verbs, the arms
named Timing OFF and Obfuscated. Every number below traces to `sweep/sweep_points.csv`,
`derived/transactions.csv` or `DATASET_ROLLUP.json`. This is a draft for review; it is not yet
in the manuscript.

---

## Contribution list

**Unifies the timing-obfuscation policies into a single two-offset mechanism.** The
acknowledgment and the response are held to two independent deadlines, $T_A = t_A + D_A$ and
$T_{RESP} = T_A + D_R$. Because the acknowledgment-only and the response-only policies are the
cases $D_R \to 0$ and $D_A \to 0$ of the same mechanism, one datapath covers the family rather
than one datapath per policy.

**Decouples the delay the mechanism costs from the timing feature an observer sees.** At a
fixed budget $D_A + D_R = 24$ ms, the response time stays within 25.31 to 25.34 ms while the
cross-layer response time (CLRT) follows $D_R$ from 0.998 ms to 22.001 ms. Consequently an
operator can move the observable without changing what the defense costs, which is the control
surface the framework exposes.

**Pins the master-visible timing of three DNP3 transaction classes on a physical relay.** Across
22 sessions and 63,360 transactions, the CLRT of READ, of the SELECT phase of select-before-
operate, and of OPERATE moves from 2.116, 2.050 and 2.937 ms with the mechanism off to 4.000 ms
with it on, and the interquartile range falls from about 2.8 ms to 0.006 ms. Under
session-disjoint evaluation the CLRT no longer indicates the transaction class, since balanced
accuracy falls to 0.333 against a three-class chance of one third.

**Identifies the operating envelope of the mechanism on silicon.** The release holds while
$D_A + D_R$ stays below the fail-open horizon of 30.8 ms, and it needs about 24 ms to cover the
outstation's own response-time tail. Beyond the horizon the acknowledgment saturates at 31.07 ms
and the CLRT is no longer pinned, so the usable window is bounded on both sides and the chosen
operating point gives the tightest release, with a CLRT standard deviation of 0.007 ms.

---

## Design: the policy family

**A family, not a single policy.** The mechanism holds two packets of a DNP3 transaction, the
outstation's transport-layer acknowledgment and its application-layer response, and releases each
on a deadline the operator sets. Writing $t_A$ for the arrival of the outstation's own acknowledgment, the
acknowledgment is released at $T_A = t_A + D_A$ and the response at $T_{RESP} = T_A + D_R$. The
two offsets are independent, and the choices of $D_A$ and $D_R$ name four policies. Setting
$D_A = 0$ releases the acknowledgment immediately and holds only the response, which we call the
response-only policy (D2). Setting $D_R = 0$ holds the acknowledgment and lets the response
follow it at once, the acknowledgment-only policy (D3). Setting both above zero holds each
packet to its own deadline, the dual-deadline policy (D4). A fourth policy releases the held
acknowledgment on the arrival of the matching response rather than on a deadline, the
event-triggered policy (D1); it is driven by an event and is therefore not a parameter case of
the other three.

**Why the split matters.** The switch can only release a packet it is already holding, so the
budget $D_A + D_R$ has to exceed the outstation's own response time; the budget is therefore both
the coverage knob and the delay the mechanism adds. An observer, on the other hand, sees only
$D_R$, because the master-visible CLRT is the interval between the two releases. Since the budget
and the observable are set by different quantities, the operator can hold the cost fixed and
still choose what the timing feature looks like, and the response-only and acknowledgment-only
policies are the two ends of that choice.

---

## Implementation: what the build realizes

**One program, one policy point.** We implement the mechanism as a single P4 program on an Intel
Tofino-1 switch, and it places in 12 of the 12 available ingress stages and 6 egress stages. Fitting the pipeline
required collapsing the disposition logic into two priority-ordered ternary tables, and those
tables carry entries only for the bypass path and the dual-deadline policy. Because a policy that
has no entry never seeds the blocker reservoir, it never arms a hold, so the evaluated program
realizes the bypass path and the dual-deadline policy even though the other mode values remain
installable. As such, the response-only and acknowledgment-only policies appear only as the limits
of the dual-deadline parameters, and they are not selectable at run time.

**What we evaluate, and what we do not.** All results in the evaluation use the dual-deadline
policy. We report the parameter range the control plane accepts, $D_R$ from 1 ms to 22 ms at a
fixed budget, which approaches the acknowledgment-only policy at one end and the response-only
policy at the other, and we do not claim the exact limits $D_R = 0$ and $D_A = 0$, which the
parameter checks reject and which leave the mechanism unarmed. We do not evaluate the event-triggered policy, which the program does
not implement.

---

## The boundary to keep

Do not write that an operator selects among four implemented modes. Configuring the
response-only and acknowledgment-only modes on the evaluated program installs the parameters and
reads back correctly, yet leaves the wire timing indistinguishable from the bypass path, at
2.108 ms and 2.098 ms CLRT with the outstation's own acknowledgment near 0.55 ms, because those
gates are not in the datapath. The
defensible claim is a parameterized policy with a measured envelope, which the sweep supports.
