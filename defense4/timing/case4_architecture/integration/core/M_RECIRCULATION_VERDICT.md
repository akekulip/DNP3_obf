# M's four-register problem: the recirculation approach is refuted

Who this is for: you, reading this cold, without having watched any of the compiles. No P4 or
Tofino background assumed beyond what is explained inline.

## The one-sentence version

We tried the "split the work across two trips through the chip" fix for M's hardest remaining
problem, built it completely and honestly this time, and the chip's compiler still refuses to fit
the program. The refusal this time is a harder, more fundamental one than every previous attempt
hit, and it rules out not just this attempt but the whole approach.

## Some background you need first

M is one stage of a larger packet-processing pipeline running on a programmable network switch
(a Tofino chip). The switch compiles your program into a fixed number of sequential processing
steps, called **stages** -- think of them as numbered workbenches a packet walks past, in order,
each one allowed to do a small, fixed amount of work. M's program is allowed at most 12 stages.
Every table (a rule that reads some fields and decides what to do) gets assigned to one stage by
the compiler, not by you -- you only write the logic, the compiler decides placement.

Four pieces of **per-flow memory** (small persistent counters the switch keeps between packets,
called **registers**) are the problem. Each one has two users: an early, cheap check that reads it
(these naturally want to sit in an early stage, near the front of the line) and a later step that
actually updates it (this naturally wants to sit in a later stage, because it has to wait for other
checks to finish first). The compiler's rule is strict: **one register can only live in one stage,
period** -- every table that touches it, no matter which one, must be given that same stage number.
An early reader and a late writer on the same register are therefore pulling the stage assignment
in opposite directions, and when neither will move, the compiler gives up and the program doesn't
fit.

This has already been through seven earlier rounds of fixes (recorded in `LEDGER.md`, dated
2026-10-07, labelled m13 through m22). Three of the four registers got fixed by clever
restructuring that didn't need anything exotic. The fourth kept resisting, and a deeper pattern
emerged: there are genuinely **four** of these early-reader/late-writer conflicts, not one, and the
last one or two keep reappearing in new shapes no matter how the surrounding code is rearranged.

## The idea this document is about: recirculation

A Tofino chip can send a packet back through its own front door a second time -- out one internal
port, back in another, running the whole program again on the same packet. This is called
**recirculation**. The idea: split the work for each stubborn register into two trips. Trip one
does the early validation and sends the packet back around. Trip two, now treated by the compiler
as a *separate* pass through the pipeline, does the late update -- and because it's a fresh pass,
the update is now "early" *in its own trip*, which might let it share a stage with the other
early readers after all.

This looked promising on paper (written up in `M_STRUCTURAL_OPTIONS.md`), with one real risk
flagged in advance: nothing guarantees the compiler actually treats "early in the second trip" the
same as "early in the first trip." That risk is exactly what killed this attempt.

## What was tried, in order, with the real numbers

All of this is measured by actually running the chip's compiler, not estimated. "Fits" means 12 or
fewer stages with no errors; "doesn't fit" means the compiler refuses.

| attempt | what it did | result |
|---|---|---|
| m13 (baseline) | -- | 13 stages, doesn't fit |
| m16 | merged two chains that were wastefully run one-after-another instead of side-by-side | 13 → 9, fits |
| m17 | moved two read-only checks earlier so they'd land next to a related early check | 9 → 8, fits |
| m18 | merged two touches on the first stubborn register into one table | 8 → 10, fits, but uncovered a brand-new, fourth conflict on a different register (a wider attempt at the same idea made things much worse, 8 → 14, and was undone) |
| m19 | an unrelated, free cleanup (recompute a value from data already on hand instead of re-reading something just written) | still 10, no change to the fit question, kept because it's a genuine small win |
| m20 | tried restructuring the code a different way | 10 → 15, clearly worse, dropped |
| m21 | confirmed m19's cleanup is now the real baseline | 10, same stubborn conflict remains |
| m22 | first recirculation attempt: built the two-trip plumbing (new internal routing, a marker, a second pass), but only split the work for 2 of the 4 registers, and the second trip simply trusted whatever the first trip told it, without rechecking | doesn't fit -- and made it *worse*: now 5 separate conflicts instead of 2, with a brand-new, dominant one on the very register (reservation) that recirculation hadn't even touched yet |
| **m23 (this attempt, today)** | the full, honest version: all 4 registers split across the two trips, every late-update step actually rereads its own register's real state before trusting anything the first trip claimed (so a forged or duplicated "second trip" packet can't sneak a false update through) | **the compiler stops with an outright error, not just a bad number** |

## What exactly broke this time, in plain terms

Two of the four registers (reservation, and a second one tied to it) worked. The split genuinely
fixed them: the first trip stopped touching that memory at all, and the second trip's update step
could be placed anywhere the compiler wanted, since nothing else was competing for it.

The other two registers are a problem because they're both gated by a shared piece of state: "has
this request already been approved." Approving a request is a real, necessary check that can only
happen after several earlier steps have run (confirming the connection is allowed, confirming the
packet's format is right, and so on) -- it has to be deep in the first trip, there's no way around
that without skipping a real safety check. But the second trip, to defend against someone forging
or replaying a fake "second trip" packet, has to *recheck* that same approval right at its own
start -- which means it wants to be shallow, right at the front of the second trip.

That's one memory cell with two legitimate needs pulling in opposite directions again -- the exact
same shape of problem recirculation was supposed to fix, just reproduced on the hand-off itself.
The compiler's answer, quoted exactly from its log, was:

> Table placement was not able to allocate Ingress.confirm_activation_t, Ingress.claim_once_t in
> the same stage along with Register Ingress.activation_receipt

The detail that makes this a *harder* failure than every earlier one: the two steps' allowed
stage ranges actually **overlap** (one could sit anywhere from stage 1 to 8, the other from stage 4
to 10 -- stages 4 through 8 would work for both on paper). The compiler still couldn't do it. That
means this isn't just "these two things want different timing and we need to adjust the timing" --
it's the chip's hardware refusing to let two different kinds of memory operations share one
physical unit even when the timing lines up. There is no code rearrangement that fixes a hardware
limit.

## Why this is a refutation, not just another setback

Every earlier attempt failed because of a *timing* mismatch -- two things wanted different stage
numbers, and some clever reordering could sometimes close the gap (that's what m16, m17, and m18
did, successfully, for three of the four registers). This attempt deliberately built the strongest,
most complete version of the two-trip idea, including the security recheck the design always said
it would need, and the recheck itself recreates an unavoidable conflict, now confirmed to be a
*hardware* conflict, not a timing one. There is no variant of "split it into two trips" left to try
for this specific register pair -- the recheck the design requires is precisely what breaks it.

This is why, per the plan agreed before this attempt started, no further version of the
recirculation idea was tried after this result. The idea has had a fair, complete test.

## What's left: two honest options, both needing your decision

**Option B -- move the four registers to a different part of the chip (the "egress" side).**
Already looked at on paper before this attempt and found insufficient by itself: moving the
registers alone doesn't fix an early-reader/late-writer conflict, because the new location has the
exact same one-register-one-stage rule. It would only help if paired with a much larger
rewrite of which checks happen where -- a bigger undertaking than this attempt, for an
uncertain payoff.

**Option C -- redesign M from scratch with this four-register limitation known from day one.**
Nobody has done the design work to say whether this would actually succeed; a first attempt would
likely run into the same reread-vs-approve-early conflict unless the new design intentionally avoids it. This is the most
work and the least certain payoff of the three options.

Both of these are real engineering projects, not quick follow-ups -- each would need you to decide
it's worth the time before anyone starts. Nothing in this repository was changed or left broken to
get this answer: the working parts of M are untouched, and the failed attempt lives only in a new,
separate set of files that don't affect anything else.
