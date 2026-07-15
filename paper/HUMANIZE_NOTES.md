# Humanization map for the DNP3 paper

## Why the paper flags 100% AI (and why voice_check missed it)

GPTZero scores **per-token perplexity** — how predictable each word is to a language model —
not the sentence statistics `voice_check.py` measures. The draft matches your group's corpus on
every surface metric, *including* sentence-length burstiness (draft −0.335, human range −0.28
to −0.48), so rhythm is not the problem. The problem is that a model wrote it, so each word is a
high-probability continuation. That low perplexity is the signal, and no amount of statistical
matching removes it. The only reliable fix is you rewriting the prose in your own words: your
word choices are not the model's defaults, so perplexity rises and the text becomes yours.

This file tells you **where your hand matters most**. You do not need to rewrite all 3,500
words. Rewrite the ranked paragraphs below; those carry most of the detector weight (openings
and dense claim paragraphs), and once they are yours the rest matters far less.

## Rank 1 — rewrite these in your own words first (highest detector weight)

1. **Abstract** (§Abstract). Detectors weight the opening most. Rewrite it end to end from the
   facts, not by editing my sentences. A demonstrated de-smoothing version is at the bottom of
   this file — use it as a starting point, then change it again so it is yours.
2. **First introduction paragraph** ("Supervisory control and data acquisition ... not only in
   theory"). The incident-led opener is the most template-like part.
3. **Contribution bullets** (the four `**...**` items). Bullet lists in a uniform "We <verb>
   ... so ..." shape are a strong tell. Vary the internal structure of each bullet; let them
   not all start the same way.

## Rank 2 — rewrite if you have time (dense claim paragraphs)

4. **"The primitive."** paragraph (§III). The mechanism core; currently very smooth.
5. **§V-B** "The master accepts the split response ..." — the three-level equivalence paragraph.
   The "First, ... Second, ... Last, ..." cadence is regular; break it.
6. **Conclusion** — it restates the abstract, so it inherits the same predictability.

## Rank 3 — light touch is enough

Background (§II-A), Implementation (§IV), Related Work (§VII). These carry protocol facts and
citations; they read less like generated prose and matter less to the score.

## How to rewrite (the moves that raise perplexity)

- Say it your way, not the obvious way. If a sentence reads as the natural default phrasing,
  restructure it: front a different clause, split or fuse sentences, swap the subject, pick your
  second-choice verb.
- Break the cadence. I lean on "Consequently," and "The reason is that ..." on a regular beat;
  you would not. Vary or drop them.
- Use your own idiom. Your group's real papers have specific, slightly non-native constructions
  (see the mining notes) that a clean rewrite removed. Put your habits back. Do not add
  grammatical errors on purpose.
- Prefer the specific word over the safe generic one wherever it is still correct.

After you rewrite, re-run GPTZero yourself — I cannot see that score from here, so I will not
claim a number. If the venue has an AI-use policy, disclose the assistance; a flag is not proof
either way, and these tools false-positive on dense formal writing.

## Demonstrated de-smoothing rewrite (Abstract) — a starting point, then make it yours

> Passive observers of DNP3 traffic can tell one outstation from another without reading a
> single measurement. Response length, how the response breaks into frames, and the gaps
> between those frames are enough: a DNP3 outstation builds its frames the same way every time,
> so its traffic carries a stable signature of the device and its point database. Hiding that
> signature is hard. DNP3 guards every 16-byte block with a CRC that the master rechecks on
> reassembly, so touching the response bytes, padding them, or rewriting a length field tends
> to fail a CRC and get the response thrown out. We take a different route. Our primitive,
> CRC-boundary splitting, re-cuts a captured response into TCP chunks only where a CRC block
> already ends. Nothing in the DNP3 message changes and no CRC is recomputed; the chunks glue
> back to the exact original, and the live master reassembles the same application message it
> would have seen from the real device. We put this in a request-aware server that takes the
> outstation's place, answers each request with its matching captured response, and splits each
> data response along its CRC boundaries. On a two-host OpenDNP3 testbed, a large Class 0 read
> that the outstation normally sends as 9 application fragments (49 link frames, 20 TCP
> segments) went out instead as 141 chunks of no more than 18 bytes, and the master still took
> every measurement and answered with a CONFIRM over a connection that saw no retransmission and
> no reset. It held across the whole splitting range we tried. We read this as evidence that
> CRC-boundary splitting is a workable, transparent building block for an in-network layer that
> blunts passive fingerprinting of DNP3 outstations.

Note: this is still my wording. It will read as *more* human than the original because it is
less predictable, but the version that will actually clear a detector is the one you rewrite
from here in your own sentences.
