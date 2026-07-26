# Evidence reconciliation — the two circulating CLRT result sets

Scope: settle, from the raw packet captures alone, which of the two incompatible result sets in
circulation is correct. Nothing in this document is inherited from a prior report. Every number was
recomputed this session from the four pcaps in `evidence/corrected_v2/pcaps/`, under two
independently written extraction pipelines that were then cross-checked against each other.

Machine-readable form of everything below: `evidence/corrected_v2/reconciliation.json`.

---

## 1. Verdict

**Both result sets are real, both are correct, and they describe two different live runs.** Neither is
a fabrication and neither supersedes the other. The defect is not in the measurements. It is that a
single shipped bundle quotes one campaign's numbers in its prose while shipping the other campaign's
packet captures as its evidence, and labels neither.

| circulating set | belongs to | pcaps | recomputed this session |
|---|---|---|---|
| n = 10 / 11, native sd 6.261 ms, protected sd 0.028 ms, "224x tighter" | **campaign A** | `campaignA_native_n10.pcap`, `campaignA_protected_n11.pcap` | exact match |
| n = 13 / 13, native max 37.215 ms, native sd 9.514 ms, "329x tighter" | **campaign B** | `campaignB_native_n13.pcap`, `campaignB_protected_n13.pcap` | exact match |

Campaign A ran at 17:55:57 and 18:02:08 on 2026-07-25. Campaign B ran at 18:16:42 and 18:22:26 the
same evening, about twenty minutes later, against the same relay.

The decisive fact is a hash comparison. The published bundle at `deliverables/dnp3_inline_live/`
ships exactly two pcaps, `evidence/native_inline2.pcap` and `evidence/prot_inline.pcap`. Their
SHA-256 digests are `c2ed9fc1…` and `cba20f38…`, which are the **campaign A** pair. Neither campaign
B capture appears anywhere under `deliverables/` or `archive/`. Yet `index.html`, `README.md`,
`source/report_source.md`, `interactive.html` and `run/README.md` in that same bundle all carry
**campaign B** statistics as the headline result. Until the campaign B captures were recovered into
`evidence/corrected_v2/pcaps/` this session, every campaign B number in the published report was
unsupported by any packet capture shipped alongside it.

---

## 2. Method, and why the numbers can be trusted

CLRT is defined as `t(DNP3 RESPONSE, application function 129) − t(the qualifying pure TCP ACK)`,
observed at the master-side capture point, following Formby et al. (NDSS 2016).

Pairing is exact, never by timing proximity. For each transaction the extraction requires all of:

* a READ, meaning a master-to-outstation segment whose DNP3 application function code is 1;
* an expected acknowledgement number computed as `READ.tcp.seq_raw + READ.tcp.len`;
* a qualifying ACK, meaning the first outstation-to-master segment after that READ with
  `tcp.len == 0`, the ACK flag set, no SYN, FIN or RST, and `tcp.ack_raw` equal to the expected
  acknowledgement number;
* a RESPONSE, meaning the first outstation-to-master segment after that ACK carrying DNP3
  application function code 129.

The scan for both the ACK and the RESPONSE stops at the next READ, so a later transaction's packets
can never be borrowed by an earlier one. Every transaction is additionally checked for DNP3
application-sequence agreement between request and response, mirrored DNP3 link addresses, a valid
CRC-16/DNP link header on both frames, and continuity of the outstation byte stream. Anything failing
a check is recorded as a validation failure rather than guessed at.

Two pipelines were written, deliberately sharing nothing that could hide a common bug.

* **Pipeline (a)**, `evidence/corrected_v2/scripts/analyze_live_clrt.py`, does not use Wireshark's
  DNP3 dissector at all. It decodes the DNP3 link, transport and application headers itself from
  `tcp.payload` bytes and validates the link-header CRC. It uses raw TCP sequence numbers and keeps
  every timestamp as an integer nanosecond count, so no floating-point error enters before the final
  subtraction.
* **Pipeline (b)**, `evidence/corrected_v2/scripts/pipeline_b_tshark.sh`, is tshark and awk only. It
  trusts the DNP3 dissector, uses relative sequence numbers and `tcp.nxtseq` instead of raw sequence
  arithmetic, uses `frame.time_relative` instead of `frame.time_epoch`, reads TCP flags as separate
  boolean fields rather than a bitmask, and keys the pairing on the DNP3 application sequence number
  rather than on a positional scan.

**The two pipelines agree on all 47 transactions in all four captures**: same READ, ACK and RESPONSE
frame numbers, and CLRT values agreeing to within 1 ns, which is the timestamp resolution of the
captures. There are zero ambiguous transactions and zero validation failures. Full detail in
`evidence/corrected_v2/transactions/pipeline_crosscheck.json`.

As a third check, the bundle's own `deliverables/dnp3_inline_live/run/clrt.py` was run unmodified on
all four captures. It reproduces its published output exactly, including the campaign B strip plot
with its `-0.39` to `38.66 ms` axis.

Two conventions matter and were both confirmed against the published tool rather than assumed. The
published standard deviations are **population** standard deviations, `ddof = 0`; `clrt.py` calls
`statistics.pstdev` at lines 103 and 146. The published histogram uses **bin width 1 ms, bin origin
0.0 ms, half-open intervals `[k·w, (k+1)·w)` with `k = floor(v / w)`**; `clrt.py` line 65 computes
`int(math.floor(v / bin_ms))` with `BIN_MS = 1.0`. Both conventions are used throughout this report,
and both the population and sample standard deviations are given so the choice is visible.

---

## 3. Recomputed statistics

All values in milliseconds. Percentiles use linear interpolation between order statistics. MAD is the
median absolute deviation from the median, without consistency scaling. Bootstrap confidence
intervals are nonparametric percentile bootstraps at 95 percent, **20,000 iterations**, fixed seed
**20260725** (seed + 1 for the standard-deviation intervals), resampling with replacement via
`random.Random(seed).randrange(n)`.

| series | n | min | max | mean | median | sd (pop, ddof 0) | sd (sample, ddof 1) | range | MAD |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| A native | 10 | 1.061187 | 22.660154 | 4.095775 | 2.125565 | **6.261538** | 6.600241 | 21.598967 | 1.032428 |
| A protected | 11 | 24.998041 | 25.077301 | 25.048618 | 25.056966 | **0.027916** | 0.029278 | 0.079260 | 0.017169 |
| B native | 13 | 1.060807 | 37.215337 | 5.176772 | 1.602638 | **9.513555** | 9.902022 | 36.154530 | 0.522761 |
| B protected | 13 | 25.002590 | 25.082605 | 25.054208 | 25.069842 | **0.028960** | 0.030143 | 0.080015 | 0.012325 |

| series | p5 | p25 | p75 | p95 | p99 | bootstrap 95% CI, median | bootstrap 95% CI, sd (pop) |
|---|--:|--:|--:|--:|--:|---|---|
| A native | 1.0710 | 1.1286 | 3.0718 | 14.2710 | 20.9823 | [1.103220, 3.355322] | [0.534056, 9.615785] |
| A protected | 24.9999 | 25.0330 | 25.0707 | 25.0769 | 25.0772 | [25.018286, 25.074135] | [0.010898, 0.033669] |
| B native | 1.0662 | 1.0846 | 3.5962 | 20.3217 | 33.8366 | [1.084586, 3.596183] | [0.895414, 14.986011] |
| B protected | 25.0052 | 25.0315 | 25.0747 | 25.0823 | 25.0826 | [25.031549, 25.074729] | [0.015640, 0.033859] |

The native bootstrap intervals are the honest reading of these samples. Campaign B native has a
95 percent interval for its own standard deviation of 0.895 to 14.986 ms, a seventeen-fold span,
because the statistic is carried by a single observation that the resample either includes or does
not. At n = 10 to 13 these standard deviations are not stable quantities, and the ratios built from
them inherit that instability. This is a sample-size problem, not an extraction problem.

---

## 4. Observer entropy, tied to a stated resolution

Bin origin 0.0 ms, half-open intervals `[k·w, (k+1)·w)`. Each cell gives occupied bins and Shannon
entropy in bits.

| series | 10 µs | 50 µs | 100 µs | 500 µs | 1 ms |
|---|---|---|---|---|---|
| A native | 10 bins, 3.3219 | 9 bins, 3.1219 | 9 bins, 3.1219 | 5 bins, 2.0464 | 5 bins, 2.0464 |
| A protected | 7 bins, 2.6635 | 3 bins, 1.2407 | 2 bins, **0.4395** | 2 bins, **0.4395** | 2 bins, **0.4395** |
| B native | 11 bins, 3.3927 | 9 bins, 2.8074 | 8 bins, 2.6535 | 7 bins, 2.3535 | 6 bins, **2.0349** |
| B protected | 7 bins, 2.6235 | 2 bins, 0.8905 | 1 bin, **0.0000** | 1 bin, **0.0000** | 1 bin, **0.0000** |

Two things follow, and the report should say both.

The published "6 occupied bins, 2.035 bits" for native and "1 bin, 0.000 bits" for protected are
**campaign B at 1 ms bins**, and they reproduce exactly. Campaign B protected reaches zero entropy at
100 µs, 500 µs and 1 ms.

But zero entropy is not a property of the defense, it is a property of the defense **and** the
observer's chosen resolution **and** the bin origin. At 50 µs campaign B protected occupies two bins
and carries 0.8905 bits. At 10 µs it occupies seven bins and carries 2.6235 bits, against a
theoretical maximum of 3.7004 bits for thirteen samples. An observer who bins more finely than about
100 µs still recovers information.

Campaign A protected never reaches zero at any tested resolution. Its floor is 0.4395 bits across two
bins, because its minimum, 24.998041 ms, falls just below the 25 ms bin edge and lands in bin 24
while the other ten samples land in bin 25. This is a bin-origin artifact, not a difference in the
defense, and it demonstrates how fragile the zero-entropy result is: an 84.6 µs spread straddling a
bin boundary is the difference between "0.000 bits" and "0.4395 bits". Running the published
`clrt.py` on the published bundle's own pcaps prints `2 occupied, entropy 0.439 bits`, not the
0.000 bits the bundle's prose claims.

---

## 5. The 37.215 ms sample

**Genuine.** It is not a rounding artifact, a mispairing, or a duplicated record.

* File: `evidence/corrected_v2/pcaps/campaignB_native_n13.pcap`, SHA-256 `2065ff7a…`
* Qualifying pure TCP ACK: **frame 5**, `tcp.len = 0`, `tcp.ack_raw = 2528248577`, timestamp
  `1785017802.500778247`
* DNP3 RESPONSE, function 129: **frame 6**, `tcp.len = 54`, timestamp `1785017802.537993584`
* CLRT: **37.215337 ms**
* DNP3 application sequence 0, that is, the first transaction of the connection

Both pipelines and the published `clrt.py` agree on it independently. It exceeds G = 25 ms by
**12.215337 ms**.

---

## 6. Protection-miss candidates

A protection-miss candidate is a **native** transaction whose undefended CLRT already exceeded
G = 25 ms. A hold-to-deadline scheme cannot delay a response that arrived after its own deadline, so
such a transaction passes through unprotected with no wire-visible symptom. The flag is not
meaningful on a protected series, where a CLRT marginally above G is the intended outcome.

| campaign | native protection-miss candidates |
|---|---|
| A | **none.** Maximum native CLRT 22.660154 ms, which is 2.339846 ms below G |
| B | **one.** Transaction 0, DNP3 application sequence 0, ACK frame 5 to RESPONSE frame 6, 37.215337 ms, exceeding G by 12.215337 ms |

The sharper point is in section 8, finding F3: no *protected* transaction in either campaign exceeds
25.082605 ms, so this failure mode has never actually been observed under protection.

---

## 7. Claim-by-claim ledger

Fourteen entries, with per-claim detail and file:line provenance in
`evidence/corrected_v2/reconciliation.json` under `claim_ledger`.

| id | published claim | origin | verdict |
|---|---|---|---|
| C1 | native n=10, median 2.126, mean 4.096, min 1.061, max 22.660, sd 6.261 ms | A | reproduced exactly |
| C2 | protected n=11, median 25.057, mean 25.049, min 24.998, max 25.077, sd 0.028 ms | A | reproduced exactly |
| C3 | 6.261 → 0.028 ms sd, "224x tighter", range 21.6 → 0.079 ms | A | reproduced, ratio 224.2999 |
| C4 | native n=13, median 1.603, min 1.061, max 37.215, sd 9.514 ms, 6 bins, 2.035 bits | B | reproduced exactly |
| C5 | protected n=13, median 25.070, min 25.003, max 25.083, sd 0.029 ms, 1 bin, 0.000 bits | B | statistics exact; entropy half is resolution-dependent |
| C6 | "329x tighter", range 36.155 → 0.080 ms | B | reproduced, ratio 328.5052 |
| C7 | one native transaction took 37.215 ms, above G = 25 ms | B | reproduced, correctly characterised |
| C8 | "the entropy of the timing channel drops to 0.000 bits", unqualified | B asserted, A shipped | **not supported** |
| C9 | "Eleven samples occupy six separate 1 ms bins" | matches nothing | **not supported** |
| C10 | "Every protected transaction lands on G = 25 ms" | A | **not supported** |
| C11 | "All responses 54 bytes in both runs" | A | true at the TCP layer; conflates layers |
| C12 | `_ws.malformed = 0` and `tcp.analysis.flags = 0` in both captures | A | reproduced, and extends to all four |
| C13 | "native max 22.660 ms, only 2.3 ms of headroom" | A | arithmetically right, misleading at programme level |
| C14 | campaign B statistics presented beside campaign A evidence files | mixed | **not supported**, confirmed by hash |

### The two ratios

Both are reproducible, and both depend on conventions worth stating.

**224x** recomputes as **224.2999**, using population standard deviations, 6.261538 / 0.027916. Under
the sample standard deviation the same comparison gives 225.4299, which would have been published as
225. The published figure therefore pins the convention to `ddof = 0`. Note also that this ratio
compares an n = 10 arm against an n = 11 arm.

**329x** recomputes as **328.5052**, from 9.513555 / 0.028960. It reaches 329 only by rounding half
up; 328 is an equally defensible rendering of the same measurement. Under the sample standard
deviation it is also 328.5052, since the `(n−1)/n` correction cancels between two arms of equal
n = 13, so this one is insensitive to the convention.

---

## 8. Claims not supported by any shipped pcap

**Every campaign B number, until this session.** The published bundle ships only the campaign A pair,
confirmed by SHA-256. The n = 13/13 table, native sd 9.514 ms, native max 37.215 ms, median
1.603 ms, six occupied bins, 2.035 bits, protected one bin and 0.000 bits, and the 329x headline all
originate in captures that bundle does not contain. They are now supported, but only by
`campaignB_native_n13.pcap` and `campaignB_protected_n13.pcap` as recovered into
`evidence/corrected_v2/pcaps/`. Any future bundle quoting those numbers must ship those two files.

**"The entropy of the timing channel drops to 0.000 bits", stated without a resolution.** Appears at
`deliverables/dnp3_inline_live/README.md:9`, `index.html:217-218`, `interactive.html:400-401` and
`interactive.html:578`. It is false for the pcaps that bundle ships: campaign A protected measures
0.4395 bits across two bins at 1 ms, and never reaches zero at 10 µs, 50 µs, 100 µs, 500 µs or 1 ms.
It is true for campaign B protected only at 100 µs and coarser. The bundle's own tool, run on the
bundle's own evidence, contradicts the bundle's own prose.

**"Eleven samples occupy six separate 1 ms bins — about 2 bits of information."**
`deliverables/dnp3_inline_live/interactive.html:169` and the identical line in the archive copy. No
measured series matches this. Campaign A native is 10 samples in 5 bins carrying 2.0464 bits.
Campaign B native is 13 samples in 6 bins carrying 2.0349 bits. The sentence pairs campaign A's
*protected* sample count with campaign B's *native* bin count, which is a third combination
belonging to neither run.

**"Every protected transaction lands on G = 25 ms."** `evidence/RESULT.md:24` in both the shipped and
archived bundles. Campaign A protected transaction 6, ACK frame 29 to RESPONSE frame 30, measures
24.998041 ms, which is below G. Across both campaigns the protected observations span 24.998041 to
25.082605 ms, an 84.6 µs spread around G. This confirms correction 10 in `CORRECTIONS_REGISTER.md`
with specific frame numbers.

**"Native max observed 22.660 ms … only 2.3 ms of headroom."** `evidence/RESULT.md:38`. Correct for
campaign A read in isolation, but presented as a property of the relay. Twenty minutes later the same
relay produced 37.215 ms, which is 12.215 ms *above* G rather than 2.3 ms below it. As a
programme-level statement about G selection it understates the exposure by more than a factor of
five.

---

## 9. Additional findings from the captures

These were not among the disputed claims but bear directly on how much the comparison can carry.

**F1 — the campaign A arms were not polled at the same rate.** The master's idle gap between one
DNP3 response and its next READ has a median of **300.436 ms in campaign A native** but
**400.451 ms in campaign A protected**. Campaign B used 400.435 ms and 400.427 ms, matched. Relay
response latency can depend on how long the link has been idle, so campaign A's native and protected
arms are not a like-for-like comparison, while campaign B's are. This sharpens correction 13 in
`CORRECTIONS_REGISTER.md` from a general observation to a measured 100 ms cadence difference.

**F2 — the entire native spread is one cold-start transaction, in both campaigns.** Excluding
transaction 0 from every series:

| campaign | native sd, all | native sd, warm only | protected sd, warm only | published ratio | warm-only ratio |
|---|--:|--:|--:|--:|--:|
| A | 6.261538 (n=10) | **1.007720** (n=9) | 0.029223 (n=10) | 224x | **34.48x** |
| B | 9.513555 (n=13) | **2.320054** (n=12) | 0.028948 (n=12) | 329x | **80.14x** |

The headline collapse ratios are therefore statements about a single cold first poll per run, not
about steady-state relay jitter. The defense's effect on warm traffic is real but roughly an order of
magnitude smaller than advertised. Note that `CORRECTIONS_REGISTER.md` correction 14 already flags
that these observations were "treated as outliers to warm away rather than characterised"; this
quantifies exactly how much of the result rests on them.

**F3 — the failure mode the native data proves exists has never been exercised under protection.**
No protected transaction in either campaign exceeds 25.082605 ms. A hold-to-deadline release cannot
pull a 37.215 ms response back to 25 ms, so had the relay been in the same state during campaign B
protected as during campaign B native, a sample near 37 ms would necessarily have appeared in the
protected capture. None did. The relay was therefore not in a matched state across the two arms, and
the ">G passes through silently" failure has no measurement anywhere in the shipped evidence. It is
correctly *predicted* by the campaign B native data and never *observed* under protection.

**F4 — the tool that produced the published numbers does not do exact pairing.**
`deliverables/dnp3_inline_live/run/clrt.py:42-58` takes any zero-length packet from the relay's IP
address as the ACK and the next non-zero-length packet from that address as the response. It checks
no TCP sequence or acknowledgement number, does not exclude SYN, FIN or RST, is not TCP-stream aware,
and never confirms the payload is a DNP3 function 129 response. On these four clean captures it
produces the right answer, which the exact pipelines here independently confirm, but it is correct by
luck of the capture rather than by construction. A retransmission, a segmented response, a second
stream, or a relay-side keepalive would mispair it silently. The SYN-ACK and the closing FIN
exchanges only fail to corrupt the result because the tool overwrites its pending ACK each time it
sees another zero-length packet.

**F5 — `clrt.py` loses timestamp precision, though not enough to matter here.** It parses
`frame.time_epoch` with `float()` at line 48, and at these epoch magnitudes a float64 unit in the
last place is about 238 ns. Measured worst-case disagreement against integer-nanosecond arithmetic is
**197 ns**, which is below 1 µs and so cannot change any figure quoted to three decimal places in
milliseconds. Recorded so it is not rediscovered.

**F6 — the DNP3 outstation link address on this relay is 0, not 10.** All four captures show master
link address 1 and outstation link address 0, decoded from `tcp.payload` bytes with a validated
CRC-16/DNP link header check on every frame. `CLAUDE.md:134`, `dnp3_split_harness/README.md:75` and
`RESUME_STATE.md:1418` all state outstation = 10. That is correct for the software harness but not
for the physical SEL-751 on this testbed.

**Integrity checks that do hold.** In all four captures: zero retransmissions, zero duplicate ACKs,
zero out-of-order segments, zero lost-segment indications, `tcp.analysis.flags` empty on every
packet, `_ws.malformed` zero, and every DNP3 link-header CRC valid. Every response is
`tcp.len = 54`, `ip.len = 106`, `frame.len = 120`, `tcp.hdr_len = 32`, with no variation anywhere.
Each capture is a single TCP stream, opened with a SYN and closed cleanly with FIN, with no RST.

---

## 10. Files produced

Written by this analysis, all under `evidence/corrected_v2/` plus this report at the repository root.
No pcap was modified; the four SHA-256 digests are unchanged from the inventory.

```
evidence/corrected_v2/
├── reconciliation.json                          machine-readable form of this report
├── scripts/
│   ├── analyze_live_clrt.py                     pipeline (a): own DNP3 byte decoder, exact pairing
│   ├── pipeline_b_tshark.sh                     pipeline (b): dissector + awk, app-sequence keyed
│   ├── crosscheck_pipelines.py                  transaction-by-transaction comparison of (a) and (b)
│   └── build_reconciliation.py                  builds reconciliation.json from the summaries
└── transactions/
    ├── pipeline_crosscheck.json                 0 disagreements across 47 transactions
    ├── campaignA/
    │   ├── native_transactions.csv              10 rows, 47 columns
    │   ├── native_summary.json
    │   ├── protected_transactions.csv           11 rows
    │   └── protected_summary.json
    └── campaignB/
        ├── native_transactions.csv              13 rows
        ├── native_summary.json
        ├── protected_transactions.csv           13 rows
        └── protected_summary.json
```

Each transactions CSV carries, per transaction: TCP stream; READ frame number, timestamp, sequence,
length, header length, IP length and frame length; the expected acknowledgement number; the ACK frame
number, timestamp, sequence and acknowledgement; the RESPONSE frame number, timestamp, sequence,
acknowledgement and sizes; DNP3 function code, application sequence, transport sequence, source and
destination link addresses and link-header CRC validity for both request and response; CLRT in
milliseconds and in exact nanoseconds; the READ-to-ACK and inter-poll intervals; retransmission
flags; `tcp.analysis.flags`; `_ws.malformed`; the protection-miss flag; and explicit ambiguity and
validation-failure fields. Those last two are empty for all 47 transactions.

To reproduce:

```bash
cd evidence/corrected_v2
python3 scripts/analyze_live_clrt.py --pcap pcaps/campaignA_native_n10.pcap    --label native    --outdir transactions/campaignA
python3 scripts/analyze_live_clrt.py --pcap pcaps/campaignA_protected_n11.pcap --label protected --outdir transactions/campaignA
python3 scripts/analyze_live_clrt.py --pcap pcaps/campaignB_native_n13.pcap    --label native    --outdir transactions/campaignB
python3 scripts/analyze_live_clrt.py --pcap pcaps/campaignB_protected_n13.pcap --label protected --outdir transactions/campaignB
python3 scripts/crosscheck_pipelines.py
python3 scripts/build_reconciliation.py
```

Environment: TShark 4.4.9, Python 3.8.10, analysis run 2026-07-25. No pcap was modified; no lab host
was contacted.
