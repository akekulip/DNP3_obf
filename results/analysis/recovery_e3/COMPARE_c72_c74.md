# E3 recovery: failed against successful transactions, c72 and c74 (2026-10-30)

c72 recovered 16 of 18 OPERATEs, c74 13 of 18. This note checks the retained master-NIC captures of all 36 trials for
any field that separates a TIMEOUT from a SUCCESS, or one build from the other. Output: `compare_c72_c74.json`, from
`scripts/analysis/recovery_compare.py`. No new hardware was used.

## What the captures show

- **Relay clock.** All 1,729 relay segments carry the TCP timestamp option, and every TSval is a multiple of 30. The
  unit fits 1.000015–1.000026 ms of master capture time per block, so the relay's clock resolution is 30 ms.
- **Ticks between SELECT and OPERATE.** The relay acknowledged the OPERATE exactly 34 ticks (1,020 ms) after the
  SELECT in 34 of 36 trials, on both builds and with either outcome. The exceptions are both on c72:
  - r2 t2 at 35 ticks, a SUCCESS;
  - r1 t3 at 41 ticks, a TIMEOUT whose OPERATE was retransmitted.
- **Application bytes.** These are the same in every trial:
  - SELECT and OPERATE control bytes `c4` and `c5`;
  - OPERATE objects equal to the SELECT objects;
  - IIN `80 00` in both responses.
  The only byte that differs is the CROB status: 00 SUCCESS or 01 TIMEOUT.
- **Transport.** There are no relay IP-ID gaps in any trial. One trial has a second identical relay pure ACK: c74 r2 t4,
  at connection start, about 0.7 s before the SELECT. That is the late-ACK reply pattern, and it is absent from the
  other four c74 TIMEOUTs. Only c72 r1 t3 sent more than one OPERATE copy.
- **Timing and windows.** The TIMEOUT and SUCCESS ranges overlap on every field, pooled and within each build:
  - the master-side SELECT-to-OPERATE time;
  - the derived tick phase of the OPERATE departure (c74: SUCCESS 1.06–3.24 ms, TIMEOUT 1.55–4.59 ms; derived, about
    1 ms systematic error);
  - the relay ACK delays and the first-copy and retransmission timings;
  - the relay windows.

## Reading

None of the 12 checked features separates the outcomes or the builds. The relay decides at about 1.02 s, a granularity
that the master captures cannot resolve. The c74 difference (5 TIMEOUTs against 2) is therefore not explained by
anything recorded. It stays unresolved, and 18 trials per build do not establish equivalence either. c75's E3 trials
will be added with the same tool.
