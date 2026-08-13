# SEL-751 isolation fanout trace — per DNP3 control point

Device: SEL-751A Feeder Relay, FID `SEL-751A-R403-V0-Z007003-D20100709`,
PART `751A51A6XDA71851230`, 192.168.10.7. Active setting group = 1 (SS1:=1 fixed;
only groups 1-3 exist — `SHO L 4/5/6` return "unknown"). Read-only, Access Level 1.

## The complete set of physical outputs and their equations (authoritative)

Enumerated from `SHO L 1/2/3` "Base Output Set" + "Slot D Output Set". `TAR OUT104`
and `TAR OUT201` return "unknown" — there are no other output contacts. Analog
outputs AO301-304 are all `OFF` (Global) and carry no DNP3 AO map (all `NA`).

| Physical output | Group 1 eqn | Group 2/3 eqn | Remote-bit input? |
|---|---|---|---|
| OUT101 (alarm) | `HALARM OR SALARM OR AFALARM` | same | none |
| OUT102 | `RB07 OR PB01` | `CLOSE` | **RB07** (this is the breaker-CLOSE contact in grp 2/3) |
| OUT103 (trip) | `TRIP` | same | none |
| OUT401 | `0` | `0` | none (hardwired 0) |
| OUT402 | `0` | `0` | none |
| OUT403 | `0` | `0` | none |
| TR (trip eqn) | protection `OR SV01 OR OC OR SV04T OR PB04 OR REMTRIP` | same | none |
| CL (close eqn) | `SV03T AND LT02 OR CC OR PB03` | `SV03T AND LT02 OR CC` | none |

## Exhaustive remote-bit fanout search

`grep RBxx` across every equation dump (Group 1-3 relay + logic, Global, Port,
Front Panel; excludes the DNP map file which only lists the BO->RB assignment):

```
OUT102   := RB07 OR PB01                (11_sho_selogic_g1.txt:52)   -> physical output
PB1A_LED := 79RS OR RB07 OR PB01        (16_...:239)                 -> front-panel LED
PB1B_LED := 79LO OR NOT RB07            (16_...:240)                 -> front-panel LED
```

**RB07 is the ONLY remote bit referenced by any equation on the relay.** All other
remote bits (RB01-RB06, RB08-RB32) appear in zero equations — they are exposed as
DNP3 Binary Outputs but drive nothing.

## DNP3 Binary-Output map (DNP Map 1, `SHO DNP 1`)

`BO_n := RB(n+1)` for n = 0..31. Therefore:

| DNP3 BO index | Remote bit | Fanout | Isolated? |
|---|---|---|---|
| 0 | RB01 | none | yes |
| **1** | **RB02** | **none** | **CANDIDATE (chosen)** |
| 2 | RB03 | none | yes |
| **3** | **RB04** | **none** | **CANDIDATE (chosen)** |
| 4 | RB05 | none | yes |
| 5 | RB06 | none | yes |
| **6** | **RB07** | **OUT102 (breaker CLOSE contact in grp 2/3) + PB1A/PB1B LEDs** | **NO — REJECTED** |
| 7 | RB08 | none | yes |
| 8..31 | RB09..RB32 | none | yes |

Note on the design convention (even=real / odd=decoy): the one live control point
(RB07) sits at DNP3 BO index **6 (even)**; every **odd** index maps to an unused
remote bit. The chosen candidates are both odd indices.

## Chosen isolated candidates — empty-fanout proof

### Candidate 1 — DNP3 BO index 1 -> RB02
- `SHO DNP 1`: `BO_01 := RB02`.
- RB02 appears in NO output equation (OUT101/102/103/401/402/403), NO trip (TR),
  NO close (CL), NO SELOGIC variable (SV01-SV05), NO latch (SET/RST 01-04), NO
  global equation (FAULT/BFI/BKMON), NO front-panel LED/pushbutton logic, NO SER
  trigger list. Fanout set = {} (empty).
- Conclusion: asserting RB02 energizes nothing — no output contact, no analog
  output, no trip, no close, no protection element, no breaker.

### Candidate 2 — DNP3 BO index 3 -> RB04
- `SHO DNP 1`: `BO_03 := RB04`.
- RB04 appears in NO equation anywhere (same exhaustive surfaces as above).
  Fanout set = {} (empty).
- Conclusion: asserting RB04 energizes nothing.

## Rejected point — DNP3 BO index 6 -> RB07
- `BO_06 := RB07`. RB07 drives `OUT102` (a physical output contact — in setting
  groups 2 and 3 this same contact is the breaker `CLOSE` output) and the two
  front-panel pushbutton LEDs. RB07 has real physical fanout and is therefore
  **excluded** from candidacy. This is the single live DNP3 control on the relay.

## Points intentionally NOT nominated
RB01, RB03, RB05, RB06, RB08-RB32 also have empty fanout and are isolated, but only
the two odd-index candidates (indices 1 and 3) were selected per the decoy
convention and to keep the validated set minimal. Any point whose fanout could not
be fully determined would be excluded — none applied here, because the equation
surface is small (5 SV, 4 latches, 6 outputs, 3 groups) and fully dumped.
