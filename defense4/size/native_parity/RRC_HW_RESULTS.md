# RRC hardware results — the native primitive works on silicon

Physical Tofino run of `defense4_rrc_kernel.p4` (compiled on the switch, BF-SDE 9.13.2, 0 errors).
Evidence: `defense4/size/native_parity/evidence/hw_rrc_20260812T202605Z/`.

## Headline

**The Release–Replicate–Carve primitive is proven on silicon.** The one genuinely-unproven mechanism —
a PRE multicast group with **two same-port level-1 nodes and distinct RIDs** — really does produce two
carved copies on this Tofino. A physical 49 B SEL-751 READ response is transformed into `[28,21]` with no
source copy, correct flags, byte-exact reassembly, and (with timing on) held to the deadline first.

## Gate results

```
R1 — PRE two-node/same-port replication:      PASS
R2 — 100-packet segmentation stress:          PASS
R3 — physical SEL READ [28,21]:               PASS
R4 — physical SEL READ timing + [28,21]:      PASS
R5 — SBO (SELECT) timing + [28,21]:           PASS (multi-function admission + type-agnostic carve on hw)
R6 — physical SEL two-CROB SELECT:            PASS (non-actuating; both points stayed OPEN)
Physical OPERATE:                             NOT RUN (gated on explicit authorization)
Rollback:                                      PASS (verified; RRC then RE-LOADED and LEFT RUNNING per request)
```

- **R5/R6 (PASS):** a physical, non-actuating **2-CROB SELECT** (real even point 0 + decoy odd point 1)
  armed the RRC (echo func `0x81`, group `0x0C` G12, status `0x00`) and its **49 B G12 echo carved to
  `[28,21]`** (wire histogram 1×28 + 1×21), while the 58 B G10-all reads in the same session stayed
  **unsplit** (2×58). This proves **SELECT `0x03` arms the same transaction engine as READ (multi-function
  admission)**, the carve is **type-agnostic** (G12 split identically to G10), and eligibility keys on the
  49 B size (not "any response"). Both points read OPEN before and after — nothing actuated. The OpenDNP3
  software SBO *semantics* (real callback once / odd inert / per-object status) are the software-proven Gate
  E (1072 assertions); the hardware size + admission proof is here. Physical OPERATE not run.

**Switch state (left running per request):** `defense4_rrc_kernel` loaded, **D4 timing hold + size carve**
active on the master↔relay flow; a READ is held to the deadline then delivered as `[28,21]` (reassembles to
49 B). This is the complete joint size+time normalization operating on silicon.

- **R1 (PASS):** capture shows the response direction as two segments — **28 B (no PSH, prefix = RID 1,
  seq=orig)** and **21 B (PSH, suffix = RID 2, seq=orig+28)** — and **no 49 B source copy**. The app
  reassembles to 49 B and parses G10 var 2 count 23. The PRE same-port/two-RID fan-out works.
- **R2 (PASS):** 200 responses over a persistent connection → histogram exactly **200×28 + 200×21**, zero
  unsplit 49 B, zero other sizes, zero loss (all reassembled to 49 B).
- **R3 (PASS):** these ARE physical SEL-751 READs; response values unchanged, no timeout/reset.
- **R4 (PASS):** with caseA **D4** hold + shape, the response is held then carved to `[28,21]`
  (histogram 28+21) and reassembled to 49 B — the first proof of the complete primitive (timing→size).

## Measured values

```
READ request payload:   20 B            SELECT/OPERATE request: 45 B (software-derived, confirm on wire)
Native response payload: 49 B
TCP data offset:        8 (32 B header, 12 B nop,nop,timestamp options)
IPv4 total length:      101
Output payload vector:  [28,21]  (28+21 = 49, byte-exact reassembly, G10 count 23 parsed)
RID1 / RID2:            proven by the two distinct wire segments (prefix 28 / suffix 21); PRE nodes RID 1, RID 2
Program left loaded:    defense4_caseA (transparent), relay reachable, all outputs OPEN
```

## Concrete setup defects found (for a clean full campaign)

1. **`configure-all` aborts on a vestigial check.** The RRC kernel retired `read_len` (per-function
   expected-ACK), but the caseA setup verifies `tbl_params.read_len == 18` → fails → `configure-all`
   aborts before installing the PRE. Workaround used: run the timing config and `configure-rrc` separately
   (the PRE install then succeeds, RESULT PASS). Fix: treat the read_len check as non-fatal for the RRC
   program, or have the RRC setup write read_len=18 (harmless — the field is unread in RRC).
2. **`shape_enable` is clobbered by a timing reconfig.** `shape_enable` lives in `tbl_params`; re-running
   the caseA timing setup rewrites the table and clears it → the response stops splitting. Fix / order:
   always run `configure-rrc` (shape + PRE) **after** the timing config, never before. `configure-all`
   already sequences timing→shape; the manual R4 run tripped it and was corrected by re-running
   `configure-rrc`.

## Next
R1–R4 prove the size+timing primitive on the physical READ path. R5 (SELECT/OPERATE multi-function
admission through the switch, via the OpenDNP3 software outstation) and R6 (physical SEL SELECT, gated on
odd-point isolation evidence) remain. No physical OPERATE run or recommended.
