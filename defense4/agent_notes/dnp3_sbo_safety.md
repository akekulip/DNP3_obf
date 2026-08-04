# Agent note — DNP3/SBO safety and state machines (wave 1)

**power-systems-expert, 2026-08-04. Analysis only, no hardware. Key deliverables preserved for
the synthesis; full transcript in the task output. Labels VERIFIED/REPORTED/INFERRED/PROPOSED/
BLOCKED.**

## Headline findings

1. **Emulator SBO is sufficient to fix the app-layer state machine but not the two Defense-4
   inputs.** `multi_crob_sbo.pcap` is a real SELECT→SELECT-RESP→OPERATE→OPERATE-RESP (VERIFIED),
   but it is (a) a single fixed 2-CROB transaction, not the 1/2/4/8 size sweep, and (b) produced
   by the opendnp3 emulator which **piggybacks the reverse ACK (Case B, CLRT≈0)** — it cannot
   reproduce the physical SEL's separate-ACK CLRT that Defenses 1/2/3 shape.
2. **The corpus generator already exists and is relay-safe by construction:**
   `run_multicrob_sweep.py` launches a *simulated* outstation (`run_outstation.py --control-test
   --control-point-count N`) and issues one SBO per N — no physical actuation. This is the whole
   Phase-1 corpus path.
3. **SBO timing budget is huge on the emulator, unknown on the relay.** Emulator native
   SELECT→OPERATE-RESP = **3.118 ms** vs **10 s** selectTimeout (~3204×). Meaningless for the
   SEL-751 until its *device* select timeout is read (BLOCKED — device profile).
4. **Tofino can build the transaction key from fixed-offset first-block bytes, not the CROB
   list.** Link addrs, direction, transport/app control, 4-bit app-seq, function code all sit
   before the first 16-B block CRC (VERIFIED from frame-13 dissection). The CROB object list
   crosses block CRCs and is variable-length → bounded max or opaque treatment (arch doc §8).
5. **Hard safety line holds:** timing plane + outer-size/filler plane are safe to build now;
   everything that could actuate the relay is gated AND blocked on a device-profile read.

## Byte offsets Tofino parses at line rate (VERIFIED from multi_crob_sbo.pcap frame 13)

| TCP-payload offset | field | parseable |
|---|---|---|
| 0–1 | link start 0x0564 | yes |
| 4–5 / 6–7 | DEST / SRC link addr (LE) | **yes** |
| 10 | transport control (FIR/FIN/SEQ) | yes |
| 11 | app control (FIR/FIN/CON/UNS + 4-bit SEQ) | **yes** |
| 12 | **app function code** (READ=1,WRITE=2,SELECT=3,OPERATE=4,ENABLE_UNSOL=20,RESPONSE=129) | **yes** |
| 13+ | object headers + CROBs | **no — crosses block CRC at offset 26, variable length** |

**Transaction key (line-rate):** canonical 5-tuple + DNP3 DEST + SRC + direction + phase(internal)
+ generation(internal); app_seq(off 11 low nibble) and func(off 12) as per-phase correlators;
tcp.len==0 + seq/ack as pure-ACK/ordering evidence.
**Cannot key on:** app_seq across phases (SELECT seq **3** ≠ OPERATE seq **4**, VERIFIED) — **SBO
linkage must be state-table + generation, never app-seq**; and the CROB count (crosses block CRCs).

## State machines (see transcript for mermaid)

READ: IDLE→READ_SEEN→ACK_PENDING→ACK_HELD→ACK_OUT→RESP_HELD→RESP_OUT→(MULTIFRAG|CONFIRM_WAIT)→DONE.
Piggyback/absent-ACK path skips ACK_HELD; **response gate anchors to the scheduled public ACK slot,
never waits for a nonexistent native ACK.**
SBO: SEL_SEEN→SEL_RESP_HELD→(SEL_OK→AWAIT_OPERATE | SEL_FAIL→ABORT_SBO). Linkage: next M→O func=4 on
same flow+link_pair+generation binds to the SBO entry regardless of app-seq; operate_window =
now+selectTimeout_margin; on expiry SEL_TIMEOUT→fail open, **never synthesize an OPERATE.** OPERATE:
OP_SEEN→OP_RESP_HELD→(OP_CONFIRM|OP_DONE)→cleanup. Enforcement: `OutstationContext.cpp:770`
`ValidateSelection(seq, now, selectTimeout, objects)` rejects OPERATE if window expired or objects
mismatch → Defense 4 must never delay the forward OPERATE past that window.

## Corner cases with HIGH safety weight (full 22-row table in transcript)

- **#7/#8 TCP retransmission / duplicate request:** must be idempotent on (flow,link,app_seq,seq);
  a duplicate OPERATE bound twice = **double actuation**. PROPOSED, high weight.
- **#11 SELECT failure:** must suppress the OPERATE public slot + abort template + fail open
  (VERIFIED: non-SUCCESS → outstation `Unselect()`).
- **#13 OPERATE after its slot:** default policy must be abort+fail-open; **never invent/replay a
  real OPERATE** (= unauthorized actuation).
- **#14 CONFIRM:** forward verbatim only if the RESPONSE CON bit is set; **fabricated CONFIRM →
  permanent SOE deletion** (VERIFIED hazard).
- **#21 queue overflow:** dropping a real OPERATE-RESP makes the master retry OPERATE → double
  actuation; must fail open (bypass) not drop.

## SBO timing envelope (arch doc §10)

`D_SELECT-resp(shaped) + D_master-proc + D_OPERATE-sched(shaped) + D_network < selectTimeout`.
Emulator native (VERIFIED): SELECT-resp 1.370 ms, master-proc 0.408 ms, OPERATE-resp 1.340 ms,
total 3.118 ms. **Critical coupling READ lacks:** a reverse-path hold on the SELECT-RESP delays
when the master learns SELECT succeeded → delays OPERATE → **consumes the outstation's
select-timeout budget**. So G_R,SELECT is bounded by `selectTimeout − D_master-proc −
D_OPERATE-sched − D_network`; G_R,READ is bounded only by RTO. **Phase-specific Θ_p is mandatory —
one D/G cannot serve all phases.**

MEASURE from the emulator sweep (safe): D_master-proc per N; reverse-path resp timing per N; per-N
size envelope (frame/tcp/dnp3 len); app-seq increment behavior.
READ from the SEL-751 before any live SELECT (BLOCKED): device selectTimeout; control-point→output
vs SELOGIC/remote-bit wiring (decoy inertness); separate-ACK reverse timing (infer from READ CLRT
1.4–1.9 ms + emulator deltas — never operate the relay).

## Safe corpus plan

Run entirely on the emulator (prefer dev-box loopback: `run_outstation.py` binds 0.0.0.0:20000).
`--points 1,2,4,8,16`; reuse `run_crob_boundary_index_test.py` (invalid index → OUT_OF_RANGE,
partial-SELECT suppresses OPERATE = rejected-SELECT corpus) and `run_crob_padding_candidate_tests.py`
(valid-but-unwired → SELECT success, OPERATE proceeds). Extract sizes with `analyze_multicrob_pcap.py`.
**Address caveat:** emulator uses outstation addr **10**; physical relay is **0** — re-key any
template before it is ever pointed at the relay; do not hardcode 10.
**Filler must be outer-encapsulated and stripped by the decoder — never an inner DNP3 object:** a
g110 octet-string filler crashes the rig master (`run_master.py:137` `_VISITOR_CLASS_TYPES` lacks
the octet-string visitor).

## Safety verdict

SAFE to build/evaluate now: reverse-path timing shaping of READ ACK/RESPONSE (silicon-validated on
the SEL); outer-encapsulation size padding with a decoder restoring byte-identical inner packets;
filler that dies at the decoder; emulator SBO corpus; physical READ-only measurement.
GATED + BLOCKED on a device-profile read: any live SELECT to the relay (arms select state); any
decoy/filler CROB reaching an endpoint (a point may drive a SELOGIC remote bit, not just an output);
the two-edge decoder (prove no filler passes toward an endpoint); any fabricated DNP3. Live OPERATE
to the physical relay is a hard prohibition for Defense 4 development.

BLOCKED sources: IEEE 1815 clause numbers (behavior verified from pcap+opendnp3, clauses not opened);
SEL-751 device profile / App. D (selectTimeout, wiring, separate-ACK). No live SELECT/OPERATE
admissible until these are read.
