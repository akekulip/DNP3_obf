# Defense 4 mechanism, in diagrams

Exact causal, topology, timing, and state diagrams for Defense 4. These are checked against the P4 and
the setup code, not invented. Measured plots (the CLRT ECDFs) live with the campaign evidence; these
are the mechanism schematics.

## 1. Topology and the adversary

The switch sits between the master and the relay. The passive adversary watches the master-facing
segment, where only the released, shaped timing is visible.

```mermaid
flowchart LR
  M["DNP3 master<br/>(Vision 192.168.10.1)"] <-->|master-facing segment<br/>adversary watches here| SW
  SW["Tofino-1 switch<br/>defense4_caseA (97175e7d)"] <-->|relay-facing segment| R["SEL-751 relay<br/>192.168.10.7:20000 (READ-only)"]
  A["passive observer<br/>measures CLRT"] -. taps .-> M
```

## 2. The four queues and the packet journey

The original acknowledgment and response wait in the hold queues. Higher-priority blocker tokens
recirculate to hold their place, and the traffic manager releases the held packets on schedule.
Strict priority (7 > 6 > 5 > 4) guarantees the acknowledgment is never released after the response.

```mermaid
flowchart TB
  READ["master READ (func 1)"] --> CLS["parser + classify<br/>match flow, DNP3 function,<br/>TCP flags, generation C0..CF"]
  CLS --> ARM["arm transaction<br/>(reg_tag = generation)"]
  ARM --> PG["pktgen creates K blocker tokens<br/>(EtherType 0x88C1)"]
  ACKp["relay pure TCP ACK"] --> QAB["Q_ACK_BLOCK qid7 (blocker)"]
  ACKp --> QAH["Q_ACK_HOLD qid6 (the real ACK waits)"]
  RESPp["relay DNP3 RESPONSE"] --> QRB["Q_RESP_BLOCK qid5 (blocker)"]
  RESPp --> QRH["Q_RESP_HOLD qid4 (the real RESPONSE waits)"]
  QAB --> TM
  QAH --> TM
  QRB --> TM
  QRH --> TM["Traffic Manager<br/>strict priority 7 &gt; 6 &gt; 5 &gt; 4"]
  TM -->|release ACK at T_A, RESPONSE at T_RESP| OUT["master-facing egress<br/>(blocker tokens never leave)"]
```

## 3. Timing semantics and the arrival buckets

`t_A` is when the acknowledgment arrives. `T_A = t_A + D_A` is the acknowledgment deadline.
`T_RESP = t_A + D_A + D_R` is the response deadline. A response can arrive in three places, and all
three are held safely; only after the fail-open horizon does the fail-open path release early.

```mermaid
flowchart LR
  tA["t_A<br/>ACK arrives"] --> TA["T_A = t_A + D_A<br/>ACK released"]
  TA --> TR["T_RESP = t_A + D_A + D_R<br/>RESPONSE released"]
  TR --> FO["fail-open horizon"]
  subgraph buckets["response arrival buckets (all held, 0 bypass on D2/D4)"]
    b1["before T_A<br/>RESP_HOLD_EARLY"]
    b2["between T_A and T_RESP<br/>RESP_HOLD_LATE (survives ACK release)"]
    b3["after T_RESP<br/>late safe release, not normalization"]
    b4["after fail-open horizon<br/>RELEASE_FAILOPEN (bounded)"]
  end
```

## 4. Transaction lifecycle (the state machine, including the bug that was fixed)

The pre-fix bug retired the transaction at the acknowledgment release, so a later response found a dead
transaction and bypassed. The fix keeps the response obligation alive after the acknowledgment release
for the must-hold modes.

```mermaid
stateDiagram-v2
  [*] --> Idle
  Idle --> Armed: READ classified, reg_tag = generation
  Armed --> AckHeld: ACK arrives, held to T_A
  AckHeld --> AckReleased: T_A reached, ACK released
  note right of AckReleased
    D2/D4: keep the transaction ALIVE
    (obligation survives ACK release).
    Pre-fix bug retired here -> bypass.
  end note
  AckReleased --> RespHeld: RESPONSE arrives (early or late), held to T_RESP
  RespHeld --> Released: T_RESP reached, RESPONSE released
  AckReleased --> FailOpen: reservoir drains before RESPONSE (budget)
  FailOpen --> Released: bounded release, never stranded
  Released --> Retired: retire transaction
  Retired --> Idle: next READ re-arms (ARM_FRESH)
```

## 5. The modes as one framework

```mermaid
flowchart TB
  F["one framework<br/>(hold ACK and/or RESPONSE, release on schedule)"]
  F --> OFF["OFF: pass through (native fingerprint)"]
  F --> D1["D1 event: hold ACK to the RESPONSE event"]
  F --> D2["D2: D_A=0, hold RESPONSE to T_RESP (normalize CLRT)"]
  F --> D3["D3: D_R=0, hold ACK to T_A (collapse CLRT to ~0)"]
  F --> D4["D4: hold both (normalize CLRT, tolerate the ACK-release gap)"]
```

Measured outcome (corrected binary, physical SEL-751, 1200 transactions): OFF spreads the CLRT from
about 1.8 to 7.6 ms across the middle 90 percent; D2 and D4 pull that band to about 0.1 ms around a
fixed 10 ms, with a small late tail; D3 collapses it to about zero; D1 shapes it to about 11 ms. See
`../timing/evidence/final_run/campaignA_corrected_binary/fig_clrt_ecdf.png`.
