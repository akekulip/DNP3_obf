# SELECT validation — baseline vs. post-SELECT (no OPERATE)

## What was sent
One DNP3 Application-layer **SELECT** (function code `0x03`), 2-CROB, G12V1,
qualifier `0x17` (1-byte count + 1-byte index prefix), indices **1 and 3**
(RB02, RB04 — both proven-isolated), LATCH_ON, on/off time 0.

- Tool: `dnp3_select_only.py` (structurally SELECT-only — contains no OPERATE
  0x04 / DirectOperate 0x05/0x06 path).
- Request hex: `056424c4000001004a59c0c0030c011702010301000000000000e20a0000000303010000000000000000005f7f`
- Response hex: `05642644010000002f77e2c08184000c01170201030100000000a04700000000000303010000000000000000731200ffff`
- Parsed response: `func=0x81 (RESPONSE), IIN=0x0084` (IIN1.7 device-restart +
  IIN1.2 class-data-available, both benign), echoed CROBs:
  - CROB index 1 -> status **0 (SUCCESS)** — selectable
  - CROB index 3 -> status **0 (SUCCESS)** — selectable

No OPERATE was sent. A DNP3 SELECT arms a point for a subsequent OPERATE and by
design does not actuate; the follow-up OPERATE was never issued.

## Relay Word: baseline (before) vs. post-SELECT (after)

Source: `TAR RB01/RB09/RB17/RB25`, `TAR OUT101`, `TAR OUT401` before
(`20_baseline_tar.txt`) and after (`31_post_select_tar.txt`).

| Element | Baseline | After SELECT | Changed? |
|---|---|---|---|
| RB01..RB32 (all 32 remote bits) | all 0 | all 0 | no |
| RB02 (selected) | 0 | 0 | no |
| RB04 (selected) | 0 | 0 | no |
| TRIP | 0 | 0 | no |
| OUT101 | 0 | 0 | no |
| OUT102 | 0 | 0 | no |
| OUT103 | 0 | 0 | no |
| OUT401 / OUT402 / OUT403 | 0 | 0 | no |

**Every physical output and every binary-output point state is identical to
baseline.** The SELECT was accepted (SUCCESS) yet changed nothing — confirming both
the isolation of the chosen points and that SELECT alone actuates nothing.

## Wire capture note
Passwordless `tcpdump` was not available on Vision, so no `.pcap` was written. The
full request and response byte strings above (captured by the tool at the socket)
are the authoritative record of the exchange.
