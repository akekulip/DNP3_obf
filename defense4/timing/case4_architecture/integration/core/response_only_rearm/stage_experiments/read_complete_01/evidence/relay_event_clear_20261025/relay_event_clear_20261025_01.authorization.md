# Authorization record — relay_event_clear_20261025_01 (one-time SEL-751 class-2 event poll + confirm)

- Authority: Philip, 2026-10-25, answering the blocker report: "I poll and confirm it once". The c68 hardware run
  (and an unchanged-c67 A/B, rc01_hw_c67_20261025_09) failed because the relay has held IIN1.2 (class 2 events
  available) since between 16:10 and 22:25; the integrity READ (classes 1,2,3,0) then returns event data instead
  of the admitted 134-octet class-0 shape.
- Operation: through the existing guarded native-baseline path (production program case4_response_path, pure
  dev9<->dev64 forwarding, no candidate load): one TCP connection 192.168.10.1:59410 -> 192.168.10.7:20000; READ
  class 2 (G60 V3 q 0x06), application CONFIRM for every response fragment that requests it (at most 3 polls while
  IIN1.2 stays set), then one READ class 0 (G60 V1) to check the IIN. Functions sent: READ (0x01) and CONFIRM (0x00)
  only, asserted before every send. No control point, no write, no relay configuration change.
- Admission: production-baseline freeze native_freeze_event_clear_01.json checked OK; exact argv dry-ran with exit 0.
- Restoration: the runner's restore and restore_verify.py, as for every native block; an unverified restoration
  stops all hardware work.
