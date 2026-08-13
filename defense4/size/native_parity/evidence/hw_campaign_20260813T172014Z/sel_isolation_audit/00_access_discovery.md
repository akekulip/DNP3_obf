# SEL-751 read-only access discovery (2026-08-13)

Path: gambit -> ssh decps@10.10.54.19 (Vision, 192.168.10.1/24) -> relay 192.168.10.7

## Reachability (read-only TCP probe from Vision)
- 192.168.10.7:23   OPEN  (SEL ASCII engineering interface, telnet/IAC)
- 192.168.10.7:20000 OPEN (DNP3 outstation)
- 79, 1024, 25, 502(Modbus), 80, 443 : closed/filtered
- ICMP: 2/2, rtt ~0.37 ms

## SEL ASCII interface
- On connect: telnet IAC (WILL ECHO/SGA/BINARY), then STX `=` ETX -> Access Level 0 prompt.
- ACC + factory-default Level-1 password ("OTTER") -> Access Level 1 (READ privilege). Accepted.
- Level 1 gives read-only SHO/STA/TAR/MET/ID. Level 2 (2AC, setting/CONTROL writes) NOT entered.
- Client capped at Level 1 by construction (sel_ro_client.py default-deny whitelist).

## Device identity
- DEVID SEL-751A  FID=SEL-751A-R403-V0-Z007003-D20100709  PART NUM 751A51A6XDA71851230
- Option cards C, D, E present (CURRENT card OK). Relay Enabled, self-tests OK.
