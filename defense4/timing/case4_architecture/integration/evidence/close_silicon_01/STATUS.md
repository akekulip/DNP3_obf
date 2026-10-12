# Close-path and RESET-event fix verified on silicon (2026-10-12)

Build `route_ab_01/close_reset_fix_01/hw_compile_switch_9132` (commits b72285d13 + 4b228aa88): bfrt.json
7c7e7f3b, p0/tofino.bin e15b6177, p1/tofino.bin 7ab242e8; hardware map relay 9 / 48 / 180 / 181 / 182. Installed
with all six hold/blocker queues shaped at 14,892 PPS (burst 1 hold, 64 blocker), T on, 5 ms separate-ACK fixture,
20 READs (20-byte range-8 request, 20 ms gap) + 1 SELECT/OPERATE + a normal client close, master port 54600,
fresh cold bring-up. Run `close14892/`.

## Verified in the bytes and counters

| criterion | before (sbo_admission_01, prod_shape) | now |
|---|---|---|
| port 180 received-vs-good octets | constant 80 B gap (one 76 B RESET event + FCS, every run) | **0** |
| other loop ports (48, 181, 182) gap | 0 | 0 |
| outstation FIN seq on the master side | native 507958287 (master had ACKed the padded 507958419) | **949031398 = the padded data frontier** (sent native 949031176, +222 B = 20x9 + 2x21) |
| master FIN reaches the outstation | first FIN absent, retransmitted ~209 ms later | present once, no retransmission |
| master's ack of the outstation FIN, as the outstation sees it | n/a (untranslated) | 949031177 = native FIN + 1 (reverse-mapped from the master's 949031399) |
| FIN retransmissions in the returned stream | repeated outstation FINs | 1 per direction |
| `wire_check.py` | exit 1 | **exit 0**: 94 sent, 94 returned, 0 unmatched, 0 duplicates |
| application | OK | master success, 20/20 READs match seed, one real SELECT + OPERATE, zero decoy |
| outcomes | | OUT_ACK_COMMIT 20, OUT_RESP_RELEASE 20, OUT_OP_RELEASE 1 |

## Open item surfaced while checking: stale tokens and generator triggers in shaped runs

`OUT_TOKEN_STALE` is 26,814 in this run and the READ generator fired 3,411 triggers (13,644 packets) for 20 READs.
The same pattern is present in every shaped production run from `p2_production_01`, which I reported without flagging
it: unshaped 64 triggers / 0 stale; hold+blocker 3,723 PPS 3,499 / 27,007; 14,892 PPS 2,006 / 26,805; 59,570 PPS
826 / 21,885. So it is a property of shaped operation, not of the close fix. It does not affect correctness
(zero fallback, all commits and releases exact) and the stale tokens are dropped, but it is extra generator and loop
traffic that the packet/byte totals include, and the trigger count is not explained by 20 admitted READs. Cause not
yet established; to be traced with the T/scheduling owner (candidate: repeated admissions or re-fires of READ clones
while the shaped hold keeps a request resident). Until explained, the 24-67x loop-traffic figures stand as measured
totals, with this caveat.

Rig restored after the run (relay slot read back, ping .1 -> .7 ok, NIC flag off, loopback cleared).
