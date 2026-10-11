# Production-build confirmation: shaped hold+blocker queues cut loop-port traffic 24-67x at unshaped precision (2026-10-11)

Production build `sbo_admission_01` (bfrt ee998605, p0 741fee7e, p1 084e4963), T on, 5 ms separate-ACK fixture,
installer from commit 4cc5952c5 (loop-port counters) + 364aa3471 (blocker shaping), 50 READs (20-byte range-8
request, 20 ms gap) + 1 SELECT/OPERATE on one connection per configuration, fresh cold bring-up each, master
ports 54480 and 54501-54503. Counters are `$PORT_STAT` transmitted frames and octets on the four loop ports
(48, 180, 181, 182) between the before and after snapshots: true physical internal packets and bytes.
`report.txt` is the generated table; `prodreport.py` produced it.

| config | loop packets | loop bytes | vs unshaped | READ CLRT median | pop SD | sample SD | req->ACK med | req->resp med |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| unshaped | 2,026,007 | 148,144,122 | 1.0x | 809 us | 16.7 | 16.9 | 5,486 | 6,295 |
| hold + blocker 3,723 PPS | 30,370 | 2,204,288 | 66.7x | 811 | 5.3 | 5.4 | 5,615 | 6,426 |
| hold + blocker 14,892 PPS | 43,295 | 3,154,949 | 46.8x | 823 | 14.3 | 14.4 | 5,428 | 6,257 |
| hold + blocker 59,570 PPS | 84,416 | 6,197,338 | 24.0x | 825 | 14.3 | 14.4 | 5,448 | 6,270 |

Every row: master success, 50/50 READs match seed, one real SELECT + one real OPERATE, zero decoy,
OUT_ACK_COMMIT=50, OUT_RESP_RELEASE=50, OUT_OP_RELEASE=1, zero fallback. Hold queues burst 1, blocker queues
burst 64, all six at the same achieved rate (readback equals the request on these ladder points).

Per-port detail (frames, bytes), unshaped -> 3,723 PPS: held_return(182) 2,007,772 / 146.7 MB -> 30,024 / 2.17 MB;
hb_return(181) 17,972 -> 83; n_ack_return(48) 111 and t_in(180) 152 unchanged (they carry the transaction, not
the hold). Unshaped, the ladder port carries ~40,000 packets and ~3 MB per READ; at 3,723 PPS about 600 packets
and 44 KB per READ.

## Reading the trade-off

- **Precision** is preserved at every rate: median within +0 to +16 us of the unshaped median and +11 to +25 us
  of the 800 us gap, SD 5-17 us (slow 232-PPS shaping: 4,293 us / 1,043 us).
- **Added latency** follows half the poll interval: +129 us request->ACK and +131 us request->response at 3,723 PPS
  (269 us interval); no measurable change at 14,892 or 59,570 PPS (differences of -58 to -25 us are noise at
  n = 50).
- **Total traffic** falls with the rate: fewer polls per hold.
- A defensible default is **14,892 PPS** (46.8x less loop traffic, no measurable added latency); **3,723 PPS** is the
  low-traffic choice where about +130 us of release latency is acceptable. The choice is the error budget's, not
  the hardware's. The slow 232-PPS setting stays a comparison only.

## Also in these snapshots: the RESET event is dropped by the MAC

Port 180 received 152 frames and 15,039 octets in every run but only 14,959 octets in good frames: a constant
**80-byte** gap = one 76-byte RESET event + 4 B FCS, counted received and not good. The other three loop ports show
no gap. At the same time `OUT_REQ_BYPASS`/close handling is what the captured FIN defect traces to (close_defect_01):
N's RESET event puts a length-like value at wire bytes 12-13. This confirms the envelope hypothesis from counters.

## Limits

- One connection and one 50-READ block per configuration, one fixture delay (5 ms), one gap (0.8 ms), one SBO.
  Not a distribution across blocks; fixture delay, spacing and start phase not varied yet.
- Loop-port totals are over the run window, not normalized per second; all configurations ran the same workload.
- A first attempt reused run labels that already existed on Vision (a script aborted after traffic but before the
  snapshots were copied), producing all-zero snapshot rows; those invalid rows were discarded and the three shaped
  configurations rerun under new labels. The scripts here are the corrected ones (snapshot args without
  `--block-burst`, teardown on an exit trap).
