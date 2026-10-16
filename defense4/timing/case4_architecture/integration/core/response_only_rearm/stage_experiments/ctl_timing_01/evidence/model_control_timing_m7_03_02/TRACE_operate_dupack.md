# model_control_timing_m7_03_02: 91/141, a cascade from OPERATE_dupack (2026-10-16)

The run's result stays 91/141.

**What the log shows** (`model_*.log`, parsed with `../../trace_model_log.py`). The OPERATE request (client SEQ
0x1d2) entered N at 12:40:12.256 and left for E's normalize lap. Before it came back, the outstation ACK sent twice
(`0x29a`, `0x29b`; ACK 0x1f5) and the response (`0x29c`) entered N. The ACK claimed the work cell
(`seq_forward_fresh`) and the response retried (`busy_retry`). The returning request (`0x29d`, 12:40:12.31) found
the cell busy and was dropped (`busy_t → busy_drop`): a request busy-drops by design, and a master retransmits it.

**Why the ACK came first.** The driver's request capture waits 0.6 s (wall) for the relayed command. The model
processed the request after the driver had given up, so the driver sent an outstation ACK for a command the switch
had not yet relayed. No real outstation can do that. The driver's master never retransmits, so the connection's
later cases all failed (`*_request` dropped).

**Not a dataplane wedge** (source replay, `../support_20261016/request_busy_drop_recovery.py`, m6 and m7 alike). When an ACK arrives 1 µs after the
OPERATE, the request is busy-dropped and the master's retransmission is then relayed. With later ACKs, the request
is processed first.

**Host load.** syncthing was using about 40% CPU, with load average about 2. It is probably hashing the model logs
that these runs write into the synced tree; that is inferred, not shown. The driver now keeps capturing, up to 3 s,
until the relayed command appears before it sends the outstation's ACK (a causal precondition of the stimulus).
