# c72 overhead v2: latency tails and bytes from the retained evaluation

Schema `c72-overhead-v2`. Rows `/home/philip/Projects/DNP3/results/analysis/evaluation/final/rows/rows.csv` (sha256 `29b028228c69245e`); 256 connections, 512 pcaps (512 matched the rows manifest hashes).

## Labels

- **payload**: TCP payload octets (DNP3 link frames), master NIC capture
- **captured**: Ethernet frame octets as captured (pcap caplen; no FCS unless one is detected)
- **wire**: ESTIMATE of physical wire occupancy: per frame max(frame without FCS, 60) + FCS 4 + preamble/SFD 8 + IFG 12; not a measurement

## Capture format

- Link types [1]; snaplen [262144]; 0 of 150288 connection frames carry a detected FCS; 0 truncated (caplen < wirelen); 0 with Ethernet padding; 0 frames outside the connection 4-tuple; largest frame 224 octets (below the MTU, so no segmentation-offload super-frames).
- out.pcap is the master NIC transmit capture (taken in the host before the NIC), in.pcap the receive capture; rx-fcs during capture per capture_offloads.json: ['False']. FCS, preamble and IFG therefore appear only in the estimate.

## Bytes and packets per D and arm (sums over connections)

| D | arm | conn | payload req+resp | payload resp | retx bytes | retx segs | frames | pure ACKs | captured frame B | wire estimate B |
|---|---|---|---|---|---|---|---|---|---|---|
| 5 | combined | 16 | 397408 | 278224 | 0 | 0 | 9392 | 3152 | 1017600 | 1243008 |
| 5 | off | 16 | 336192 | 217008 | 0 | 0 | 9392 | 3152 | 956384 | 1181792 |
| 5 | size_only | 16 | 397408 | 278224 | 0 | 0 | 9392 | 3152 | 1017600 | 1243008 |
| 5 | timing_only | 16 | 336192 | 217008 | 75 | 3 | 9395 | 3152 | 956657 | 1182137 |
| 10 | combined | 16 | 397408 | 278224 | 50 | 2 | 9394 | 3152 | 1017782 | 1243238 |
| 10 | off | 16 | 336192 | 217008 | 25 | 1 | 9393 | 3152 | 956475 | 1181907 |
| 10 | size_only | 16 | 397408 | 278224 | 25 | 1 | 9393 | 3152 | 1017691 | 1243123 |
| 10 | timing_only | 16 | 336192 | 217008 | 25 | 1 | 9393 | 3152 | 956475 | 1181907 |
| 15 | combined | 16 | 397408 | 278224 | 50 | 2 | 9394 | 3152 | 1017782 | 1243238 |
| 15 | off | 16 | 336192 | 217008 | 50 | 2 | 9394 | 3152 | 956566 | 1182022 |
| 15 | size_only | 16 | 397408 | 278224 | 50 | 2 | 9394 | 3152 | 1017782 | 1243238 |
| 15 | timing_only | 16 | 336192 | 217008 | 25 | 1 | 9393 | 3152 | 956475 | 1181907 |
| 20 | combined | 16 | 397408 | 278224 | 0 | 0 | 9392 | 3152 | 1017600 | 1243008 |
| 20 | off | 16 | 336192 | 217008 | 0 | 0 | 9392 | 3152 | 956384 | 1181792 |
| 20 | size_only | 16 | 397408 | 278224 | 0 | 0 | 9392 | 3152 | 1017600 | 1243008 |
| 20 | timing_only | 16 | 336192 | 217008 | 25 | 1 | 9393 | 3152 | 956475 | 1181907 |
| all | combined | 64 | 1589632 | 1112896 | 100 | 4 | 37572 | 12608 | 4070764 | 4972492 |
| all | off | 64 | 1344768 | 868032 | 75 | 3 | 37571 | 12608 | 3825809 | 4727513 |
| all | size_only | 64 | 1589632 | 1112896 | 75 | 3 | 37571 | 12608 | 4070673 | 4972377 |
| all | timing_only | 64 | 1344768 | 868032 | 150 | 6 | 37574 | 12608 | 3826082 | 4727858 |

Overhead relative to off at the same D (%):

| D | arm | payload_request_response | payload_response | payload_with_retransmissions | captured_frame_bytes | wire_estimate_bytes | frames |
|---|---|---|---|---|---|---|---|
| 5 | combined | 18.2086 | 28.2091 | 18.2086 | 6.4008 | 5.1799 | 0.0000 |
| 5 | size_only | 18.2086 | 28.2091 | 18.2086 | 6.4008 | 5.1799 | 0.0000 |
| 5 | timing_only | 0.0000 | 0.0000 | 0.0223 | 0.0285 | 0.0292 | 0.0319 |
| 10 | combined | 18.2086 | 28.2091 | 18.2147 | 6.4097 | 5.1892 | 0.0106 |
| 10 | size_only | 18.2086 | 28.2091 | 18.2073 | 6.4002 | 5.1794 | 0.0000 |
| 10 | timing_only | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 15 | combined | 18.2086 | 28.2091 | 18.2059 | 6.3996 | 5.1789 | 0.0000 |
| 15 | size_only | 18.2086 | 28.2091 | 18.2059 | 6.3996 | 5.1789 | 0.0000 |
| 15 | timing_only | 0.0000 | 0.0000 | -0.0074 | -0.0095 | -0.0097 | -0.0106 |
| 20 | combined | 18.2086 | 28.2091 | 18.2086 | 6.4008 | 5.1799 | 0.0000 |
| 20 | size_only | 18.2086 | 28.2091 | 18.2086 | 6.4008 | 5.1799 | 0.0000 |
| 20 | timing_only | 0.0000 | 0.0000 | 0.0074 | 0.0095 | 0.0097 | 0.0106 |
| all | combined | 18.2086 | 28.2091 | 18.2095 | 6.4027 | 5.1820 | 0.0027 |
| all | size_only | 18.2086 | 28.2091 | 18.2076 | 6.4003 | 5.1796 | 0.0000 |
| all | timing_only | 0.0000 | 0.0000 | 0.0056 | 0.0071 | 0.0073 | 0.0080 |

## Reproduction of T4 and the response-only figure

- Unique request+response payload overhead from the pcaps equals T4 `bytes_per_txn_pct` in 16 of 16 D/arm cells (|difference| < 1e-9 percentage points); size_only/combined: ['18.2086'] %.
- Response-only payload overhead from the pcaps: ['28.2091'] % (rows: 28.2091 %).
- Unique pcap payload equals the rows per connection (requests, responses): 256 of 256 connections.
- Added p50/p95 request->response (all classes) equals T4 in 24 of 24 cells.
- Byte-overlap retransmitted segments equal relay_check identical-copy counts in 256 of 256 connections; connections with any retransmitted byte: {'size_only': 3, 'timing_only': 6, 'off': 3, 'combined': 4}.

## Latency tails, all classes (pooled over blocks; numpy linear percentiles; ms)

Exchanges above 150 ms: 16; all are the first exchange of a connection whose first request was retransmitted: True. They set the maxima below.

| D | arm | field | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| 5 | combined | rt_ms | 3088 | 10.7725 | 16.7546 | 23.6554 | 42.9320 |
| 5 | combined | ack_ms | 3088 | 5.8890 | 11.6502 | 18.9368 | 39.7560 |
| 5 | off | rt_ms | 3088 | 6.0190 | 11.9609 | 18.0195 | 54.9490 |
| 5 | off | ack_ms | 3088 | 3.4525 | 5.9922 | 7.5559 | 9.9180 |
| 5 | size_only | rt_ms | 3088 | 6.0905 | 11.3743 | 17.2720 | 84.0070 |
| 5 | size_only | ack_ms | 3088 | 3.4750 | 6.0493 | 7.5469 | 10.3640 |
| 5 | timing_only | rt_ms | 3088 | 10.9200 | 16.4724 | 23.2399 | 224.7440 |
| 5 | timing_only | ack_ms | 3088 | 6.0230 | 11.3470 | 18.0449 | 218.1530 |
| 10 | combined | rt_ms | 3088 | 15.9585 | 21.6070 | 28.2803 | 226.4590 |
| 10 | combined | ack_ms | 3088 | 6.0570 | 11.8049 | 18.5735 | 216.4760 |
| 10 | off | rt_ms | 3088 | 6.0710 | 12.1882 | 18.2405 | 234.1350 |
| 10 | off | ack_ms | 3088 | 3.4880 | 6.1248 | 7.8290 | 213.8550 |
| 10 | size_only | rt_ms | 3088 | 6.0975 | 12.0546 | 17.9041 | 209.2660 |
| 10 | size_only | ack_ms | 3088 | 3.4745 | 6.1755 | 7.8040 | 208.9890 |
| 10 | timing_only | rt_ms | 3088 | 15.9930 | 21.3506 | 27.8371 | 234.0240 |
| 10 | timing_only | ack_ms | 3088 | 6.0370 | 11.3551 | 18.2043 | 225.0020 |
| 15 | combined | rt_ms | 3088 | 20.8425 | 27.6287 | 33.5058 | 235.9760 |
| 15 | combined | ack_ms | 3088 | 5.9655 | 12.9056 | 18.3385 | 221.4640 |
| 15 | off | rt_ms | 3088 | 5.9495 | 11.5297 | 18.0605 | 220.1500 |
| 15 | off | ack_ms | 3088 | 3.4090 | 6.0119 | 7.6034 | 215.9250 |
| 15 | size_only | rt_ms | 3088 | 6.0795 | 11.9534 | 18.4190 | 220.1480 |
| 15 | size_only | ack_ms | 3088 | 3.4680 | 6.1743 | 8.0378 | 218.9950 |
| 15 | timing_only | rt_ms | 3088 | 20.7975 | 26.5879 | 33.3822 | 230.9010 |
| 15 | timing_only | ack_ms | 3088 | 5.9760 | 11.5559 | 18.5775 | 217.1380 |
| 20 | combined | rt_ms | 3088 | 25.6615 | 31.3535 | 37.7421 | 126.9810 |
| 20 | combined | ack_ms | 3088 | 5.7755 | 11.1786 | 17.6977 | 106.5440 |
| 20 | off | rt_ms | 3088 | 6.0025 | 11.7643 | 17.5716 | 95.8670 |
| 20 | off | ack_ms | 3088 | 3.4225 | 6.0075 | 7.5460 | 11.0430 |
| 20 | size_only | rt_ms | 3088 | 6.0405 | 11.4279 | 17.8376 | 77.1850 |
| 20 | size_only | ack_ms | 3088 | 3.3995 | 5.9836 | 7.5450 | 11.5030 |
| 20 | timing_only | rt_ms | 3088 | 25.7770 | 30.9322 | 36.9426 | 235.8870 |
| 20 | timing_only | ack_ms | 3088 | 5.8580 | 10.9260 | 16.7698 | 215.6880 |

Per-class tails for every D, arm and class are in latency_tails.csv.

## Added latency vs the same block's off arm (all classes; mean over blocks [95% block bootstrap]; ms)

A per-block p99 over [193] exchanges per connection sits close to the block maximum. Per-class values for every D/arm/class are in latency_added.csv.

| D | arm | field | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 5 | combined | ack_ms | 2.469 [2.386, 2.559] | 5.897 [5.314, 6.515] | 10.629 [9.559, 11.496] |
| 5 | combined | rt_ms | 4.739 [4.640, 4.838] | 5.227 [4.435, 5.961] | 5.514 [4.277, 6.622] |
| 5 | size_only | ack_ms | 0.042 [-0.009, 0.097] | 0.025 [-0.104, 0.143] | 0.089 [-0.302, 0.454] |
| 5 | size_only | rt_ms | 0.078 [0.002, 0.170] | -0.304 [-0.783, 0.228] | -1.223 [-2.610, 0.186] |
| 5 | timing_only | ack_ms | 2.597 [2.523, 2.661] | 5.496 [5.055, 6.006] | 9.840 [9.015, 10.746] |
| 5 | timing_only | rt_ms | 4.918 [4.770, 5.063] | 4.580 [4.068, 5.045] | 5.134 [4.045, 6.207] |
| 10 | combined | ack_ms | 2.607 [2.504, 2.707] | 5.775 [5.353, 6.218] | 10.405 [9.442, 11.329] |
| 10 | combined | rt_ms | 9.932 [9.817, 10.036] | 9.560 [8.668, 10.331] | 10.495 [9.370, 11.585] |
| 10 | size_only | ack_ms | 0.003 [-0.055, 0.061] | 0.072 [-0.063, 0.224] | 0.216 [-0.185, 0.630] |
| 10 | size_only | rt_ms | 0.031 [-0.094, 0.159] | -0.159 [-1.168, 0.854] | -0.183 [-1.392, 1.122] |
| 10 | timing_only | ack_ms | 2.582 [2.491, 2.677] | 5.379 [5.023, 5.743] | 9.647 [8.393, 10.926] |
| 10 | timing_only | rt_ms | 9.901 [9.741, 10.075] | 9.278 [8.615, 9.866] | 9.698 [8.657, 10.706] |
| 15 | combined | ack_ms | 2.564 [2.451, 2.669] | 6.313 [5.658, 7.011] | 10.358 [9.641, 10.999] |
| 15 | combined | rt_ms | 14.902 [14.815, 14.998] | 15.913 [15.193, 16.661] | 15.938 [14.759, 17.007] |
| 15 | size_only | ack_ms | 0.079 [-0.009, 0.176] | 0.143 [-0.022, 0.302] | 0.541 [0.147, 0.918] |
| 15 | size_only | rt_ms | 0.111 [-0.006, 0.228] | 0.197 [-0.639, 1.034] | 0.720 [-0.897, 2.200] |
| 15 | timing_only | ack_ms | 2.591 [2.483, 2.692] | 5.652 [5.154, 6.217] | 10.410 [9.364, 11.337] |
| 15 | timing_only | rt_ms | 14.880 [14.751, 15.032] | 15.023 [14.384, 15.611] | 15.507 [14.162, 16.869] |
| 20 | combined | ack_ms | 2.375 [2.270, 2.481] | 5.397 [4.941, 5.911] | 9.560 [8.522, 10.456] |
| 20 | combined | rt_ms | 19.639 [19.531, 19.736] | 19.548 [18.996, 20.043] | 19.908 [18.482, 21.221] |
| 20 | size_only | ack_ms | -0.032 [-0.123, 0.059] | -0.010 [-0.154, 0.125] | 0.158 [-0.179, 0.439] |
| 20 | size_only | rt_ms | 0.037 [-0.111, 0.173] | -0.035 [-0.895, 0.854] | -0.606 [-2.184, 1.150] |
| 20 | timing_only | ack_ms | 2.463 [2.366, 2.554] | 5.106 [4.674, 5.601] | 8.611 [7.718, 9.565] |
| 20 | timing_only | rt_ms | 19.778 [19.654, 19.904] | 19.277 [18.704, 19.879] | 19.062 [17.727, 20.300] |
