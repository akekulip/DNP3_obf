# Gate 4: control-tail CRC dependency experiment (stopped; baseline kept)

**Result: no stage recovered. E stays at 12 stages on SDK 9.13.1 and 9.13.2; N rose from 11 to 12 although its source is byte-identical, because N and E share pipe 0's stages. The qualified `seg61_02/full_04` source remains the working candidate. Nothing here ran on silicon.**

## What changed (E only)

The audit's factorization, re-derived independently in `crc_probe.py`: for a zero-status eligible control response with native transport sequence `s`, segment 2 carries `TH2(s) || B` and segment 3 `TH3(s) || 0x00`, and the DNP3 CRC is affine, so `CRC2 = CRC(0x00 || B) ^ delta[s]` with `delta[s] = CRC(TH2(s) || 0^6) ^ CRC(0^7)`, and `CRC3[s] = CRC(TH3(s) || 0x00)`.

`generate.py` rewrites only E of the qualified source (SHA256 `1b2d62d1…65aa`):
- `crc_ctl_base_t` hashes `0x00 || on_lo || off` with no input from the sequence lookup;
- `ctl_sequences_t` returns TH2, TH3, `delta[s]` and `CRC3[s]`, both constants already in wire byte order;
- `ctl_eligible` emits `cs2.crc = swap(base) ^ delta_le` and `cs3.crc = crc3_le`;
- `crc_ctl_tail2_t`, `crc_ctl_tail3_t` and their two hashes are removed.

The generator asserts that N and T are byte-identical, that replacing the new E with the old reconstructs the input, and that each table constant matches the probe. Output: `evidence/full_01/response_only.p4`, SHA256 `1789b5cb…19e3`.

## Verification

| Check | Result |
|---|---|
| `crc_probe.py`: 64 sequences x 65,536 seeded random tails, numeric | 4,194,304 / 4,194,304 |
| emitted little-endian CRC bytes inside the full 61-octet image (encode61 oracle) | 16,384 / 16,384 |
| compile, SDK 9.13.1 local and 9.13.2 on the switch host | both exit 0 |
| compiled-model packet gate (`seg61_02/model_packets.py`, the baseline's suite) | 622 / 622 (`evidence/model_packets_01`) |

## Resources (pipe 0, identical on both SDKs; `resource_review.json`)

| | baseline | experiment |
|---|---:|---:|
| stages N / E / T | 11 / 12 / 11 | 12 / 12 / 11 |
| hash bits | 1154 | 1102 |
| hash distribution units | 36 | 34 |
| exact-match input crossbar | 558 | 542 |
| ternary input crossbar | 268 | 292 |
| gateways | 78 | 76 |
| SRAM | 154 | 155 |
| logical tables | 127 | 126 |
| PHV containers / bits (9.13.2) | 222 / 4017 | 220 / 4019 |

The control chain does start one stage earlier (several E tables moved from stage 3 to 2), but E's last stage is fixed by a different dependency chain, so the program length does not change. These are resource numbers, not latency or recirculation savings; none are claimed. Per Philip's amendment A5 the experiment stops here.

Large model logs are not committed; see `UNTRACKED_LARGE_LOGS.sha256`.
