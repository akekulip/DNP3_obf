# E_FINAL — Defense4 unified RRC+BOR final evidence package (E0-E8)

One physical Tofino (defense4_rrc_bor_unified12, sha 33fa3a77, 12 ingress stages) between master
(Vision) and the physical SEL-751. Native vs defended paired trials on the SAME testbed.

## Reproduction
- Native baseline (defense OFF timing): configure `--mode OFF`; drivers on Vision `relay_read_g10_23.py N`,
  `relay_sbo_operate_guarded.py --select-only --count N`. Native SIZE ([49]) needs shape_enable=0 (ref: raw_pcaps/e1_native_size_shapeoff.pcap).
- Defended: configure `--mode D4 --op-a-ms 20 --op-r-ms 24 --j-set "<J>" --read-len 0`.
- Capture (Vision, master-facing, one clock): `dumpcap -i enp59s0f0np0 -a duration:N -w x.pcap -f "host 192.168.10.7 and tcp port 20000"`.
- Extract: `scripts/clrt_extract.py <pcap> <class> <mode>` -> transaction CSV. Stats/classifier: `scripts/e4e5_analysis.py`. SBO timing: `scripts/sbo_timing.py`. Size: `scripts/size_analysis.py`.

## Size provenance (audit-corrected)
Size claims derive from `csv/size_verdict.csv` (TCP-sequence reconstruction + DNP3 block-CRC + IP/TCP checksum validation), NOT arrival-order. Defended: 1280 responses ALL [28,21], seq-contiguous, CRC+checksum valid, 0 escapes. The `resp_seg_vector` column in the clrt/timing CSVs is superseded by size_verdict.csv.

## Added-latency table (from CLRT medians)
| Class | Native median | Defended median | Added latency |
|---|---|---|---|
| READ CLRT | 1.27 ms | 4.001 ms | +2.73 ms |
| SELECT CLRT | 2.11 ms | 4.001 ms | +1.89 ms |
| OPERATE echo (T0->echo) | ~native fast | 25.0 ms (T0+R) | held to policy R |

## Testbed invariance table (E0; native vs defended paired trials)
| Element | Native trial | Defended trial | Same? |
|---|---|---|---|
| Physical Tofino | one switch | one switch | YES |
| Master endpoint | Vision 192.168.10.1 dp9 | same | YES |
| Relay | SEL-751 192.168.10.7 dp64 (MAC 00:30:a7:02:4c:a2) | same | YES |
| Loaded program | defense4_rrc_bor_unified12 (33fa3a77) mode OFF | same binary mode D4 | YES (mode toggle only) |
| dp8/dp10 loopbacks | internal (switch implementation) | internal | YES (not inline devices) |
| Capture clock | Vision kernel clock | same | YES |

See CLAIM_MATRIX.md and VERDICT.json for results. dp68 relay-facing capture is unavailable
(internal pktgen/recirc port) -> Relay-facing T0+J and release multiplicity were not observable. Exactly-once BOR is not demonstrated on hardware.
