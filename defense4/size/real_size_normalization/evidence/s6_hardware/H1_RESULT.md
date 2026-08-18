# H1 — cell protocol over the hardware path: milestone 1 PASS

Date: 2026-08-18. Builds on H0 (CPU path proven). Switch restored to RRC after.

## Milestone 1 (of H1): the real S4 fixed-cell codec round-trips over silicon — PASS

The S4 `S3-RNL-256-v1` fixed-cell protocol — actual `cell_codec` with
ChaCha20-Poly1305 AEAD, 256-byte cells, EtherType 0x88B5 — was carried over the
real Tofino CPU path and reconstructed the exact inner frames.

### What ran

- `hw/h1_cellgate.p4`: cell-gate for EtherType 0x88B5 (dp9 -> CPU 192; CPU 192 ->
  dp9). Compiled clean, loaded via `swap_generic.sh` (RRC displaced), dp9 up.
- Vision (`enp59s0f0np0`): the real `offline/cell_codec.py`, deployed standalone
  (needs only `cryptography`, present). For 20 epochs it `encode_slot`s two inner
  Ethernet frames into a 4-cell request slot, sends the cells on dp9, receives the
  cells reflected by a byte-identical CPU echo shim, and `decode_slot`s them.
- Switch (`ens1`): a byte-identical 256-byte / 0x88B5 cell reflector.

### Result

```
epochs=20  cells_reflected=80  slots_decoded_byte_equal=20
slot_rtt_ms  median=0.838  max=1.127
```

- **20/20 slots decoded byte-equal** — every AEAD cell slot traversed
  Vision -> dp9 -> CPU(192)/ens1 -> dp9 -> Vision intact, and the inner frames
  reconstructed exactly (`decode.frames == originals`).
- 80/80 cells reflected; slot RTT sub-2 ms, far inside one 210 ms epoch.
- The MAC self-loop gotcha from H0 does not arise here: cell outer MACs are
  `02:00:00:00:00:01/02`, neither is Vision's MAC.

### Significance

The fixed-cell protocol itself (encryption, framing, slot batching, exact
reconstruction) works over the proven hardware CPU path. Combined with H0, the
path can carry real S4 cells, not just marked test frames.

## Not yet done (rest of H1 / H2)

- The full two-shim bridge end to end: the actual `l2_shim` running on both
  boundaries with the DNP3 master and relay. The switch-CPU shim needs adapting
  for a single CPU netdev (`ens1` carries both cell and inner traffic, demuxed by
  EtherType) or a second CPU netdev; and the cell-gate must add the dp64/relay
  demux (dp64 inner -> CPU, CPU inner -> dp64). This is the larger integration.
- Cross-host epoch sync (R1): here Vision both encodes and decodes, so no
  cross-host clock was needed; the real bridge needs the two hosts phase-locked.
- The SEL-751 (still never contacted) and `bf_kpkt` sustained cell-rate (R2).

## Switch state after

Restored: `defense4_rrc_kernel` + dp8/dp9/dp64 up (matches pre-H0 snapshot). SEL-751
never contacted. `h1_cellgate` left installed for the next step.
