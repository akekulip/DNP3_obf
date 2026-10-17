# m10_02 compiled-model smoke failure: bisect (2026-10-17, diagnostic only, never a candidate)

`model_smoke_m10_02_01` fails `SELECT_61`: the SELECT response reaches the master unpadded (91 octets, not 115).
The m9_01 control under the same record_closure launcher passes 30/30. The first divergence in the model logs is
N's stage-1 pass of an ACK (event 0x0103 -> 0x0203). Its input frame is identical on both builds, but m10's output
origin header carries wire_ack 0x00000000 and normalized_epoch 0x03850000, where m9 emits 0x00000385 and
0x00000001: the origin fields shifted by 16 bits. Nothing m10 changed in the source is on that path.

Variants, each m9_01 with one part of m10 (local SDK 9.13.1 compile, then model_smoke):
- `v1_metadata_only`: the 16-bit `m.rst_laps` field, its parser assignments and first_close restoring it;
- `v2_table_only`: m10's reset_boundary and restart actions, without the metadata field.

## Result

| variant | local compile | model_smoke |
|---|---|---|
| `v1_metadata_only` | rc 0 | **FAIL** 2/4 (`SYNACK`, exception): fails earlier than m10_02 |
| `v2_table_only` | rc 0 | **PASS** 30/30 |

The compiled-model defect comes with the new metadata field and its parser assignments, not with m10's
reset_boundary rows or restart actions. The source interpreter does not reproduce it, so it lies in how bf-p4c
9.13.1 compiles that field. The exact mechanism was not established. The correction drops the field: m10_03
carries the lap counter in the already-valid envelope instead (snapshot variants that keep `reserved` on retry
rows). m10_03's smoke run passes 30/30.
