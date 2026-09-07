# Corrected active harness

The drivers that ran are in `../implementation/harness/` and are byte-identical to the
campaign. They are not edited, because their hashes are part of the provenance chain. This
directory holds the corrected versions, for any future run.

Nothing here has contacted the relay. `--dry-run` is the default in both drivers, and live
operation additionally refuses unless `DEFENSE4_HW_AUTHORIZED=1` is set.

## Layout

```
active_harness/
├── dnp3_codec.py        framing, CRC validation, reassembly, response parsing and validation
├── session.py           one TCP session with an explicit monotonic transaction deadline
├── frozen_builders.py   imports the frozen frame builders and the {1,3} guard, unchanged
├── read_driver.py       READ, function 1, G10V2 points 0..22
├── sbo_driver.py        SELECT then OPERATE, with the OPERATE gated on the SELECT
└── tests/               42 offline tests, no socket and no hardware
```

## What each correction fixes, and where the defect was

| correction | the defect it replaces |
|---|---|
| explicit monotonic transaction deadline; the **remaining** budget is passed to every blocking receive | `relay_read_g10_23.poll` and `relay_sbo_operate_guarded._recv_frame` re-armed `settimeout` per read, so nothing bounded the transaction; `campaign_run.recv` did the same with 3.0 s |
| complete frame reassembly across TCP reads | `poll` broke out of its read loop on `len(buf) > 8 and len(d) < 4096`, a heuristic on read size rather than on DNP3 framing, and could return a partial frame |
| bytes past the end of a frame are preserved | `poll` discarded its buffer per transaction and `campaign_run.recv` returned `buf[j:j+tot]`, dropping anything after it; a coalesced next frame was lost and the stream could desynchronise |
| every per-block CRC is verified | `dnp3_wire.deframe` steps over CRC octets with `p += t + 2` and never compares them; no driver validated a CRC |
| the two-octet IIN is skipped before the object header | `relay_sbo_operate_guarded._status` used `obj = userdata[3:]` and tested `obj[2] == 0x17`; with the IIN present that octet is the group `0x0C`, so the CROB status was never read and every transaction reported `st=None` |
| function, group, variation, qualifier, count, point list and CROB status are all checked | `poll`/`analyze` recorded the function without asserting it; `campaign_run.parse` checked group and status but not the point list or the sequence number |
| the response's application sequence number must match the request | no driver associated a response with its request; any response could complete any transaction |
| a stale or unrelated response is discarded, not accepted as completion | a late response from the previous transaction would have satisfied the next one |
| a matching successful SELECT response is required before an OPERATE is built | `relay_sbo_operate_guarded` built and sent the OPERATE at lines 134 to 137 and computed `sel_ok` at line 140; `campaign_run` likewise sends the OPERATE without gating on `st1` |
| distinct sequence numbers for SELECT and OPERATE | the frozen driver reused one, which the campaign manifest records as having produced `NO_SELECT` |
| timeout, peer close, framing error, invalid response and not-attempted are distinct outcomes | a timeout returned a short buffer that then parsed as a missing response, indistinguishable from a malformed one |
| missing transport acknowledgment is recorded as not observable | it cannot be observed from a socket at all; the field says so instead of carrying an invented value |
| no automatic OPERATE retry | none existed, and none is added: a retried OPERATE is a second control action and needs an argued policy |
| `TCP_NODELAY` is set | `campaign_run.py` left Nagle enabled |
| the `{1, 3}` allowlist and both construction-time guards are imported from the frozen module | preserved exactly rather than reimplemented, so the authorized set cannot drift |

## Outcomes

`Outcome` records the operation, function, application sequence number, the outcome, monotonic
send and completion instants, elapsed and remaining budget, the response function and IIN, the
per-point statuses by name, the reasons for any rejection, how many stale frames were
discarded, how many bytes were left buffered, and the acknowledgment-evidence note. One JSON
object per transaction with `--out`.

## Tests

```sh
python3 tests/test_active_harness.py          # 42 tests, Python 3.8 and later
python3 -m pytest tests -q                    # same suite under pytest
```

They are adversarial: corrupted header CRCs, corrupted block CRCs, flipped payload bits,
frames split at every one of their byte boundaries, byte-at-a-time delivery, coalesced frames,
leading garbage, a split start pattern, truncated object blocks, every defined CROB status
code, wrong function, wrong group, wrong variation, wrong qualifier, wrong point list,
sequence mismatch, stale responses, peer close, and the forbidden index set.

The suite was checked against six deliberate regressions, each of which it catches:

| regression | tests that fail |
|---|---|
| the SELECT gate removed | 1 |
| the full budget re-armed on each receive | 1 |
| CRC verification disabled | 5 |
| the IIN not skipped when locating the object header | 10 |
| a stale response accepted as completion | 2 |
| bytes after a frame discarded | 4 |

The codec is also checked against the SEL-751A reference response embedded in the frozen
`dnp3_wire.py` self-check: its header CRC, its block CRCs, its IIN at `user_data[3:5]`, its
object group at `user_data[5]`, and both CROB statuses.

## What these drivers do not do

They do not run hardware, and they are not a rerun. The rerun package, including what a run
would need to instrument that this evidence lacks, is `../TIMING_ONLY_RERUN_PLAN.md`.
