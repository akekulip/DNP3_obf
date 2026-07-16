# DATA_PROVENANCE.md

Provenance and run-isolation contract for the DNP3 traffic-obfuscation harness.
Created during Phase 00 (repository audit). This document is authoritative for how
raw inputs are treated and how every experiment run records itself.

> Scope note: this file governs the obfuscation research line rooted at
> `dnp3_split_harness/`. The sibling `dnp3_multicrob_harness/` is a separate,
> non-obfuscation protocol-check line and is out of scope here.

---

## 1. Raw inputs are immutable

Raw captures are never modified, re-saved, filtered in place, or moved without a
recorded reason. Every derived artifact is regenerated from a raw input plus a
documented command — never edited by hand.

### 1.1 The six real-device traces (Phase 01 input set)

Location (current): `Traffic Trace/` at the repository root.
Hashes and capture metadata recorded during Phase 00 (2026-07-16 UTC), measured
directly from the files this session with `sha256sum` and `capinfos`.

| File | Bytes | Packets | Capture duration (s) | SHA-256 |
|---|---:|---:|---:|---|
| AB1400.pcap    | 242,066   | 2,407  | 972.81    | `01dceb19965f42fec16fad2b6bf2a563849d3a052c53831fe6c49d47f2dc86b5` |
| AB1400L.pcap   | 1,208,466 | 12,007 | 4,922.33  | `7c631744fe5d1f7748e517a05d1571164201a0ee63e216ac91dc3257a60f6e76` |
| SEL751.pcap    | 216,416   | 2,104  | 1,168.13  | `519cae47ea3863ea5c08783ee435935aca7a570a31e15e86e72b17681b0e981c` |
| SEL751L.pcap   | 2,888,482 | 28,007 | 11,444.61 | `be6159026c1b4ffff62b698eb9939cd675fd6ae8ff9f11d42029c6b084ddc2bb` |
| ION7550.pcap   | 498,327   | 4,904  | 1,675.75  | `f41681a631ed08ef6458d47d181f46222fd48c3b885e5e7c061cbe1a9ce12d6f` |
| ION7550L.pcap  | 2,452,655 | 24,097 | 8,514.35  | `69c9dcf9c2ccf012ae5d09817bb860361acb122938892417c09c7825a06dc2b9` |

Total packets across the six raw traces: **73,526**. The "base" capture and its
`…L` ("long") sibling are the same device at different capture lengths. They MUST
be kept disjoint when used as train/test (see PROJECT_CONVENTIONS.md, capture-level
split); the base/L pair for one device must never straddle a train/test boundary.

Naming convention observed: `<DEVICE>.pcap` = base capture, `<DEVICE>L.pcap` = long
capture. Devices: AB1400 (Allen-Bradley), SEL751 (SEL relay), ION7550 (ION meter).

### 1.2 Derived and replay captures

`dnp3_split_harness/captures/` (baseline/, manual/, replay/) and
`dnp3_split_harness/reports/**/*.pcap` are DERIVED or REPLAY captures produced by
the harness (loopback or Vision/Hulk rig). They are outputs, not raw inputs, and
carry no independent provenance value beyond the run that produced them. A Phase 00
gap: these live beside source and are not yet hash-manifested. Phase 01+ moves raw
vs derived apart (see proposed tree) and manifests every run.

---

## 2. Every experiment gets a fresh, isolated run directory

Target layout (Phase 01 onward):

```
runs/<UTC_timestamp>_<phase>_<short_name>/
├── manifest.json
├── config.json
├── stdout.log
├── events.jsonl        # machine-readable per-transaction log
├── pcaps/
├── tables/
└── figures/
```

`<UTC_timestamp>` is `YYYYmmddTHHMMSSZ`. A run directory is created once, written
once, and never reused. The current single `runs/run_01/` predates this contract
and is treated as legacy (documented, not overwritten).

### 2.1 Required `manifest.json` fields

Every run's `manifest.json` records, at minimum:

- `run_id`, `phase`
- `git_commit`, `branch`, `dirty_tree` (bool + list of dirty files)
- `hostname`, `os`, `kernel`
- `python_version`, `dependency_versions` (pinned, from the interpreter that ran it)
- `nic_info` and `tcp_offload_settings` where the run touches the wire
- `input_sha256` (map of every input file → SHA-256)
- `config` (the full resolved config), `random_seed`
- `command` (the exact argv)
- `start_ts`, `end_ts`, `exit_status`

If a field is not applicable (e.g. NIC info for a pure PCAP-analysis run), it is
recorded as `null` with a reason — never silently omitted.

---

## 3. Anti-staleness rules (hard)

- **Never append** new results to an existing CSV/JSON. Each run writes fresh files
  under its own run directory.
- **Never reuse** an old PCAP output path, CSV path, JSON path, figure path, or a
  stale replay directory. New run → new paths.
- A report's numbers must be regenerable from `runs/<run_id>/` + a documented
  command. A number with no machine-readable backing is marked UNSUPPORTED, not
  published as a result.

---

## 4. Baseline / exact-replay / split-replay comparisons use one source state

When comparing native vs exact-replay vs split-replay, all three derive from the
**same deterministic source state and the same source capture**:

```
fresh deterministic state
  -> baseline capture
  -> extraction from that exact capture
  -> exact replay
  -> split replay
  -> comparison
```

Never compare across different database states, different captures, or stale CSVs.
Byte preservation (`b"".join(chunks) == original`) is asserted at the point of
split, and response-byte identity is a required correctness check for every timing
or split run (see PROJECT_CONVENTIONS.md §correctness).

---

## 5. Result labels (never blur these)

Every reported number is labeled exactly one of: **measured** (real wire capture),
**replayed** (replay server on the wire), **simulated**, **inferred**, or
**projected** (computed from a scheduler plan, not observed on the wire). A
scheduler projection is never reported as a live defended-device capture. See
RESEARCH_CLAIMS.md for the current claim ledger.
