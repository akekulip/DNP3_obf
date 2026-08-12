# Cover-frame gate — corrected classification and results

DNP3-over-TCP cover-frame mechanism: prepend one or more CRC-valid DNP3 **cover** link frames
addressed to a non-endpoint link address in front of a **real** frame in the same byte stream.
The endpoint's link layer discards the cover and processes the real frame; a passive size
observer sees a larger, tunable public size.

This directory holds two independent test levels plus a size-convergence demonstration. The
labels below **supersede** any earlier "cover-frame gate PASS" wording. All software only —
no hardware, no relay, no switch. Evidence produced against the OpenDNP3 community fork
**3.1.2** (`opendnp3_commit 4648fcb`), GCC 9.4.0, CMake 3.16.3, Python 3.8.10 (see `evidence/env.txt`).

Reproduce: `bash src/run.sh` (builds two out-of-tree Catch targets in an isolated build dir,
runs them + the Python generators, sanitizes paths, then restores the fork; nothing is
committed or pushed to the fork).

---

## Result 1 — link-layer address-filter compatibility (COMPONENT). PASS.

**Reclassified label:** `OpenDNP3 3.1.2 link-layer address-filter compatibility`.
Source `src/test_cover_frame_gate.cpp`; output `evidence/cpp_test_stdout.txt`,
`evidence/results_table.csv` (**263 assertions, 5 cases, all pass**).

This drives the **real** `LinkLayerParser` + `LinkLayer` address filter with a **mock transport**
above (`MockTransportLayer`). It establishes exactly one bounded fact: for an unconfirmed
user-data frame, the link layer **discards** a cover addressed to a non-endpoint destination
(`numUnknownDestination++`, nothing pushed up, no link ACK) and **delivers** the real frame's
user data byte-identically, across the address matrix, application framings (READ/SELECT/OPERATE
request and response), multiple covers, and split TCP delivery.

**It does NOT, by itself, prove:** application-transaction completion; absence of a TCP/link
close; full master/outstation behavior; absence of application retries or CONFIRMs. Those are
Result 2. Broadcast destinations (`0xFFFD/E/F`) are **accepted** (pushed up) — a FAIL of the
discard property, locked in as evidence, not tuned away.

## Result 2 — full software transaction (real master + real outstation). PASS.

**Harness type:** in-memory full-duplex, one process. Real master `MContext` (`MasterTestFixture`)
wired to real outstation `OContext` (`OutstationTestObject`); every emitted APDU is framed into a
real DNP3 link frame, optionally prepended with cover frame(s), and fed as a DNP3-over-TCP byte
stream (optionally split) through the **receiver's real `LinkLayer` address filter**; survivors
are delivered up to the peer context. Single-fragment transport (link user-data = `0xC0 || APDU`).
This is a genuine application+transport transaction driven by the real state machines, with the
real link address filter on the delivery path — chosen over live TCP loopback to avoid the known
live-binding `SIGSTKFLT`.

Source `src/test_full_transaction.cpp`; output `evidence/full_transaction_stdout.txt`,
`evidence/full_transaction_results.csv` (**130 assertions, 5 cases, all pass**).

| Case | Transaction | Cover | Completed | master SOE | out Select/Operate | cover reached app | link ACK | closes | == baseline transcript | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| FT1 | integrity READ | individual, on request | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT2 | integrity READ | individual, on response | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT3 | SELECT+OPERATE | individual, on request | yes | – | 1 / 1 | 0 | 0 | 0 | yes | PASS |
| FT4 | integrity READ | 3 covers + split TCP | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT5 | integrity READ | **broadcast**, on request | yes | 4 | – | **2** | 0 | 0 | **no** | HAZARD_CONFIRMED |

Supported claim (individual cover): the real transaction completes byte-for-byte identically to
the no-cover baseline (identical APDU transcript ⇒ **no extra retry, no spurious CONFIRM, no
close**); the cover is dropped at the receiver's link layer, **never reaches the application**
(`cover reached app = 0`), provokes **no link ACK**, and the outstation executes exactly one
real Select and one real Operate. FT5 shows a **broadcast** cover is passed up to the application
and perturbs the transcript — the reason broadcast is a hazard and the individual address is
recommended.

## Result 3 — target convergence (size NORMALIZATION, not just enlargement). PASS.

Source `src/convergence.py`; output `evidence/convergence_sizes.csv`,
`evidence/convergence_result.json`, `evidence/convergence_stdout.txt`. Two **different** native
frames are driven to **one common public target** `S_public = 63` in the same measured length
domain by adding one legal CRC-valid cover each (cover address `0x0032`, all frame CRCs
independently verified):

| Profile | native user-data | native DNP3 link bytes | cover DNP3 link bytes | **final DNP3 link = TCP-payload (MEASURED)** | IP bytes (COMPUTED, 1 seg) | Eth bytes (COMPUTED, 1 seg) |
|---|---|---|---|---|---|---|
| profile_1 (READ class-1) | 6 | **18** | 45 | **63** | 83 | 97 |
| profile_2 (OPERATE, 2 CROB) | 31 | **45** | 18 | **63** | 83 | 97 |

Two native sizes (18 ≠ 45) reach **one measured common target (63)** at the DNP3-serialized-link
= TCP-payload layer. **IP and Ethernet are COMPUTED per single unfragmented segment, not
captured** — no normalization is claimed at any layer that was not measured. Serialized hex of
every frame is in `convergence_result.json`; e.g. `final_1 = 05640BC432…6F87 | 05640BC40A…54E0`
(63 B) and `final_2 = 05640BC432…FF50 | 056424C40A…44AA` (63 B).

---

## Recommended cover address

- **Recommended (safe):** a configured **non-local INDIVIDUAL** address proven **unused** in the
  protection domain. Here the domain is `{master=1, outstation=10}`; `0x0032` (50) is neither
  endpoint, not reserved, not self, not broadcast, and is discarded by the link filter (Results 1–2).
- **Observed-but-not-recommended:** reserved `0xFFF0–0xFFFB` and self `0xFFFC` are *observed* to be
  discarded on this device, but must **not** be recommended as universally safe — reserved is
  undefined per IEEE 1815, and self-address handling is device-configuration-dependent.
- **Hazard (do not use):** broadcast `0xFFFD/0xFFFE/0xFFFF` — accepted and passed up to the
  application (Results 1 FAIL, FT5 HAZARD_CONFIRMED).

## Supported vs prohibited claims

**Supported:** the OpenDNP3 3.1.2 endpoint discards an individual-addressed cover at the link
layer and completes the real transaction unchanged (Results 1–2); two different native frame
sizes can be driven to one common **TCP-payload / DNP3-link-byte** target with legal cover frames
(Result 3), defeating a **counting** (size-only) observer.

**Prohibited / not shown here:** that covers defeat a **parsing** observer — a parser reassembles
the TCP stream and strips covers by link address, recovering each real frame's native size (the
bounded additive-cover impossibility result stands, `convergence_result.json.parsing_observer =
NOT defeated`); any IP/Ethernet-layer normalization (computed, not measured); any multi-device or
multi-segment/fragmented generalization; any packet-observer protection.

## Model / assumptions

| Aspect | This gate |
|---|---|
| Stack | OpenDNP3 3.1.2 community fork; real link + (Result 2) real master/outstation contexts |
| Layer measured | link (Result 1); application+transport transaction with real link filter (Result 2); DNP3-serialized-link = TCP-payload bytes (Result 3) |
| Transport | single-fragment (one `0xC0` TPDU per APDU) |
| Frame type | unconfirmed user-data (func 4); no data-link confirms |
| Domain | one master (addr 1), one outstation (addr 10), one flow |
| IP / Ethernet | computed for a single unfragmented segment; **not captured** |
| Threat model | passive on-path observer; counting observer defeated, parsing observer not |

## Evidence map (sha256 in `evidence/sha256sums.txt`, `evidence/convergence_sha256.txt`)

- `src/test_cover_frame_gate.cpp` → `evidence/cpp_test_stdout.txt`, `results_table.csv`, `cpp_frames_hex.txt`
- `src/test_full_transaction.cpp` → `evidence/full_transaction_stdout.txt`, `full_transaction_results.csv`
- `src/gen_and_measure.py` → `evidence/frames_hex.json`, `sizes.csv`, `tcp_payload_sizes.csv`
- `src/convergence.py` → `evidence/convergence_result.json`, `convergence_sizes.csv`, `convergence_stdout.txt`
- `src/run.sh` → `evidence/cmake_configure.log`, `build.log`, `cmake_unittests.patch`, `env.txt`
