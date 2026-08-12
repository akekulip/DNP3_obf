# Cover-frame gate — corrected classification and results

DNP3-over-TCP cover-frame mechanism: prepend one or more CRC-valid DNP3 **cover** link frames
addressed to a non-endpoint link address in front of a **real** frame in the same byte stream.
The endpoint's link layer discards the cover and processes the real frame; a passive size
observer sees a larger, tunable public size.

The labels below **supersede** any earlier "cover-frame gate PASS" and "full software
transaction" wording (corrected 2026-08-12, audit M2). All software only — no hardware, no
relay, no switch. Evidence against the OpenDNP3 community fork **3.1.2**, GCC 9.4.0, CMake
3.16.3, Python 3.8.10 (see `evidence/env.txt`).

**Evidence classes are kept strictly separate** — this is the whole point of the correction:

- **Result 1 (link):** the real `LinkLayer` address filter, mock transport above. `src/run.sh`.
- **Result 2 (application-context + link):** an in-process round trip through the real master
  and outstation APPLICATION state machines and the real link address filter. **NOT** TCP, NOT a
  socket, NOT persistent transport reassembly. `src/run.sh`.
- **Result 3 (size arithmetic):** DNP3-serialized-link byte convergence, **numerically** equal to
  a one-segment TCP payload by construction (not a captured measurement). `src/convergence.py`.
- **Gate C — real channel (socket / TCP / transport / captured-wire):** a live single-process
  OpenDNP3 `DNP3Manager` TCP loopback, captured with `dumpcap`. See **`real_channel/`**
  (`bash real_channel/src/run_real_channel.sh`). **Gate C = PARTIAL** — the baseline READ/SBO real
  channel passes and is captured; the full-stack cover-injection case is **BLOCKED-BY-SANDBOX**
  (SIGSTKFLT on any loopback relay; `real_channel/evidence/sigstkflt_root_cause.txt`).

Reproduce Results 1–3: `bash src/run.sh` (builds two out-of-tree Catch targets in an isolated
build dir, runs them + the Python generators, sanitizes paths, then restores the fork; nothing is
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
request and response), multiple covers, and delivery split across successive
`LinkLayerParser.OnRead()` calls (parser-level chunking, **not** TCP segments).

**It does NOT, by itself, prove:** application-transaction completion; absence of a TCP/link
close; full master/outstation behavior; absence of application retries or CONFIRMs. Those are
Result 2. Broadcast destinations (`0xFFFD/E/F`) are **accepted** (pushed up) — a FAIL of the
discard property, locked in as evidence, not tuned away.

## Result 2 — bounded application-context round trip through a real link address filter. PASS.

**Evidence class: application-context + link. NOT TCP, NOT a socket, NOT persistent transport.**
Real master `MContext` (`MasterTestFixture`) and real outstation `OContext`
(`OutstationTestObject`) run in one process. For each emitted APDU the harness manually prepends
**one** `0xC0` transport octet (a single-TPDU stand-in — there is no transport layer and no
reassembly), manually frames it, optionally prepends CRC-valid cover frame(s), and feeds the
bytes into a **newly constructed** `LinkLayerParser`+`LinkLayer` fixture (its real **address
filter** decides discard vs deliver); survivors are stripped back to APDU hex and injected into
the peer context. "Split" here splits successive `LinkLayerParser.OnRead()` **calls**, not TCP
segments. The `closes` column counts application `MockMasterApplication` OnClose callbacks; it is
0 and says **nothing** about a TCP or link-session close (no such session exists in this harness).
The real socket / TCP / transport / captured-wire evidence is in **`real_channel/`**.

Source `src/test_full_transaction.cpp`; output `evidence/full_transaction_stdout.txt`,
`evidence/full_transaction_results.csv` (**130 assertions, 5 cases, all pass**).

| Case | Txn | Cover | App round trip completed | master SOE | out Select/Operate | cover reached app | link ACK | app OnClose | == baseline transcript | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| FT1 | integrity READ | individual, on request | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT2 | integrity READ | individual, on response | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT3 | SELECT+OPERATE | individual, on request | yes | – | 1 / 1 | 0 | 0 | 0 | yes | PASS |
| FT4 | integrity READ | 3 covers + `OnRead()`-split | yes | 4 | – | 0 | 0 | 0 | yes | PASS |
| FT5 | integrity READ | **broadcast**, on request | yes | 4 | – | **2** | 0 | 0 | **no** | HAZARD_CONFIRMED |

Supported claim (individual cover): the application-context round trip completes byte-for-byte
identically to the no-cover baseline (identical reconstructed APDU transcript ⇒ **no extra app
retry, no spurious CONFIRM**); the cover is dropped at the receiver's link **address filter**,
**never reaches the application** (`cover reached app = 0`), provokes **no link ACK**, and the
outstation executes exactly one real Select and one real Operate. This claim does **not** cover
TCP/link close (see `real_channel/` for the socket/TCP class). FT5 shows a **broadcast** cover is
passed up to the application and perturbs the reconstructed transcript — the reason broadcast is a
hazard and the individual address is recommended.

## Result 3 — target convergence (size NORMALIZATION, not just enlargement). PASS.

Source `src/convergence.py`; output `evidence/convergence_sizes.csv`,
`evidence/convergence_result.json`, `evidence/convergence_stdout.txt`. Two **different** native
frames are driven to **one common public target** `S_public = 63` **DNP3-serialized-link bytes**
by adding one legal CRC-valid cover each (cover address `0x0032`, all frame CRCs independently
verified). The 18/45→63 figures are **DNP3 serialized bytes** (byte length of the emitted link
frames), which are **numerically equal to a one-segment TCP payload BY CONSTRUCTION** — not a
captured TCP measurement:

| Profile | native user-data | native DNP3 link bytes | cover DNP3 link bytes | **final DNP3-serialized-link bytes** (= 1-seg TCP payload by construction) | IP bytes (COMPUTED, 1 seg) | Eth bytes (COMPUTED, 1 seg) |
|---|---|---|---|---|---|---|
| profile_1 (READ class-1) | 6 | **18** | 45 | **63** | 83 | 97 |
| profile_2 (OPERATE, 2 CROB) | 31 | **45** | 18 | **63** | 83 | 97 |

Two native sizes (18 ≠ 45) reach **one common target (63)** in DNP3-serialized-link bytes. A
single unsegmented TCP payload carries exactly those bytes, so the target is equal to a one-segment
TCP payload **by construction, not by packet capture**. **IP and Ethernet are COMPUTED per single
unfragmented segment, not captured.** (For an actually-captured DNP3-over-TCP byte stream on the
wire — with real segmentation — see `real_channel/`.) Serialized hex of every frame is in
`convergence_result.json`; e.g. `final_1 = 05640BC432…6F87 | 05640BC40A…54E0` (63 B) and
`final_2 = 05640BC432…FF50 | 056424C40A…44AA` (63 B).

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
**address filter** and the application-context round trip completes unchanged (Results 1–2); two
different native frame sizes can be driven to one common **DNP3-serialized-link byte** target with
legal cover frames (numerically equal to a one-segment TCP payload by construction, Result 3),
defeating a **counting** (size-only) observer; and a **real** single-process OpenDNP3 TCP loopback
completes READ and SBO on the captured wire (Gate C, `real_channel/`).

**Prohibited / not shown here:** that covers defeat a **parsing** observer — a parser reassembles
the TCP stream and strips covers by link address, recovering each real frame's native size (the
bounded additive-cover impossibility result stands, `convergence_result.json.parsing_observer =
NOT defeated`); any IP/Ethernet-layer normalization (computed, not measured); any multi-device
generalization; any packet-observer protection; **any TCP/link-close conclusion from Results 1–3**
(no socket exists there — that class lives only in `real_channel/`); and the **full-stack
cover-injection** case, which is BLOCKED-BY-SANDBOX (`real_channel/evidence/sigstkflt_root_cause.txt`).

## Model / assumptions

| Aspect | Results 1–3 (this dir) | Gate C (`real_channel/`) |
|---|---|---|
| Stack | OpenDNP3 3.1.2; real link filter + (R2) real master/outstation contexts | OpenDNP3 3.1.2 real `DNP3Manager` TCP server + client, one process |
| Evidence class | link (R1); application-context + link (R2); size arithmetic (R3) | socket / TCP / transport-reassembly / captured-wire |
| Transport | one hand-added `0xC0` TPDU per APDU; **no reassembly** | real transport, **multi-segment reassembly captured** (SEQ 0..6, 1574 B) |
| Socket / TCP | **none** (in-process; `OnRead()` chunking, not TCP segments) | real asio sockets on `lo`; SYN/ACK/PSH/FIN/RST captured |
| Frame type | unconfirmed user-data (func 4); no data-link confirms | as emitted by the real stack (unconfirmed user-data) |
| Domain | one master (addr 1), one outstation (addr 10), one flow | one master (addr 1), one outstation (addr 10), one flow |
| IP / Ethernet | computed for a single unfragmented segment; **not captured** | captured (loopback Ethernet/IP headers on the wire) |
| Threat model | passive on-path observer; counting defeated, parsing not | n/a (functional real-channel evidence, not an obfuscation claim) |

## Evidence map (sha256 in `evidence/sha256sums.txt`, `evidence/convergence_sha256.txt`)

- `src/test_cover_frame_gate.cpp` → `evidence/cpp_test_stdout.txt`, `results_table.csv`, `cpp_frames_hex.txt` — **link** class
- `src/test_full_transaction.cpp` → `evidence/full_transaction_stdout.txt`, `full_transaction_results.csv` — **application-context + link** class (NOT TCP/transport)
- `src/gen_and_measure.py` → `evidence/frames_hex.json`, `sizes.csv`, `tcp_payload_sizes.csv`
- `src/convergence.py` → `evidence/convergence_result.json`, `convergence_sizes.csv`, `convergence_stdout.txt`
- `src/run.sh` → `evidence/cmake_configure.log`, `build.log`, `cmake_unittests.patch`, `env.txt`
- `real_channel/` → **socket / TCP / transport / captured-wire** class (Gate C, PARTIAL): `run_real_channel.sh`, `rt_loopback.cpp`, `cap_*.pcapng`, `tcp_flow_baseline.txt`, `transport_reassembly_frag.txt`, `dnp3_baseline.txt`, `sigstkflt_root_cause.txt`
