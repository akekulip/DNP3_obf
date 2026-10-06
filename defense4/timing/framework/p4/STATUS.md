# Case 4 size target compiler evidence

This directory contains a non-deployable fixed-layout Tofino compiler candidate and independent software oracles. The complete target implementation is **blocked**. No source here establishes safe TCP byte insertion, target runtime behavior, a functioning joint Case 4 pipeline, or hardware admission.

The fixed geometry is one native G12V1 qualifier 0x28 CROB, APDU 20 bytes, DNP3 wire frame 35 bytes. A separate trailing header and one configured inert CROB add 18 APDU bytes and two CRC bytes: transformed APDU 38, request frame 55. A successful native echoed response has APDU 40 and frame 57. Historical response frame 49 remains a separate profile. The carve preserves the original frame bytes and cuts at byte 28: `[28,21]` and `[28,29]` respectively.

`case4_size_kernel.p4` includes actual header insertion, native and transformed DNP3 CRC hash operations, IPv4/TCP checksum recomputation, two singleton insertion boundaries, cached native object fields, whole-frame SELECT/OPERATE retransmission matching, inverse partial ACK clamps and unscaled receive-window right-edge accounting. It is a compiler candidate; these operations are not target execution evidence. Tables default to disabled insertion/carving and forwarding defaults to drop. Register sentinel initialization, tuple ownership and feature admission require additional implementation.

The control seam is `insertion_profile`, keyed by IPv4 source/destination and TCP source/destination ports. `configured_decoy(index_wire, code, count, on_wire, off_wire)` takes already encoded little-endian object fields represented as P4 integers; `configured_reverse()` identifies the reverse tuple. For example, the isolated software gate's index 201 and duration 100 encode as `index_wire=0xC900`, `on_wire=off_wire=0x64000000`. This example conveys encoding, not a physical inert-point authorization. `shape` selects the 49/57 response profile and a configured PRE group; replication IDs 1/2 denote the prefix/suffix. These seams are not integrated with the current hardware adapter and must remain disabled.

The independent `fixed_layout.py` oracle uses polynomial long division rather than the strict codec's CRC implementation. Nine tests compare geometry and bytes against the strict codec, explicit response profiles and the actual replacement-image transport oracle, check source operations, and verify source/assembler evidence binding. They do not execute P4. The production OpenDNP3 semantic and software transport proofs are documented separately in `../size/CASE4_SOFTWARE_EVIDENCE.md`.

## Compiler results

Every attempt preserves its exact source, command, compiler identity, output hashes and raw log. Generated SDK outputs remain ignored; the small source/log/manifest evidence is reviewable. All probes use local `p4c 9.13.1 (SHA: e558d01)`, not the intended deployment SDE 9.13.2.

| Build | Scope | Result |
|---|---|---|
| 01–03 | Fixed layout | Parser arithmetic/selection and hash action constraints; repaired in later attempts. |
| 04 | Wire layout | Assembler requires 16 egress stages, exceeding 12. |
| 05–10 | Stateful candidate | Parser checksum placement/constants, SALU comparison limit, action staging and one intermediate syntax error; snapshots retained. |
| 11–13 | Stateful candidate | PHV slicing and action source constraints persist. |
| 14–15 | Wire ablation | Compiler aborts on checksum verification/residual mode conflict. |
| 16 | Wire ablation, input TCP checker omitted | **Compiler PASS**, 9 ingress / 11 egress stages. No ledger or input TCP validation. |
| 17 | Stateful candidate with container annotations | FAIL exit 3: incompatible PHV slicing, 72 unallocated slices. |
| 18 | Stateful candidate without annotations, constant sequence/ACK updates | FAIL exit 3: `ack_clamp_first` and `ack_clamp_second` need four sliced PHV sources plus a constant; target permits one PHV source with a constant. |
| 19 | Wire ablation retaining TCP checker | FAIL exit 134: parser checksum instance cannot mix residual/subtract mode and verification. |
| 20–23 | Checksum syntax and joint command repairs | Intermediate parser/control negation, missing U_BOR command definition and field rename errors; corrected before the final resource probes. |
| 24 | Wire ablation with input IPv4/TCP guards, no ledger | **Compiler PASS**, 9 ingress / 12 egress stages; zero spare egress stages. |
| 25 | Timing ingress plus wire24 egress | Historical compiler PASS, 10 ingress / 10 egress; superseded after eligibility review. |
| 26 | Current timing ingress plus corrected size egress | **Current compiler PASS**, 10 ingress / 10 egress, two stage slots free each; component coexistence only. |

Build 18's source is `3fe6843d53e5c31d6b64fd1760d6478a36c4f2cce2ee012e17ff4a05073bf605`. Build 19's source is `8dc42bddc1e17e7bbee348c9bd3db9a631d8cc9497a3700dc5c59e22a16de89d`. Build 16's successful ablation source is `9bdbe436ac07d1bd5dcd32693a8d5900f8486cab4694bed9031b632a45d2feb8`; its success cannot be transferred to the full source. Historical wire24 is `3c87e69959b84fff01eb62ec4c2ff7241e16c5f1d5cb8b32e683eb160b41d57d` and has its own source-bound compiler PASS and `resources.json`; it predates the egress version guard correction. Current corrected wire is `3a189e1491783f2c63f1065c43d7c32023d46e86b8704befdd245d638214d566` and is compiler-bound through joint26. `evidence/build_16/resources.json` binds that historical 9/11 stage summary to source and assembler hashes. Stage bounds are 12 ingress and 12 egress; the old seven-stage timing criterion is not applied here.

Current joint26 is `bada4652c28cb532e457674234f83124ef1bbbad9b3a160034fbacc51ff9b5c3`, composed from root timing source `3f759d06e6c610814def05ce9c83d3688b1bf8397f04000ddf546181674d2f09` and the corrected wire source above. Its assembler hash is `99de18321534709c4e3ec61a78b36a74025b3869a84d920fb08a8af289df84b1`; `evidence/build_26/{inputs,manifest,resources}.json` binds the exact input identities, command and 10/10 stage summary. Both input files matched those identities after compilation. The stage verifier requires both directions to have positive allocated stages and refuses missing-direction evidence. This is a current compiler coexistence proof, not complete functional integration.

The current inactive full prototype is `77fd7ee7255f1f2c0ba129ad047735d018884e52d2d9831649510cdbc432f65b` after the same version/TCP eligibility fixes. It has no current full compiler fit. Build18 preserves the exact earlier failed snapshot; its hash must not be described as the current prototype. The native TCP guard permits ACK/ACK+PSH, excludes ECN/control flags, and requires zero reserved bits and urgent pointer. Both size parsers require IPv4 version4, IHL5, TCP, no fragments and flags0-or-DF. A negative regression changes the native packet to version6 while recomputing valid IPv4/TCP checksum arithmetic, then checks rejection at the source-bound egress selector before padding.

The shipped SDK `tna_checksum` example treats `Checksum.verify()`'s Boolean as an error flag. The final wire component stores that raw flag as `ip_error` and requires `ip_error==false`. Its TCP checksum instance exclusively subtracts the extracted pseudo-header and complete TCP frame, then reads the residual. Using IPv4 total_len contributes twenty extra bytes for fixed IHL=5; valid input's residual is therefore `0xFFEB`. The independent arithmetic oracle checks that value and bit-corruption rejection for ACK, request and both response sizes. This establishes software arithmetic and source intent, not execution of the compiled parser. The full failed candidate retains its earlier verifier formulation; it is not an activation path. The compiler warns that `get()` is deprecated in favor of `subtract_all_and_deposit`; SDE 9.13.2 behavior remains untested.

## Remaining transport and integration blockers

The inactive target candidate has no partial or resegmented request byte-image replay. It drops active unsupported payload layouts instead of claiming loss recovery. It does not implement FIN retirement, tuple reuse quarantine, negotiated SACK/window-scale admission, or exact caches of the configured decoy across policy changes. Singleton register ownership is not a general connection table. These are blockers even if a future source compiles; a finite boundary arithmetic oracle cannot certify a complete TCP translator. The inactive full prototype also retains the unsafe old ACK clamp to the native frame end, which can retire all upstream bytes before an inserted tail is received. The repaired Python transport and arithmetic oracles hold native-end-1 until wire completion and use that same mapping for the window right edge; a modeled last-native-byte retransmission replays the exact 21-byte cached tail. Twelve software transport tests cover both boundaries, every partial-tail ACK, zero/max windows and wrap. This does not establish automatic kernel retransmission or target loss repair. The full prototype remains blocked and must never be enabled; joint26 contains no ledger and is unchanged by the Python-only repair.

`make_joint_component_probe.py` composes the current timing ingress with distinct size egress headers/parser/control and records hashes of both inputs. The resulting `case4_joint_component_probe.p4` is a compiler coexistence probe only. It omits the ledger and size ingress response CRC/shape decision and cannot establish joint operation. Timing association also needs the exact phase-dependent request ACK: SELECT's wire advance is 55, while OPERATE after the first insertion adds the prior 20-byte translation to its own 55-byte expanded request. Replacing all control advances with one constant is insufficient. Ingress timing cannot read an egress-only insertion ledger.

## Reproduction

Run from the repository root:

```sh
python3 -m unittest discover -s defense4/timing/framework/tests -p test_case4_p4_size.py -v
python3 defense4/timing/framework/p4/make_wire_probe.py
python3 defense4/timing/framework/p4/compile_size.py build_NEW case4_size_kernel.p4
python3 defense4/timing/framework/p4/compile_size.py build_NEW_WIRE case4_wire_only.p4
python3 defense4/timing/framework/p4/report_resources.py defense4/timing/framework/p4/evidence/build_26
python3 defense4/timing/framework/p4/make_joint_component_probe.py
```

Use fresh build directory names; the compiler runner refuses overwrite. Resource summary regeneration requires the ignored local assembler output. Preserved raw logs and manifest hashes remain available without SDK outputs. No hardware, control-plane loading, data ports or physical OPERATE were used by this lane.
