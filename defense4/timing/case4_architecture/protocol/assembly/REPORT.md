# Bounded OPERATE assembly: structural result

The required complete target producer remains **blocked**. New executable TNA
experiments implement12 scratch banks, atomic snapshot/CAS, constant offset-specific
three-byte merging, actual raw IPv4/TCP fragment admission, full35 reconstruction
and CRC/object matching before publication. The current full candidate does not
compile; neither primitive compilation nor source-fragment tests qualify it.
Completed protocol sources and their previous evidence remain unchanged.

## Compiler evidence

All attempts use actual SDE9.13.1 in fresh source-bound directories.

- `evidence/buckets_02`: paired64 `{generation32,encoded32}` snapshot/CAS fails
  input-crossbar placement. CAS needs generation32, expected32 and new32, but
  each bank supports only two PHV inputs. Per-word generation CAS is not fitted.
- `scalar_buckets.p4`, `evidence/scalar_01`: **PASS5 ingress/0 egress**, critical
  path2, twelve scalar32 banks of one slot. Source SHA
  `bac997d88fc61f4321d32cc73a7ca908361d7d783b136c34b5ecb44407bf84d7`.
  It snapshots actual words and CASes expected→candidate using two PHV inputs.
  It requires actual protected whole-work no-reuse authority; the bench envelope
  by itself is not that authority.
- `evidence/merge_scalar_01` retains the multi-stage three-operand OR failure.
  The generator now separates its OR operations and clears absent fragment bytes.
- Current `producer.p4`, `evidence/producer_05`: **FAIL**, exit3,165.583seconds,
  SHA `94ae6fbeb8cd736c3563682eb38b82cc1ff34fb40a8efa053ed6f9aa7b0fe698`.
  Actual compiler reports action constraints and failed PHV allocation. Packed
  bucket presence bits26:24 and status bits31:27 force incompatible slices:
  retain/merge/finish then need three PHV sources where only two are supported.
  No allocated stage counts or executable target artifacts are claimed.
- Prior producer attempts retain syntax/table-control failures and the earlier
  PHV grouping failure. The current attempt fixes repeated table applications,
  uses separate full32 length for end-offset arithmetic, separates OR operations,
  and records genuine recirculation roles. No tolerance or limit was relaxed.

A next structural alternative would separate presence masks from unsliced data
banks, or parse a native-aligned transformed frame on a genuine return before
CRC validation. Either requires actual source-bound compilation and protected
whole-work lifetime integration. The existing failure is not a capability proof
that every possible assembler is infeasible.

## Implemented source candidate and limits

Actual raw parsing checks IPv4v4/IHL5/TCP, fragments/options/flags/urgent/reserved,
exact payload lengths1..35, IPv4 checksum and whole TCP checksum before scratch
processing. The original raw TCP packet remains unchanged inside private work.
The constant offset tables derive exact byte alignment without runtime shifts.
Overlap conflicts quarantine; consistent duplicate and reordered fragments merge.
CAS collisions retry by taking a new actual snapshot, under a16-processing-hop
bound. All35 covered bytes are reconstructed and all three DNP3 CRCs plus the
native OPERATE profile and exact selected-object fields checked before emitting
native35 for the separate validated padder. No partial OPERATE forwards and no
ACK is fabricated.

First-fragment observation is tagged by full32 work generation, so timestamp0
is valid. Later fragments do not extend the original deadline. Full32 subtraction
checks the30ms absolute deadline across wrap. Clocks follow the project's256ns
mask. A dedicated genuine private fault-return event latches quarantine before
future scratch updates; old private epoch/generation does not poison current state.
The source records current TCP ACK/window fields and restores native stream start
on full publication. Source tests cover early fault blocking of an already
prepared CAS, not merely blocking subsequent new fragments.

The full candidate remains unqualified even if its PHV problem were resolved:

- `connection`/`selected_objects` are external immutable-context table seams.
  They are not an autonomous verified handshake/SELECT publisher. There is no
  actual active-selected publication gate before first scratch mutation; this
  requires the connection producer and actual stored context integration.
- Scalar banks require actual WorkRecord pinning, authorized initialization/reset,
  actual outstanding-fragment terminal credits and retirement/reuse accounting.
  Those operations are not implemented by the candidate. The work envelope and
  supplied generation are insufficient to establish them.
- Connection abandonment, policy-off, active-ledger continuation and exact
  all-overlap cached replay remain integration obligations; this source must not
  replace or erase the committed transport ledger on a fault.
- The16B identity envelope is followed by48B actual snapshot words,48B candidate
  words and14B fragment observation/cursor header:126B private prefix, plus the
  original Ethernet/IPv4/TCP fragment. These additional bytes need topology and
  bandwidth accounting. Ports68/69/70 are unconfigured bench roles.
- The deadline is a source clock check, not a measured service bound. Independent
  recovery, queue service, no-reuse barriers and complete pipeline fit remain open.

## Independent executable checks

Ten checks pass in `assembly/tests/`: actual source constant-table byte merges
for every native offset, reordered fragments, duplicates and overlap conflicts;
actual atomic register bodies; origin0 and full32 wrap; full35 source reconstruction
and CRC acceptance; corrupt CRC and sticky faults; old private cookie exclusion;
prepared-CAS suppression under an already latched fault; and hop/deadline bounds.
The control-fragment interpreter supplies parser/checksum outcomes and external
immutable-context fixtures. Expected bytes come from the independent existing
software codec. These are not compiled target-model or physical packet tests.

`test_denied_writer.py` executes the **frozen** `padding_cache_writer.p4` admission
bug: forwardingdeny sets `drop_ctl=1`, but all14 image banks still mutate. An
in-memory admission guard prevents those writes. The old source remains frozen;
its standalone cache writes must not be activated under denied admission.

`test_branch_cache.py` independently executes root's actual padding/replay
controls, actual outer admission guards and actual shared Cache register actions.
Against root source SHA
`7ee6777dd32b3f8fb8e222f34f6cdc8b1dae2959e141d386e8c77604f12534c5`, denial
causes0writes/reads; allowed padding writes14 exact words; allowed matching replay
reads14 and renders the last24 bits and stream start. Wrong native-byte replay
causes0reads. This establishes the scoped source guard fix, not current-owner
publication, model behavior or complete fit.

No commits, target loading/configuration or external traffic occurred. New work
is confined to `protocol/assembly/`; prior protocol sources/evidence are frozen.
