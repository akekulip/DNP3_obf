# Case 4 architecture implementation

Work is in progress. **There is no complete qualified target.** Sources here are
offline engineering candidates and executable resource experiments. Do not load
an individual probe as Case4. The controller qualification registry is empty.

The current structural direction uses protected bounded returns for ownership,
role-specific validation, and egress image banks for materialization/replay.
Holding loops bypass egress. Actual terminal receipts protect original/work
lifetimes; timestamps establish internal eligibility, not physical departure.

Continue from [PLAN.md](PLAN.md) and [HANDOVER.md](HANDOVER.md). Current N/T
prerequisite repairs at base834372cbb have40 N/T and50 T functional model cases;
M/E remain absent from that composed source. N/T/M each use12 ingress stages.
The reusable renderer uses7 egress stages, a separate budget. M admission and
dependency repairs are active; actual padding/carving/mapping/replay integration
remains unfinished. Source-harness tests and component fits do not close that gate.

| Source-bound milestone | Local SDE9.13.1 fit | Remaining interface |
|---|---:|---|
| `integration/egress_wire.p4`, `egress_wire_06` | 10 ingress / 7 egress | Connection publication, payload mapping and cache lifetime |
| `integration/egress_selected_wire.p4`, `egress_selected_wire_04` | 10 / 7 | Configured object table is not the autonomous SELECT publisher |
| `integration/handshake.p4`, `handshake_14` | 12 / 0 | Retirement/reuse and coalesced final ACK plus SELECT |
| `integration/connection/selected.p4`, `selected_22` | 12 / 0 | Live connection epoch; scheduler/transformer join |
| `integration/read/validator.p4`, `validator_05` | 6 / 0 | Request/response association and timing admission |
| `protocol/payload_mapping/forward.p4`, `forward_03` | 10 / 0 | Actual current WorkRecord and full upstream validator |
| `protocol/payload_mapping/reverse.p4`, `reverse_12` | 11 / 0 | Same protected producer/owner seam; configured geometry |
| `ownership/p4/held_timing_expected_probe.p4`, `held_timing_expected_02` | 12 / 0 | Native READ/timing admission, service/loss and physical gap |

The wire composition has one actual shared set of fourteen two-slot32-bit egress
image banks. Native35 is validated and expanded to55 before caching. A validated
native one-byte tail can retrieve that image while retaining its current TCP
header fields. Carving uses PRE IDs1/2 and recomputes TCP/IP checksums for[28,29].
The private cache descriptor is12 bytes. READ20/49 validation forwards the
original frame. Pure ACK roles implement two-boundary full32 sequence/window
mapping. **Payload roles do not yet pass through that mapping**; coexistence does
not establish correct end-to-end transformed transport or all-overlap replay.

Independent review repaired descriptor-free response routing into cache banks:
ordinary responses now bypass egress; admitted full-CRC split traffic alone
enters carving. Parser errors precede state mutation. READ checks configured
link addresses as well as all frame/network checks. Counterexamples and repaired
source checks are retained in `protocol/review/`; they are supporting execution
of source fragments, not target-model packet tests.

Each egress image bank now has one store/load dispatch table. This removes the
same-bank placement conflict and retains one shared image bank set. A stale
descriptor can still read an overwritten scalar slot; the retained counterexample
requires a genuine current-owner pin and no-reuse gate before integration.
Payload mapping preserves arbitrary payload bytes and computes checksum changes
for both boundaries and both window edges, but its private WorkRef is not yet
checked against the live WorkRecord. These remain explicit incomplete interfaces.

Three families have genuine retained experiments:

| Family | Established result | Decision |
|---|---|---|
| Same pipe | Shared ingress cache required13–15 stages or failed CRC PHV placement; egress placement fits the wire composition10/7 | Prefer egress image placement; complete lifecycle join still required |
| Bounded additional passes | Protected handshake12/0 and SELECT association12/0 fit; direct holder/timing bridge exceeded12 stages | Continue qualified handoffs and bounded service/assembly alternatives |
| Separate functional pipes | Historical authority compositions failed; later local cross-pipe probe and current N0/T2 prerequisite composition run | N0/M1/T2 with E0 is the selected integration placement; full publication/credit join remains unfinished |

`integration/PIPE_SPLIT.md`, component reports and immutable evidence record
precise failures. These results do not prove every possible full architecture
infeasible. Outstanding features remain requirements, never an implicit scope
reduction. `integration/assembly_passes/REPORT.md` records actual grouped merge,
separate stateless worker, byte worker and staged-byte worker experiments. Even
one four-bank worker retains PHV conflicts; no complete fragment producer fits.

Run from this directory, with a locally installed licensed SDK:

```sh
python3 integration/egress_compose.py integration/egress_selected_wire.p4 --selected-carve
python3 build.py integration/egress_selected_wire.p4 integration/evidence/new_wire_run
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s protocol/review -p 'test_*.py'
```

Every compiler output directory must be new. `build.verify_evidence` checks actual
current source/includes, compiler, logs, every declared pipeline's binary/context,
schema and resource-report bytes. SDK outputs are ignored; retained hashes cannot
qualify a fresh checkout without rebuilding. Source-bound checks are in
`integration/evidence/verified_milestones_02.json`. Earlier milestone files refer
to their immutable historical source snapshots and must not qualify changed code.

An early isolated target-model startup failed for lack of CAP_NET_RAW. The later
private namespace launcher runs functional packet tests; see the current N/T
evidence index and handover for exact identities and diagnostic fixture limits.
It does not establish physical timing. Deployment also requires current SDE9.13.2 and a complete
reviewed inventory. Hardware loading, traffic, service measurements and physical
OPERATE have not occurred. The fixed44-block/16,168-attempt campaign remains
unchanged, with no additional calibration, retries or use of spare allowance.

Component reports: `ownership/REPORT.md`, `protocol/REPORT.md`,
`protocol/assembly/REPORT.md`, `protocol/egress/REPORT.md`,
`integration/REPORT.md`. `PLAN.md` defines the preserved contracts and `LEDGER.md`
records execution milestones.
