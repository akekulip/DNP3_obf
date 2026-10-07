# Bounded assembly structural experiments

**Primitive implemented; complete producer not compiled or qualified.** These
new candidates preserve the frozen protocol/assembly sources. They keep full32
TCP sequence/clock arithmetic, actual expected/candidate snapshots, exact byte
overlap checks and the native35 CRC/profile validator. The126-byte prefix is
16-byte reference +48-byte expected +48-byte candidate +14-byte fragment control;
it is true recirculation traffic, not an eight-byte resubmit.

| Candidate / immutable run | Structural hypothesis | Actual local9.13.1 result |
|---|---|---|
| `producer.p4` / producer04 | Three four-bank merge returns, separate from snapshot/CAS returns | FAIL460 PHV slices; source `758da06ea3c3c125b2dadabe992a7f34438983714820b4c03d42b57e08585cd0` |
| `worker.p4` / worker02 | Stateless merge worker; parent retains all origin/scratch/owner state | FAIL419 PHV slices; no worker state copied |
| `byte_worker.p4` / byte_worker01 | Byte operations in worker; full32 atomic CAS stays at authority | FAIL140 PHV slices |
| `fixed_worker_0.p4` / fixed_worker0_03 | Only four banks in a physical worker | FAIL48 PHV slices |
| `fixed_worker_0.p4` / fixed_worker0_04 | Explicit eight-bit containers on those active bytes | FAIL same48 slices; source `71f1bbf6d54318c4886c40793edcb4e6e15f9cd5a025e157decf2ed1b9daeb38` |
| `staged_worker_0.p4` / staged_worker0_01 | First rotate fragment bytes into candidate positions, then compare aligned expected/candidate bytes in later tables | FAIL48 PHV slices; source `c1b8f60af20c78de850f1525df29345343ff6f751bec5aea8e80838a2100db89` |

Every run retains source, compiler/log hashes and outcome in `evidence/`; no
failed build has a target binary. Fields in the remaining conflict include the
incoming bytes, expected/candidate bytes and comparison results constrained by
the many offset-dependent byte moves. Group1/2 workers have not compiled. These
failures reject the tested layouts, not every possible assembly architecture.
A parser that normalizes incoming bytes into fixed absolute frame positions, or
a serialized per-byte worker with a different envelope and independently measured
pass/bandwidth cost, is an additional architectural choice; neither is implemented
or claimed to fit here. Authority must still pin the whole work until every
actual producer terminal before any slot can be cleared or reused.

Independent review repaired three concrete authority defects. Parser errors now
precede origin/scratch/quarantine writes. A packet carrying hops16 faults before
increment or state access; hops15 can become16. The readiness predicate uses
29,999,872ns at256ns quantum: across all256 origin residues, it never accepts a
write at/after a true30ms deadline, with at most383ns early refusal. This is a
conservative assembly admission bound, not a changed clock or measured service
deadline. Immutable producer02/03 retain the original counterexamples.

`tests/` executes the actual generated control/table fragments against an
independent byte expectation: grouped real returns, every fragment offset,
duplicates/reordering, exact wire-word encoding and overlap conflicts. Review
adds all630 legal offset/length pairs for group0, including duplicate cases,
unchanged inactive candidate words and invalid envelopes; it also checks2560
clock/residue/wrap cases. These interpreters establish supporting algorithm
evidence, not complete compiled parser/deparser or Tofino execution.

Reproduce locally from the architecture directory:

```sh
python3 -m unittest discover -s integration/assembly_passes/tests -p 'test_*.py' -v
python3 -m unittest discover -s protocol/review -p 'test_*.py' -v
python3 integration/assembly_passes/generate.py --byte-masks
python3 build.py integration/assembly_passes/producer.p4 integration/assembly_passes/evidence/new_producer_run
```

Missing live epoch/WorkRecord pin, protected scratch installation, terminal/debt
integration, current publication and actual private return topology remain full
target requirements. Configuration context is not their substitute. No packet
traffic, switch activation or physical operation occurred.
