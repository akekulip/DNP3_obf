# Gate S4 Adversarial Plan Critique

Role: critic

Initial verdict: **REJECT before a committed S4 plan**

The mission alone did not pin the namespace graph, trusted-boundary byte oracle, no-proxy invariant, privilege assumptions, leakage gate, or failure metrics. Direct coding could therefore produce a dual TCP proxy that passes application tests while contradicting the selected packet-preserving design.

Required repairs now captured by `S4_SOFTWARE_SPEC.md`:

1. explicit endpoint, shim, observed-link, and capture topology;
2. complete Layer-2 frame carriage and a hard ban on TCP termination;
3. trusted-input, observed-link, and trusted-output capture oracles;
4. runtime-only prototype keys and non-sensitive evidence rules;
5. fixed-transcript, replay, fault, overflow, buffer, latency, and resource gates;
6. an S4-only claim and stop before hardware integration.

The critic should re-review the implementation and generated evidence before S4 can pass.

## Contract rereview and repairs

A second review found two remaining blockers: unspecified ARP/MAC resolution and unspecified TCP lifecycle/control handling. The contract now fixes endpoint MAC/IP identities, forbids static neighbor preconditioning, carries ARP and all TCP lifecycle frames through fixed cells, separates lifecycle/reconnect evaluation from the RN-L classifier, requires a rootless veth/raw-socket capability preflight, and pins the S3-equivalent 1,000-permutation/2,000-bootstrap leakage analysis. With those repairs, implementation may begin; final approval still depends on evidence rereview.
