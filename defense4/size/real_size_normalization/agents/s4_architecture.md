# Gate S4 Architecture Review

Role: architecture

Verdict: **WATCH - proceed only with the packet-preserving namespace design**

The faithful S4 shape is a dual-shim Layer-2 bridge around native endpoint TCP. The committed S3 codec supplies the correct fixed-cell contract; a pair of TCP proxies would terminate the original session and violate the selected S2 boundary semantics.

Required properties:

- isolate endpoint and shim roles with veth/network-namespace boundaries;
- carry complete Ethernet frames through raw Layer-2 capture and reinjection;
- expose only the dedicated fixed-cell EtherType on the observed link;
- reuse the fixed 22-cell S3 schedule and fail-closed state machine unchanged;
- inject loss, duplicate, reorder, and replay at the outer link, not by weakening inner endpoints;
- measure latency, bandwidth, CPU, RSS, queue depth, deadline misses, and exact recovery;
- retain the RN-L/software-only claim boundary.

Promotion remains blocked on the later Tofino CPU punt/reinject proof.
