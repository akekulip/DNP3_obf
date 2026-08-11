# Combined normalizer — handshake + ACK-mode on one Tofino-1 program

Integrates the two solved axes into a single program (`p4src/combined_normalizer.p4`): the handshake
header normalizer (device-indistinguishable SYN/SYN-ACK) **and** the ACK-mode normalizer (suppress
the outstation's standalone pure ACK) run together in one ingress pipeline.

- **Compile PASS** — bf-p4c 9.13.1 (`tofino.bin` 1.43 MB, sha `e75d8da5`) and 9.13.2 on the switch, 0 errors.
- **Silicon 4/4** (`evidence/hardware_9132/asic_combined.log`, pktgen + hardware counters):
  SEL751 full SYN → norm_syn (ctr 1); SEL751 full SYN-ACK → synack_normalize (ctr 3);
  outstation pure ACK → **ack_suppressed (ctr 12)**; outstation response → forwarded (ctr 0).
- Both mechanisms coexist with no new resources of concern; the ACK-mode suppression is one added
  branch (`ig_dprsr.drop_ctl`) plus the counter index 12.

So a single Tofino-1 program collapses the SEL-751 and ION7550 together on **both** the handshake
header axis and the ACK-mode axis simultaneously — verified on real silicon.
