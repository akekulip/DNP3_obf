# Limitations (corrected)

- Tested on one physical SEL-751, with read-only DNP3 traffic only (Class-0 READ, function 1).
- The CLRT-magnitude channel only.
- No full anonymity claim. ACK mode, response size and TCP-stack characteristics are unchanged by
  this mechanism.
- No size-obfuscation claim.
- The blocker reservoir is currently **host-seeded**; it circulates internally after seeding and the
  release decision is data-plane controlled, but the seed frames are transmitted by the host. There
  is no claim of fully internal blocker generation.
- The first connection-cold transaction of each capture is reported separately and is never
  discarded.
- Live byte identity is **not independently proven** in this inline configuration: the relay leg
  cannot be tapped, so the same frame cannot be compared before and after holding. Constant response
  lengths, valid CRCs and absence of transport anomalies are supporting evidence, not proof.
- Sample sizes are those of the shipped captures: 10, 11, 13 and 13 transactions.
- Entropy values are meaningful only with the stated bin width, bin origin and edge convention.
