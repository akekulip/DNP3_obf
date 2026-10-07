# Native READ profile validator

`validator.p4` observes the frozen20-byte group10/variation2 range0..22 request
and its49-byte response. It validates actual IPv4/TCP headers/checksums, the
configured ingress/tuple/link direction, full profile, and every DNP3 CRC before
incrementing the request/response observation bank. It forwards original bytes.
The link-address regression first reproduced acceptance of a CRC-valid wrong
destination, then verified refusal after the fix.

Current `evidence/validator_05` compiles with p4c9.13.1e558d01:6 ingress stages,
0 egress, critical path5. Source SHA is
`2788c885b5645eb21b4285c19bab4827477c900eb9019bffe7910133d5626011`.
Earlier CRC-gateway/PHV and parser-match-register failures remain intact.

An explicit target parser-error guard was added with a red-to-green refusal test.
Five supporting control-fragment tests are in `../../tests/test_read_validator.py`.
Independent review is in `../../protocol/review/REPORT.md`. Actual request epoch,
application/TCP association, owner admission, timing, holding and response carving
are absent. This compiled observer is not complete READ implementation, target
packet execution or physical evidence.
