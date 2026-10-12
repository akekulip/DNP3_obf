# N CRC Residue Stage Experiment

This is an isolated experiment from `evidence/incremental_55/response_only.p4`.
It does not edit the active generator path.

The change hashes each DNP3 block together with its two wire CRC bytes and
matches the fixed residue `0x993a` in the N guard. The READ link-address
mismatch bit stays separate so a CRC-correct frame for the wrong link address
still fails closed.
