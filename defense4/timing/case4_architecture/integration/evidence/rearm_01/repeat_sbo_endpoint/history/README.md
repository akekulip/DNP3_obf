# Retained endpoint source history

`SocketGatePad58B.d11f9490.cpp` (SHA256 `d11f9490…5302`) is the source of binary `e4872697…42ae`, which ran in the
failed attempt `candidate61_repeat_sbo_950_b1` on 2026-10-14. It was built before a one-line edit (the master's
`reads_requested` field reported the initial READ count, not the total) and was never committed. It was
reconstructed by reverting that line in the committed source; the reconstruction has the recorded source hash and
rebuilds, with the pinned compiler and OpenDNP3 tree, to the byte-identical binary `e4872697…42ae`.
The `tests/test_repeat_sbo.py::test_build_matches_the_current_source` guard now fails if a stale build is used.
