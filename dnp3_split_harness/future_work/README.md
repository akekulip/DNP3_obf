# future_work/

Experimental, NOT used by the current byte-preserving replay path. Archived here
(2026-06-18) so the flat, self-contained harness in the parent folder is the
validated workflow only.

- `dnp3_frame_codec.py` — parse/rebuild DNP3 link frames with recomputed CRCs.
- `dnp3_aware_splitter.py` — re-segment a response into new frames (rebuilds frames,
  **recomputes CRCs** → changes on-wire bytes). This is the later "true DNP3-aware
  modification" phase, gated by `docs/implementation_guide.md`.

The current validated path does the opposite — cuts captured bytes only on existing
CRC boundaries, never modifying them (`../dnp3_crc_splitter.py`, also inlined into
`../split_server.py`). Run these standalone if revived:

    python3 future_work/dnp3_aware_splitter.py --help   # reuses ../dnp3_crc.py
