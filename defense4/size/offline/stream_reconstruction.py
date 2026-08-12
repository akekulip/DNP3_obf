#!/usr/bin/env python3
"""Stream-reconstruction oracle for the transport translation model.

The per-packet fields in transport_oracle.py are only trustworthy if the bytes they
describe actually reassemble, at the receiver, into ONE consistent transformed stream.
This module provides that end-to-end check, independent of the oracle's internal ledger:

  * StreamReassembler mimics a receiver's TCP reassembly of ONE direction. Each emitted
    image is written at its translated offset. A re-write at an already-filled offset
    must be byte-identical (retransmit consistency); a mismatch is recorded as a conflict.
    Missing offsets are reported as gaps.

  * build_canonical() computes the single correct transformed stream directly from the
    original bytes and the committed insertion plan, using the SAME reproducible byte
    generators the oracle uses. Placement/accounting are computed here independently, so
    equality with the reassembled buffer is a real cross-check, not a tautology.

A direction PASSES reconstruction iff reassembled == canonical, with no gap, no conflict,
and therefore no duplicated logical insertion and no inconsistent retransmitted data.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from transport_oracle import Dir, mod32, render_insertion, default_orig_byte


class StreamReassembler:
    """Receiver-side reassembly of ONE direction's transformed stream."""

    def __init__(self, isn: int):
        self.isn = isn
        self.buf: dict = {}                      # transformed offset -> byte
        self.conflicts: List[Tuple[int, int, int]] = []   # (off, had, got)

    def deliver(self, wire_seq: int, emitted: bytes) -> None:
        if not emitted:
            return
        off = mod32(wire_seq - self.isn)
        for i, b in enumerate(emitted):
            p = off + i
            if p in self.buf and self.buf[p] != b:
                self.conflicts.append((p, self.buf[p], b))
            self.buf[p] = b

    def reconstruct(self) -> Tuple[bytes, List[int]]:
        """Return (contiguous_bytes_from_0, gap_offsets). Gaps are offsets below the
        high-water mark that were never written."""
        if not self.buf:
            return b"", []
        hi = max(self.buf) + 1
        gaps = [p for p in range(hi) if p not in self.buf]
        data = bytes(self.buf.get(p, 0) for p in range(hi))
        return data, gaps

    def ok_against(self, canonical: bytes) -> bool:
        data, gaps = self.reconstruct()
        return data == canonical and not gaps and not self.conflicts


def build_canonical(direction: Dir, total_len: int,
                    insertions: List[Tuple[int, int, int]], generation: int,
                    orig: Optional[bytes] = None) -> bytes:
    """The single correct transformed stream for one direction.

    total_len   -- length of the original (unpadded) stream, in bytes.
    insertions  -- committed plan as (boundary, size, template_id) tuples.
    generation  -- owning generation (feeds the reproducible byte generator).
    orig        -- explicit original bytes; None -> deterministic default_orig_byte().

    Convention matches TransportOracle._emit_segment(): an insertion at boundary b is
    placed immediately before original byte b (a tail boundary b == total_len lands at
    the end). Each boundary therefore appears exactly once."""
    by_boundary = {b: (s, t) for (b, s, t) in insertions}
    out = bytearray()
    for off in range(total_len + 1):
        if off in by_boundary:
            s, t = by_boundary[off]
            out.extend(render_insertion(t, s, off, generation))
        if off < total_len:
            if orig is not None:
                out.append(orig[off])
            else:
                out.append(default_orig_byte(direction, off))
    return bytes(out)
