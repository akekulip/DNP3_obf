"""Two-request replacement-image TCP oracle, software only.

Sequence accounting places each size delta at the native request end. Cached
images replace *all* retransmitted native bytes, including rewritten link CRCs.
This intentionally differs from the historical append-only synthetic oracle.
One instance belongs to one connection; no hash-table/tuple-reuse or hardware
claim. The caller must retain it through teardown, translate FIN/RST before
retirement, and quarantine old-connection packets before creating a new one.
Unsupported negotiation must be excluded before inserting the first image.
"""
from dataclasses import dataclass

MASK = 0xffffffff
HALF = 0x80000000


@dataclass(frozen=True)
class Image:
    start: int
    original: bytes
    transformed: bytes

    @property
    def end(self):
        return self.start + len(self.original)

    @property
    def delta(self):
        return len(self.transformed) - len(self.original)


@dataclass(frozen=True)
class Forward:
    seq: int
    payload: bytes
    inserted: bool = False


class RequestLedger:
    """Finite one-SBO-per-connection ledger. No I/O, packet injection or actuation."""
    def __init__(self, base_seq, excluded_features=()):
        self.base_seq = base_seq & MASK
        self.entries = []
        self.excluded_features = set(excluded_features)

    def exclude(self, feature):
        self.excluded_features.add(feature)

    def _offset(self, seq):
        offset = (seq - self.base_seq) & MASK
        # A connection span must remain below the modular half-range. Older
        # packets can have negative offsets; ambiguity at exactly half is denied.
        if offset == HALF:
            raise ValueError('ambiguous modular TCP offset')
        return offset if offset < HALF else offset - (MASK + 1)

    def _wire_offset(self, offset):
        return offset + sum(e.delta for e in self.entries if e.end <= offset)

    def _native_offset(self, wire):
        delta = 0
        for e in self.entries:
            start = e.end + delta
            if wire < start:
                break
            if wire < start + e.delta:
                # Keep the final native byte outstanding until all growth has
                # been acknowledged. Its ordinary upstream retransmission
                # overlaps the cached image's last byte and replays the tail.
                # Mapping to e.end here would retire the sender's entire frame
                # while the receiver could still be missing inserted bytes.
                return e.end - 1
            delta += e.delta
        return wire - delta

    def forward(self, seq, payload, replacement=None):
        """Translate any payload and replay committed images on every overlap.

        A replacement can only commit in order, with no overlap, at positive
        growth, within the finite capacity. Refusal never discards an existing
        translation. Conflicting retransmission bytes are explicit errors,
        because passing their native image would corrupt the established stream.
        """
        start = self._offset(seq)
        end = start + len(payload)
        if end >= HALF:
            raise ValueError('connection span exceeds modular half-range')
        for e in self.entries:
            lo, hi = max(start, e.start), min(end, e.end)
            if lo < hi and payload[lo - start:hi - start] != e.original[lo - e.start:hi - e.start]:
                raise ValueError('conflicting native retransmission bytes')
            if replacement is not None and start == e.start and payload == e.original and replacement != e.transformed:
                raise ValueError('conflicting replacement image')
        inserted = False
        if (replacement is not None and len(replacement) > len(payload) and payload and
                not self.excluded_features and len(self.entries) < 2 and start >= 0 and
                (not self.entries or start >= self.entries[-1].end)):
            self.entries.append(Image(start, bytes(payload), bytes(replacement)))
            inserted = True
        out = bytearray()
        cursor = start
        for e in self.entries:
            if e.end <= start or e.start >= end:
                continue
            lo, hi = max(cursor, e.start), min(end, e.end)
            if cursor < lo:
                out += payload[cursor - start:lo - start]
            out += e.transformed[lo - e.start:hi - e.start]
            if hi == e.end:
                out += e.transformed[len(e.original):]
            cursor = hi
        out += payload[cursor - start:]
        return Forward((self.base_seq + self._wire_offset(start)) & MASK, bytes(out), inserted)

    def reverse(self, ack, window):
        """Withhold native completion until the entire image is acknowledged.

        Apply the same monotone inverse to both window edges. In particular,
        a zero downstream window remains zero while the tail is outstanding.
        This performs no retransmission itself; the upstream sender retains
        ownership of its final native byte.
        """
        if not 0 <= window <= 65535:
            raise ValueError('only an unscaled uint16 TCP window is supported')
        wire = self._offset(ack)
        left = self._native_offset(wire)
        right = self._native_offset(wire + window)
        return (self.base_seq + left) & MASK, right - left

    def reset(self, seq, payload):
        """Model RST: translate the final packet before explicitly retiring state."""
        out = self.forward(seq, payload)
        self.entries.clear()
        return out


class ControlConnection:
    """Fixed one-native-CROB/one-decoy SELECT then matching OPERATE profile.

    Committed cache replay always takes precedence over eligibility for another
    insertion. New operations beyond the single pair remain translated native.
    An incompatible OPERATE cannot safely acquire a fresh decoy object set.
    """
    def __init__(self, base_seq, decoy, excluded_features=()):
        self.ledger = RequestLedger(base_seq, excluded_features)
        self.decoy = decoy
        self.selected = None
        self.operated = False

    def forward(self, seq, frame):
        from case4_padding import decode_frame, expand_control
        image, delta = expand_control(frame, self.decoy)
        replacement = None
        native_objects = None
        function = None
        if delta:
            header, user = decode_frame(frame)
            function = user[2]
            native_objects = (header[3:8], user[3:])
            if ((function == 3 and self.selected is None) or
                    (function == 4 and not self.operated and self.selected == native_objects)):
                replacement = image
        result = self.ledger.forward(seq, frame, replacement)
        if result.inserted:
            if function == 3:
                self.selected = native_objects
            else:
                self.operated = True
        return result
