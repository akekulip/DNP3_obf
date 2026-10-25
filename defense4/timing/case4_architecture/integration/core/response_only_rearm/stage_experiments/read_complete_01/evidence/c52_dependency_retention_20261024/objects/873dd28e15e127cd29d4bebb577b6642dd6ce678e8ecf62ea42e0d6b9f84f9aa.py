"""Response-side (outstation -> master) TCP mapper for Option B' padding, software only.

This is the executable form of `case4_architecture/protocol/TRANSPORT_MAPPER_SPEC.md`. It keeps
exactly the per-connection state the P4 realization keeps (six registers, one image slot) and
uses the same 32-bit modular arithmetic, so the P4 can be checked against it packet by packet.
`case4_transport.RequestLedger` is the correctness oracle; the tests compare the two.

It performs no padding itself. The caller supplies the padder's verdict (`delta` 0, 9 or 21) and,
when the mapper answers `pad=True`, applies `case4_pad58b` to the native frame.
"""
from dataclasses import dataclass

MASK = 0xffffffff
HALF = 0x80000000
IMAGE_LEN = 58               # every Option B' image is a 58-byte TCP payload
DELTAS = (9, 21)             # READ 49->58, CONTROL 37->58

NATIVE, MAPPED = 0, 1


def signed(x):
    x &= MASK
    return x - (MASK + 1) if x & HALF else x


@dataclass(frozen=True)
class Fwd:
    case: str        # passthrough | commit | translate | zero | replay | stale | drop_ahead | drop_overlap | drop_merged | drop_unsupported
    seq: int = None
    pad: bool = False   # wire payload = padded image of the leading frame + the rest of the payload

    @property
    def dropped(self):
        return self.case.startswith('drop')


@dataclass(frozen=True)
class Rev:
    case: str        # passthrough | translate | withhold | drop_stale | drop_unsupported
    ack: int = None
    window: int = None

    @property
    def dropped(self):
        return self.case.startswith('drop')


class ResponseMapper:
    """One connection slot. Field names match the P4 registers."""

    def __init__(self, pad_enable=True, merged_suffix_ok=True):
        """merged_suffix_ok=False is the Tofino-1 profile (case4_response_path.p4): a replay that carries
        native bytes after the frame is dropped, because the odd growth moves that suffix to the other
        byte parity and the pass cannot repair its TCP checksum (spec section 10)."""
        self.pad_enable = pad_enable
        self.merged_suffix_ok = merged_suffix_ok
        self.mode = NATIVE
        self.front = 0       # N
        self.acct_w = 0      # W
        self.acct_a = 0      # A
        self.img_end = 0     # e_end
        self.img_start = 0   # e_start
        self.img_wend = 0    # we

    # ---- lifecycle -------------------------------------------------------------------------
    def syn_ack(self, isn, mss_only=True):
        """Outstation SYN-ACK. Arms the slot (mapped) only for an MSS-only option set."""
        if not mss_only:
            self.mode = NATIVE
            return
        nxt = (isn + 1) & MASK
        self.mode = MAPPED
        self.front = self.acct_w = self.acct_a = self.img_end = self.img_wend = nxt
        self.img_start = (nxt - IMAGE_LEN) & MASK     # virtual zero-growth image

    # ---- outstation -> master --------------------------------------------------------------
    def forward(self, seq, length, delta=0, fin=False, supported=True, rst=False):
        """`delta` is the padder's verdict on the frame at the START of the payload (0, 9 or 21);
        that frame is 58 - delta bytes long, and the payload may continue past it (a merged
        retransmission). A commit needs the payload to be exactly that one frame."""
        if self.mode != MAPPED:
            return Fwd('passthrough', seq & MASK)
        if not supported:
            return Fwd('drop_unsupported')
        if delta not in (0,) + DELTAS:
            raise ValueError('verdict delta must be 0, 9 or 21')
        s = seq & MASK
        leff = length + (1 if fin else 0)
        # front: frontier test and advance
        ret = signed(s - self.front)
        if ret > 0:
            return Fwd('drop_ahead')
        grant = False
        if ret == 0:
            self.front = (s + leff) & MASK
            cand = (self.pad_enable and delta and length == IMAGE_LEN - delta and
                    not fin and not rst)
            # acct: commit iff everything sent so far is acknowledged
            if cand and self.acct_w == self.acct_a:
                self.acct_w = (self.acct_w + leff + delta) & MASK
                grant = True
            else:
                self.acct_w = (self.acct_w + leff) & MASK
        # img_end / img_start: offsets against the latest image (old values)
        q = signed(s - self.img_end)
        p = signed(s - self.img_start)
        we = self.img_wend
        ws = (we - IMAGE_LEN) & MASK
        if grant:
            self.img_end = (s + length) & MASK
            self.img_start = s
            self.img_wend = (we + q + length + delta) & MASK
            return Fwd('commit', (we + q) & MASK, True)
        if q >= 0:
            return Fwd('translate', (we + q) & MASK)
        if leff == 0:
            return Fwd('zero', (ws + p) & MASK)
        if p == 0 and q + leff >= 0 and delta:
            # Starts at the image and covers it: the image, then any native suffix (a merged
            # retransmission, a FIN), which lands at e_end + D because the image ends at we.
            if q + length > 0 and not self.merged_suffix_ok:
                return Fwd('drop_merged')
            return Fwd('replay', ws, True)
        if p + leff <= 0:
            return Fwd('stale', (ws + p) & MASK)
        return Fwd('drop_overlap')

    # ---- master -> outstation --------------------------------------------------------------
    def reverse(self, ack, window, has_ack=True, supported=True):
        if self.mode != MAPPED or not has_ack:
            return Rev('passthrough', ack & MASK, window)
        if not supported:
            return Rev('drop_unsupported')
        if not 0 <= window <= 0xffff:
            raise ValueError('unscaled uint16 window only')
        a = ack & MASK
        # The P4 keeps U = W - A; a master ACK sets U = W - ack. A is therefore the LATEST
        # master ACK, not a running maximum (a one-memory-operand SALU cannot take a max of
        # A against U). A reordered older ACK can only refuse a commit, never permit one.
        self.acct_a = a
        r = signed(a - self.img_wend)
        if r >= 0:
            return Rev('translate', (self.img_end + r) & MASK, window)
        if r < -IMAGE_LEN:
            return Rev('drop_stale')
        r2 = r + window
        if r2 < 0:
            return Rev('withhold', self.img_start, 0)
        e_len = signed(self.img_end - self.img_start)
        return Rev('withhold', self.img_start, min(r2 + e_len, 0xffff))
