"""Bounded ownership experiment, not a model of the complete Case 4 program.

Each of the two producer roles issues once per timing association. That barrier
prevents a delayed old producer from touching a reused record. Supporting the
full fragmented workload requires multiple protected records at integration.
"""
from dataclasses import dataclass, replace

MASK = 0xFFFFFFFF
PHASE = 0x00030000
ACTIVE = 0x00010000
COMMITTED = 0x00020000
QUARANTINE = 0x00030000
ORIGINAL = {"ack": 0x00040000, "response": 0x00080000, "operate": 0x00100000}
BUSY = {"request": 0x00200000, "response": 0x00400000}
ISSUED = {"request": 0x00800000, "response": 0x01000000}
CREDITS = 0x007C0000


@dataclass(frozen=True)
class WorkRef:
    epoch: int
    generation: int

    def to_bytes(self):
        return self.epoch.to_bytes(4, "big") + self.generation.to_bytes(4, "big")


class Authority:
    def __init__(self, epoch):
        self.epoch = epoch
        self.word = 0
        self.next_work = 0
        self.enabled = True
        self.records = {}

    def compare_swap(self, expected, desired):
        if self.word != expected:
            return False
        self.word = desired & MASK
        return True

    def begin(self, epoch):
        if epoch != self.epoch or not self.enabled or self.word >= 65535:
            return None
        self.word = ACTIVE | (self.word + 1)
        self.records.clear()
        return self.word & 65535

    def hold(self, cookie, kind):
        bit = ORIGINAL[kind]
        if cookie != (self.word & 65535) or self.word & PHASE != ACTIVE or self.word & bit:
            return False
        self.word |= bit
        return True

    def acquire_work(self, cookie, role):
        if (cookie != (self.word & 65535) or self.word & PHASE != ACTIVE
                or self.word & ISSUED[role] or self.next_work == MASK):
            return None
        self.next_work += 1
        ref = WorkRef(self.epoch, self.next_work)
        self.records[role] = {"ref": ref, "active": True, "payload": None}
        self.word |= BUSY[role] | ISSUED[role]
        return ref

    def publish(self, ref, payload):
        for record in self.records.values():
            if record["ref"] == ref and record["active"] and self.word & PHASE == ACTIVE:
                record["payload"] = bytes(payload)
                return True
        return False

    def terminal_work(self, ref):
        for role, record in self.records.items():
            if record["ref"] == ref and record["active"]:
                record["active"] = False
                self.word &= ~BUSY[role]
                return True
        return False

    def reset(self, epoch):
        if epoch == self.epoch and self.word & PHASE:
            self.word = (self.word & ~PHASE) | QUARANTINE

    def disable(self):
        self.enabled = False
        self.reset(self.epoch)

    def terminal_original(self, cookie, kind):
        bit = ORIGINAL[kind]
        if cookie != (self.word & 65535) or not self.word & bit:
            return "reject"
        disposition = "abort" if kind == "operate" and (
            not self.enabled or self.word & PHASE == QUARANTINE) else "forward"
        self.word &= ~bit
        return disposition

    def finish(self):
        if self.word & PHASE != QUARANTINE or self.word & CREDITS:
            return False
        self.word &= 65535
        return True

    def retire_connection(self, epoch):
        if epoch != self.epoch or self.word & ~65535 or self.epoch == MASK:
            return False
        self.epoch += 1
        self.records.clear()
        return True


def due(now, deadline):
    """Half-range-safe modular comparison; intervals must be below 2**31 ns."""
    return ((now - deadline) & MASK) < 0x80000000


def quantize(time):
    return time & 0xFFFFFF00


class Schedule:
    def __init__(self, t0, d_a_ns):
        self.operate_deadline = quantize(t0 + d_a_ns)
        self.readiness_deadline = quantize(t0 + 30_000_000)
        self.ack_seen = False
        self.response_seen = False
        self.response_deadline = None

    def operate_due(self, now):
        return due(quantize(now), self.operate_deadline)

    def ack_due(self, now):
        return self.ack_seen and self.response_seen and self.operate_due(now)

    def fallback_due(self, now):
        return self.response_deadline is None and due(quantize(now), self.readiness_deadline)

    def commit_ack(self, now):
        self.response_deadline = (quantize(now) + 999_936) & MASK

    def readiness_expired(self, now):
        return self.fallback_due(now)

    def response_due(self, now):
        return self.response_deadline is not None and due(quantize(now), self.response_deadline)


class PinnedWork:
    """Atomic 64-bit {generation, phase} experiment, with a separate epoch.

    Allocation occurs before claim, so rejected busy producers consume a
    generation. The allocator refuses after its last full 32-bit value.
    """
    def __init__(self, epoch):
        self.epoch = epoch
        self.counter = 0
        self.phase = 4
        self.reference = None

    def claim(self, epoch):
        if epoch != self.epoch or self.counter == MASK:
            return None
        self.counter += 1
        if self.phase != 4:
            return None
        self.reference = WorkRef(epoch, self.counter)
        self.phase = 1
        return self.reference

    def advance(self, reference):
        if reference != self.reference or self.phase >= 4:
            return 0
        old = self.phase
        self.phase += 1
        return old

    def close(self, epoch):
        if epoch != self.epoch:
            return False
        if self.phase in (1, 2):
            self.phase = 3
        return True

    def can_retire(self):
        return self.phase == 4


@dataclass(frozen=True)
class RecircEnvelope:
    epoch: int
    generation: int
    expected: int
    event: int
    reserved: int = 0

    def to_bytes(self):
        return (self.epoch.to_bytes(4, "big") + self.generation.to_bytes(4, "big")
                + self.expected.to_bytes(4, "big") + self.event.to_bytes(2, "big")
                + self.reserved.to_bytes(2, "big"))

    @classmethod
    def from_bytes(cls, data):
        if len(data) != 16:
            raise ValueError("recirculation envelope must be exactly 16 bytes")
        return cls(*(int.from_bytes(data[start:end], "big") for start, end in
                     ((0, 4), (4, 8), (8, 12), (12, 14), (14, 16))))


class HeldCredits:
    """Single-association, one-original-per-kind atomic credit experiment.

    An issued bit survives terminal debit. That prevents a delayed duplicate
    terminal from consuming a new original of the same kind in this cookie.
    Full connection epoch and full expected credit word qualify every write.
    This bounded primitive does not support arbitrary fragmented originals.
    """
    def __init__(self, epoch, cookie):
        if not 0 < epoch <= MASK or not 0 < cookie <= 0xFFFF:
            raise ValueError("nonzero full epoch and minted timing cookie required")
        self.epoch = epoch
        self.word = cookie << 16

    def admit(self, epoch, expected, kind):
        if kind not in (1, 2, 3):
            return False
        bit = 1 << (kind - 1)
        if epoch != self.epoch or expected != self.word or expected & (bit | bit << 8):
            return False
        self.word = expected | bit | bit << 8
        return True

    def terminal(self, epoch, expected, kind, policy_enabled):
        if policy_enabled or kind not in (1, 2, 3):
            return None
        bit = 1 << (kind - 1)
        if epoch != self.epoch or expected != self.word or not expected & bit:
            return None
        self.word = expected & (MASK ^ bit)
        return "abort" if kind == 3 else "forward"

    def can_reuse(self, work):
        return work.can_retire() and self.word & 7 == 0


@dataclass(frozen=True)
class HeldPacket:
    epoch: int
    generation: int
    cookie: int
    expected: int
    kind: int
    stage: int
    packet: bytes

    def to_bytes(self):
        return (b"".join(value.to_bytes(4, "big") for value in
                         (self.epoch, self.generation, self.cookie, self.expected))
                + bytes((self.kind, self.stage, 0, 0)) + self.packet)

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 34 or data[18:20] != b"\0\0":
            raise ValueError("20-byte holder envelope and inner Ethernet required")
        words = [int.from_bytes(data[start:start + 4], "big") for start in (0, 4, 8, 12)]
        return cls(*words, data[16], data[17], data[20:])


class HeldPacketLoop:
    """Event/byte reference for the fixed three-receipt P4 holder experiment.

    Software results do not validate target queue service or native publishers.
    Full original bytes are carried rather than placed in a circulating cache.
    """
    def __init__(self, epoch, cookie):
        if not 0 < cookie <= 0xFFFF:
            raise ValueError("nonwrapping minted cookie required")
        self.epoch = epoch
        self.cookie = cookie
        self.receipts = [cookie << 16] * 3
        self.work = PinnedWork(epoch)
        self.enabled = True

    @staticmethod
    def outcome(kind, packet):
        return ("abort", None) if kind == 3 else ("forward", packet)

    def begin(self, packet, kind):
        if kind not in (1, 2, 3):
            raise ValueError("ACK/response/unsent OPERATE kind required")
        if not self.enabled:
            return self.outcome(kind, packet)
        ref = self.work.claim(self.epoch)
        if ref is None:
            return self.outcome(kind, packet)
        return HeldPacket(ref.epoch, ref.generation, self.cookie,
                          self.receipts[kind - 1], kind, 1, packet)

    def return_packet(self, token):
        if token.kind not in (1, 2, 3) or token.cookie != token.expected >> 16:
            return "suppress", None
        index = token.kind - 1
        if token.stage in (1, 2, 3, 12, 13):
            phase = self.work.advance(WorkRef(token.epoch, token.generation))
            if phase == 1:
                accepted = token.epoch == self.epoch and token.expected == self.receipts[index] and not token.expected & 0x101
                if accepted:
                    self.receipts[index] = token.expected | 0x101
                    return replace(token, expected=self.receipts[index], stage=2)
                return replace(token, stage=12)
            if phase == 2:
                return replace(token, stage=13 if token.stage == 12 else 3)
            if phase == 3:
                if token.stage in (1, 12, 13):
                    return self.outcome(token.kind, token.packet)
                return replace(token, stage=4)
            return "suppress", None
        if token.stage == 5:
            return replace(token, expected=self.receipts[index], stage=4)
        if token.stage != 4:
            return "suppress", None
        if self.enabled:
            return token
        if token.epoch != self.epoch or token.expected != self.receipts[index]:
            return replace(token, stage=5)
        if token.expected & 0x101 != 0x101:
            return "suppress", None
        self.receipts[index] = token.expected & (MASK ^ 1)
        return self.outcome(token.kind, token.packet)

    def can_reuse(self):
        return self.work.can_retire() and all(word & 1 == 0 for word in self.receipts)


class ExpectedPinnedWork(PinnedWork):
    """Phase-qualified return experiment; quarantine never fabricates a return.

    The epoch remains authoritative outside the atomic generation/phase cell.
    A producer emits its next expected phase into the actual private packet.
    Duplicate/reordered phases cannot authorize another protected bank write.
    """
    def __init__(self, epoch):
        super().__init__(epoch)
        self.quarantined = False

    def advance_expected(self, reference, expected_phase):
        if reference != self.reference or expected_phase not in (1, 2, 3):
            return 0
        if self.phase != expected_phase:
            return 0
        old = self.phase
        self.phase += 1
        return old

    def advance(self, reference, expected_phase):
        return self.advance_expected(reference, expected_phase)

    def quarantine(self, reference, expected_phase):
        if reference != self.reference or expected_phase not in (1, 2, 3):
            return False
        if self.phase != expected_phase:
            return False
        self.quarantined = True
        return True

    def cancel_current_epoch(self, epoch):
        # Separate actual raw FIN/RST or policy-off current-epoch event.
        if epoch != self.epoch:
            return False
        self.quarantined = True
        return True

    def close(self, reference, expected_phase):
        return self.quarantine(reference, expected_phase)
