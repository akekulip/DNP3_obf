#!/usr/bin/env python3
"""Offline model for class-independent randomized deadline selection.

This is a model of the candidate P4 control flow, not hardware evidence. It
captures the property we need before compiling: one fresh protected request gets
one selected set of absolute deadline parameters, and the existing deadline
registers persist the resulting final deadline words.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple


@dataclass(frozen=True)
class DeadlineParams:
    seq_m: int
    da_dr: int
    a_ticks: int
    r_ticks: int

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
            if value & 0xFF:
                raise ValueError(f"{name} must be a 256 ns-grid word with low byte zero")
        if self.da_dr < self.seq_m:
            raise ValueError("da_dr must be >= seq_m")
        if self.r_ticks < self.a_ticks:
            raise ValueError("r_ticks must be >= a_ticks")


@dataclass(frozen=True)
class RandomDeadlineEntry:
    low: int
    high: int
    params: DeadlineParams
    priority: int = 1

    def __post_init__(self) -> None:
        if self.low < 0 or self.high > 255 or self.low > self.high:
            raise ValueError(f"invalid rand8 range [{self.low}, {self.high}]")


@dataclass(frozen=True)
class TransactionDeadlines:
    selected: DeadlineParams
    now_word: int
    operation: str

    def observed_deadlines(self, later_bucket: int) -> dict[str, int]:
        """Return persisted final deadline words.

        later_bucket is intentionally ignored. The data plane must not redraw on
        ACK, response, blocker-token, or release passes.
        """
        _ = later_bucket
        return {
            "ack_deadline": self.now_word + self.selected.seq_m,
            "resp_deadline": self.now_word + self.selected.da_dr,
            "operate_ack_deadline": self.now_word + self.selected.a_ticks,
            "operate_resp_deadline": self.now_word + self.selected.r_ticks,
        }


class RandomDeadlineTable:
    def __init__(self, entries: Iterable[RandomDeadlineEntry]):
        self.entries: Tuple[RandomDeadlineEntry, ...] = tuple(
            sorted(entries, key=lambda e: (e.priority, e.low, e.high))
        )
        self._validate()

    def _validate(self) -> None:
        owners = {bucket: 0 for bucket in range(256)}
        for entry in self.entries:
            for bucket in range(entry.low, entry.high + 1):
                owners[bucket] += 1
        overlaps = [bucket for bucket, count in owners.items() if count > 1]
        if overlaps:
            raise ValueError(f"overlapping rand8 buckets: {overlaps[:8]}")

    def select(self, *, bucket: int, current: DeadlineParams,
               fresh_role_arm: bool) -> DeadlineParams:
        if bucket < 0 or bucket > 255:
            raise ValueError("rand8 bucket must be in 0..255")
        if not fresh_role_arm:
            return current
        for entry in self.entries:
            if entry.low <= bucket <= entry.high:
                return entry.params
        return current

    def begin_transaction(self, *, now_word: int, bucket: int, current: DeadlineParams,
                          operation: str) -> TransactionDeadlines:
        if operation not in {"READ", "SELECT", "OPERATE"}:
            raise ValueError(f"unsupported protected request operation {operation!r}")
        selected = self.select(bucket=bucket, current=current, fresh_role_arm=True)
        return TransactionDeadlines(selected=selected, now_word=now_word, operation=operation)
