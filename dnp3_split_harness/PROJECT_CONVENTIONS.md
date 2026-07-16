# PROJECT_CONVENTIONS.md

Research-grade programming and research conventions for the DNP3 traffic-obfuscation
harness (`dnp3_split_harness/`). Created in Phase 00. Every agent and contributor
reads this before touching code. These conventions are derived from the phase plan
(`acj_delay2.md` §C) and from the conventions already exhibited by the codebase —
`timing_policy.py` is the reference model.

---

## 1. Language and interpreter

- **Supported interpreter: CPython 3.8** (system `python3` = 3.8.10). This is a hard
  constraint: `pydnp3` builds only there, and the timing unit tests run there.
- Detect the interpreter before adding syntax. On 3.8 you MUST NOT use:
  - `match`/`case` statements;
  - PEP 604 unions (`X | None`) — use `Optional[X]` / `Union[...]` from `typing`,
    and keep `from __future__ import annotations` at the top of modules that annotate;
  - any dependency that requires a newer Python.
- The research venv (`~/.venvs/research/bin/python`, 3.12, scapy 2.7.0) may be used
  for pure PCAP analysis, but code committed to the harness must remain 3.8-valid.

## 2. Structure: separate the layers

Keep these concerns in separate modules; do not fuse them:

- **policy** (what delay/target to choose) — pure, no I/O, no clock reads;
- **mechanism** (how packets are actually sent/paced) — sockets, sleeps;
- **experiment orchestration** (run configs, sweeps, run directories);
- **PCAP analysis** (transaction reconstruction, ACK classification);
- **reporting** (tables, figures, phase reports).

Data collection and plotting live in **different** files. A script that both runs an
experiment and draws its figures is a Phase 00 anti-pattern to split.

## 3. Python style

- Type hints on all public interfaces.
- `@dataclass` for structured decisions, configs, and reports (see `TimingDecision`,
  `TimingProfile`). Prefer immutable/config-like dataclasses; do not mutate inputs.
- `pathlib.Path`, never ad-hoc string path joins.
- `argparse` for CLIs; thin CLI wrappers over reusable classes (do not bury logic in
  `__main__`).
- `logging.getLogger(__name__)` — no `print()` debugging.
- Timing decisions use `time.monotonic_ns()`; keep them in **pure functions** so they
  are deterministic and unit-testable (the caller does the actual wait via an
  absolute-deadline loop, not a single relative sleep).
- Explicit units in names: `delay_ms`, `deadline_ns`, `payload_bytes`,
  `response_ready_ns`. Nanoseconds are authoritative; ms views are for humans only.
- Deterministic seeds for every randomized experiment; record the seed in the run
  manifest and the per-transaction log.
- No mutable global state. Configuration flows through dataclasses/args, not globals.

## 4. Error handling

- No bare `except`. Catch specific exceptions; log with context and re-raise where the
  caller must know.
- Never silently continue after a parse failure. A malformed frame/transaction is
  reported explicitly.
- Ambiguous transactions are surfaced as an explicit class, never forced into a clean
  bucket (see ACK classes: `COMBINED_ACK_RESPONSE`, `SEPARATE_ACK_RESPONSE`,
  `OTHER_OR_AMBIGUOUS`).
- Fail **safely** when critical config is missing.
- Record bypass reasons with a controlled enum (see `BypassReason`), never free text.
- Never infer a missing measurement and present it as observed.

## 5. Safety invariants (this phase)

- **Byte preservation**: the replay/split path keeps `b"".join(chunks) == original`.
  No CRC recompute, no DNP3 field/length edits, no random padding, no field rewrite.
- **Fail-open**: on any safety doubt (over-long hold, unknown RTO under strict mode,
  queue overflow, critical/unknown traffic), send immediately and log the reason.
- **Ordering**: preserve TCP order and per-flow FIFO; preserve SELECT-before-OPERATE.
- **No ACK forgery**: do not synthesize TCP ACKs. A user-space app may influence
  whether the kernel emits a *separate* ACK by when it calls `write()`, but it cannot
  hold an already-emitted pure ACK. Any claim that a scheduler changed packet timing
  requires a real enforcement mechanism AND a PCAP that proves it.
- Do not run on live protection traffic; do not pad/alter live control traffic.

## 6. Terminology (use precisely)

- **Pure TCP ACK**: ACK flag set, zero TCP payload, sent before the DNP3 response.
- **ACK-bearing DNP3 response**: a payload-bearing DNP3 RESPONSE that also ACKs the
  request bytes at the TCP layer. Say "the TCP ACK is piggybacked on the
  payload-bearing DNP3 RESPONSE" — never "application ACK", never "the TCP and DNP3
  ACK are together".
- **DNP3 application CONFIRM**: the DNP3 application-layer CONFIRM function — NOT a TCP
  ACK. Never label a CONFIRM as a TCP ACK.

## 7. Testing

- Preserve existing tests. Current baseline: 22 timing-policy unit tests pass on 3.8.
- Add unit tests for new logic; integration tests per active CLI; regression tests for
  every fixed bug. Use small-PCAP fixtures and deterministic timing decisions.
- Prefer testing pure functions over wall-clock-dependent behavior.
- Mark privileged/two-host (rig) tests separately. **Never report a privileged test as
  passed if it was skipped.** A loopback pass is not a rig pass.

## 8. Change discipline

- Small, phase-scoped changes. No full-repository rewrite. Do not delete working
  scripts because the layout is untidy — archive with a documented reason.
- Preserve existing command-line entry points through thin wrappers if files move.
- Do not create two competing implementations of the same scheduler. Consolidate
  duplicate logic only after tests show equivalent behavior.
- One config source of truth (`lab_config.py`); never reintroduce inline config
  mirrors.

## 9. Naming rule (hard)

The internal project codename must never appear anywhere — filenames, comments,
identifiers, logs, reports. Use generic descriptive names only. A codename occurrence
is a bug to remove.

## 10. Outputs are publication-grade and provenance-tracked

- Figures via Matplotlib; label units; include sample counts; grayscale-readable;
  export PNG + vector PDF (SVG where practical); never overwrite an old figure.
- Tables exported as CSV + JSON + Markdown + LaTeX.
- Each figure carries a `figure_name.metadata.json` sidecar (source run IDs, source
  CSV, script, git commit, generation command, filters, transform, timestamp).
- See DATA_PROVENANCE.md for run isolation and manifest requirements.
