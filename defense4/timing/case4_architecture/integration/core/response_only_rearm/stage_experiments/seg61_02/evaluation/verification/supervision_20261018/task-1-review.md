# Task 1 independent review

Verdict: **REQUEST CHANGES**. Spec compliance: **FAIL pending two safety fixes**. Code quality: generally clear and conservative, but the execution admission boundary needs repair. Architectural status: **BLOCK** until testbed ownership and deadline admission are enforced by the independent block process.

Reviewed the task brief and implementation report, `evaluation_campaign.py`, `tests/test_evaluation_campaign.py`, and `tests/campaign_systemd_fixture.py`. Read `guarded_block.py` and `restore_verify.py` only to establish the existing wrapper/restoration interface. The parent additionally clarified that active hardware blocks require a shared testbed lock across campaign IDs. No implementation files were edited, no hardware was accessed, no services were started or stopped, and no subagents were used. This report is the only authored artifact.

All source paths below are relative to `defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/`. Line numbers refer to the implementation reviewed before root integration fixes.

## Actionable findings

### HIGH — Distinct campaigns can enter the same testbed concurrently

Evidence: `evaluation_campaign.py:229`, `:281`, and `:365` scope launch/state/execution locks to a campaign directory or a step directory. `:379` enters the block command without acquiring any shared hardware/testbed ownership lock. The frozen wrapper's retained-root/run-ID reservations do not provide testbed exclusion for distinct run roots and IDs.

Starting a second campaign with a different ID therefore bypasses every existing lock while the first campaign's block is active. Both can mutate the same hardware, and one block's restoration can race the other block's experiment. The current serial guarantee applies only within one manifest. Separate detached services are the correct lifetime boundary, but they need shared hardware ownership.

Harmless reproduction: initialized two `supervision_fixture` campaigns with distinct IDs and run roots. Each block was a local Python command that created a started marker and waited on a release file. Ran both independent `run_step()` owners concurrently. Both started markers appeared before either was released; both finished without errors. Output: `{"distinct_campaign_overlap": true, "errors": []}`. The execution path has no hardware-only lock either, so the fixture demonstrates the missing exclusion without touching hardware.

Smallest fix: acquire a nonblocking persistent shared testbed `flock` from the independent block service before any hardware command, using a stable path shared across campaign IDs (and across storage aliases for campaigns targeting this testbed). Keep its file descriptor owned by that service through command completion, restoration acceptance, and durable terminal publication. Contention must prevent hardware entry and stop/refuse the conflicting campaign without replay. Do not place ownership in the controller, since killing the controller must leave the active block protected. Recheck the deadline after admission to the lock. Include a concurrent-two-campaign regression and a controller-death test that proves the block still holds ownership.

### HIGH — A queued block can begin after the persisted 24-hour deadline

Evidence: the only cutoff check is `evaluation_campaign.py:309`, based on `now` captured at `:282`. Dispatch happens later at `:325` with `systemd-run --no-block` (`:195`). The independent service claims its step at `:367-375` and starts its command at `:379` without checking the persisted deadline.

A service dispatched just before expiry can be queued, scheduled late, or delayed by process startup and enter the hardware after expiry. The same stale `now` also permits dispatch after a slow service-state query. Persistence across resume is correct, but it does not enforce the cutoff at actual block entry.

Harmless reproduction: completed fixture block 0, dispatched fixture block 1 at `deadline - 1`, then invoked its independent owner with the clock fixed at `deadline + 1`. The command executed and its terminal record said `completed`, with `started` one second greater than `deadline`. Representative output: `{"deadline": 1792425699.077934, "block_started": 1792425700.077934, "command_executed": true, "status": "completed"}`.

Smallest fix: have the independent owner re-read/check the persisted deadline immediately before hardware command entry, after shared testbed lock acquisition. When expired before entry, publish a durable explicit nonexecuted/deadline outcome that reconciliation stops on, retaining once-only intent and leaving the block unexecuted in status. Update the terminal-record/status contract accordingly. A refresh before controller dispatch is also useful, but cannot replace the independent service check. Never apply this cutoff to a command that has already entered: its execution and restoration must finish. Add a delayed-service regression proving no command marker is created after the deadline, plus the existing active-block-past-deadline behavior.

## Compliance and quality assessment

The implementation otherwise follows the brief well:

- Manifest copy, identity digest, unique campaign directory creation, bounded service names, immutable planned order, and command/root validation prevent accidental overwrites and ordinary reordering.
- Atomic replace/link publication with file and directory fsync gives durable launch intent, claims, terminal records, and state transitions. A crash in an uncertain interval refuses replay rather than guessing.
- Controller and step services have distinct units and no lifetime binding; `Restart=no` and no campaign runtime kill preserve active-block completion. Resume consults terminal records or service state, and an inactive step with no terminal record is refused.
- Deadline/start values persist before dispatch and are not reset by resume. Existing tests correctly cover expiry before the next controller dispatch and continued execution/restoration of an already active block; the queued-service case above is missing.
- A missing, false, or malformed restore proof produces an unsafe terminal result. Command, hook, and postcheck failures stop further sequencing. Restoration hashes and file identity are retained and rechecked when the active terminal record is reconciled.
- Fixture status explicitly excludes it from hardware evidence; incomplete planned cohorts report `INCOMPLETE`. Hardware manifests must enter through the frozen wrapper.
- The module uses the Python standard library, keeps persistence and service-manager boundaries explicit, and avoids unnecessary abstractions. No unrelated style changes are recommended.

`tests/test_evaluation_campaign.py` contains useful behavior-level coverage for the principal conservative failure cases. The fake manager intentionally omits real service scheduling, which explains why it misses delayed admission. The helper independently tests actual service lifetime separation using harmless local commands and limits cleanup by a random fixture identity. Its current seven checks do not establish cross-campaign exclusion or actual delayed-service expiry. The parent is extending real-service fixture coverage; this reviewer did not run that helper or claim its historical evidence as a fresh result.

## Fresh validation

- `python3 -m unittest discover -s defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/tests -p test_evaluation_campaign.py`: **21 passed**.
- Standalone bounded local deadline reproduction: **defect reproduced**, command entered at `deadline + 1` and completed.
- Standalone bounded local two-campaign barrier reproduction: **defect reproduced**, both independent commands active simultaneously.

The two reproductions imported the real implementation, used temporary directories and harmless Python subprocesses, and replaced only manager dispatch/clock where needed. No testbed hardware, SSH, systemd services, or source mutations were involved. Hardware use should wait for the two fixes and fresh targeted validation.
