# Task 1 scoped rereview

Spec verdict: **PASS for both previously reported HIGH findings**. Code-quality verdict: **PASS for the reviewed fixes**. No new CRITICAL or HIGH regression was found in the admission, restoration, or stale-owner paths. This is a scoped independent rereview, not a fresh review of the whole hardware campaign or its remote execution evidence.

Reviewed `task-1-brief.md`, the preceding `task-1-review.md`, the current `evaluation_campaign.py`, and its focused unit tests. The source changed during this review: the parent additionally moved the final deadline check inside `command_to_log()`. The conclusions and final test run below include that strengthening. No implementation or test files were edited, no hardware was accessed, no systemd services were started or stopped, and no subagents were used. This report is the only authored artifact.

All implementation paths below are relative to `defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/`.

## Prior finding: distinct campaigns overlap the testbed

**Fixed.** `evaluation_campaign.py:376` chooses the persistent user-local `~/.local/state/dnp3-evaluation/tofino1-testbed` directory for hardware blocks regardless of campaign ID, controller checkout, or manifest storage directory. The independent step owner acquires its nonblocking `active.lock` before command admission. That owner retains the lock through command completion, restoration inspection, optional postcheck, terminal publication, and final ownership publication. Controller death therefore does not release block ownership.

Before hardware command entry, line 423 durably publishes `active=true`. A killed owner leaves that record behind even though the OS releases its flock. A later process refuses that unresolved owner at lines 381–384. A missing or false restoration proof produces `unsafe_restoration`, and ownership retains `unsafe_restoration=true` after terminal publication. A distinct campaign cannot bypass either condition. Successful restoration publishes a clear ownership record only after the terminal record is durable. Failure during either publication conservatively leaves a retained claim, unresolved ownership, or both.

Contention and unresolved ownership produce an explicit `unexecuted/testbed_refused` terminal record at lines 455–457. Reconciliation stops on that result rather than selecting the step again (`advance()`, lines 296–303). Fixture ownership uses a separate parent-local directory and cannot set the real hardware ownership record.

Fresh harmless subprocess probes verified that a live independent owner excludes a distinct campaign; killing the owner retains refusal after its lock releases and its harmless child finishes; and failed restoration blocks a distinct campaign. The competing command marker was absent in all refusal cases. Successful-owner completion cleared ownership only after verified restoration.

Boundary: the hardware guard covers campaigns run by the same host user, including independent controller checkouts. This rereview does not claim exclusion against unrelated tools, other operating-system users, or controllers on different hosts targeting the same physical testbed.

## Prior finding: queued service enters after deadline

**Fixed.** The independent owner reloads persisted campaign state and checks the cutoff after acquiring the testbed guard (lines 413–417). More importantly, `command_to_log()` checks again after opening the command log and immediately before `subprocess.call()` (lines 350–357). Slow ownership publication therefore cannot preserve stale deadline admission.

If admission expires before command entry, the independent owner publishes `status=unexecuted`, `reason=deadline_expired`, and no restoration success claim. The final cutoff path also sets `hardware_entry=null` and clears its temporary active ownership (lines 428–434). Once-only claims remain retained. Terminal validation accepts only the enumerated nonexecuted reasons, status exposes the nonexecuted result, and `advance()` stops the campaign instead of replaying it.

A deterministic harmless probe advanced the clock from 86499 to 86501 while publishing active ownership, against a persisted deadline of 86500. The command marker was absent; the terminal result was `unexecuted`, with `hardware_entry=null`. This specifically checks the filesystem-delay boundary in addition to the queued-service unit test. A separate real subprocess command admitted before a near cutoff finished its command and restoration after the deadline and remained `completed`; active execution is not interrupted by the new admission checks.

## Quality and failure-path assessment

The fix keeps ownership in the correct independent service, adds no dependencies, and preserves immutable launch intent and once-only claims. The terminal/status extension accurately distinguishes refusal before command entry from an executed failed block. Durable unsafe ownership is conservative across process death and restoration failure. Hook behavior remains independent of the hardware lock and deadline admission, consistent with offline hook semantics.

There is an intentionally conservative crash interval after terminal publication and before clear ownership publication. A crash there can require explicit inspection even when restoration succeeded; it does not permit unsafe entry or replay. A contender admitted during that short interval may also be refused rather than queued. Those are availability tradeoffs of nonblocking, fail-closed admission, not regressions that invalidate these safety fixes.

The existing two new unit tests cover queued-service expiry and shared guard contention. The standalone probes below add evidence for process death, cross-campaign restoration refusal, and the ownership-write deadline boundary; they are not committed regression tests. The parent owns the separate real-systemd fixture extension and its evidence, which this reviewer did not execute or independently certify.

## Fresh validation

- `python3 -m unittest discover -s defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/tests -p test_evaluation_campaign.py`: **23 tests passed**, including fresh runs after the final deadline strengthening and user-local hardware guard relocation.
- Independent-process live-owner exclusion across two campaign IDs: **passed**; competitor unexecuted, owner completed safely.
- Killed independent owner, released flock, completed harmless child, then distinct campaign admission: **refused**, with durable unresolved ownership retained.
- False restoration proof followed by distinct campaign admission: **refused**; no competing command entry.
- Ownership publication crosses the persisted deadline: **no command launched**, explicit nonexecuted result.
- Already admitted command crosses the cutoff: **command and restoration completed**, no deadline kill.

The subprocess probes imported the real implementation, used temporary fixture directories and harmless local Python commands, and replaced only the manager dispatch boundary. The ownership-delay probe additionally controlled the clock and wrapped the real atomic publication function. No retained hardware ownership directory was created or modified by these probes.
