You are working in an existing DNP3/OpenDNP3 experimental repository.

Your task is to implement a safe, reproducible **multi-CROB Select-Before-Operate validation experiment** while preserving all existing Class 0 READ, TCP replay, and CRC-boundary split functionality.

Do not rename unrelated files, delete existing code, redesign the repository, add P4, add padding, add fake traffic, or modify the current TCP replay/split experiment. This task is only about validating whether multiple CROB control objects can be carried and processed in one DNP3 control transaction.

# 1. Research context and motivation

The current project has already built a controlled DNP3 replay experiment:

* Vision acts as the DNP3 master.
* Hulk hosts the OpenDNP3 outstation during baseline capture.
* Hulk can later replace the outstation with a plain TCP replay/split server.
* The replay server preserves original DNP3 bytes and splits TCP delivery at existing DNP3 CRC boundaries.
* The present validation target is Class 0 READ/RESPONSE behavior.

The next protocol question from the supervisor is:

> Can a DNP3 SELECT/OPERATE transaction contain multiple valid CROB control objects targeting multiple output indexes?

This matters because ordinary binary-control messages are often small and predictable. If the DNP3 stack permits multiple valid CROBs in one command set, that establishes a legitimate DNP3-native way to vary control-message structure. This task is only to prove protocol/API behavior safely. It is not yet an obfuscation implementation.

# 2. Required conceptual model

Use this terminology correctly in comments, logs, README text, and CLI help:

* CROB means Control Relay Output Block.
* CROB is DNP3 Group 12 Variation 1.
* CROB is an application-layer object, not a DNP3 function code.
* SELECT and OPERATE are DNP3 application function codes.
* A CROB includes an output point index and a control code such as LATCH_ON or LATCH_OFF.
* The point index identifies the target binary output/control point.
* Multiple CROBs means multiple indexed control objects inside one logical DNP3 command set.
* Select-Before-Operate means:

  1. Master sends SELECT for the requested CROBs.
  2. Outstation validates and accepts/rejects them.
  3. Master sends OPERATE containing the same CROBs.
  4. Outstation executes or rejects each requested control.

Do not describe LATCH_ON or LATCH_OFF as multiple physical latches. They are control codes applied to a specified binary output point.

# 3. Safety requirements

This must be a software-only experiment.

* Do not map any CROB to physical GPIO, a real breaker, relay, PLC, or external device.
* Use only two simulated binary output/control points.
* Default behavior of the normal outstation must remain unchanged.
* Multi-CROB behavior must be enabled only with an explicit CLI flag such as `--control-test`.
* Never send a non-existent point index by default.
* Do not add “decoy” control operations, random controls, fake CROBs, custom DNP3 headers, or padding.
* Do not use DIRECT_OPERATE for this experiment.
* Use SELECT followed by OPERATE only.

# 4. First inspect the repository

Before editing code:

1. Identify the actual current master runner, outstation runner, command handler, and CLI entry points.
2. Locate how the existing master creates OpenDNP3 commands.
3. Locate how the current outstation handles SELECT and OPERATE callbacks.
4. Locate existing CSV/logging utilities.
5. Preserve naming and style already used in the repository.
6. Do not assume filenames are correct if their contents indicate otherwise.

Provide a short implementation plan before making edits.

# 5. Outstation implementation requirements

Extend the existing OpenDNP3 outstation in a minimal and explicit way.

When `--control-test` is enabled, create these two simulated binary output points:

* Index 0: simulated feeder-A control output.
* Index 1: simulated feeder-B control output.

Initial state:

```text
index 0 = False
index 1 = True
```

Required behavior:

## SELECT handling

For each incoming CROB:

* Accept only indexes 0 and 1.
* Accept only LATCH_ON and LATCH_OFF for the first experiment.
* Record the selected command using enough information to verify that OPERATE matches:

  * point index
  * control code
  * count
  * on-time
  * off-time
* Return success only for valid supported CROBs.
* Return an explicit failure/status for unsupported index or unsupported code.
* Do not change the simulated output state during SELECT.

## OPERATE handling

For each incoming CROB:

* Require a matching prior SELECT for that point and CROB parameters.
* If matching selection is present:

  * LATCH_ON changes that point state to True.
  * LATCH_OFF changes that point state to False.
  * emit a clear log line with index, operation, previous state, resulting state, and success.
* If no matching selection is present:

  * reject the operation and log why.
* Return per-command status accurately.
* Clear consumed selection state after a successful or failed OPERATE, so stale selects cannot be reused.

Use a safe in-memory dictionary or equivalent structure for:

```text
selected_commands[index]
simulated_output_state[index]
```

Add a readable outstation status function or endpoint that prints:

```text
Simulated CROB Output State
  Index 0: False
  Index 1: True
```

before and after each test.

# 6. Master implementation requirements

Add a dedicated safe CLI action. Follow the existing CLI style; use a name such as:

```text
--action multi-crob-sbo
```

The action must build one OpenDNP3 command set containing exactly two valid CROBs:

```text
CROB 1:
  index 0
  LATCH_ON

CROB 2:
  index 1
  LATCH_OFF
```

Use the OpenDNP3 CommandSet/SelectAndOperate API already available in the project.

The transaction must be:

```text
Master
  SELECT [index 0 LATCH_ON, index 1 LATCH_OFF]
  wait for valid SELECT response
  OPERATE [index 0 LATCH_ON, index 1 LATCH_OFF]
  wait for final command response
```

Do not send two separate independent SELECT/OPERATE transactions. The experiment must construct one command set containing two CROBs.

Capture and log:

* transaction start time
* each command index
* each control code
* Select response status
* Operate response status
* per-index command status, if exposed by OpenDNP3
* overall task completion status
* elapsed time

Write a readable result file such as:

```text
logs/master/multi_crob_sbo_summary.txt
```

Expected successful output:

```text
Multi-CROB Select-Before-Operate Result

Requested controls:
  Index 0: LATCH_ON
  Index 1: LATCH_OFF

Select result:
  Index 0: SUCCESS
  Index 1: SUCCESS

Operate result:
  Index 0: SUCCESS
  Index 1: SUCCESS

Expected final simulated states:
  Index 0: True
  Index 1: False

Status: PASS
```

If the API exposes only a task-level status and not per-command status, state that explicitly in the report and rely on the outstation-side logs/state report for per-index evidence.

# 7. Test plan

Implement the following staged tests. Each must have its own log and clearly named output file.

## Test A: Single-CROB baseline

```text
SELECT index 0, LATCH_ON
OPERATE index 0, LATCH_ON
```

Expected:

```text
index 0 changes False → True
operation succeeds
```

## Test B: Second single-CROB baseline

Reset test state, then:

```text
SELECT index 1, LATCH_OFF
OPERATE index 1, LATCH_OFF
```

Expected:

```text
index 1 changes True → False
operation succeeds
```

## Test C: Multi-CROB command set

Reset state to:

```text
index 0 = False
index 1 = True
```

Then send:

```text
SELECT:
  index 0 LATCH_ON
  index 1 LATCH_OFF

OPERATE:
  index 0 LATCH_ON
  index 1 LATCH_OFF
```

Expected:

```text
index 0 = True
index 1 = False
both operations reported successful
```

## Test D: Optional negative test

Implement only behind an explicit flag such as:

```text
--control-test-negative
```

Send one valid CROB and one unsupported index, for example index 99.

This test must:

* never run by default;
* document the actual observed OpenDNP3 behavior;
* not assume partial success or whole-command failure;
* log task-level status and any per-index status;
* confirm the valid control does not cause unsafe or ambiguous state changes.

# 8. Wireshark validation requirements

Provide a concise `docs/multi_crob_validation.md` explaining how to capture and inspect the test.

Use a capture command appropriate for the environment, for example:

```bash
sudo tcpdump -i <interface> -s 0 -w captures/multi_crob_sbo.pcap tcp port 20000
```

Document how to identify the expected transaction in Wireshark:

1. Filter DNP3 traffic:

```text
tcp.port == 20000
```

or, if Wireshark decodes it correctly:

```text
dnp3
```

2. Find the master-to-outstation SELECT request.
3. Expand:

```text
DNP3
  Application Layer
    Function Code: SELECT
  Object Header
    Group 12
    Variation 1
```

4. Verify that the message contains two CROB/control-point instances:

   * index 0 with LATCH_ON
   * index 1 with LATCH_OFF

5. Find the outstation response and record its status.

6. Find the master-to-outstation OPERATE request.

7. Verify it carries the same two CROB instances and same parameter values.

8. Find the final outstation response and record completion/status.

The documentation must explain that a Wireshark decode may show multiple objects under one Group 12 Variation 1 object header, or may display them as repeated indexed CROB entries depending on the qualifier and dissector version.

Also document what NOT to claim:

* Do not claim actions are physically simultaneous.
* Do not claim one overall success proves both outputs changed.
* Do not claim packet size variation is an obfuscation defense at this stage.
* Do not claim the experiment validates fake/unknown control objects.

# 9. Required deliverables

Produce:

1. Minimal code changes to master and outstation.
2. A clear CLI action for the multi-CROB test.
3. A clear CLI flag to enable simulated control-test state on the outstation.
4. Human-readable master result summary.
5. Human-readable outstation state/result log.
6. `docs/multi_crob_validation.md`.
7. A short `README` section with:

   * experiment purpose;
   * topology;
   * commands to run;
   * expected output;
   * Wireshark validation steps;
   * known limitations.

# 10. Commands to document

Adapt exact commands to the repository’s actual CLI.

The documentation should contain an equivalent sequence to:

```bash
# Terminal 1: start simulated outstation
python run_outstation.py --control-test

# Terminal 2: start packet capture
sudo tcpdump -i <interface> -s 0 -w captures/multi_crob_sbo.pcap tcp port 20000

# Terminal 3: execute master-side multi-CROB SBO test
python run_master.py --action multi-crob-sbo

# Stop capture after test completion
```

# 11. Acceptance criteria

The implementation is complete only when all of the following hold:

```text
[ ] Existing Class 0 READ/replay/split functionality still works.
[ ] The normal outstation behavior is unchanged unless --control-test is enabled.
[ ] Single-CROB Test A passes.
[ ] Single-CROB Test B passes.
[ ] Multi-CROB Test C sends one command set containing two CROBs.
[ ] Outstation logs show both SELECTs and both OPERATEs.
[ ] Simulated output state ends at index 0 = True and index 1 = False.
[ ] Master summary reports successful completion.
[ ] PCAP exists and is documented for Wireshark inspection.
[ ] No physical device operation, padding, noise, custom headers, or replay-server modifications are introduced.
```

# 12. Important limitation to state in the final implementation report

This experiment establishes that the controlled OpenDNP3 master/outstation setup can encode and process multiple valid CROB objects in one Select-Before-Operate command set.

It does not establish:

* universal support across all vendor devices;
* atomic or simultaneous physical execution;
* safe use of unknown or non-existent indexes;
* a complete traffic-obfuscation mechanism;
* P4/Tofino feasibility;
* a justification to inject dummy controls.

At the end, report:

1. files changed;
2. commands to run;
3. observed behavior;
4. any OpenDNP3 API limitation;
5. the exact Wireshark fields that demonstrate the two CROBs in the SELECT and OPERATE messages.
