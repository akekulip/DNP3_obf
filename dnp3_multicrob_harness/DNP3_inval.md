Review the following files carefully before making changes:

- run_outstation.py
- run_master.py
- run_crob_boundary_index_test.py
- run_crob_padding_candidate_tests.py

Goal
Remove the current behavior where our custom test code explicitly decides that an unsupported CROB index must return OUT_OF_RANGE.

At the moment, run_outstation.py contains logic similar to:

    if index not in self.supported_indexes:
        return 'OUT_OF_RANGE', ...

and later maps that string to:

    opendnp3.CommandStatus.OUT_OF_RANGE

I do not want the test harness to manufacture or assume the error status.

Required behavior
1. The master must send the requested CROB indexes exactly as before.
2. The test scripts may choose valid and invalid indexes and their order.
3. The test scripts must not assign, rewrite, or assume the returned DNP3 CommandStatus.
4. The outstation must use the most native OpenDNP3 mechanism available to determine whether an output index exists.
5. The response status must come from the outstation/OpenDNP3 command-processing path and then be captured from the PCAP, logs, or callback.
6. The analysis must report the status exactly as observed.
7. Do not hardcode OUT_OF_RANGE, NOT_SUPPORTED, or SUCCESS for invalid indexes in the experiment runner.
8. Do not rewrite any DNP3 response.
9. Do not change the transmitted CROB order.
10. Keep the experiment software-only. No physical output may be operated.

Important technical check
Before editing, inspect the installed pydnp3/OpenDNP3 API and determine whether OpenDNP3 provides:

- a native control-point database;
- a default command handler;
- a command-point configuration;
- an output-point lookup;
- or another built-in mechanism that automatically rejects an unconfigured CROB index.

Do not assume this capability exists.

If OpenDNP3 requires ICommandHandler.Select() and Operate() to return a CommandStatus, clearly explain that the protocol stack cannot independently infer whether an application-level control point exists.

In that case, implement the closest correct design:

- move index validity into a separate outstation control-point backend or registry;
- let that backend return the native application result;
- make the experiment orchestration code only send requests and observe responses;
- remove any OUT_OF_RANGE assumption from the test scripts and analyzers;
- record the returned status without predicting it;
- clearly document that the application backend, not the test runner, determines the command status.

Do not silently replace OUT_OF_RANGE with another hardcoded status.

Files and responsibilities

run_crob_padding_candidate_tests.py
- Keep the case definitions:
  - invalid at beginning;
  - invalid in middle;
  - invalid at end;
  - multiple invalid;
  - invalid-only.
- These cases should only define the indexes sent.
- They must not define the expected error status.
- Change analyzer expectations from a specific status to “observe and report.”

run_crob_boundary_index_test.py
- Keep K configured points and N requested CROBs.
- Do not assume index K returns OUT_OF_RANGE.
- Report the first non-success status exactly as received.

run_master.py
- Preserve --crob-plan and the transmitted order.
- Do not validate whether an index exists on the outstation.
- Do not infer the response status.
- Record the response/task evidence exactly as observed.

run_outstation.py
- Remove the direct hardcoded mapping:

      unsupported index -> OUT_OF_RANGE

- Use the native OpenDNP3 output-point handling mechanism if one exists.
- If no native mechanism exists, create a clean control-point backend interface instead of embedding the status decision in the experiment logic.
- The command handler should delegate to that backend.
- Document where the final CommandStatus originates.

Analyzer and reporting changes
- Do not state that an invalid index “should return OUT_OF_RANGE.”
- Use wording such as:

      observed_status
      first_non_success_status
      returned_command_status

- Preserve all raw status values and status names.
- Do not mark a test failed simply because the returned status is not OUT_OF_RANGE.
- A test should fail only if:
  - the expected request was not transmitted;
  - the response was not captured;
  - index order changed;
  - the PCAP and logs disagree;
  - or an unexpected OPERATE was sent after a failed SELECT, based on the selected test condition.

Add a startup log showing:
- configured control indexes;
- requested indexes;
- source of the returned status;
- whether the status came from OpenDNP3, the application backend, or test code.

Expected output
Provide:

1. A short explanation of whether OpenDNP3 can natively detect an unconfigured CROB index.
2. A list of changed files.
3. A diff for each changed section.
4. The exact new control flow from:
   master request -> outstation handler -> status source -> DNP3 response -> PCAP analyzer.
5. Updated commands for running:
   - valid K=5, N=5;
   - invalid-at-end;
   - invalid-at-beginning;
   - invalid-in-middle;
   - invalid-only.
6. A sample report that displays the observed status without assuming OUT_OF_RANGE.
7. Unit tests or dry-run tests proving that the experiment code no longer hardcodes the invalid-index status.

Do not claim that the status is “from DNP3” unless the OpenDNP3 stack itself actually determines it. Be precise about whether the status originates from the protocol stack, the outstation application, or the control-point backend.