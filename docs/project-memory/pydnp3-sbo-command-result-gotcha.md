---
name: pydnp3-sbo-command-result-gotcha
description: pydnp3 SelectAndOperate/DirectOperate command-result callback aborts (Py3.12) or hangs (Py3.8); capture task status via OnTaskComplete instead
metadata: 
  node_type: memory
  type: project
  originSessionId: 4e32be25-f931-4e82-aba6-a66bd6242d7b
---

For DNP3 **control commands** (SelectAndOperate / DirectOperate) in this harness,
the async command-result `ICommandTaskResult` delivered to a Python callback is
**non-copyable** and pybind11 cannot marshal it: on the rig (Python 3.12 /
pybind11 2.13) it throws `pybind11::cast_error` and **aborts the process** (exit
134) right AFTER the protocol exchange completes; on gambit (Python 3.8) the same
path **hangs** instead. This hits any callback that receives the result —
`result.ForeachItem(...)`, even reading `result.summary`, and even the C++
`asiodnp3.PrintingCommandCallback.Get()`. The wire exchange (SELECT/OPERATE +
responses) is fully correct regardless; only the master-side result delivery breaks.

**Working pattern** (used by `run_master.py --action multi-crob-sbo`):
- Capture **task-level** completion (TaskCompletion SUCCESS/…) from a custom
  `IMasterApplication.OnTaskComplete(info)` — `info.type`/`info.result` (TaskInfo)
  marshal fine and it fires just before the result delivery.
- In that callback, hand the result to the main thread and **block forever**
  (`threading.Event().wait()` on an event never set). The DNP3 manager runs ONE
  thread (`DNP3Manager(1, …)`), so blocking it freezes further DNP3 work and the
  aborting result delivery never happens.
- Do the summary **file I/O on the MAIN thread**, then `os._exit(0)` — file I/O on
  the DNP3 callback thread deadlocks against pydnp3's C++ (observed: build hangs
  between building the text and writing the file).
- Also keep the `opendnp3.CommandSet` **alive** (store on the instance) — it is a
  local that the async task keeps referencing; letting it be GC'd hangs the DNP3
  thread.

**Per-command status is therefore not available on the master.** Get authoritative
per-index SELECT/OPERATE status + final states from the outstation-side handler log
and the PCAP (Wireshark decodes Group 12 Var 1 CROBs directly). See
`reports/multi_crob_sbo_results.md`, `docs/multi_crob_validation.md`. Related:
[[pydnp3-install]], [[dnp3-harness-verified]], [[lab-hosts-dnp3]].
