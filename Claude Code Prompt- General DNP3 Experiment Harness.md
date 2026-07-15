# Claude Code Prompt: General DNP3 Experiment Harness

You are working on a general DNP3 protocol experiment harness using the existing pydnp3 scripts provided in this repository.

Do **not** name the project GridCloak.  
Do **not** use GridCloak in file names, comments, README text, class names, or logs.  
Use general names such as:

- `dnp3_experiment_harness`
- `dnp3_protocol_lab`
- `dnp3_replay_lab`
- `dnp3_segmentation_lab`

The research goal is to build a reproducible DNP3 test harness that can generate controlled DNP3 READ/RESPONSE traffic, capture PCAPs, analyze response segmentation, and later support replay/splitting/padding experiments.

The immediate goal is **not** P4 implementation.  
The immediate goal is to prepare clean, scriptable, reproducible DNP3 traffic generation and validation.

---

## 1. Existing Scripts and Coding Style

The repository already contains these files:

- `master.py`
- `master_cmd.py`
- `outstation.py`
- `outstation_cmd.py`
- `simple_master.py`
- `simple_outstation.py`
- `visitors.py`

Study these files before making changes.

The existing style has the following characteristics. Preserve this style unless there is a strong technical reason not to.

### Logging Style

Use the same module-level logging pattern:

```python
import logging
import sys

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)
```

Requirements:

- Keep `_log` as the module logger.
- Use `_log.debug()` for step-by-step internal execution.
- Use `_log.info()` for high-level experiment progress.
- Use `_log.warning()` for safety warnings or questionable configuration.
- Use `_log.error()` for failures.
- Do not replace this style with a completely different logging framework.

### Class-Based Structure

The current code uses class wrappers:

- `MyMaster`
- `MasterCmd`
- `OutstationApplication`
- `OutstationCmd`
- `SimpleMaster`
- `SimpleOutstation`
- Visitor classes in `visitors.py`

Preserve this class-based structure.

Do not turn the whole project into loose procedural scripts.

New files should also use clear classes where appropriate, for example:

- `ExperimentMaster`
- `ExperimentOutstation`
- `CSVSOEHandler`
- `DNP3PayloadExtractor`
- `DNP3ReplayServer`
- `TCPAckAnalyzer`

### Docstring Style

The existing scripts use multi-line docstrings to explain classes and methods.

Preserve that style.

Every public class and method should have a short docstring explaining:

- what it does,
- why it exists,
- what parameters mean where useful.

### pydnp3 Style

Preserve the existing pydnp3 import pattern:

```python
from pydnp3 import opendnp3, openpal, asiopal, asiodnp3
```

Only import what is needed in each file.

Do not hide pydnp3 behind unnecessary abstractions.

### Command Method Style

The command files use `do_*` methods such as:

- `do_scan_all`
- `do_scan_range`
- `do_scan_fast`
- `do_scan_slow`
- `do_disable_unsol`
- `do_o1`
- `do_s1`

Keep this naming pattern for command-style functionality.

However, for reproducible experiments, add non-interactive CLI scripts using `argparse`. Keep the pydnp3 logic inside reusable classes and use `argparse` only in entrypoint scripts.

### Main Entrypoint Style

Every executable script should end with:

```python
def main():
    ...

if __name__ == '__main__':
    main()
```

Preserve this style.

### Comments

Use comments sparingly and practically.

Do not add excessive comments explaining obvious Python syntax.

Do add comments for:

- DNP3-specific behavior,
- safety constraints,
- why controls are disabled by default,
- why unsolicited responses are disabled for clean captures,
- why exact byte-stream replay must be tested before DNP3-aware modification.

---

## 2. Important Research Goal

The goal is to experimentally answer these questions:

1. Can we generate clean, controlled DNP3 READ/RESPONSE traffic?
2. Can we scale the outstation database to force larger responses?
3. Does OpenDNP3 naturally split large responses into multiple TCP payloads or DNP3 frames?
4. Can we capture and extract the raw DNP3 TCP payload bytes?
5. Can a simple TCP socket replay server send captured responses back to the OpenDNP3 master?
6. Can the same response be delivered in multiple TCP writes without breaking the master?
7. What fields are needed later for true DNP3-aware splitting and padding?

This project is a protocol experiment harness. It is not yet the final obfuscation implementation.

---

## 3. Safety Rules

Follow these strictly.

### Do Not Use GridCloak Branding

Do not write:

- GridCloak
- gridcloak
- GC
- project-specific branding

Use general DNP3 experiment naming.

### Do Not Use Control Commands by Default

Do not send these in baseline experiments:

- `DirectOperate`
- `SelectAndOperate`
- `Operate`
- `ColdRestart`

The current `master_cmd.py` has direct-operate and select-and-operate examples. Keep them available only behind explicit unsafe flags or keep them in a separate manual testing section.

Baseline experiments must use READ/RESPONSE only.

### Do Not Enable Unsolicited Responses by Default

For clean PCAPs, unsolicited responses should be disabled by default.

The first baseline should be:

```text
Master sends READ
Outstation sends RESPONSE
```

No background unsolicited events unless explicitly enabled.

### Do Not Implement P4

Do not implement or modify P4 code in this phase.

The current objective is software validation.

### Do Not Modify Raw DNP3 Bytes Yet

The first phase should not alter DNP3 bytes.

Before DNP3-aware modification, first prove:

```text
exact captured response bytes can be replayed
same bytes can be split across multiple TCP send() calls
```

Only after that should later phases attempt true DNP3 semantic splitting or padding.

### Do Not Append Random Bytes as Padding

Random bytes are not DNP3 padding.

Padding must eventually be protocol-valid, such as:

- dummy measurement objects,
- nonexistent or unconfigured measurement indices,
- reserved/proprietary function-code frames,
- gateway-removable dummy frames.

But do not implement those until replay and split-replay are proven.

---

## 4. Required Repository Structure

Create or reorganize the project into this structure:

```text
dnp3_experiment_harness/
│
├── README.md
├── requirements.txt
│
├── pydnp3_harness/
│   ├── __init__.py
│   ├── master_base.py
│   ├── experiment_master.py
│   ├── outstation_base.py
│   ├── experiment_outstation.py
│   ├── soe_csv_logger.py
│   └── visitors.py
│
├── replay_tools/
│   ├── __init__.py
│   ├── extract_dnp3_payloads.py
│   ├── dnp3_replay_server.py
│   ├── dnp3_split_replay_server.py
│   ├── dnp3_field_map.py
│   └── dnp3_crc.py
│
├── analysis_tools/
│   ├── __init__.py
│   └── analyze_tcp_ack_behavior.py
│
├── scripts/
│   ├── run_small_read_capture.sh
│   ├── run_large_read_capture.sh
│   ├── run_range_sweep.sh
│   ├── run_replay_test.sh
│   └── run_split_replay_test.sh
│
├── captures/
│   ├── baseline/
│   ├── replay/
│   ├── split/
│   └── raw/
│
├── payloads/
│   ├── baseline/
│   ├── replay/
│   └── split/
│
├── logs/
│   ├── master/
│   ├── outstation/
│   ├── replay/
│   └── analysis/
│
└── reports/
    ├── baseline_segmentation.md
    ├── replay_results.md
    ├── split_results.md
    ├── field_map_results.md
    └── tcp_ack_fingerprinting.md
```

Do not delete the original scripts immediately.

Move them into an `archive_original/` directory or leave them untouched and create the new structure beside them.

---

## 5. Phase-Based Work Requirement

You must complete the work in phases.

For each phase:

1. Implement the phase.
2. Review the code you wrote.
3. Run whatever local checks are possible.
4. Fix any bugs or issues discovered.
5. Update the README if needed.
6. At the end of the phase, print a section titled:

```text
Manual Commands for User to Run
```

This section must include the exact commands I should run manually on my machine or hosts.

Do not provide only generic instructions. Provide command examples with placeholders where needed.

When a command requires environment-specific values, use clear placeholders such as:

```text
<MASTER_IP>
<OUTSTATION_IP>
<INTERFACE>
<PROJECT_DIR>
```

Do not claim a network experiment succeeded unless you actually ran it in the correct environment.

If a command cannot be run locally because it requires my hosts, say so clearly and still provide the manual command.

---

# Phase 0: Audit and Preserve Existing Code

## Goal

Understand the current scripts and preserve their behavior before refactoring.

## Tasks

1. Inspect all existing scripts:
   - `master.py`
   - `master_cmd.py`
   - `outstation.py`
   - `outstation_cmd.py`
   - `simple_master.py`
   - `simple_outstation.py`
   - `visitors.py`

2. Create `archive_original/`.

3. Copy the original scripts into `archive_original/`.

4. Create a short audit report:

```text
reports/original_code_audit.md
```

The audit report should include:

- what each original file does,
- which parts are reusable,
- which parts are unsafe for baseline READ experiments,
- which values are currently hard-coded,
- which parts need refactoring.

## Things to notice

- `master.py` hard-codes `HOST`, `LOCAL`, and `PORT`.
- `master.py` creates slow and fast scans inside `MyMaster`.
- `master.py` accepts a custom SOE handler but currently uses `PrintingSOEHandler` when adding the master.
- `master_cmd.py` provides useful scan commands but also unsafe control commands.
- `outstation.py` configures a small database and enables unsolicited responses.
- `outstation.py` returns `SUCCESS` for Select and Operate.
- `simple_master.py` should not be used as-is because it sends SelectAndOperate by default.
- `visitors.py` is reusable for extracting index/value pairs.

## Local checks to run

Run:

```bash
python -m py_compile master.py master_cmd.py outstation.py outstation_cmd.py simple_master.py simple_outstation.py visitors.py
```

Fix only syntax/import issues that are clearly local and safe.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>
python -m py_compile master.py master_cmd.py outstation.py outstation_cmd.py simple_master.py simple_outstation.py visitors.py
ls -la archive_original/
cat reports/original_code_audit.md
```

---

# Phase 1: Create Style-Preserving Master Harness

## Goal

Create a reusable, parameterized master module while preserving the original coding style.

## Create

```text
pydnp3_harness/master_base.py
pydnp3_harness/experiment_master.py
```

## `master_base.py` Requirements

Create a class named:

```python
class ExperimentMaster:
```

It should preserve the style of `MyMaster`.

Constructor parameters:

```python
def __init__(self,
             host='127.0.0.1',
             local='0.0.0.0',
             port=20000,
             master_addr=1,
             outstation_addr=10,
             response_timeout_sec=2,
             log_handler=None,
             listener=None,
             soe_handler=None,
             master_application=None,
             enable_periodic_scans=False,
             fast_scan_sec=60,
             slow_scan_sec=1800):
```

Behavior:

- Create `DNP3Manager`.
- Create TCP client using `host`, `local`, and `port`.
- Configure `MasterStackConfig`.
- Set `stack_config.link.LocalAddr = master_addr` if supported.
- Set `stack_config.link.RemoteAddr = outstation_addr`.
- Set response timeout.
- Add the master using the passed `soe_handler`.
- Enable periodic scans only if `enable_periodic_scans=True`.
- Enable the master.
- Preserve debug logs at each step.

Important fix:

If a custom `soe_handler` is passed, actually use it in `AddMaster`.

Do not always use `PrintingSOEHandler`.

## Master Methods

Implement:

```python
scan_class0()
scan_all_classes()
scan_range(group, variation, start, stop)
scan_all_objects(group, variation)
disable_unsolicited()
shutdown()
```

Keep existing command methods, but mark them with warnings:

```python
send_direct_operate_command(...)
send_direct_operate_command_set(...)
send_select_and_operate_command(...)
send_select_and_operate_command_set(...)
```

Each unsafe method must log a warning:

```text
This control command is unsafe for baseline experiments and should not be used unless explicitly required.
```

## `experiment_master.py` Requirements

Non-interactive CLI using `argparse`.

Arguments:

```text
--host
--local
--port
--master-addr
--outstation-addr
--response-timeout-sec
--action
--group
--variation
--start
--stop
--repeat
--delay-between
--wait-after-action
--log-dir
--csv
--enable-periodic-scans
```

Supported actions:

```text
connect-only
scan-class0
scan-all-classes
scan-range
scan-all-objects
disable-unsolicited
```

Do not expose DirectOperate or SelectAndOperate in this CLI unless behind:

```text
--unsafe-allow-controls
```

For now, do not implement that flag unless necessary.

## Phase 1 Local Checks

Run:

```bash
python -m py_compile pydnp3_harness/master_base.py pydnp3_harness/experiment_master.py
python pydnp3_harness/experiment_master.py --help
```

Fix all errors.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile pydnp3_harness/master_base.py pydnp3_harness/experiment_master.py

python pydnp3_harness/experiment_master.py --help

python pydnp3_harness/experiment_master.py \
  --host <OUTSTATION_IP> \
  --local 0.0.0.0 \
  --port 20000 \
  --master-addr 1 \
  --outstation-addr 10 \
  --action connect-only \
  --wait-after-action 5 \
  --log-dir logs/master
```

---

# Phase 2: Create Configurable Outstation Harness

## Goal

Create a configurable outstation that can generate small and large measurement databases.

## Create

```text
pydnp3_harness/outstation_base.py
pydnp3_harness/experiment_outstation.py
```

## `outstation_base.py` Requirements

Create class:

```python
class ExperimentOutstation(opendnp3.IOutstationApplication):
```

Preserve style from `OutstationApplication`.

Constructor parameters:

```python
def __init__(self,
             host='0.0.0.0',
             port=20000,
             local_addr=10,
             remote_addr=1,
             db_size=10,
             num_analog=2,
             num_binary=2,
             num_counter=0,
             allow_unsolicited=False,
             allow_controls=False,
             log_handler=None,
             listener=None):
```

Behavior:

- Configure `OutstationStackConfig(opendnp3.DatabaseSizes.AllTypes(db_size))`.
- Configure event buffer.
- Set `allowUnsolicited = allow_unsolicited`.
- Set link local/remote addresses.
- Configure analog, binary, and counter points in loops.
- Start TCP server on `host:port`.
- Add outstation.
- Enable outstation.
- Store singleton outstation reference, like the original code.

## Database Configuration

For analog points:

```python
for index in range(num_analog):
    db_config.analog[index].clazz = opendnp3.PointClass.Class0
    db_config.analog[index].svariation = opendnp3.StaticAnalogVariation.Group30Var1
    db_config.analog[index].evariation = opendnp3.EventAnalogVariation.Group32Var7
```

For binary points:

```python
for index in range(num_binary):
    db_config.binary[index].clazz = opendnp3.PointClass.Class0
    db_config.binary[index].svariation = opendnp3.StaticBinaryVariation.Group1Var2
    db_config.binary[index].evariation = opendnp3.EventBinaryVariation.Group2Var2
```

For counters, use appropriate counter static/event variations if supported.

## Initial Values

Add methods:

```python
apply_update(value, index)
apply_initial_values()
apply_bulk_updates()
```

Use deterministic values:

```text
analog index i = 100.0 + i
binary index i = True if i is even else False
counter index i = i
```

## Command Safety

Create command handler:

```python
class ExperimentCommandHandler(opendnp3.ICommandHandler):
```

It should return:

```python
opendnp3.CommandStatus.NOT_SUPPORTED
```

for `Select` and `Operate` unless `allow_controls=True`.

If `allow_controls=True`, it may log and return `SUCCESS`, matching the original style.

## `experiment_outstation.py` Requirements

CLI arguments:

```text
--host
--port
--local-addr
--remote-addr
--db-size
--num-analog
--num-binary
--num-counter
--allow-unsolicited
--allow-controls
--apply-initial-values
--hold
--log-dir
```

Behavior:

- Start the outstation.
- Optionally apply initial values.
- If `--hold`, stay running until Ctrl+C.
- On Ctrl+C, call `shutdown()` cleanly.

## Phase 2 Local Checks

Run:

```bash
python -m py_compile pydnp3_harness/outstation_base.py pydnp3_harness/experiment_outstation.py
python pydnp3_harness/experiment_outstation.py --help
```

Fix all errors.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile pydnp3_harness/outstation_base.py pydnp3_harness/experiment_outstation.py

python pydnp3_harness/experiment_outstation.py --help

python pydnp3_harness/experiment_outstation.py \
  --host 0.0.0.0 \
  --port 20000 \
  --local-addr 10 \
  --remote-addr 1 \
  --db-size 20 \
  --num-analog 5 \
  --num-binary 5 \
  --num-counter 0 \
  --apply-initial-values \
  --hold \
  --log-dir logs/outstation
```

---

# Phase 3: CSV SOE Logging

## Goal

Extend the visitor pattern so received master measurements are written to CSV.

## Create

```text
pydnp3_harness/soe_csv_logger.py
```

You may reuse and extend `visitors.py`.

## Requirements

Create:

```python
class CSVSOEHandler(opendnp3.ISOEHandler):
```

It should:

- follow the same `Start`, `Process`, `End` style as `SOEHandler`,
- use visitors to extract index/value pairs,
- write CSV rows.

CSV columns:

```text
timestamp,header_index,group_variation,data_type,index,value
```

It should create the CSV file if it does not exist.

It should append rows if it already exists.

It should log every received point with `_log.debug()`.

## Integration

Update `experiment_master.py` to support:

```text
--csv logs/master/soe.csv
```

When `--csv` is provided, use `CSVSOEHandler`.

When `--csv` is not provided, use the debug-printing handler.

## Phase 3 Local Checks

Run:

```bash
python -m py_compile pydnp3_harness/soe_csv_logger.py pydnp3_harness/experiment_master.py
python pydnp3_harness/experiment_master.py --help
```

Fix all errors.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile pydnp3_harness/soe_csv_logger.py pydnp3_harness/experiment_master.py

# Terminal 1: run outstation
python pydnp3_harness/experiment_outstation.py \
  --host 0.0.0.0 \
  --port 20000 \
  --local-addr 10 \
  --remote-addr 1 \
  --db-size 20 \
  --num-analog 5 \
  --num-binary 5 \
  --apply-initial-values \
  --hold \
  --log-dir logs/outstation

# Terminal 2: run master scan and write SOE CSV
python pydnp3_harness/experiment_master.py \
  --host <OUTSTATION_IP> \
  --local 0.0.0.0 \
  --port 20000 \
  --master-addr 1 \
  --outstation-addr 10 \
  --action scan-all-classes \
  --repeat 1 \
  --wait-after-action 5 \
  --csv logs/master/soe.csv \
  --log-dir logs/master

cat logs/master/soe.csv
```

---

# Phase 4: Baseline Capture Scripts

## Goal

Create shell scripts that run small and large READ experiments with tcpdump.

## Create

```text
scripts/run_small_read_capture.sh
scripts/run_large_read_capture.sh
scripts/run_range_sweep.sh
```

## Requirements

Shell scripts should:

- use `set -euo pipefail`,
- print each major step,
- create output directories,
- accept environment variables for IPs and interface,
- not hard-code host-specific IPs except as examples in comments.

Environment variables:

```bash
MASTER_IP=${MASTER_IP:-""}
OUTSTATION_IP=${OUTSTATION_IP:-""}
IFACE=${IFACE:-"eth0"}
PORT=${PORT:-"20000"}
```

If required variables are missing, print a clear error.

## Small Capture

Goal:

```text
small database, clean READ/RESPONSE
```

## Large Capture

Goal:

```text
large database, test whether responses naturally segment
```

## Range Sweep

Goal:

```text
scan increasing ranges and observe when response size/segmentation changes
```

Example ranges:

```text
0..9
0..49
0..99
0..199
```

## Phase 4 Local Checks

Run:

```bash
bash -n scripts/run_small_read_capture.sh
bash -n scripts/run_large_read_capture.sh
bash -n scripts/run_range_sweep.sh
```

Fix all shell syntax errors.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

bash -n scripts/run_small_read_capture.sh
bash -n scripts/run_large_read_capture.sh
bash -n scripts/run_range_sweep.sh

# Example manual run
export MASTER_IP=<MASTER_IP>
export OUTSTATION_IP=<OUTSTATION_IP>
export IFACE=<INTERFACE>
export PORT=20000

bash scripts/run_small_read_capture.sh
bash scripts/run_large_read_capture.sh
bash scripts/run_range_sweep.sh

ls -lh captures/baseline/
ls -lh logs/master/
ls -lh logs/outstation/
```

---

# Phase 5: Payload Extraction Tool

## Goal

Extract raw DNP3 TCP payload bytes from PCAPs.

## Create

```text
replay_tools/extract_dnp3_payloads.py
```

## Requirements

Use Scapy if available. If Scapy is not installed, print a clear installation message.

CLI arguments:

```text
--pcap
--master-ip
--outstation-ip
--port
--output-dir
```

Extract:

- master-to-outstation payloads,
- outstation-to-master payloads.

Do not save Ethernet/IP/TCP headers.

Save payloads as:

```text
orig_0001.bin
resp_0001.bin
```

Save metadata:

```text
metadata.json
```

Metadata should include:

- timestamp,
- src IP,
- dst IP,
- source port,
- destination port,
- payload length,
- TCP flags,
- TCP seq,
- TCP ack,
- direction.

## Phase 5 Local Checks

Run:

```bash
python -m py_compile replay_tools/extract_dnp3_payloads.py
python replay_tools/extract_dnp3_payloads.py --help
```

If a sample PCAP exists, run extraction.

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile replay_tools/extract_dnp3_payloads.py

python replay_tools/extract_dnp3_payloads.py --help

python replay_tools/extract_dnp3_payloads.py \
  --pcap captures/baseline/<CAPTURE_FILE>.pcap \
  --master-ip <MASTER_IP> \
  --outstation-ip <OUTSTATION_IP> \
  --port 20000 \
  --output-dir payloads/baseline

ls -lh payloads/baseline/
cat payloads/baseline/metadata.json
```

---

# Phase 6: Exact Replay Server

## Goal

Build a raw TCP socket server that replays captured DNP3 response bytes.

## Create

```text
replay_tools/dnp3_replay_server.py
```

## Requirements

Use Python sockets.

Do not craft raw TCP packets.

Let the OS handle:

- TCP sequence numbers,
- ACKs,
- retransmissions,
- TCP checksums.

CLI arguments:

```text
--host
--port
--response
--delay-before-response-ms
--hold-after-response-sec
--log-dir
```

Behavior:

- Listen on TCP port 20000.
- Accept one connection.
- Receive request bytes from master.
- Save received bytes.
- Send exact response bytes from file.
- Save sent bytes.
- Log timestamps.
- Keep connection open for configurable seconds.
- Exit cleanly.

## Critical Rule

The first replay server must not modify the response bytes.

It must replay the exact byte stream.

## Phase 6 Local Checks

Run:

```bash
python -m py_compile replay_tools/dnp3_replay_server.py
python replay_tools/dnp3_replay_server.py --help
```

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile replay_tools/dnp3_replay_server.py

python replay_tools/dnp3_replay_server.py --help

# Terminal 1: start replay server instead of real outstation
python replay_tools/dnp3_replay_server.py \
  --host 0.0.0.0 \
  --port 20000 \
  --response payloads/baseline/resp_0001.bin \
  --delay-before-response-ms 0 \
  --hold-after-response-sec 5 \
  --log-dir logs/replay

# Terminal 2: run master against replay server
python pydnp3_harness/experiment_master.py \
  --host <REPLAY_SERVER_IP> \
  --local 0.0.0.0 \
  --port 20000 \
  --master-addr 1 \
  --outstation-addr 10 \
  --action scan-all-classes \
  --repeat 1 \
  --wait-after-action 5 \
  --csv logs/master/replay_soe.csv \
  --log-dir logs/master

ls -lh logs/replay/
cat logs/master/replay_soe.csv
```

---

# Phase 7: Split Replay Server

## Goal

Send the same captured response bytes in multiple TCP writes.

This tests stream robustness.  
This is not yet DNP3 semantic splitting.

## Create

```text
replay_tools/dnp3_split_replay_server.py
```

## Requirements

CLI arguments:

```text
--host
--port
--response
--split-mode
--fixed-size
--offsets
--delay-between-chunks-ms
--hold-after-response-sec
--log-dir
```

Supported split modes:

```text
full
half
byte
fixed
offsets
```

Behavior:

- Load response bytes.
- Split them according to the chosen mode.
- Send each chunk with `sendall()`.
- Sleep between chunks if requested.
- Save each chunk to disk.
- Log chunk index, size, and timestamp.
- Confirm that concatenating chunks equals the original response bytes.

## Required Internal Check

Before sending, verify:

```python
b''.join(chunks) == original_payload
```

If false, abort.

## Phase 7 Local Checks

Run:

```bash
python -m py_compile replay_tools/dnp3_split_replay_server.py
python replay_tools/dnp3_split_replay_server.py --help
```

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile replay_tools/dnp3_split_replay_server.py

python replay_tools/dnp3_split_replay_server.py --help

# Terminal 1: split replay server
python replay_tools/dnp3_split_replay_server.py \
  --host 0.0.0.0 \
  --port 20000 \
  --response payloads/baseline/resp_0001.bin \
  --split-mode fixed \
  --fixed-size 40 \
  --delay-between-chunks-ms 10 \
  --hold-after-response-sec 5 \
  --log-dir logs/replay

# Terminal 2: master
python pydnp3_harness/experiment_master.py \
  --host <REPLAY_SERVER_IP> \
  --local 0.0.0.0 \
  --port 20000 \
  --master-addr 1 \
  --outstation-addr 10 \
  --action scan-all-classes \
  --repeat 1 \
  --wait-after-action 5 \
  --csv logs/master/split_soe.csv \
  --log-dir logs/master

ls -lh logs/replay/
cat logs/master/split_soe.csv
```

---

# Phase 8: DNP3 Field Mapping and CRC Utility

## Goal

Prepare for later true DNP3-aware splitting and padding.

## Create

```text
replay_tools/dnp3_field_map.py
replay_tools/dnp3_crc.py
```

## `dnp3_field_map.py` Requirements

Input:

```text
--payload
--output
```

Parse enough to identify:

- DNP3 start bytes,
- length,
- link control,
- destination,
- source,
- header CRC,
- transport byte,
- transport FIR,
- transport FIN,
- transport sequence,
- application control,
- application FIR,
- application FIN,
- application CON,
- application UNS,
- application sequence,
- function code,
- likely object header offset.

Do not attempt full object parsing unless simple.

Output Markdown table:

```text
offset,length,field,value,meaning
```

## `dnp3_crc.py` Requirements

Implement CRC-16/DNP utilities.

Include:

```python
dnp3_crc16(data: bytes) -> int
verify_crc(data: bytes, crc_bytes: bytes) -> bool
append_crc(data: bytes) -> bytes
```

Validate against known test value if possible.

Log clearly if CRC validation is experimental.

## Phase 8 Local Checks

Run:

```bash
python -m py_compile replay_tools/dnp3_field_map.py replay_tools/dnp3_crc.py
python replay_tools/dnp3_field_map.py --help
```

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile replay_tools/dnp3_field_map.py replay_tools/dnp3_crc.py

python replay_tools/dnp3_field_map.py \
  --payload payloads/baseline/resp_0001.bin \
  --output reports/field_map_results.md

cat reports/field_map_results.md
```

---

# Phase 9: TCP ACK Behavior Analyzer

## Goal

Analyze inter-layer response fingerprinting and TCP ACK behavior.

## Create

```text
analysis_tools/analyze_tcp_ack_behavior.py
```

## Requirements

CLI arguments:

```text
--pcap
--master-ip
--outstation-ip
--port
--output-csv
--summary
```

Analyze:

- pure ACK after request,
- piggybacked ACK on application response,
- request-to-ACK delay,
- request-to-application-response delay,
- TCP options,
- window size,
- TTL,
- IP ID behavior,
- PSH flag behavior.

Output CSV columns:

```text
pcap,flow_id,request_time,has_pure_ack,ack_delay_ms,has_piggyback_ack,response_delay_ms,tcp_options,ttl,ip_id,window_size,notes
```

Summary columns:

```text
device,pcap,total_requests,pure_ack_count,piggyback_ack_count,pure_ack_ratio,mean_ack_delay_ms,mean_response_delay_ms,tcp_option_signature
```

## Phase 9 Local Checks

Run:

```bash
python -m py_compile analysis_tools/analyze_tcp_ack_behavior.py
python analysis_tools/analyze_tcp_ack_behavior.py --help
```

## Manual Commands for User to Run

At the end of this phase, provide:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

python -m py_compile analysis_tools/analyze_tcp_ack_behavior.py

python analysis_tools/analyze_tcp_ack_behavior.py \
  --pcap captures/baseline/<CAPTURE_FILE>.pcap \
  --master-ip <MASTER_IP> \
  --outstation-ip <OUTSTATION_IP> \
  --port 20000 \
  --output-csv reports/tcp_ack_details.csv \
  --summary reports/tcp_ack_summary.csv

cat reports/tcp_ack_summary.csv
```

---

# Phase 10: README and Final Validation

## Goal

Make the project usable manually.

## README Must Explain

The README must explain:

1. Purpose of the harness.
2. Why it is general and not project-branded.
3. How to run the outstation.
4. How to run the master.
5. How to capture traffic.
6. How to run small READ.
7. How to run large READ.
8. How to run range sweep.
9. How to extract payloads.
10. How to replay exact responses.
11. How to split replay responses.
12. How to map DNP3 fields.
13. How to analyze TCP ACK behavior.
14. What not to do.
15. How to interpret results.

## Final Local Checks

Run:

```bash
find . -name "*.py" -print0 | xargs -0 python -m py_compile
bash -n scripts/run_small_read_capture.sh
bash -n scripts/run_large_read_capture.sh
bash -n scripts/run_range_sweep.sh
bash -n scripts/run_replay_test.sh
bash -n scripts/run_split_replay_test.sh
```

Fix all issues.

## Manual Commands for User to Run

At the end of this phase, provide one full end-to-end manual workflow:

```bash
cd <PROJECT_DIR>/dnp3_experiment_harness

# 1. Compile-check all Python files
find . -name "*.py" -print0 | xargs -0 python -m py_compile

# 2. Check shell scripts
bash -n scripts/run_small_read_capture.sh
bash -n scripts/run_large_read_capture.sh
bash -n scripts/run_range_sweep.sh
bash -n scripts/run_replay_test.sh
bash -n scripts/run_split_replay_test.sh

# 3. Start outstation
python pydnp3_harness/experiment_outstation.py \
  --host 0.0.0.0 \
  --port 20000 \
  --local-addr 10 \
  --remote-addr 1 \
  --db-size 300 \
  --num-analog 200 \
  --num-binary 50 \
  --num-counter 50 \
  --apply-initial-values \
  --hold \
  --log-dir logs/outstation

# 4. In another terminal, capture traffic
sudo tcpdump -i <INTERFACE> -w captures/baseline/large_read.pcap 'tcp port 20000'

# 5. In another terminal, run master scan
python pydnp3_harness/experiment_master.py \
  --host <OUTSTATION_IP> \
  --local 0.0.0.0 \
  --port 20000 \
  --master-addr 1 \
  --outstation-addr 10 \
  --action scan-all-classes \
  --repeat 1 \
  --wait-after-action 5 \
  --csv logs/master/large_read_soe.csv \
  --log-dir logs/master

# 6. Extract payloads
python replay_tools/extract_dnp3_payloads.py \
  --pcap captures/baseline/large_read.pcap \
  --master-ip <MASTER_IP> \
  --outstation-ip <OUTSTATION_IP> \
  --port 20000 \
  --output-dir payloads/baseline

# 7. Map DNP3 fields
python replay_tools/dnp3_field_map.py \
  --payload payloads/baseline/resp_0001.bin \
  --output reports/field_map_results.md

# 8. Analyze TCP ACK behavior
python analysis_tools/analyze_tcp_ack_behavior.py \
  --pcap captures/baseline/large_read.pcap \
  --master-ip <MASTER_IP> \
  --outstation-ip <OUTSTATION_IP> \
  --port 20000 \
  --output-csv reports/tcp_ack_details.csv \
  --summary reports/tcp_ack_summary.csv
```

---

# Final Expected Outcome

At the end, the repository should provide a general DNP3 experiment harness that can:

1. Run a configurable pydnp3 outstation.
2. Run a controllable pydnp3 master.
3. Generate small and large READ/RESPONSE traffic.
4. Capture SOE values into CSV.
5. Capture PCAPs.
6. Extract raw TCP payloads.
7. Replay exact DNP3 responses from a socket server.
8. Split exact responses across multiple TCP writes.
9. Map DNP3 fields.
10. Analyze TCP ACK behavior.

Do not proceed to P4 or true DNP3 byte modification until the exact replay and split replay experiments are working.