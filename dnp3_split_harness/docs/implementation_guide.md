# DNP3 Replay/Split Experiment: No-IP Manual Command Version

## Purpose

This document updates the DNP3 replay/split experiment plan so the manual commands are short and do **not** require the user to type node IP addresses every time.

Claude Code must bake the lab node settings into the Python scripts or a small Python configuration module. The user should mainly run three simple files:

```bash
python run_outstation.py
python run_master.py
python split_server.py
```

The split server must replace the outstation during the replay/splitting experiment.

Do **not** use project-specific names such as GridCloak in the code, filenames, comments, logs, or README text. Keep the implementation general.

---

## 1. Core Research Goal

The goal is to validate whether a DNP3 master can accept a captured DNP3 READ response when the response is replayed and split by a simple TCP server.

The experiment has two major phases:

### Baseline phase

```text
Master  --->  Real pydnp3/OpenDNP3 Outstation
```

The master sends a READ request. The real outstation responds. We capture this traffic and extract the valid DNP3 response bytes.

### Replay/split phase

```text
Master  --->  TCP Replay/Split Server
```

The real outstation is stopped. The split server runs in its place on TCP port `20000`. The split server receives the master's READ request and sends back the previously captured DNP3 response bytes, either as one exact replay or split into smaller TCP chunks.

The first split experiment must preserve the exact DNP3 byte stream:

```python
b"".join(chunks) == original_response_bytes
```

No DNP3 fields should be modified in this phase.

---

## 2. Where the Split Server Sits

For the current experiment, the split server sits **where the outstation normally sits**.

It should not sit in the middle yet.

### Correct for this phase

```text
Master  --->  Split Server pretending to be Outstation
```

### Not yet

```text
Master  --->  Split Proxy  --->  Real Outstation
```

The proxy version can be implemented later after exact replay and split replay are proven.

---

## 3. Lab Configuration Must Be Baked Into the Python Project

Claude Code must remove long manual commands that require IP addresses.

Create this file:

```text
dnp3_experiment_harness/lab_config.py
```

Use this configuration pattern:

```python
"""
Lab-wide configuration for the DNP3 replay/split experiment.

Update these values once if the lab roles change.
Do not require the user to type IP addresses in manual commands.
"""

# Based on the latest captured DNP3 session:
# 10.10.54.19 used the ephemeral TCP client port, so it is the master.
# 10.10.54.158 listened on TCP/20000, so it is the outstation.
MASTER_IP = "10.10.54.19"
OUTSTATION_IP = "10.10.54.158"

# In the replay/split phase, the split server replaces the outstation.
SPLIT_SERVER_IP = OUTSTATION_IP

# Servers bind to all interfaces on their host.
BIND_IP = "0.0.0.0"

DNP3_PORT = 20000

# DNP3 link-layer addresses.
MASTER_LINK_ADDR = 1
OUTSTATION_LINK_ADDR = 10

# Default experiment behavior.
DEFAULT_RESPONSE_TIMEOUT_SEC = 2
DEFAULT_WAIT_AFTER_ACTION_SEC = 5
DEFAULT_SPLIT_MODE = "crc-boundary"
DEFAULT_CHUNK_DELAY_MS = 10

# Default local paths.
BASE_DIR = "dnp3_experiment_harness"
CAPTURE_DIR = "captures"
PAYLOAD_DIR = "payloads"
LOG_DIR = "logs"
REPORT_DIR = "reports"

# Default response payload path used by split_server.py.
DEFAULT_RESPONSE_PAYLOAD = "payloads/baseline/resp_0001.bin"

# For large response generation.
DEFAULT_DB_SIZE = 300
DEFAULT_NUM_ANALOG = 200
DEFAULT_NUM_BINARY = 50
DEFAULT_NUM_COUNTER = 50
```

Important: if the lab roles are reversed, the user should only edit `lab_config.py`, not every command.

---

## 4. Required Top-Level Runner Files

Claude Code must create these three simple top-level files:

```text
run_master.py
run_outstation.py
split_server.py
```

These files must import `lab_config.py` and run with no required command-line arguments.

Optional flags are allowed later, but the default behavior must work with:

```bash
python run_master.py
python run_outstation.py
python split_server.py
```

---

# 5. `run_outstation.py`

## Purpose

Start the real pydnp3/OpenDNP3 outstation for baseline traffic generation.

This file is used in the baseline phase only.

## Expected behavior

When the user runs:

```bash
python run_outstation.py
```

the script should:

1. read defaults from `lab_config.py`,
2. bind to `0.0.0.0:20000`,
3. start a DNP3 outstation with link address `10`,
4. expect master link address `1`,
5. create a large configurable database,
6. disable unsolicited responses by default,
7. disable controls by default,
8. apply deterministic measurement values,
9. hold until the user stops it with `Ctrl+C`.

## Required implementation details

Use the existing coding style from the uploaded scripts:

```python
import logging
import sys

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)
```

Use a class-based design.

Do not use project-specific branding.

## Outstation safety defaults

The outstation must use:

```text
allow_unsolicited = False
allow_controls = False
```

Control commands should return `NOT_SUPPORTED` unless explicitly enabled later.

## Manual command

```bash
python run_outstation.py
```

No IP address should be typed by the user.

---

# 6. `run_master.py`

## Purpose

Start the pydnp3/OpenDNP3 master and send a controlled READ request.

This same file is used in both:

1. baseline phase, where the real outstation is running,
2. replay/split phase, where the split server has replaced the outstation.

The master should always connect to `OUTSTATION_IP:20000` from `lab_config.py`. During replay, the split server runs at the same address/port as the outstation, so the master command does not change.

## Expected behavior

When the user runs:

```bash
python run_master.py
```

the script should:

1. read defaults from `lab_config.py`,
2. connect to `OUTSTATION_IP:20000`,
3. use master link address `1`,
4. target outstation link address `10`,
5. disable unsolicited responses if needed,
6. send one controlled READ action,
7. wait for responses,
8. write SOE output to CSV,
9. exit cleanly.

## Default READ action

Use a safe READ/RESPONSE action.

Preferred default:

```text
scan-all-classes
```

or a controlled Class 0/static scan if the harness supports it reliably.

Do not send DirectOperate, SelectAndOperate, ColdRestart, or other control commands by default.

## Output

Write logs and SOE output to:

```text
logs/master/
logs/master/soe.csv
```

## Manual command

```bash
python run_master.py
```

No IP address should be typed by the user.

---

# 7. `split_server.py`

## Purpose

Replace the real outstation with a TCP replay/split server.

This file should listen on TCP port `20000`, receive the master's READ request, and replay the captured DNP3 response bytes.

## Expected behavior

When the user runs:

```bash
python split_server.py
```

the script should:

1. read defaults from `lab_config.py`,
2. bind to `0.0.0.0:20000`,
3. load the default captured response payload from `DEFAULT_RESPONSE_PAYLOAD`,
4. accept a TCP connection from the master,
5. receive and save the READ request bytes,
6. split the response using the default split mode,
7. verify `b"".join(chunks) == original_response_bytes`,
8. send chunks in order,
9. keep the connection open,
10. receive and save any follow-up bytes such as DNP3 CONFIRM,
11. exit cleanly.

## Important

Before running `split_server.py`, the real outstation must be stopped because both need port `20000`.

## Manual command

```bash
python split_server.py
```

No IP address should be typed by the user.

---

## 8. Required Supporting Files

Although the user should mainly run three files, Claude Code should still implement clean reusable modules underneath.

Recommended structure:

```text
dnp3_experiment_harness/
│
│   # Flat, single-folder layout (2026-06-22). Each entry point is
│   # self-contained: at runtime it loads only itself + lab_config.py.
├── lab_config.py
├── run_master.py                 # self-contained master (class + visitors + CSV SOE + CLI)
├── run_outstation.py             # self-contained outstation (class + handler + CLI)
├── split_server.py               # self-contained request-aware split server (no pydnp3)
│
├── extract_payloads.py           # self-contained: PCAP -> raw DNP3 payloads + metadata.json
├── map_response.py               # self-contained: decode DNP3 header fields -> reports/
├── analyze_ack.py                # self-contained: TCP ACK behavior analyzer -> reports/
├── dnp3_crc.py                   # CRC-16/DNP helpers (used by map_response.py)
├── dnp3_crc_splitter.py          # standalone CRC-boundary splitter CLI
├── dnp3_replay_server.py         # exact verbatim replay server
├── dnp3_ordered_replay_server.py # positional/ordered confirm-aware server
├── legacy_single_response_server.py
│
├── captures/
│   ├── baseline/
│   ├── replay/
│   └── split/
│
├── payloads/
│   ├── baseline/
│   ├── replay/
│   └── split/
│
├── logs/
│   ├── master/
│   ├── outstation/
│   └── replay/
│
└── reports/
```

Top-level runner files should be short wrappers around reusable classes.

---

## 9. Baseline Workflow with Short Commands

The user should be able to run this manually.

### Terminal 1: on the outstation host

```bash
python run_outstation.py
```

### Terminal 2: on the master host

```bash
python run_master.py
```

### Optional packet capture

Packet capture may still require an interface name, but it must not require IP addresses.

If Claude Code creates a capture helper, it should also read IPs from `lab_config.py`.

A simple manual tcpdump command is acceptable:

```bash
sudo tcpdump -i <INTERFACE> -w captures/baseline/read_exchange.pcap 'tcp port 20000'
```

---

## 10. Replay/Split Workflow with Short Commands

### Step 1: stop the real outstation on the outstation host

```bash
sudo fuser -k 20000/tcp
```

### Step 2: start split server on the outstation host

```bash
python split_server.py
```

### Step 3: run master again on the master host

```bash
python run_master.py
```

The master still connects to the same outstation IP/port. It does not know the real outstation has been replaced by the split server.

---

## 11. Payload Extraction Should Also Avoid Manual IPs

Create a convenience file:

```text
extract_payloads.py
```

or make the existing extractor use `lab_config.py` by default.

The user should be able to run:

```bash
python extract_payloads.py
```

It should default to:

```text
captures/baseline/read_exchange.pcap
payloads/baseline/
MASTER_IP from lab_config.py
OUTSTATION_IP from lab_config.py
DNP3_PORT from lab_config.py
```

Optional CLI overrides are acceptable, but not required for normal use.

---

## 12. Field Mapping Should Also Be Short

Create:

```text
map_response.py
```

Default behavior:

```bash
python map_response.py
```

It should read:

```text
payloads/baseline/resp_0001.bin
```

and write:

```text
reports/field_map_results.md
```

---

## 13. TCP ACK Analysis Should Also Be Short

Create:

```text
analyze_ack.py
```

Default behavior:

```bash
python analyze_ack.py
```

It should read:

```text
captures/baseline/read_exchange.pcap
```

and write:

```text
reports/tcp_ack_details.csv
reports/tcp_ack_summary.csv
```

using IPs and port from `lab_config.py`.

---

## 14. Required Validation Logic in `split_server.py`

The split server must log and enforce these checks.

### Check 1: payload file exists

If `DEFAULT_RESPONSE_PAYLOAD` does not exist, print a clear error:

```text
Missing response payload. Run baseline capture and extract_payloads.py first.
```

### Check 2: split chunks preserve exact bytes

Before sending:

```python
joined = b"".join(chunks)
if joined != original_response:
    raise RuntimeError("Split chunks do not reconstruct the original response payload")
```

### Check 3: chunk summary

Print:

```text
Loaded response payload: N bytes
Split mode: crc-boundary
Chunk count: X
Chunk sizes: [...]
Byte-preservation check: PASS
```

### Check 4: connection behavior

Log:

```text
Listening on 0.0.0.0:20000
Accepted connection from <client>
Received READ request: N bytes
Sent chunk 1/X: N bytes
...
Waiting for follow-up data / DNP3 CONFIRM
Received follow-up bytes: N
Connection closed cleanly
```

---

## 15. Handling Multi-Fragment Responses and DNP3 CONFIRM

The captured response may contain more than one DNP3 application fragment.

In the observed PCAP, a typical flow may look like:

```text
Master:
READ Class 0

Outstation:
Response fragment group 1

Master:
DNP3 CONFIRM

Outstation:
Response fragment group 2
```

Therefore, `split_server.py` should support two modes.

### Simple mode

Send one response payload file:

```text
resp_0001.bin
```

Use this first.

### Confirm-aware mode

Later support:

```text
resp_frag1.bin
resp_frag2.bin
```

Workflow:

```text
send fragment 1 chunks
wait for master confirm bytes
send fragment 2 chunks
wait and close
```

If confirm-aware mode is not implemented immediately, the README must clearly state that the first milestone uses simple exact response replay.

---

## 16. Coding Style Requirements

Follow the style of the uploaded scripts:

- module-level `_log`,
- stdout logging format with tabs,
- class-based wrappers,
- docstrings,
- explicit `main()`,
- pydnp3 imports where needed,
- practical comments only.

Do not rewrite the project into a different style.

Do not make deeply abstract frameworks.

Keep the files readable and close to the original pydnp3 examples.

---

## 17. What Not To Do

Do not:

- require the user to type IP addresses in manual commands,
- use project-specific branding,
- run real outstation and split server on port `20000` at the same time,
- make the split server sit in the middle yet,
- implement P4,
- send DirectOperate as baseline traffic,
- send SelectAndOperate as baseline traffic,
- append random bytes as padding,
- modify DNP3 length fields in this phase,
- recalculate CRCs in this first phase,
- assume TCP ACK means DNP3 accepted the response,
- close the replay socket immediately after sending,
- ignore DNP3 CONFIRM behavior,
- delete original scripts without archiving them.

---

## 18. Success Criteria

The implementation is successful when the user can do the following with short commands.

### Baseline

```bash
python run_outstation.py
python run_master.py
```

This should produce:

```text
logs/master/soe.csv
baseline PCAP if capture is running
```

### Extraction

```bash
python extract_payloads.py
```

This should produce:

```text
payloads/baseline/resp_0001.bin
payloads/baseline/metadata.json
```

### Split replay

```bash
sudo fuser -k 20000/tcp
python split_server.py
python run_master.py
```

This should produce:

```text
logs/replay/
logs/master/soe.csv or split_soe.csv
```

### Verification

The split replay is accepted only if:

1. `split_server.py` confirms byte preservation,
2. master logs show no DNP3 parser/CRC errors,
3. SOE output matches baseline,
4. Wireshark shows valid DNP3 decoding/reassembly,
5. DNP3 CONFIRM appears if it appeared in the baseline.

---

## 19. Final Manual Commands Section

After Claude Code implements and checks the code, the manual commands shown to the user should look like this.

### Baseline experiment

On the outstation host:

```bash
cd dnp3_experiment_harness
python run_outstation.py
```

On the master host:

```bash
cd dnp3_experiment_harness
python run_master.py
```

Optional capture:

```bash
sudo tcpdump -i <INTERFACE> -w captures/baseline/read_exchange.pcap 'tcp port 20000'
```

Extract payloads:

```bash
python extract_payloads.py
```

Map response fields:

```bash
python map_response.py
```

Analyze ACK behavior:

```bash
python analyze_ack.py
```

### Split replay experiment

On the outstation/replay host:

```bash
cd dnp3_experiment_harness
sudo fuser -k 20000/tcp
python split_server.py
```

On the master host:

```bash
cd dnp3_experiment_harness
python run_master.py
```

Compare outputs:

```bash
cat logs/master/soe.csv
ls -lh logs/replay/
```

No command above should require the user to type master, outstation, or split-server IP addresses.

---

## 20. Final Expected Outcome

At the end, the repository should provide a general DNP3 experiment harness where:

- `run_outstation.py` starts the real outstation,
- `run_master.py` sends controlled READ traffic,
- `split_server.py` replaces the outstation and replays/splits captured response bytes,
- IPs and DNP3 link addresses are baked into `lab_config.py`,
- manual commands are short,
- original byte preservation is enforced,
- no P4 or proxy logic is implemented prematurely.
