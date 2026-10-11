# hw_vepa campaign tooling — pinned dependencies

What the campaign tooling and the software endpoints depend on, pinned so a run is reproducible. The
per-run evidence additionally binds the source commit, the generated P4, both binaries/contexts, the
BFRT schema and the per-block table readbacks (see `run.py`, `campaign.py` and `switch.json`); this file
pins the things that live outside the run directory.

## OpenDNP3 (software endpoints)

- Commit **`4648fcb898456d1cb70b5baecc38cc256c859c2e`** (ChargePoint/opendnp3 fork).
- The `master` / `outstation` endpoint binary (`case4_socket_gate_pad58b`, run by `vision_run.py`) is built
  against this exact commit. Its SHA-256 and the SHA-256 of its `lib/` are recorded in the run manifest;
  do not substitute a differently built binary without updating that manifest.
- Keep this commit unless an explicitly tested new dependency replaces it, in which case record the new
  commit here and in the run manifest.

## Python

- Floor: **Python 3.8** (the version the test suite runs under; `python3 --version` = 3.8.10 on this host).
- The analyzers `wire_check.py` and `clrt_check.py` and the orchestrators `run.py` / `vision_run.py` use
  the **standard library only** — `struct`, `json`, `argparse`, `pathlib`, `statistics`, `re`, `subprocess`.
  They do **not** require scapy any more: the pcap reader, the IP/TCP checksum and the DNP3 CRC are all
  built in, which is what lets the tests run under a plain `python3 -m pytest`.
- `run.py` invokes the analyzers through `$RESEARCH_PYTHON` when set (the Python 3.12 research venv,
  `~/.venvs/research/bin/python`); because the analyzers are stdlib-only, the system `python3` runs them
  identically. See `requirements.txt`.

## Host tools (Vision, under sudo)

`vision_run.py` shells out to these; they are provided by the OS, not pip:

- `tcpdump` — the two per-run captures (`-Q out` / `-Q in`) and their drop statistics.
- `iproute2` — `ip netns exec`, `ip route`, `ss`, `tc` (the Case-A netem/quickack emulation).
- `ethtool` — the `disable-source-pruning` private flag on the parent NIC.
- `procps` `sysctl` — the namespace TCP profile, written with readback.

## Switch tools

`switch_slot.py` / `switch_counters.py` and the composite installer run under the proprietary SDE Python on
the switch (owned by the hw/ installer, not pinned here). The compiler identity, both binaries/contexts and
the BFRT schema are bound per run by the composite installer and carried into the run identity.
