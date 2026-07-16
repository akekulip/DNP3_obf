---
name: pydnp3-install
description: How to install a working pydnp3 for the DNP3 harness (PyPI package is broken on Python 3)
metadata: 
  node_type: memory
  type: project
  originSessionId: a1652c5e-2f90-4c4f-9658-90a51824211e
---

On philip's machine (Ubuntu 20.04, Python 3.8.10), `pip install pydnp3` installs
the abandoned Kisensum `pydnp3 0.1.0`, whose `src/asiodnp3/ConsoleLogger.h`
hardcodes `#include <python2.7/Python.h>` — it CANNOT build for Python 3.

Working install = build the maintained ChargePoint fork from source:
```bash
git clone --recursive --depth 1 https://github.com/ChargePoint/pydnp3.git
cd pydnp3 && python setup.py build && python setup.py install --user
```
It compiles the full OpenDNP3 stack (~minutes) + a pybind11 binding. Needs
`cmake`, `g++`, `make`, and `python3.8-dev` headers (all present on this box).
Result lands in `~/.local/lib/python3.8/site-packages/pydnp3-0.1.0-*.egg` and
`from pydnp3 import opendnp3, openpal, asiopal, asiodnp3` then works.

**Known runtime quirk:** pydnp3 double-frees its C++ objects during interpreter
teardown (`free(): double free detected`, exit 134) even after a clean
`DNP3Manager.Shutdown()`. The harness entrypoints work around this by calling
`os._exit(0)` after the orderly shutdown — see [[dnp3-harness-verified]].

**Python 3.12 (Vision/Hulk, Ubuntu 24.04):** the bundled pybind11 (Kisensum
fork) FAILS to compile on 3.12 — uses removed internals (`PyFrameObject` now
opaque, `PyThreadState.frame` gone). Fix: replace `deps/pybind11` with modern
pybind11 (v2.13.6 works) before `setup.py build`; the ChargePoint binding code
compiles clean against it. Built on Vision (has python3.12-dev), then the egg
was copied to Hulk (identical R440/Ubuntu24.04/py3.12 — runtime needs no
-dev headers, no build, no sudo). Egg lives at
`~/.local/lib/python3.12/site-packages/pydnp3-0.1.0-py3.12-*.egg` registered via
`easy-install.pth`.
