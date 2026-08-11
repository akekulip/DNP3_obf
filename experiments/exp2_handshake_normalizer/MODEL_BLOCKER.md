# Experiment 2B — model gate: BLOCKED_ENVIRONMENT (proven)

The tofino-model + bf_switchd + PTF functional run **cannot be executed in this environment**, and
this was established by making the minimal model program fail in a way that proves the required
component is genuinely unavailable — not by stopping at a setup step.

## Proof (exact commands + logs preserved in `evidence/model/`)

1. **The model binary itself needs elevated privileges and cannot get them.** A direct launch:
   ```
   tofino-model -c build/handshake_normalizer.conf --p4-target-config build/handshake_normalizer.conf
   ```
   fails (exit 1) with:
   ```
   capset: Operation not permitted
   tofino-model: Unable to drop privileges to purely CAP_NET_RAW
    PRIVS: Eff=0x00000000 Perm=0x00000000 Inh=0x00000000
   ```
   The process has **no capabilities** (`Eff=0x0`) and cannot obtain `CAP_NET_RAW`, which the model
   requires to do raw packet I/O. (`evidence/model/model_direct.log`.)

2. **The veth network PTF needs does not exist and cannot be created without root.**
   - `ip link show | grep -c veth` → **0** veth interfaces present.
   - `ip link add name vprobe0 type veth peer name vprobe1` → `RTNETLINK answers: Operation not
     permitted` (rootless).
   - `sudo -n /home/philip/bf-sde-9.13.1/install/bin/veth_setup.sh` → `sudo: a password is required`
     (sudo is interactive; no non-interactive path in this session).

Both the packet-I/O capability and the interface fabric require root, which is unavailable to this
non-interactive session. This is the "minimal model program fails, proving the component is
unavailable" condition the authorization set for `BLOCKED_ENVIRONMENT`.

## The one-line unblock (mechanical root prep, not a re-authorization)

The model gate becomes runnable the moment the interfaces exist and the stack runs with privileges.
In a session where Philip can grant sudo, run (via the `!` prefix, which executes in this session):

```bash
! sudo /home/philip/bf-sde-9.13.1/install/bin/veth_setup.sh
```

then bring up the stack (each needs sudo for `CAP_NET_RAW`):

```bash
SDE=/home/philip/bf-sde-9.13.1
sudo -E $SDE/run_tofino_model.sh -c experiments/exp2_handshake_normalizer/build/handshake_normalizer.conf &
sudo -E $SDE/run_switchd.sh      -c experiments/exp2_handshake_normalizer/build/handshake_normalizer.conf &
# after switchd WARM_INIT completes:
sudo -E $SDE/run_p4_tests.sh -p handshake_normalizer -t experiments/exp2_handshake_normalizer/tests/ptf
```

The program's tables use `const entries`, so no runtime table programming is needed — loading the
program is sufficient. Expected results are pinned by the offline oracle (`tests/oracle.py`,
27/27), which computes the golden output packets the PTF cases compare against.

## What was done in place of the model run (all runnable without root)

- Compiled the final source clean (`evidence/compile_*`, `source.sha256`).
- Ran the offline oracle over the full 27-case matrix (`evidence/oracle_results.txt`, **27/27**):
  every specified output is a well-formed packet with valid IPv4 + TCP checksums, seq/ack/window are
  never modified, and every fail-open case keeps the entire TCP header byte-identical. The oracle
  **caught a real safety defect** (a first fragment, MF=1 offset 0, would have been parsed and
  normalized) which was fixed in the parser gate before this evidence was recorded.

The oracle proves the **specification** is coherent and safe; it does not prove the **compiled
datapath** matches — that is exactly what the (blocked) model run remains responsible for.
