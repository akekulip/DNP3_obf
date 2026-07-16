# Phase 04 — EDT Load-and-Release Test

**Human-authorized 2026-07-16** ("run the EDT load-and-release test"). This is the behavioural
check the feasibility report requires *before* building the eBPF DNP3 state machine: prove that a
loaded tc-egress BPF program can set `skb->tstamp` and that `fq` enforces the earliest-departure
time on **this host**. It builds no DNP3 mechanism.

## Result: PASS (run by the PI as root, 2026-07-16)

The PI ran `sudo bash edt_test/run_edt_test.sh` (turnkey, netns-isolated). Outcome:

| Step | Outcome |
|---|---|
| Compile `edt.c` (sets `skb->tstamp = now + 30 ms` on egress) | **PASS** — valid eBPF ELF |
| Create isolated netns; add `fq` root + `clsact` | **PASS** |
| **Load the BPF program** (`tc filter add dev lo egress bpf da obj edt.o sec tc`) | **PASS** — loaded, JIT-compiled (`id 151`, `tag 91e7d05514c1c5f8`, `direct-action`) |
| Baseline ping RTT (no EDT) | 0.010 / **0.024** / 0.035 ms |
| Ping RTT **with EDT** (30 ms/egress → expect ~60 ms) | 60.051 / **60.069** / 60.079 ms |

**A loaded tc-egress BPF program set `skb->tstamp` and `fq` enforced it** — RTT rose from ~0.024 ms
to ~60.069 ms (30 ms on each of the request and reply egress). The BPF-written tstamp is honored
exactly like the `SO_TXTIME` one (no `mono_delivery_time` problem on this kernel). **The EDT
release primitive works on this host with a real loaded BPF program.**

**Benign warning:** `BTF debug data section '.BTF' rejected: Invalid argument (22)` — the old
iproute2 (ss200127) could not load the `-g` debug BTF section, but the program itself loaded and
JIT-compiled fine without it. Drop `-g` from the build (or update iproute2) to silence it; it does
not affect the EDT behaviour.

## Earlier finding (why this needed a privileged run)

Before the PI ran it, loading was blocked non-sudo:
- `kernel.unprivileged_bpf_disabled = 2` — unprivileged BPF loading is disabled and requires real
  `CAP_BPF`. (Mode 2 is not re-enablable without a reboot.)
- The non-sudo `unshare -rn` path grants full caps *inside the namespace*, but **loading a BPF
  program is a global operation**, not namespace-scoped — a user-namespace root does **not** hold
  real `CAP_BPF`, so `BPF_PROG_LOAD` returned `EPERM`. (This is the key difference from the netem
  smoke test: `tc`/netem is namespace-scoped and worked non-sudo; BPF loading is not.)
- Passwordless sudo is not available on this host (`sudo -n` → "a password is required").

So there is **no non-sudo path** to load a tc BPF program here, and I did not use sudo (standing
rule) or change the sysctl (state-changing, needs your decision).

## fq EDT enforcement half — VALIDATED non-sudo (via SO_TXTIME)

The mechanism has two halves: (1) a loaded BPF program **sets** `skb->tstamp`, and (2) `fq`
**enforces** that departure time. Half (2) can be tested without loading any BPF program, using the
unprivileged `SO_TXTIME` socket option to set the departure time instead — run in the same
`unshare -rn` netns (`edt_test/so_txtime_test.py`, `tc qdisc replace dev lo root fq`):

| packet | median arrival |
|---|---|
| no SO_TXTIME | **0.008 ms** |
| SO_TXTIME = now + 30 ms (`CLOCK_MONOTONIC`) | **30.034 ms** |

**`fq` holds the packet to the per-packet EDT tstamp on this host** (30 ms, exact). So the
enforcement primitive works, and the clock domain that works is `CLOCK_MONOTONIC` — the same clock
a BPF program would use (`bpf_ktime_get_ns()`).

## What this does and does not tell us

- The BPF program is correct and compiles; **`fq` EDT enforcement is proven** (SO_TXTIME, above).
- The one remaining unknown is whether a **BPF-written** `skb->tstamp` is honored the same as an
  `SO_TXTIME`-written one (a possible `mono_delivery_time` flagging nuance on 5.15). Because the
  clock domain and target field are identical, the residual risk is **low** — but it is unproven
  until the program is actually loaded, which needs BPF-load privilege.
- Net: the eBPF mechanism **cannot be loaded in the current non-sudo environment**, but the
  hard part it depends on (`fq` pacing by `skb->tstamp`) is confirmed to work here.

## Privilege note (for future eBPF runs)

Loading a BPF program needs real `CAP_BPF` on this host (`kernel.unprivileged_bpf_disabled = 2`,
mode 2 not re-enablable without a reboot), and `unshare -rn` cannot grant it because BPF loading is
a global operation. So each BPF-load run needs either a privileged invocation
(`sudo bash edt_test/run_edt_test.sh`, as done here) or a one-time `setcap cap_bpf,cap_net_admin+ep`
on a dedicated loader if repeated non-sudo loads are wanted for the prototype. `tc`/netem and
packet capture do **not** need this (they ran non-sudo via `unshare -rn` / `sg wireshark`).

## Status

EDT load-and-release test **PASS** (PI-run, 2026-07-16): a loaded tc-egress BPF program set
`skb->tstamp` and `fq` enforced the 30 ms departure time (RTT ~0.024 → ~60.069 ms). The
enforcement half was independently corroborated non-sudo via `SO_TXTIME` (same 30 ms hold). **The
EDT release primitive is confirmed on this host** — prerequisite (2) for the eBPF prototype is
**satisfied**. No DNP3 mechanism was built. `next_phase_allowed = false`; building the (narrowed-
scope) eBPF prototype still needs explicit PI authorization.

```
STOP: EDT load-and-release test PASSED; the eBPF prototype now needs only explicit PI build-authorization.
```
