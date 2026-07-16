# Phase 04 — EDT Load-and-Release Test

**Human-authorized 2026-07-16** ("run the EDT load-and-release test"). This is the behavioural
check the feasibility report requires *before* building the eBPF DNP3 state machine: prove that a
loaded tc-egress BPF program can set `skb->tstamp` and that `fq` enforces the earliest-departure
time on **this host**. It builds no DNP3 mechanism.

## Result: BLOCKED on BPF-load privilege (the test did its job — it caught this early)

| Step | Outcome |
|---|---|
| Compile `edt.c` (sets `skb->tstamp = now + 30 ms` on egress) | **PASS** — valid eBPF ELF, 6 instructions (`edt_test/edt.c`) |
| Add `clsact` qdisc in a user netns (`unshare -rn`) | **PASS** (namespace-scoped `CAP_NET_ADMIN`) |
| **Load the BPF program** (`tc filter add dev lo egress bpf da obj edt.o sec tc`) | **FAIL** — `Prog section 'tc' rejected: Operation not permitted (1)` |

**Why it's blocked, definitively:**
- `kernel.unprivileged_bpf_disabled = 2` — unprivileged BPF loading is disabled and requires real
  `CAP_BPF`. (Mode 2 is not re-enablable without a reboot.)
- The non-sudo `unshare -rn` path grants full caps *inside the namespace*, but **loading a BPF
  program is a global operation**, not namespace-scoped — a user-namespace root does **not** hold
  real `CAP_BPF`, so `BPF_PROG_LOAD` returns `EPERM`. (This is the key difference from the netem
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

## Options to unblock (a privilege/provisioning decision — analogous to the earlier `wireshark`-group grant)

1. **Run the turnkey test script once as root (RECOMMENDED, isolated):**
   `sudo bash reports/phases/phase_04/edt_test/run_edt_test.sh`. It compiles `edt.c`, creates a
   throwaway network namespace (no effect on the host loopback), loads the BPF program with `fq` +
   `clsact`, and pings to show whether `fq` enforces the BPF-set 30 ms EDT (RTT ~60 ms = PASS,
   ~0 ms = FAIL). Paste the output back and I'll interpret + record it.
2. **Persistent grant** (if you want the *upcoming* eBPF prototype work to load non-sudo too):
   `sudo setcap cap_bpf,cap_net_admin+ep` on a dedicated loader — heavier, leaves a capable binary
   on the system; only worth it for repeated loads, not this one test.
3. **Defer the eBPF path** and pursue the parts that need no BPF load first (e.g. the response-delay
   / gap-normalization directions the application already controls, or a `SO_TXTIME` userspace EDT
   check which is unprivileged for the socket side).

Note: flipping `kernel.unprivileged_bpf_disabled` back to 0 is **not** a clean option — it is
disabled in mode 2 and not re-enablable without a reboot, and tc `cls_bpf` needs `CAP_BPF`/
`CAP_NET_ADMIN` regardless.

## Status

EDT load-and-release test **partially complete**: the `fq` EDT **enforcement** half is **VALIDATED
non-sudo** (SO_TXTIME, 30 ms hold); the BPF **load** half is **BLOCKED on BPF-load privilege** and
needs one privileged run (`sudo bash edt_test/run_edt_test.sh`). The prerequisite is therefore
**not yet fully satisfied**, but the residual risk is low (only the BPF-written-tstamp path is
unproven, on a mechanism whose enforcement already works here). No DNP3 mechanism was built.
`next_phase_allowed = false`.

```
STOP: fq EDT enforcement proven non-sudo; the BPF-load half needs one sudo run (edt_test/run_edt_test.sh) or a defer decision.
```
