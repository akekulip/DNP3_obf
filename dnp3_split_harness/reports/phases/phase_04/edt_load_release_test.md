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

## What this does and does not tell us

- The program is correct and compiles; the mechanism's *authoring* is fine.
- The `fq` EDT enforcement half (does `fq` honor a per-packet future `skb->tstamp`?) is **not yet
  proven** either — it needs the program loaded (or a userspace `SO_TXTIME` sender), so it is
  gated behind the same privilege wall.
- Net: the eBPF mechanism **cannot even be loaded in the current non-sudo environment.** This is a
  genuine environment blocker for the whole eBPF path — exactly what a load-and-release test is
  meant to surface before the DNP3 state machine is written.

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

EDT load-and-release test **attempted; BLOCKED on BPF-load privilege**. The eBPF prototype's first
prerequisite is therefore **not yet satisfied**. No DNP3 mechanism was built. `next_phase_allowed =
false`.

```
STOP: EDT load blocked on BPF privilege; awaiting your decision on how to grant it (or to defer the eBPF path).
```
