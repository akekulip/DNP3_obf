# Port-role dependency audit — for the dp11/dp9 topology remap (2026-07-24)

Fault isolated to lane 15/0 (dp8). Authorized role-based remap: **master/Vision ingress = dir 0 = dp11**,
**outstation/Hulk ingress = dir 1 = dp9**. This audit lists every place a physical dev_port is bound to a
role, so the remap touches the minimum and the frozen baselines are copied (not edited in place).

## Where the topology is bound

| File | Binding | Role | Action for dp11/dp9 |
|---|---|---|---|
| `dnp3_shadow.p4:56` | `PORT_VISION = 9w8` | master / dir 0 | **variant copy** → `9w11` |
| `dnp3_shadow.p4:57` | `PORT_HULK = 9w9` | outstation / dir 1 | unchanged (9) |
| `dnp3_shadow.p4:385` | `dir = 0 iff ingress==PORT_VISION` | direction gate | derives from the constant — no edit |
| `dnp3_shadow.p4:457-460` | fwd: ingress==PORT_VISION→PORT_HULK else→PORT_VISION | forwarding | derives from constants — no edit |
| `dnp3_shadow_setup.py:38` | `PORT_VISION,PORT_HULK = 8,9` | bring-up loop | **parameterize** `--master-port/--outstation-port` (default 8/9) + `--program` |
| `gate1_run.py:40` | `PORT_VISION,PORT_HULK = 8,9` | precondition + orchestration | **parameterize** `--master-port/--outstation-port` |
| `shadow_read_counters.py:21` | `PORT_VISION,PORT_HULK = 8,9` | port-stat read | **parameterize** ports |
| `dcrn_defense1.p4:62-63` | `PORT_VISION=9w8, PORT_HULK=9w9` | Defense-1 (Stage 8) | **variant copy** → `9w11` |
| `dcrn_defense2.p4:75-77` | `PORT_VISION=9w8, PORT_HULK=9w9, PORT_RECIRC=9w68` | Defense-2 (Stage 8) | **variant copy** → master `9w11`; recirc 68 unchanged |

## Where there is NO topology binding (no change needed)

- `verify_shadow_run.py` — classifies/labels direction by **TCP port** (dst/src 20000) and by which
  inject/capture file, NOT by dev_port. The `--dp8-inject` arg name is a label for the master-side half;
  its content (master→outstation frames) is injected from Vision→dp11 unchanged. No topology edit.
- `shadow_refmodel.py` — direction-agnostic (classifies by TCP port). No dev_port.
- `gate1_validator_selftest.py` — operates on pcaps only. No dev_port.
- `lane_probe.py` — dev_port is a CLI argument already (`add/read/remove <dev_port>`). Works for dp11.
- `PORT_RECIRC` (defenses) = dp68, an internal pipe-0 recirc port — unaffected by the host-lane remap.

## Net change set

1. **New variant P4 (copy, frozen originals untouched):** `dnp3_shadow_dp11_dp9.p4` (`PORT_VISION 9w8→9w11`).
   Later Stage 8: `dcrn_defense1_dp11_dp9.p4`, `dcrn_defense2_dp11_dp9.p4`.
2. **Parameterize (in place, defaults preserve dp8/dp9):** `dnp3_shadow_setup.py`, `gate1_run.py`,
   `shadow_read_counters.py` — accept role-port args; the GATE-1 precondition checks the SELECTED ports.
3. **No change:** verify/refmodel/validator/lane_probe (direction is TCP-port- or arg-driven).

Only the `PORT_VISION` constant carries the master-facing dir-0 binding; changing it to `9w11` (in a copy)
plus the parameterized bring-up is sufficient and role-consistent. `PORT_HULK=9` and `dir` semantics are
unchanged.

## Stage-3 offline regression (before any load) — PASS

- **Compile (local bf-p4c 9.13.1):** frozen `dnp3_shadow.p4` and `dnp3_shadow_dp11_dp9.p4` both exit 0,
  0 errors, 2 benign TNA parser warnings each.
- **Resource parity:** stage count, RAMs, TCAM (0), hash, crossbar **identical**; the ONLY delta is a
  couple of action-data bytes at stage 2 — the expected consequence of the `PORT_VISION` immediate
  changing 8→11. Shadow uses 4/12 ingress (unchanged).
- **Structural diff variant vs frozen:** ONLY the banner comment + the `PORT_VISION` constant differ. The
  direction gate (`dir=0 iff ingress==PORT_VISION`), the READ/RESP classification (`READ` needs dir 0,
  `RESP` needs dir 1), and the forwarding are byte-identical to the silicon-validated frozen file.
- **Direction semantics (structural + design):** port 11 → dir 0; port 9 → dir 1; an **unrelated** ingress
  port → dir 1 (else branch) → can only match `DNP3_RESP` (func 129 + src 20000), **never** `DNP3_READ`
  (which requires dir 0). So no unrelated port is silently assigned a valid READ role.
- **Topology-independent offline tests (unchanged, re-run):** shadow refmodel replay PASS (300/300),
  14/14 negatives, GATE-1 validator self-test PASS.
- **TNA-specific limitation (documented):** the physical-direction gate (`dir` from `ingress_port`) cannot
  be executed off-switch (no TNA model); it is verified structurally here and confirmed empirically on
  silicon in GATE-1 Stage 5 (READs injected from dp11 must classify as `DNP3_READ`=dir 0).

**Cleared to load** (all offline regression passed).
