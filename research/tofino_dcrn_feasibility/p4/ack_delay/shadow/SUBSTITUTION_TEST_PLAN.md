# dp8/Vision link — on-site controlled substitution test plan

Goal: determine whether the dp8 link fault follows the **Vision NIC**, the **DAC**, or the **switch
lane 15/0**. The dp8 probe (`dp8_link_probe_20260724.md`) could not isolate it; only physical
substitution can. **No replay traffic. No relay contact. No Vision reboot until these tests conclude.**

## Fixed identifiers (from `~/Projects/Tooling/tofino_25g_connectivity_map.md`)

| Element | Value |
|---|---|
| Vision NIC | `enp59s0f0np0`, MAC **3c:fd:fe:cc:5d:c0** (i40e) |
| Hulk NIC (known-good) | `enp59s0f0np0`, MAC **3c:fd:fe:e5:f9:90** (i40e) |
| **DAC-V** | the cable currently on Vision ↔ switch **15/0** |
| **DAC-H** | the cable currently on Hulk ↔ switch **15/1** (known-good) |
| Lane 15/0 → dev_port | **8 (dp8)** |
| Lane 15/1 → dev_port | **9 (dp9)** — known-good (Hulk links here) |
| Verified switch config (every test) | `25G / RS-FEC / PM_AN_DEFAULT / LPBK_NONE / ENABLE` |

## Roles per side

- **On-site (physical):** photograph original placement; move DACs/NICs per each test; restore after.
- **Me (switch + hosts, on your signal):** for each test I enable **only the target dev_port** with the
  verified config (`lane_probe.py add <dp>`), read switch + host state, then **remove** it
  (`lane_probe.py remove <dp>`) to restore the empty microbench `$PORT`. Host reads are `ethtool`
  (no sudo). I run nothing until you confirm the cable arrangement for that test is in place.

## Tests (each: arrange → tell me → I measure → restore)

| # | Physical arrangement | Switch lane / dp | I enable | Reads if it **LINKS** | Reads if it **FAILS** |
|---|---|---|---|---|---|
| 0 | Record + photograph original placement | 15/0=dp8 (V), 15/1=dp9 (H) | — | — | — |
| 2 | **Vision NIC** ↔ **DAC-H** ↔ **15/1/dp9** (Hulk unplugged) | 15/1 / **dp9** | dp9 | Vision NIC good → fault is **DAC-V or lane 15/0** | **Vision NIC** is the fault |
| 3 | **Hulk NIC** ↔ **DAC-V** ↔ **15/0/dp8** | 15/0 / **dp8** | dp8 | DAC-V + lane 15/0 good → fault is **Vision NIC** | **DAC-V or lane 15/0** is the fault |
| 4 | (if needed) **Hulk NIC** ↔ **DAC-V** ↔ **15/1/dp9** | 15/1 / **dp9** | dp9 | DAC-V good → fault is **lane 15/0** | **DAC-V** is the fault |

(Test numbering follows your message: 1 = record/photo, 2–4 = substitutions.)

## Interpretation matrix (combined)

- Test 2 links **and** Test 3 links → intermittent/seating; re-seat original and retest 15/0.
- Test 2 **fails** → **Vision NIC** faulty (good DAC + good lane still no link). (Tests 3/4 optional.)
- Test 2 links, Test 3 **fails**, Test 4 links → **switch lane 15/0** faulty (DAC-V proven good on 15/1).
- Test 2 links, Test 3 **fails**, Test 4 **fails** → **DAC-V** faulty.
- Test 2 links, Test 3 links → NIC, DAC-V, and lane 15/0 all good → original fault was seating; restore
  and re-run the dp8 probe to confirm carrier.

## Per-substitution record (I capture all of these each time)

NIC + MAC · DAC used (V/H) · switch lane + dev_port · switch `$PORT_ENABLE` (admin) · switch
`$PORT_UP` (oper) · host carrier (sysfs + `Link detected`) · negotiated speed (host + switch) · host
`Active FEC` + switch `$FEC` · link-training / FEC / signal counters where exposed (`$PORT_STAT`,
`ethtool -S`) · final restoration (port entry removed, `$PORT` empty, microbench operational).

## Safety / restore (every test)

- Only the single target dev_port is enabled, at the verified config; removed after the read.
- dp9 is not normally configured on the idle microbench, so a dp9 test entry is also removed after.
- No traffic is generated; the relay is never contacted; the shadow is never loaded.
- After the final test, physical cabling is restored to the original (15/0=Vision, 15/1=Hulk) and the
  queue microbench is confirmed operational with an empty `$PORT`.
- **Vision reboot stays unauthorized** until these tests identify NIC vs DAC vs lane.
