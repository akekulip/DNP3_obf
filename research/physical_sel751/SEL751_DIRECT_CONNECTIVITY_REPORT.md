# SEL751_DIRECT_CONNECTIVITY_REPORT.md

**Phase 5 — physical SEL‑751 direct connectivity (via the normal lab switch, Tofino NOT inline).**
Date: 2026‑07‑23. Master = Vision. Relay = physical SEL‑751. No Tofino, no controls, no config change.

## ✅ RESOLVED (2026-07-23, second attempt) — native Class-0 transaction captured
The **previous TCP churn (below) was caused by the relay's DNP3 master-IP allowlist mismatch**: the
relay is allowlisted to master **`DNPIP1 := 192.168.10.1`**, but Vision was at `.100` — so the relay
accepted each TCP handshake and then immediately closed it (relay-initiated FIN), which in turn drove
the opendnp3 default auto-retry to reconnect ~55×/s. It was the allowlist, not addressing or the
network. After moving Vision to **192.168.10.1** and using the relay's real **outstation
address 0** (not 10), with a **no-retry single-connect** probe, the poll SUCCEEDED:
- **ONE TCP session** (1 SYN, 0 RST, 0 retransmit); stable channel; clean FIN teardown at shutdown.
- Master `1` → outstation `0`: one Class-0 **READ** (18 B, link_func 4, FIR=FIN=1, CON=0) → **separate
  pure TCP ACK** → **RESPONSE** (134 B wire / 115 B DNP3 link frame, **single fragment** FIR=FIN=1,
  CON=0, **69 measurements** decoded).
- **Case A CONFIRMED** — separate pure ACK, then response. **No application CONFIRM** transmitted
  (response CON=0, so none was requested — matches the safety rule). No control/write, one READ only.
- **Timing (this single transaction):** request→pure-ACK **0.91 ms**; **pure-ACK→response CLRT
  6.12 ms**; request→first-response **7.03 ms**. *Single sample* — the ~13 ms figure in the meeting was
  the cluster from the original traces; a live CLRT **distribution** needs repeated Class-0 polls (not
  yet authorized — this run was one poll).
- Evidence: `evidence/native_class0_v2.pcap`, `native_probe_v2.out`, `native_class0_v2_soe.csv`.
  Probe: `native_class0_probe.py` (now .1 / outstation 0 / no-retry).
- **State:** Vision left at **192.168.10.1/24** (the relay's configured master). Relay was READ-only
  from our side (its DNP3 settings were set by the user in QuickSet, not by us). Tofino untouched.

**Phase-5 tasks 9–14 now satisfied:** valid Class-0 READ → response from outstation 0 to master 1;
separate pure-ACK behavior confirmed; CLRT measured (single sample); response size + fragment structure
recorded; TCP options/flags/seq in pcap; no control/write; one session, no RST, no retransmit.

---
_The v1 finding below is retained for the record — it documents the allowlist diagnosis that led here._

## Result in one line
The SEL‑751 is **network‑reachable and its TCP stack is healthy, but it refuses to hold a DNP3
session** for this master: it accepts the TCP handshake on 20000 and then **closes the connection
itself (~1.9 ms later, relay‑initiated FIN) without exchanging a single DNP3 byte.** No native DNP3
transaction was obtained. This is a relay‑side session policy, not a network fault.

## Reachability — Phase‑5 tasks 1–8 (PASS)
| item | value | how |
|---|---|---|
| SEL‑751 IP / mask | **192.168.10.7 / 24** | user‑supplied prior IP, confirmed on wire |
| MAC / vendor | `00:30:A7:02:4C:A2` — **Schweitzer Engineering** | ARP reply, nmap OUI |
| L2 / L3 | ARP ✓, ping ✓ (0% loss, TTL 255, ~0.4 ms) | from Vision `192.168.10.100/24` on eno1 |
| TCP 20000 | **listening** (completes handshake) | SYN→SYN‑ACK→ACK, 434× |
| DNP3 link addrs (from `Traffic Trace/SEL751.pcap`) | outstation **10**, master **1** | tshark on original capture |
| switch | TP‑Link TL‑SG1024S — **unmanaged, flat, no VLANs** | photos + capture |

The earlier "can't find it" was because the relay is **silent on an unpolled DNP3 port** and sits on
`192.168.10.0/24`, off the lab `10.10.54.0/24` subnet — not a VLAN/port problem (the switch has none).

## The native Class‑0 poll attempt — tasks 9–14 (DNP3 session FAILED)
Probe: purpose‑built `native_class0_probe.py` with **every automatic behaviour pinned OFF**
(no startup integrity poll, no ENABLE/DISABLE unsolicited, `timeSyncMode=None`, `ignoreRestartIIN=True`
so no restart‑IIN clearing WRITE), one intended session, master 1 → outstation 10, response timeout 5 s.

**What actually happened (pcap `native_class0.pcap`, 2602 TCP pkts / 40 s capture):**
- Per connection: `VIS SYN → relay SYN‑ACK → VIS ACK` (handshake OK) → **`relay FIN,PSH,ACK`** →
  `VIS FIN,ACK`. The relay closes it.
- **relay SYN‑ACK → relay FIN delay: n=427, min 0.79 ms, median 1.92 ms, max 17.72 ms.**
- **DNP3 `0x0564` payloads sent: 0 in BOTH directions.** The master never got a stable session to
  send the Class‑0 READ; the relay never sent DNP3. SOE decoded = 0 (header‑only CSV).
- TCP options — Vision SYN: `MSS 1460, SAckOK, TS, WScale 7`; relay SYN‑ACK: `MSS 1460, WScale 0,
  SAckOK, TS` (healthy, normal negotiation).
- 7 RSTs, all relay‑originated (connection cleanup). No Vision‑side RST.

## Honest disclosure — TCP‑level reconnect churn (constraint deviation)
The probe used opendnp3's **default `ChannelRetry`**, which auto‑reconnected every time the relay
closed the session: **434 SYNs in ~7.9 s ≈ 55 connections/s.** This **exceeded the "use one TCP
session" instruction** — unintended (the relay's immediate close drove opendnp3's retry loop), and it
stopped the instant the probe shut down (no churn after `16:20:37`). **Mitigating fact: zero DNP3
application bytes were transmitted** — no READ, no control, no WRITE, nothing — so every DNP3‑content
safety rule (no SELECT/OPERATE/DIRECT‑OPERATE/WRITE/time‑sync/unsol/config) held. **Fix for any
retry:** a no‑retry / single‑connect transport (raw one‑shot socket, or a `ChannelRetry` with a very
long minimum) so a relay‑close cannot trigger reconnection.

## Success‑condition scorecard
- TCP connection established — **YES** (repeatedly).
- One valid Class‑0 READ sent — **NO** (relay closed before the app layer could transmit).
- Response from addr 10 → master 1 — **NO** (no DNP3 at all).
- No control/write transmitted — **YES / CORRECT** (0 DNP3 bytes).
- No TCP reset — partial: 7 relay‑originated RSTs (cleanup), no Vision RST.
- Complete PCAP + decoded transaction — PCAP complete; **no transaction to decode.**
- Separate pure‑ACK / CLRT confirmed — **UNDETERMINED** (relay never spoke DNP3).

Per instruction: stopped after the one attempt; **did not guess another link address** (addressing is
moot — the failure is below the DNP3 layer).

## Diagnosis (most→least likely) — needs the relay's config to resolve
1. **DNP3 not enabled / no DNP3 session bound on this Ethernet port** for this connection (port
   accepts TCP, no protocol accepts the session → immediate close).
2. **Master‑IP restriction** in the relay's DNP3 settings — `192.168.10.100` isn't the allowed master.
3. **Single active session already held** by the production master → new connections refused.
All three are readable/settable only from the relay config (AcSELerator QuickSet / front panel), which
is **not installed yet**. Addressing (outstation 10) was never reached and is not implicated.

## Next steps (gated)
- Get the relay's **DNP3 settings**: is a DNP3 session enabled on this port, what **master IP** (if
  any) is allowed, and is a session already open. Needs AcSELerator/console.
- If a specific master IP is required, set Vision's temp IP to that value and retry **once** with a
  **no‑retry single‑connect** probe.
- Do **not** re‑probe until the config question is answered (avoid further TCP churn).

## State / evidence
- Vision temp IP **`192.168.10.100/24` left in place** on eno1 (per instruction, until verified —
  evidence now copied+verified; retained for a possible one‑shot retry, remove on request).
- Relay untouched (no config change, no DNP3 request ever sent). Tofino untouched.
- Evidence in `research/physical_sel751/evidence/`: `native_class0.pcap`, `native_probe.out`,
  `native_probe.err`, `native_class0_soe.csv` (header‑only), `native_tcpdump.log`. Probe script:
  `native_class0_probe.py` (in scratch; pinned‑safe config).
