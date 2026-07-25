# Physical SEL-751 — timing and size tested with the real relay

**2026-07-25.** The physical relay was brought into a live DNP3 session and both axes were tested
against its real traffic. `[OBS]` measured, `[FIX]` corrected defect, `[OPEN]` unresolved.

## Connectivity — two root causes solved (was blocked since 2026-07-23)

`[FIX]` **Source-IP allowlist:** connect from `192.168.10.1`, not `.100`, and the relay stops
self-FINning — it holds the connection and TCP-ACKs the READ.
`[FIX]` **Link address:** the relay's outstation address is **0, not the corpus's 10** (found
read-only via a Request-Link-Status scan). Re-addressed READ → live 54-byte function-129 responses.
Full detail: `evidence/relay_live/RELAY_CONNECTIVITY_SOLVED.md`.

## Live device characterization `[OBS]`

30 read-only polls of the physical relay, captured on Vision:

- **Separate-ACK device** — it emits a pure TCP ACK then its data response, so it has a CLRT and the
  IBSPG timing normalizer applies.
- **Native CLRT: p50 2.075 ms, sd 2.199 ms, range 7.61 ms, 28 distinct values over 30 polls** — a
  real, varying device fingerprint.
- **`data_offset = 8` (RFC 7323 TCP timestamps)** — the framing the ICS panel predicted, now confirmed
  on the live device.

## Timing — TESTED WITH THE RELAY'S REAL FRAMING, and it works `[OBS]`

The relay's real frames — byte-for-byte, `data_offset = 8` preserved, only the Ethernet MACs
rewritten for the Tofino path — were driven through the loaded timing normalizer (`ibspg_dnp3`,
G = 25 ms), two-sided (READ from Vision/dp9, ACK+RESPONSE from Hulk/dp11), 30 transactions.

**Classification on the real framing:** `arm=30, ack_arm=30, ack_bypass=0, resp_enq=30,
resp_release=30`. Every real relay READ (function 1), pure ACK, and RESPONSE (function 129) was
classified correctly **despite `data_offset = 8`** — the classifier's length-gate covers TCP header
depths 5–8, so the relay's timestamps do not defeat it. `reg_gen` tracked the real DNP3 application
control byte (0xC0…0xCF).

**Normalization:**

| | native (live device) | defended (real frames through Tofino) |
|---|---:|---:|
| CLRT p50 | 2.075 ms | 24.997 ms |
| CLRT sd | 2.199 ms | **0.0066 ms** |
| CLRT range | 7.61 ms | 0.031 ms |

**Standard deviation collapses 334×.** All 1,920 blocker tokens terminated on the deadline
(`ctr_block_term_deadline=1920`, `timeout=0`, `stale=0`). The relay's real timing fingerprint is
replaced by a policy constant.

> Honesty note: the separate `relay_before` (bypass) replay collapses the ACK→response gap to ~0.03 ms
> because the injector sends the ACK and response back-to-back, so it is **not** a faithful native
> baseline. The faithful native fingerprint is the **live device capture** (`relay30.pcap`, sd 2.199 ms)
> used in the table above; `relay_before` only confirms the bypass path forwards without holding.

## Size — TESTED WITH THE RELAY, and confirmed not closable this way `[OBS]`

The live device uses **`data_offset = 8`** on every frame. The egress size normalizer is built for
`data_offset = 5`, so on the real relay it cannot fire — confirmed now on the live device, not just
the corpus. And extending the table to `data_offset = 8` does not rescue it: the panel synthesis and
the silicon falsification already established that trailer padding normalizes `frame.len` while
leaving `ipv4.total_len` (which every observer and this project's own Zeek pipeline reads) untouched,
so it closes nothing regardless of `data_offset`. Worse, keying the current table on `pkt_length`
while the parser gates on `data_offset` would pad the relay's frames mid-datagram — a corruption
hazard, not a defense. `[OPEN]` Closing the relay's size channel requires the byte-modifying
prepend-with-sequence-translation construction, scoped separately.

## What was and was not done

- **Live physical relay:** read-only DNP3 polling only (Class-0 READ, Request-Link-Status, telnet
  status). No SET, control, SBO, WRITE, link reset, or retry storms. The relay was never placed inline
  behind the Tofino — it is on the unmanaged lab switch — so its bytes were captured live and then
  replayed through the Tofino with their real framing preserved. Inserting the relay physically inline
  needs re-cabling and remains a gated hardware step.
- **Timing:** proven on the relay's real `data_offset = 8` framing, sd 2.199 → 0.0066 ms.
- **Size:** confirmed not closable by the transparent-padding mechanism; the reason is the same on the
  live device as it was on the corpus.

## Artifacts

`evidence/relay_live/` — `relay30.pcap` (30 live polls), `live.pcap`, `poll.pcap`, `relay_after.pcap`
(defended, real frames through the Tofino), the switch counter reads, `relay_e2e_summary.json`, and
`figures/`. Builders: `build_relay_frames.py`; read-only probes in `harness/`.
