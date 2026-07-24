# Parser over-extraction root cause + fix (2026-07-24)

Stage-1 root-cause confirmation for the GATE-1 parser drop of DNP3 link-only control frames. Proven from
the captured packet + the frozen `dnp3_shadow.p4` parser source before any edit. Frozen file NOT modified.

## The dropped frame (measured)

| # | field | value |
|---|---|---|
| 1 | Ethernet header length | 14 B |
| 2 | IPv4 IHL | 5 (20 B, no IP options) |
| 3 | TCP dataOffset | 8 (32 B TCP header) |
| 4 | TCP-option length | 12 B |
| 5 | actual TCP payload length | **10 B** |
| 6 | DNP3 start bytes | `0x05 0x64` |
| 7 | DNP3 link length field | **5** (link-only: ctrl+dst+src, no user data) |
| 8 | DNP3 link header + CRC | 10 B total (`start(2)+len(1)+ctrl(1)+dst(2)+src(2)+crc(2)`); no user-data blocks, no block CRC |
| 9 | parser states entered | `start → parse_ethernet → parse_ipv4 → parse_tcp → parse_tcp_options → opt12 → parse_dnp3_dl → parse_dnp3_tp` |
| 10 | over-extraction | at `parse_dnp3_tp`: `pkt.extract(hdr.dnp3_tp)` after `dnp3_dl` (10 B) consumed the entire 10-B payload ⇒ 0 bytes remain ⇒ extract past end-of-packet |
| 11 | drop cause | parser **reject** (extract-past-end), not truncation/error-counter; the frame never reaches the MAU (class counter does not advance) |

Variable-length handling is correct: `parse_ipv4` selects on `ipv4.ihl` (only 5 descends), `parse_tcp`
gate uses `tcp.data_offset` and `parse_tcp_options` selects on it — so IP/TCP header lengths are honored.
The `parse_tcp` length gate (`total_len >= 30 + 4·data_offset`) guarantees only the **10-byte link header**
is present; it does NOT guarantee transport+application bytes. A link-only frame (length 5) passes that
gate, extracts `dnp3_dl`, then over-extracts `dnp3_tp`.

## Root cause (two parts)

1. **Parser:** `parse_dnp3_dl` transitions to `parse_dnp3_tp` whenever `start == 0x0564` (line 326),
   **without inspecting the link `length` field**. A link-only frame (length 5, no user data) therefore
   attempts to extract transport+app past end-of-packet → reject → drop.
2. **MAU:** even if the parser accepted a link-only frame (no `dnp3_app`), the classifier's final `else`
   (line 451-453) labels any payload-bearing DNP3-flow frame with an invalid `dnp3_app` as **MALFORMED** —
   it cannot distinguish a valid `0x0564` link-only frame from a genuine no-magic frame.

## Fix (minimal, in the hardened variant only)

1. **`parse_dnp3_dl`:** descend to `parse_dnp3_tp` only when `start==0x0564` AND `length >= 10` (the 5-byte
   link addressing + ≥5 user bytes = a full `dnp3_tp(1)+dnp3_app(4)`). A `0x0564` link-only/short frame
   (length ≤ 9) transitions to `accept` → forwarded unchanged, no over-extraction.
2. **MAU classify:** before the MALFORMED `else`, add: a valid `dnp3_dl` with `start==0x0564` (but no
   `dnp3_app`) → `CLASS_LINK_OTHER` (note = link-only), never MALFORMED, never dropped.

Result: link-only frames parse the link header, pass through **byte-identical**, classify as LINK_OTHER
(distinguishable from MALFORMED), and are forwarded. READ/RESP/ACK behavior is unchanged (length ≥ 10 for
READ len-11 and RESP; ACK payload 0). No packet bytes/lengths/options/seq/checksums/DNP3 content change.
