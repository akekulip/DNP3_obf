# Inventory (builder v1.1, schema 1.1.0)

The full per-packet inventories (`<scope>_raw.{json,csv}`, `<scope>_analysis.{json,csv}`) are **large
(12–77 MB) and regenerable**, so they are `.gitignore`d. Regenerate:

```
$RESEARCH_PYTHON extract_inventory.py --scope all     # base + long + multicrob
```

Committed here: `inventory_summary.json` (compact — provenance, per-device role/ack-mode counts, size
histograms, corpus maxima) and this README.

- **RAW** = every DNP3 (TCP/20000) packet, nothing discarded, all TCP/IP/DNP3 metadata + flags.
- **ANALYSIS** = RAW minus flagged data-retransmissions / identical-capture duplicates (distinct pure
  ACKs kept). Documented dedup policy in each file's `provenance`.
- Canonical size = `ethernet_frame_bytes_no_fcs_min_applied` (pcaps are Ethernet, no captured FCS, no
  preamble/IFG; 60 B min-frame applied). Other size fields also recorded (`_with_fcs`,
  `wire_occupancy_…preamble_ifg`, `ip_total_length`, `tcp_payload_bytes`, `dnp3_payload_bytes`).
- `ack_mode_observed` is **per-transaction** (separate|combined|ambiguous|incomplete); the device label
  is provenance only. Fields per record: see `extract_inventory.py` (schema 1.1.0).
