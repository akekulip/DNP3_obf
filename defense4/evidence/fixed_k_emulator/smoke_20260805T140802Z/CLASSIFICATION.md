# DEVELOPMENT SMOKE, NOT FORMAL CAMPAIGN-GATE EVIDENCE

**This directory is preserved UNCHANGED as historical development evidence. It is NOT a formal
round-cell campaign-gate capture.** (Marker added 2026-08-05 per review; no file here was deleted,
truncated, replaced, or retrospectively corrected.)

## Verified facts about this capture (grounded via tshark on the committed pcap)

- **The principal SBO flow is clean:** one connection setup, seven SBOs, one teardown, **zero RST**,
  and no TCP sequence gaps or overlaps — this is the valid development result (7/7 SUCCESS, wire-level
  decoy inertness, real actuation), and it is what `SMOKE_VERDICTS.txt` reports for the SBO flow.
- **The final PCAP contains 80 packets** (not the 78 quoted in the earlier RUN_LOG, which came from a
  separate throwaway loopback capture).
- **It contains four LATER SYN/RST pairs after the principal flow**, so the whole capture totals
  **5 initiating SYNs and 4 RSTs**. Those four extra SYN/RST pairs are subsequent loopback
  connection attempts to port 20000 (the `--host 127.0.0.1` no-comms guard probes run afterward),
  not part of the SBO transaction.
- **Cause:** the capture continued after the verdict because the `sg wireshark -c "dumpcap …"`
  wrapper was stopped by killing the wrapper without reliably SIGINT-ing and *waiting for* the actual
  `dumpcap` child. The formal campaign runner fixes this (process-group start, SIGINT `dumpcap`, wait
  for exit, confirm stable size+mtime, analyze only after closure, hash only when final).
- **The environment manifest records git commit `e878912`** (the state when the build command ran),
  **not** the later committed hardening state (`5dc6659` / `9ba9d6b`). A formal gate manifest pins the
  gate commit SHA and an empty `git status --porcelain`.

## Why it is not gate evidence
A formal round-cell PCAP must contain **exactly one** TCP connection to port 20000, with no extra
port-20000 flow, SYN, RST, premature FIN, retransmission, overlap, sequence gap, or post-analysis
packet. This capture has 4 extra SYN/RST flows, so it is rejected as a formal capture by the runner's
own acceptance rule — correctly. It remains valid **development** evidence for the hardened master,
the outstation evidence path, and wire-level decoy inertness.
