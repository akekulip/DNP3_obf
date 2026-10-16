# Support scripts cited by the 2026-10-16 traces (directive ba50eac69)

- `rst_linux.py` — run with `unshare -Urn python3 rst_linux.py`. It shows how this host's Linux (5.15) treats an RST
  that is exact-next, ahead inside the window, behind, or far outside the window. The result, as measured on
  2026-10-16:
  - only an RST at RCV.NXT resets the connection;
  - one ahead inside the window draws a challenge ACK;
  - the others are ignored.
  The `transform_e_m8` docstring in `../../generate.py` cites it.
- `request_busy_drop_recovery.py` — run from `../../tests`. It is the source replay behind
  `../model_control_timing_m7_03_02/TRACE_operate_dupack.md`: an outstation ACK that arrives before the OPERATE's
  normalize lap returns busy-drops the request, and the master's retransmission is then relayed, on m6 and m7 alike.
  This is not a dataplane wedge.
