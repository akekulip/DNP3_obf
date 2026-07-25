# Version-correct DNP3 tshark fields (TShark 4.4.9, verified `tshark -G fields`)

Use these exact names in the Wireshark guide and analyzer cross-checks — do not invent field names.

| purpose | field |
|---|---|
| application function code (1=READ, 129=RESPONSE) | `dnp3.al.func` |
| application control byte (FIR/FIN/CON/UNS + seq) | `dnp3.al.ctl` |
| internal indications (IIN) | `dnp3.al.iin` |
| data-link primary function code | `dnp3.ctl.prifunc` |
| data-link direction / primary bits | `dnp3.ctl.dir`, `dnp3.ctl.prm` |
| transport control | `dnp3.tr.ctl` |

Display filters used in the guide:
- all DNP3-carrying TCP: `tcp.port == 20000`
- pure TCP ACK: `tcp.len == 0 && tcp.flags.ack == 1`
- retransmissions: `tcp.analysis.retransmission || tcp.analysis.fast_retransmission`
- DNP3 responses: `dnp3.al.func == 129`
