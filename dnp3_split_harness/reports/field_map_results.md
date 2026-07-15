# DNP3 Field Map

Source payload: `payloads/baseline/data_frame.bin` (292 bytes)

> Parsing covers the link header, header CRC, transport byte, and
> application header. Object decoding is limited to identifying the
> first object-header offset (group/variation), not full objects.

| offset | length | field | value | meaning |
|---|---|---|---|---|
| 0 | 2 | start | 0564 | DNP3 start bytes (expect 0564) |
| 2 | 1 | length | 255 | LEN: octets from control byte to last user byte (excludes CRCs) |
| 3 | 1 | link_control | 0x44 | DIR=0 PRM=1 FCB=0 FCV/DFC=0 func=0x4 (UNCONFIRMED_USER_DATA) |
| 4 | 2 | destination | 1 | DNP3 destination link address (little-endian) |
| 6 | 2 | source | 10 | DNP3 source link address (little-endian) |
| 8 | 2 | header_crc | 5aeb | Link header CRC-16/DNP (little-endian); verify=True |
| 10 | 1 | transport | 0x43 | FIN=0 FIR=1 seq=3 |
| 10 | 1 | transport_fir | 1 | Transport First fragment bit |
| 10 | 1 | transport_fin | 0 | Transport Final fragment bit |
| 10 | 1 | transport_seq | 3 | Transport sequence number (0-63) |
| 11 | 1 | app_control | 0xa3 | FIR=1 FIN=0 CON=1 UNS=0 seq=3 |
| 11 | 1 | app_fir | 1 | Application First fragment bit |
| 11 | 1 | app_fin | 0 | Application Final fragment bit |
| 11 | 1 | app_con | 1 | Application Confirm-requested bit |
| 11 | 1 | app_uns | 0 | Application Unsolicited bit |
| 11 | 1 | app_seq | 3 | Application sequence number (0-15) |
| 12 | 1 | function_code | 0x81 | Application function: RESPONSE |
| 13 | 2 | iin | 0200 | Internal Indications (response only); IIN1=0x02 IIN2=0x00 |
| 15 | 2 | object_header | g1v2 | First object header: group=1 variation=2 |
