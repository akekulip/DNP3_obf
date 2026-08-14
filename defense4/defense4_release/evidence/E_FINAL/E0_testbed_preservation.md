# E0 — testbed preservation record
captured: (session 2026-08-13)
## SHAs
- branch/source SHA (repo HEAD): c18713840e8376c065909749d451a6bc9e6c5c4d
- unified P4 source sha256: 7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861
- loaded conf: conf-file /home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel_abs.conf
- loaded tofino.bin sha256: 33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa  (expect 33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa)
## Topology / port map (ONE physical Tofino, unchanged across baseline & defended)
- master = Vision 192.168.10.1 (MAC 3c:fd:fe:cc:5d:c0) on switch dp9
- relay  = physical SEL-751 192.168.10.7 (MAC 00:30:a7:02:4c:a2) on switch dp64, link master=1/outstation=0
- dp8  = RRC internal loopback (size carve/CLRT domain)   [switch-internal, NOT an inline device]
- dp10 = BOR internal loopback (OPERATE hold domain)      [switch-internal, NOT an inline device]
- dp64 = relay release port (switch -> SEL-751)
- dp68 = internal pktgen/recirc + clone-mirror (PORT_PGEN=68) [NOT a host-capturable relay-facing tap]
## Policies
- A = 20 ms (T0->ACK release), R = 24 ms (T0->echo release), R-A = 4 ms
- J codebook: fixed passes {2,6,12} ms; randomized {2,4,6,8,10,12} ms
## Safety / rollback
- TCP timestamps: net.ipv4.tcp_timestamps=0 (0=off for defended timing measurement; original=1)
- relay outputs: all_open=True closed=[]
- rollback: /home/decps/rrc_bor_build/rollback_rrc.sh (snapshot-driven, restores proven RRC defense4_rrc.conf)
- watchdog: /home/decps/rrc_bor_build/watchdog_rrc.sh
## dp68 limitation (load-bearing for the claim matrix)
dp68 is the internal pktgen/recirc/clone port, not a capturable relay-facing tap; no NIC is cabled to capture it
(Vision/Hulk spare NICs all NO-CARRIER). Relay-facing T0+J evidence is therefore NOT available -> PARTIAL.
