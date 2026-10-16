"""Inside `unshare -Urn`: how Linux (this kernel) treats an RST whose SEQ is exact-next, ahead-in-window, or behind."""
import os, socket, struct, subprocess, threading, time
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff

def tcp_rst(src, dst, sport, dport, seq, ack):
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x14, 0, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(hdr))
    return hdr[:16] + struct.pack('!H', csum(pseudo + hdr)) + hdr[18:]

def trial(label, seq_offset, payload=0):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(('127.0.0.1', 0)); srv.listen(1)
    sport = srv.getsockname()[1]
    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)); sniff.bind(('lo', 0)); sniff.settimeout(0.2)
    cli = socket.socket(); cli.connect(('127.0.0.1', sport)); conn, _ = srv.accept()
    cport = cli.getsockname()[1]
    if payload:
        conn.sendall(b'x' * payload); cli.recv(payload)
    time.sleep(0.05)
    # learn the client's RCV.NXT and SND.NXT from the last server->client and client->server segments
    srv_nxt = cli_nxt = None
    while True:
        try: f = sniff.recv(2048)
        except socket.timeout: break
        ip = f[14:]; ihl = (ip[0] & 15) * 4; tcp = ip[ihl:]
        sp, dp, seq, ack = struct.unpack('!HHII', tcp[:12]); flags = tcp[13]; plen = len(ip) - ihl - (tcp[12] >> 4) * 4
        syn = 1 if flags & 0x02 else 0
        if sp == sport and dp == cport: srv_nxt = seq + plen + syn
        if sp == cport and dp == sport: cli_nxt = seq + plen + syn
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw.sendto(tcp_rst('127.0.0.1', '127.0.0.1', sport, cport, (srv_nxt + seq_offset) & 0xffffffff, cli_nxt), ('127.0.0.1', 0))
    time.sleep(0.1)
    challenge = []
    while True:
        try: f = sniff.recv(2048)
        except socket.timeout: break
        ip = f[14:]; ihl = (ip[0] & 15) * 4; tcp = ip[ihl:]
        sp, dp, seq, ack = struct.unpack('!HHII', tcp[:12])
        if sp == cport and dp == sport and tcp[13] & 0x10 and not tcp[13] & 0x04:
            challenge.append(ack - srv_nxt)
    cli.setblocking(False)
    try:
        cli.recv(1); state = 'data?'
    except BlockingIOError: state = 'alive'
    except ConnectionResetError: state = 'RESET'
    try:
        cli.send(b'y'); sent = 'send ok'
    except OSError as e: sent = 'send ' + type(e).__name__
    print('%-34s rst seq = RCV.NXT%+d -> client %s, %s; challenge ACKs (ack - RCV.NXT): %s' % (label, seq_offset, state, sent, challenge))
    for s in (cli, conn, srv, sniff, raw): s.close()

trial('exact next', 0)
trial('ahead in window (+61, held image)', 61)
trial('ahead in window (+49, native resp)', 49)
trial('behind (-1)', -1)
trial('far outside window', 1 << 30)
