#!/usr/bin/env python3
"""
shadow_raw_replay.py — dependency-free (stdlib AF_PACKET) L2 frame replayer for the GATE-1
shadow-classifier validation. Reads a classic pcap and transmits each frame VERBATIM out --iface.

Hosts have no scapy/tcpreplay and decps cannot open raw sockets, so this mirrors the established
mb_gen_raw.py pattern: AF_PACKET SOCK_RAW needs root -> run under sudo. It sends the captured
Ethernet frame unchanged (the NIC appends the FCS); the passive shadow forwards it dp8<->dp9
without modification, so byte identity is preserved end to end.

Usage (on the injecting host, as root):
    sudo python3 shadow_raw_replay.py --iface enp59s0f0np0 --pcap dp8_inject.pcap --pace-ms 2

--pace-ms spaces frames so the far-side capture keeps up (1211 frames is tiny; any small gap is
safe). Nothing about the frame bytes is altered; only the inter-frame gap is added.
"""
import argparse, socket, struct, time, sys

PCAP_MAGIC_US = 0xa1b2c3d4      # microsecond classic pcap
PCAP_MAGIC_NS = 0xa1b23c4d      # nanosecond classic pcap


def read_pcap_frames(path):
    """Yield raw frame bytes from a classic pcap (little- or big-endian, us or ns). Ethernet only."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("pcap too short for global header")
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "<"
        else:
            magic = struct.unpack(">I", gh[:4])[0]
            if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                endian = ">"
            else:
                raise ValueError("not a classic pcap (bad magic 0x%08x); pcapng is unsupported" % magic)
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype != 1:
            raise ValueError("linktype %d != 1 (Ethernet); refusing" % linktype)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            _ts, _us, incl, _orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield data


def main():
    ap = argparse.ArgumentParser(description="stdlib AF_PACKET pcap replayer (root).")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--pace-ms", type=float, default=2.0, help="inter-frame gap in ms (default 2)")
    ap.add_argument("--count-limit", type=int, default=0, help="0 = all frames")
    args = ap.parse_args()

    frames = list(read_pcap_frames(args.pcap))
    if args.count_limit:
        frames = frames[:args.count_limit]

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((args.iface, 0))
    gap = args.pace_ms / 1000.0
    sent = tot = 0
    for fr in frames:
        s.send(fr)
        sent += 1; tot += len(fr)
        if gap > 0:
            time.sleep(gap)
    s.close()
    print("replayed %d frames (%d bytes) on %s from %s" % (sent, tot, args.iface, args.pcap))


if __name__ == "__main__":
    main()
