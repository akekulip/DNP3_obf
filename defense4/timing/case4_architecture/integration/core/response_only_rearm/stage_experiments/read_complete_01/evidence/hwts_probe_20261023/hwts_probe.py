"""NIC hardware-timestamp probe through the switch (PLAN.md). Runs on Vision as root (sudo -n python3).

  sudo -n python3 hwts_probe.py state                       # read-only: the NIC's current hardware-timestamp config
  sudo -n python3 hwts_probe.py probe --out RESULT.json     # save config, enable, 200 probes, restore, read back

The only setting changed is SIOCSHWTSTAMP on the parent NIC; the original is restored in a finally block and read
back, and the exit status is nonzero when the read-back differs from the original. All reported quantities are
differences within one clock: nic = hw_rx - hw_tx (one PHC), host = sw_rx - sw_tx (one system clock).
"""
import argparse
import ctypes
import fcntl
import json
import os
import select
import socket
import struct
import sys
import time

PARENT = 'enp59s0f0np0'
NS_TX, NS_RX = '/run/netns/ns_vepa_a', '/run/netns/ns_vepa_b'
SRC, DST, PORT = '192.168.10.61', '192.168.10.62', 319
SIOCSHWTSTAMP, SIOCGHWTSTAMP = 0x89b0, 0x89b1
HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_L4_EVENT = 1, 6
SO_TIMESTAMPING = 37
F_TX_HW, F_TX_SW, F_RX_HW, F_RX_SW, F_SW, F_RAW_HW = 1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 6
ISOLATED_GAP_S, BUSY_GAP_S, N_EACH = 0.200, 30e-6, 100


class HwtstampConfig(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_int), ('tx_type', ctypes.c_int), ('rx_filter', ctypes.c_int)]


def hwtstamp(sock, request, config=None):
    cfg = config or HwtstampConfig()
    ifreq = struct.pack('16sP', PARENT.encode(), ctypes.addressof(cfg)).ljust(40, b'\0')
    fcntl.ioctl(sock.fileno(), request, ifreq)
    return dict(flags=cfg.flags, tx_type=cfg.tx_type, rx_filter=cfg.rx_filter)


def set_config(sock, values):
    cfg = HwtstampConfig(values['flags'], values['tx_type'], values['rx_filter'])
    return hwtstamp(sock, SIOCSHWTSTAMP, cfg)


def stamps(ancdata):
    """(software ns, raw hardware ns) from an SCM_TIMESTAMPING message; 0 when absent."""
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPING and len(data) >= 48:
            s0, n0, _s1, _n1, s2, n2 = struct.unpack('6q', data[:48])
            return s0 * 10**9 + n0, s2 * 10**9 + n2
    return 0, 0


def in_netns(path, factory):
    own = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open(path, os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        return factory()
    finally:
        os.setns(own, os.CLONE_NEWNET)
        os.close(own)
        os.close(target)


def ptp_event(seq):
    """A 44-byte PTPv2 Sync message (event, version 2) so the NIC's PTP_V2_L4_EVENT receive filter stamps it."""
    header = struct.pack('!BBHBBHQ4s10sHBb', 0x00, 0x02, 44, 0, 0, 0, 0, b'\0' * 4, b'\0' * 10, seq & 0xffff, 0x00, 0x7f)
    return header + b'\0' * (44 - len(header))


def tx_stamps(sock, deadline):
    sw = hw = 0
    while time.monotonic() < deadline and not (sw and hw):
        if not select.select([sock], [], [], max(0.0, deadline - time.monotonic()))[0]:
            continue
        try:
            _data, anc, _flags, _addr = sock.recvmsg(256, 1024, socket.MSG_ERRQUEUE)
        except BlockingIOError:
            continue
        s, h = stamps(anc)
        sw, hw = sw or s, hw or h
    return sw, hw


def probe(out):
    ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    original = hwtstamp(ctl, SIOCGHWTSTAMP)
    record = dict(parent=PARENT, original=original, probes=[], started=time.time())
    restored, failure = None, None
    try:
        record['enabled'] = set_config(ctl, dict(flags=0, tx_type=HWTSTAMP_TX_ON,
                                                 rx_filter=HWTSTAMP_FILTER_PTP_V2_L4_EVENT))
        record['enabled_readback'] = hwtstamp(ctl, SIOCGHWTSTAMP)

        def receiver():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPING, F_RX_HW | F_RX_SW | F_SW | F_RAW_HW)
            s.bind((DST, PORT))
            return s

        def sender():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPING, F_TX_HW | F_TX_SW | F_SW | F_RAW_HW)
            s.bind((SRC, 0))
            return s
        rx, tx = in_netns(NS_RX, receiver), in_netns(NS_TX, sender)
        last_rx = time.monotonic() - 1.0
        for i in range(2 * N_EACH):
            mode = 'isolated' if i < N_EACH else 'busy'
            gap = ISOLATED_GAP_S if mode == 'isolated' else BUSY_GAP_S
            while time.monotonic() - last_rx < gap:
                pass
            silence_us = (time.monotonic() - last_rx) * 1e6
            tx.sendto(ptp_event(i), (DST, PORT))
            got = select.select([rx], [], [], 1.0)[0]
            row = dict(i=i, mode=mode, silence_before_us=round(silence_us, 1))
            if got:
                _data, anc, _f, _a = rx.recvmsg(256, 1024)
                last_rx = time.monotonic()
                row['sw_rx'], row['hw_rx'] = stamps(anc)
            else:
                row['lost'] = True
                last_rx = time.monotonic()
            row['sw_tx'], row['hw_tx'] = tx_stamps(tx, time.monotonic() + 0.2)
            if row.get('hw_rx') and row.get('hw_tx'):
                row['nic_us'] = (row['hw_rx'] - row['hw_tx']) / 1000.0
            if row.get('sw_rx') and row.get('sw_tx'):
                row['host_us'] = (row['sw_rx'] - row['sw_tx']) / 1000.0
            if 'nic_us' in row and 'host_us' in row:
                row['host_overhead_us'] = round(row['host_us'] - row['nic_us'], 3)
            record['probes'].append(row)
        if not any(p.get('hw_tx') for p in record['probes']) or not any(p.get('hw_rx') for p in record['probes']):
            failure = 'hardware timestamps absent on %s' % ('transmit' if not any(p.get('hw_tx') for p in record['probes'])
                                                             else 'receive')
    except Exception as error:                                     # restore below runs regardless
        failure = '%s: %s' % (type(error).__name__, error)
    finally:
        try:
            set_config(ctl, original)
            restored = hwtstamp(ctl, SIOCGHWTSTAMP)
        except Exception as error:
            restored = 'restore failed: %s: %s' % (type(error).__name__, error)
    record.update(restored_readback=restored, restore_ok=(restored == original), failure=failure, finished=time.time())
    with open(out, 'w') as stream:
        json.dump(record, stream, indent=1)
    print(json.dumps(dict(restore_ok=record['restore_ok'], original=original, restored=restored, failure=failure,
                          probes=len(record['probes']))))
    return 0 if record['restore_ok'] and not failure else (2 if not record['restore_ok'] else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('state', 'probe'))
    ap.add_argument('--out')
    a = ap.parse_args()
    if a.mode == 'state':
        print(json.dumps(hwtstamp(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SIOCGHWTSTAMP)))
        return 0
    if not a.out:
        ap.error('probe needs --out')
    return probe(a.out)


if __name__ == '__main__':
    sys.exit(main())
