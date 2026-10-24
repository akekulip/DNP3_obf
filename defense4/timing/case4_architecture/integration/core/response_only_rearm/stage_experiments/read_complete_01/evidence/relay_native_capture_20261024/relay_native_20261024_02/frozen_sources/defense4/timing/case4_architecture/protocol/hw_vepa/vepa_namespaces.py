#!/usr/bin/env python3
"""Rebuild Vision's two VEPA endpoint namespaces after a reboot (run on Vision: sudo python3 vepa_namespaces.py).

The state is the one recorded in protocol/evidence/hw_vepa_padding_01/state/vision_state_20261011.txt:
macvlans in VEPA mode on the switch-facing XXV710 port, mvA (ns_vepa_a, .61) and mvB (ns_vepa_b, .62)
with fixed MACs and permanent ARP entries for each other, and 192.168.10.1/24 on the parent. The TCP
profile sysctls and the NIC source-pruning flag are not set here: vision_run.py setup applies and
checks them on every block and restore puts them back.

    sudo python3 vepa_namespaces.py --check     # report only, change nothing; exit 1 if anything differs
    sudo python3 vepa_namespaces.py             # create what is missing, idempotent
"""
import subprocess
import sys

PARENT = 'enp59s0f0np0'
PARENT_ADDR = '192.168.10.1/24'
ENDPOINTS = (('ns_vepa_a', 'mvA', 'd2:9d:1d:1c:f4:dd', '192.168.10.61'),
             ('ns_vepa_b', 'mvB', 'ee:df:16:18:b0:a5', '192.168.10.62'))


def run(*cmd, check=True):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=check)


def ns(name, *cmd, check=True):
    return run('ip', 'netns', 'exec', name, *cmd, check=check)


def differences():
    out = []
    if run('ip', 'link', 'show', PARENT, check=False).returncode:
        return ['parent %s is absent (NIC not detected)' % PARENT]
    if PARENT_ADDR.split('/')[0] + '/' not in run('ip', '-br', 'addr', 'show', PARENT).stdout:
        out.append('parent lacks %s' % PARENT_ADDR)
    names = run('ip', 'netns', 'list').stdout.split()
    for (space, ifc, mac, addr), (_, _, peer_mac, peer) in zip(ENDPOINTS, reversed(ENDPOINTS)):
        if space not in names:
            out.append('namespace %s is absent' % space)
            continue
        link = ns(space, 'ip', '-d', 'link', 'show', ifc, check=False)
        if link.returncode or mac not in link.stdout or 'macvlan mode vepa' not in link.stdout or 'state UP' not in link.stdout:
            out.append('%s/%s is not an UP VEPA macvlan with MAC %s' % (space, ifc, mac))
        if addr + '/24' not in ns(space, 'ip', '-br', 'addr', 'show', check=False).stdout:
            out.append('%s/%s lacks %s/24' % (space, ifc, addr))
        neigh = ns(space, 'ip', 'neigh', 'show', peer, check=False).stdout
        if peer_mac not in neigh or 'PERMANENT' not in neigh:
            out.append('%s lacks the permanent ARP entry %s -> %s' % (space, peer, peer_mac))
    return out


def build():
    if run('ip', 'link', 'show', PARENT, check=False).returncode:
        sys.exit('parent %s is absent (NIC not detected); nothing changed' % PARENT)
    run('ip', 'addr', 'replace', PARENT_ADDR, 'dev', PARENT)
    names = run('ip', 'netns', 'list').stdout.split()
    for (space, ifc, mac, addr), (_, _, peer_mac, peer) in zip(ENDPOINTS, reversed(ENDPOINTS)):
        if space not in names:
            run('ip', 'netns', 'add', space)
        if ns(space, 'ip', 'link', 'show', ifc, check=False).returncode:
            run('ip', 'link', 'add', ifc, 'link', PARENT, 'address', mac, 'type', 'macvlan', 'mode', 'vepa')
            run('ip', 'link', 'set', ifc, 'netns', space)
        ns(space, 'ip', 'link', 'set', 'lo', 'up')
        ns(space, 'ip', 'addr', 'replace', addr + '/24', 'dev', ifc)
        ns(space, 'ip', 'link', 'set', ifc, 'up')
        ns(space, 'ip', 'neigh', 'replace', peer, 'dev', ifc, 'lladdr', peer_mac, 'nud', 'permanent')


def main(argv):
    if '--check' not in argv:
        build()
    missing = differences()
    for line in missing:
        print('DIFF ' + line)
    print('vepa namespaces: ' + ('as recorded' if not missing else '%d difference(s)' % len(missing)))
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
