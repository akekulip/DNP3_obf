# Hulk staging and capability state — pre-pilot

2026-07-29. No password requested, stored or used at any point.

## Injector built and in place

| Item | Value |
|---|---|
| Path | `/home/decps/fqo/oracle_inject` |
| Build | `gcc -Wall -Wextra -Werror -O2 -std=c11 -D_GNU_SOURCE` — clean, zero warnings |
| Size | 26008 bytes |
| sha256 | `3d85b4a2d44aea68f18deb03b4950576d338e7221e4c3f0914b2b61ddbb4234d` |
| Capabilities | **none yet** (`getcap` empty) |

## Capability detection verified live on Hulk

```
$ ./oracle_inject --iface enp59s0f0np0 --trial-id 0 \
      --schedule ABLOCK:64,HELD_ACK:1,RBLOCK:64,HELD_RESP:1 --seed 1
oracle_inject: cannot open an AF_PACKET raw socket on 'enp59s0f0np0': Operation not permitted
oracle_inject: this binary needs the CAP_NET_RAW capability and does not have it.
oracle_inject: grant it ONCE, on this host, with exactly:

    sudo setcap cap_net_raw+ep /home/decps/fqo/oracle_inject

EXIT=77
```

It reports the exact absolute path and exits 77. It does not attempt sudo, does not retry, and
does not fall back to any privileged path. Acceptance criterion 7 is therefore verified against
the real binary on the real host, not asserted.

## Capture side — ALREADY SATISFIED, no action needed

```
$ getcap /usr/bin/dumpcap
/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
$ groups | grep wireshark
wireshark
```

`dumpcap` already carries `cap_net_admin,cap_net_raw=eip` and `decps` is already a member of the
restricted `wireshark` group — exactly the configuration specified. The earlier `TODO(silicon) 17`
concern about capture privileges is **closed**; no further change is required for capture.

## Remaining blocker — one command, on Hulk

```
sudo setcap cap_net_raw+ep /home/decps/fqo/oracle_inject
```

Verify with `getcap /home/decps/fqo/oracle_inject` → expect `cap_net_raw=ep`.

**A rebuild replaces the file and drops the capability.** If `make` is ever re-run, `setcap` must
be re-applied. The runner re-checks the capability at the start of every run and fails with the
instruction rather than proceeding.

## Note on the data link

`enp59s0f0np0` on Hulk is currently `DOWN / NO-CARRIER` because dp11 is not configured on the
switch. The pilot runner configures dp11 at 25 G as part of its setup, and returns dp11 to its
original unconfigured state during restore.
