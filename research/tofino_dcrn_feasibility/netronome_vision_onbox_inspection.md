# Netronome on Vision — on-box hardware inspection (2026-07-21)

Live read-only inspection of the Netronome SmartNIC physically installed in **Vision** and cabled
to **Hulk** over SFP. Answers: *can this card run the full DNP3 obfuscation harness (timing + size
+ split together) — the thing the Tofino-1's 12-stage pipeline cannot?* All commands were
non-destructive (`lspci`, `ethtool`, `ip`, sysfs reads); nothing was reloaded or reconfigured.

## What is physically present (root-confirmed via `dmesg`, `lspci -vv`, `ethtool -m`)
| Property | Measured value | Source |
|---|---|---|
| Chip | **Netronome NFP-4000** (`Model 0x62000010`) | `dmesg`: "NFP4000/NFP5000/NFP6000 PCIe Card Probe" |
| Card assembly | **`SMCAMDA0097-000117291655-13`** = **Agilio CX 2×40GbE** | `dmesg` Assembly line |
| Serial / BSP | SN `00:15:4d:13:4e:e4`, BSP `01020d.01020d.01030d` | `dmesg`, PCIe DSN cap |
| Loaded firmware | **`nic_AMDA0097-0001_8x10.nffw`**, VER `0.0.3.5`, max MTU 9216, 8 Tx/RxQ per port | `dmesg` FW-load lines |
| PCIe | **Gen3 x4 = 31.5 Gb/s** — card is **x8-capable (63 Gb/s) but slot-downgraded to x4** | `dmesg`, `LnkCap x8 / LnkSta x4 (downgraded)` |
| Ports | 2 physical QSFP+ (p0, p1), each 4×10G lanes = 8 netdevs | `phys_port_name`, `dmesg` renames |
| Cable to Hulk | **40G QSFP+ `40GBASE-CR4` direct-attach copper** (10.3 Gb/s/lane) | `ethtool -m` |
| **Live link to Hulk** | lane **`enp59s0np1s3` UP @ 10 Gb/s**, IP `192.168.100.1/24` ↔ Hulk `192.168.100.2`, **RTT 0.32 ms** | `ip -br link`, `ethtool`, `ping` |
| DNP3 data route | `192.168.100.2 dev enp59s0np1s3` — Vision↔Hulk data path now rides the NFP DAC (no longer the Tofino) | `ip route get` |

NFP-4000 datasheet class: ~60 flow-processing cores (5 islands × 12), 8 HW threads each, ~800 MHz;
IMEM ~4 MB, EMEM ~2 GB DRAM-backed. (`nfp-hwinfo` for the on-card exact counts is unavailable —
BSP userspace not installed; the driver reports card identity but not the ME inventory.)

## Software state — the crux
| Layer | State | Consequence |
|---|---|---|
| Driver | in-tree mainline `nfp` (kernel 6.8.0-134) | basic NIC + limited offload only |
| **Firmware personality** | **`nic`** (`0.0.3.5 0.31 nic-2.1.16.1 nic`) | card runs as a **plain 10G NIC** |
| TC/flower HW offload | `hw-tc-offload: off [fixed]` | no offload under the `nic` personality |
| Firmware blobs on disk | **`bpf/` and `flower/` present** in `/lib/firmware/netronome/` | a personality swap needs **no download** |
| **Agilio P4C / Micro-C SDK / BSP userspace** | **ABSENT** (no `nfp-hwinfo`, `nfp4build`, `p4c-nfp`, `/opt/netronome`) | **no custom datapath is buildable today** |
| Unrelated load | Docker (streambert, adguardhome) on `docker0`/bridges — **not** on the NFP | NFP link is dedicated to the rig |

## Verdict — can it run the full obfuscation harness?

**Hardware capability: YES.** The NFP-4000 is run-to-completion and multithreaded with GBs of
packet-addressable memory — there is **no 12-stage MAU wall**. Timing-hold + size-padding + split
become sequential code plus per-flow state, which is exactly the co-residency the Tofino-1 cannot
achieve. The architectural argument from the feasibility study is confirmed against the card that
is physically in the rack.

**Runnable today, as provisioned: NO — blocked on one software dependency, not on hardware.**
- The core primitive is the **timed hold** (park a frame; release on event or at a deadline). On
  the NFP that means holding a packet descriptor in a memory ring and releasing it from a
  timer-polling thread — expressible **only** via the **Agilio P4C SDK + Micro-C sandbox**, which
  is **not installed**. This is the single gating item.
- The on-disk **bpf firmware** would enable XDP/eBPF **offload** after a personality swap, but
  offloaded XDP actions are DROP/PASS/TX/REDIRECT — **all immediate**. There is **no
  deferred-transmit / timer helper** in the offloaded eBPF path, so the ms-hold **cannot be
  expressed in offloaded eBPF** even after swapping firmware. Offload can do stateful
  match/rewrite (useful for size-pad prep and classification) but not the hold — insufficient
  alone.
- **Works today with no SDK:** use the NFP as the plain 10 G wire to Hulk and run the hold on the
  **Vision host CPU** (the eBPF-EDT prototype already proven, or an AF_XDP/userspace
  bump-in-the-wire). Because the DNP3 master runs **on Vision** and the Hulk link **terminates on
  the NFP inside Vision**, a host-side hold on Vision's Hulk-facing path **is** on the Hulk→master
  data path. That reproduces Case A/B end-to-end over the real SFP link now — but it is host-CPU
  timing, not on-silicon.

## Recommended next steps (ranked; non-disruptive first)
1. **Confirm the inventory** — `sudo dmesg | grep -i nfp` + `apt install nfp-bsp` (gives
   `nfp-hwinfo`): exact AMDA assembly, ME/core count, memory sizes. Read-only, ~5 min.
2. **Acquire Agilio P4C SDK 6.0** (P4-16 + Micro-C) from Corigine — the **only** gating
   dependency for the on-NIC hold. Card, driver, firmware blobs, and the live link are already in
   place. (Vendor-risk caveat from the study stands: Corigine, proprietary toolchain, Tofino P4
   does not port — you rewrite the hold in Micro-C.)
3. **Now, in parallel:** run the host-CPU bump-in-the-wire on Vision using the NFP SFP as the wire
   to Hulk — reproduce Case A/B with the eBPF-EDT hold on `enp59s0np1s3`. Proves the defense over
   the real link today and becomes the apples-to-apples baseline for the on-NIC version.
4. **Do NOT swap firmware to bpf/flower** to chase offload: it would drop the live
   `192.168.100.1↔.2` rig link **and** still cannot express the hold. Not worth it.

## Safety notes
- `enp59s0np1s3` is the **live Vision↔Hulk data link**. Any `nfp` module reload / firmware
  personality change **drops that link** and disrupts the rig — gated, not done here.
- Inspection was entirely read-only; the card, its firmware, and the Docker workloads are untouched.
