# Live inline demo: run it yourself

Drive the physical SEL-751 through the Tofino and watch the CLRT timing channel close.

Everything here runs **on Vision**. The Tofino keeps running `dnp3_timing_normalizer_inline`
between runs. You do not reload anything to switch between native and protected. The *only*
difference between the two runs is whether blocker tokens are injected.

```
Vision 192.168.10.1 ──25G── dp9 │ TOFINO │ dev_port 64 ──1G── unmanaged sw ──100M── SEL-751 .7
                                 dnp3_timing_normalizer_inline
```

## 0. One-time setup

```bash
ssh decps@10.10.54.166                 # Vision (use .166; .19 rides eno1 and is not reachable)
mkdir -p ~/dnp3_live && cd ~/dnp3_live
# copy poll.py, clrt.py, run.sh, status.sh, dnp3_crc.py here, then:
chmod +x run.sh status.sh clrt.py
```

## 1. Preflight: always run this first

```bash
./status.sh
```

Four checks: the inline program is loaded, the master leg is up, the relay answers **through the
Tofino**, and tcp/20000 accepts. If any says FAIL, stop and read §6.

## 2. Native run: the relay's true timing

```bash
./run.sh native
```

20 read-only Class-0 polls with nothing holding the response. Leaves `native.pcap`.
Expect `func=0x81` on every line and RTTs of roughly 1–5 ms.

## 3. Protected run: the hold armed

```bash
./run.sh protected
```

Same 20 polls, but each READ is immediately followed by 64 blocker tokens. Asks for your sudo
password (raw-socket injection needs root; the capture does not). Leaves `protected.pcap`.
Expect every RTT to land on **≈ G**.

## 4. Measure

```bash
./clrt.py native.pcap protected.pcap
```

CLRT is the interval between the relay's **pure TCP ACK** and its **DNP3 response**. That is exactly
what Formby's fingerprint keys on. What you should see: the median moves to G, and the **spread
collapses**. The spread is the whole point. The median only tells you where it collapsed to.

`clrt.py` prints three things: a strip plot of both runs on a **shared axis**, the **observer's
histogram at 1 ms bins** (what an attacker actually measures), and the **Shannon entropy** of that
histogram. Entropy 0 bits means every transaction looks identical, so the channel carries nothing.

Reference run (2026-07-25, G = 25 ms, n=13 each):

```
  native.pcap    |  @=  . .     .                                           .   |
  protected.pcap |                                       @                      |
                  -0.39                                                 38.66 ms

  native     sd 9.514 ms   6 bins occupied   entropy 2.035 bits
  protected  sd 0.029 ms   1 bin  occupied   entropy 0.000 bits   <- no information
             spread 329x tighter, range 36.155 ms -> 0.080 ms
```

> **The 37.2 ms native outlier matters.** In that native run one transaction took **37.215 ms**, which is
> *above* G = 25 ms. Had the hold been armed, that transaction would have passed through
> **unprotected, silently**. This is measured evidence that G = 25 ms is too small for this relay.
> See §7.

## 5. Watching it live in Wireshark

Start the GUI on Vision (the `wireshark` group already permits capture, no sudo needed):

```bash
wireshark -k -i enp59s0f0np0 -f "host 192.168.10.7 and tcp port 20000"
```

Then, to read the CLRT straight off the screen:

1. **Display filter:** `ip.src == 192.168.10.7`
   Now you only see packets *from the relay*, which alternate: a pure ACK (Length 0), then the
   DNP3 response (Length 54).
2. **View → Time Display Format → Seconds Since Previous Displayed Packet.**
3. The **Time value on each response row is the CLRT.**

Run `./run.sh native` in another terminal and the response rows jitter between ~0.001 and
~0.005 s. Run `./run.sh protected` and every response row pins to ~0.025 s. That is the defense,
visible without any analysis.

Useful extra filters:

| Filter | Shows |
|---|---|
| `ip.src==192.168.10.7 && tcp.len>0` | responses only |
| `ip.src==192.168.10.7 && tcp.len==0` | the separate pure ACKs |
| `tcp.analysis.retransmission` | should stay **empty**. If the hold exceeds the relay's RTO it shows up here first |
| `eth.type==0x88c1` | should stay **empty** on a host leg. Blocker tokens are internal and must never escape the switch |

Those last two are the checks that matter. The first tells you G is still inside the TCP budget; the
second is the isolation property.

## 6. If something fails

**`status.sh` says the inline program is not loaded.** Reload it on the switch:

```bash
ssh decps@10.10.54.81
sudo pkill -x bf_switchd
sudo setsid nohup bash /home/decps/timing_inline/launch_tn_inline.sh </dev/null >/dev/null 2>&1 &
sleep 45
# then re-apply ports + queues:
python3 /tmp/ibspg_paired_setup.py --prog dnp3_timing_normalizer_inline --config \
        --qb 7 --qh 1 --host-ports 9 --port-l 8 --pg-l 2
```

**Relay unreachable, or polls return 0 bytes.** The usual cause is that **dp8 is not configured**.
The held response is enqueued onto the dp8 loopback; if dp8 is absent the response is simply
lost, even though TCP looks perfectly healthy. Re-run the `ibspg_paired_setup.py` line above.

> **Do not** put `64` in `--host-ports`. That script forces host ports to 25G/RS-FEC and would
> knock the 1 G relay leg down. dev_port 64 is configured separately as
> `BF_SPEED_1G` / `BF_FEC_TYP_NONE` / `PM_AN_FORCE_DISABLE`.

**Everything looks right but protected matches native.** No tokens are reaching the ring. Check you
ran with `sudo`, and that `--iface` is the master leg (`enp59s0f0np0`).

## 7. Scope of the claim

This closes the **CLRT timing channel only**. Response *size*, ACK *mode*, and the TCP stack
fingerprint are untouched, so this is not device anonymity. It stops an observer from
identifying the device by how long it takes to answer, and nothing more.

**G must exceed the native CLRT, and this relay is spikier than it first looked.** A transaction
that natively takes longer than G passes through unprotected, and there is *no wire-visible
symptom*. The observer just sees one un-normalized sample. Measured native maxima so far:
**22.66 ms** (cold first poll) and then **37.22 ms** in an ordinary warm run. Against G = 25 ms the
second one would have escaped.

Two consequences:

1. **Raise G.** 40 ms covers everything observed so far, but only barely. Treat it as a floor rather than
   a comfortable margin until a long campaign characterises the tail.
2. **Always report the escape count.** A protected run is only meaningful if *zero* transactions had
   a native CLRT above G. The in-switch counters `ctr_response_zero_hold` (native >= G, nothing to
   hold) and `ctr_response_actually_held` are the authoritative check; a run with a non-zero
   zero-hold count must not be reported as fully protected.

The honest characterisation of the relay's tail is now the most valuable next measurement: a few
hundred native polls, so the p99 and the maximum are known rather than guessed.
