# Experiment 1 — corpus manifest

Authoritative captures, read-only in the frozen Defense 4 repository
(`/home/philip/Projects/DNP3` at `7c4a5a7`). Originals are never modified; only paths and SHA-256 are
recorded. Machine-readable form: `out/corpus_manifest.json`.

## Multi-device fingerprint corpus (`Traffic Trace/`)

| Device | File | SHA-256 (first 16) | TCP sessions | TCP packets | DNP3 coverage |
|---|---|---|---:|---:|---|
| SEL751 | SEL751.pcap | `519cae47ea3863ea` | 2 | 2104 | READ, SELECT, CONFIRM |
| SEL751 | SEL751L.pcap | `be6159026c1b4fff` | 2 | 28007 | READ, SELECT, CONFIRM |
| ION7550 | ION7550.pcap | `f41681a631ed08ef` | 2 | 4904 | READ, CONFIRM |
| ION7550 | ION7550L.pcap | `69c9dcf9c2ccf012` | 2 | 24097 | READ, CONFIRM |
| AB1400 | AB1400.pcap | `01dceb19965f42fe` | 2 | 2407 | READ, SELECT, CONFIRM |
| AB1400 | AB1400L.pcap | `7c631744fe5d1f77` | 2 | 12007 | READ, SELECT, CONFIRM |

Full SHA-256 in `out/corpus_manifest.json`. Capture point: a link between a common master (10.0.0.3) and
each outstation; capture date not embedded in the files.

## Session structure (important)

Each capture contains **two** outstation (port-20000) sessions:

- The **real physical device**: SEL751 = 10.0.0.1, ION7550 = 10.0.0.11, AB1400 = 10.0.0.12. These carry
  the device-distinctive TCP stack.
- A **shared reference endpoint at 10.0.0.2** with an identical Linux-like stack (SYN-ACK
  `MSS,SAckOK,Timestamp,NOP,WScale`, doff=10) present in every capture. It is detected automatically
  (an outstation IP seen under two or more device labels) and excluded from device attribution. It is a
  natural canonical target for the T2 transformation.

## Corpus adequacy for the required analysis

- **Two or more physical outstations / meaningfully different TCP stacks:** YES. Three physical devices
  with pairwise-distinct stacks (SEL751, ION7550, AB1400).
- **At least five independent sessions per identity:** NO. Each device has ~2 real-device sessions
  (one per short/long capture). Device-identity **classification is therefore EXPLORATORY**, not
  generalizable: the analysis reports deterministic per-device signatures and a leave-one-session-out
  1-NN, and does not make a device-family classification claim.
- **Repeated instances of the same public semantic transaction:** YES. READ polling repeats thousands
  of times per capture (see DNP3 coverage); SELECT/CONFIRM repeat for SEL751 and AB1400.

## Checksum offload and Ethernet FCS

- **Checksum offload:** the source captures show a large fraction of **invalid TCP checksums**
  (SEL751 ~43% valid, ION7550 ~34%, AB1400 ~33%; measured in `out/validation.json`). This is a transmit
  checksum-offload artifact of the capture host, not real corruption. The IPv4 checksums are valid. The
  transformed copies recompute all checksums and are 100% valid.
- **Ethernet FCS:** not present in the captures (frames end at the IP payload; short frames carry
  Ethernet minimum-length padding, which the analysis accounts for).

## The 12,204-byte READ

Not present in the `Traffic Trace/` corpus (`large_response_present: false` for all six). It lives in a
separate capture, `dnp3_split_harness/captures/baseline/large_read.pcap` (SHA-256
`787895bc16666f613e4aa5837fe289ee1ccaa5d284da47d999509bfd182b5a06`). Experiment 1 attributes and
transforms only header fields, which are per-packet and independent of response size, so the large READ
does not change the header attribution; it is relevant to the size axis, which is out of scope here.
