# DNP3 in-network timing normalizer: live inline on a physical SEL-751

Self contained bundle with the report, the dataplane, the runnable pipeline and the evidence.
Everything here was measured on the physical testbed on 2026-07-25.

**What it showed.** Running inline between the master and a physical SEL-751, the Tofino-1
normalizes the DNP3 CLRT (the relay's pure-ACK to response interval) from a scattered distribution
down to a single value. The spread tightens by 329 times, the observer's histogram goes from six
occupied 1 ms bins to one, and the entropy of the timing channel drops to 0.000 bits.

## Start here

| I want to | open |
|:--|:--|
| read the whole thing | `DNP3_INLINE_LIVE_REPORT.pdf`, 22 pp, single column, all diagrams |
| read it in a browser | `index.html`, same content with sidebar navigation, works offline |
| explore it interactively | `interactive.html`, drag G and step through the pipeline |
| run it myself | `run/README.md`, then `run/status.sh` |
| see the raw result | `evidence/RESULT.md` |
| read the dataplane | `p4/dnp3_timing_normalizer_inline.p4` |

The report is the main document. Section 9 has every command needed to run it, section 10 is the
Wireshark guide, and section 5 walks through the code with line references.

## Layout

```
dnp3_inline_live/
├── DNP3_INLINE_LIVE_REPORT.pdf   the report, single column, 22 pp
├── index.html                    the report, browser version, self contained
├── interactive.html              interactive explainer: G explorer and pipeline walk
├── assets/                       4 editable SVG schematics + 2 data figures
├── run/                          the runnable pipeline, deploy to the master host
│   ├── status.sh                 4 preflight checks, exits non-zero on failure
│   ├── run.sh native|protected   capture and poll in one command
│   ├── poll.py                   the poller, read-only READs, tokens in protected mode
│   ├── clrt.py                   CLRT, clustering and entropy from a pcap
│   └── dnp3_crc.py               CRC-16/DNP helper
├── p4/
│   ├── dnp3_timing_normalizer_inline.p4    sha fb3b10da…, 10/12 ingress stages
│   └── lab.env.inline                      PROG / P4_SRC_SHA256 / DP_HULK=64
├── evidence/
│   ├── RESULT.md                 measured result and scope
│   ├── native_inline2.pcap       native run
│   └── prot_inline.pcap          protected run at G = 25 ms
├── design/                       the two design analyses, topology and relay safety
└── source/                       report source, generators, build.sh
```

## Rebuilding

```bash
source/build.sh
```

This regenerates the diagrams and data figures from source, then renders the HTML and the PDF from
the same markdown, so the prose and the figures cannot drift apart. Needs `pandoc`,
`google-chrome` for the PDF, and the research python for matplotlib.

## Three things to know before using this

**G = 25 ms is too small for this relay.** Two native runs hit maxima of 22.66 ms and 37.22 ms. A
transaction whose native CLRT is above G goes through unprotected and leaves no trace on the wire.
At G = 25 ms the observer's entropy is still 0.44 bits rather than zero, and it only reaches zero
at G of 38 ms or more. Use G = 40 ms, and treat that as a floor until the tail is measured. Report
section 8 covers this.

**This is the timing channel only.** Response size, ACK mode and the TCP stack fingerprint are
untouched, and the SEL-751 is the only separate-ACK device in the corpus, so the anonymity set is
one device. Fixing when a device answers does not make it look like another device.

**Byte identity is not proven in this setup.** The relay leg cannot be tapped, since the unmanaged
switch has no span port, so we cannot compare the same frame on both sides. Byte identity rests on
the earlier replay campaign, where it held 100 out of 100. Report section 11 covers this.
