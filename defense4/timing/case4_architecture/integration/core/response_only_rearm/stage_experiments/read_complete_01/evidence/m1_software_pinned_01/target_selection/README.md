# READ target selection from retained native captures

Selected software policy: **163, 269, 399 encoded DNP3 octets per complete
response**. For the base database alone, use **163, 269**. The 399 bucket covers
the retained naturally segmented large-database response.

| Native response | Observations | Selected target | Added octets |
|---|---:|---:|---:|
| 49 | 200 | 163 | 114 |
| 141 | 200 | 163 | 22 |
| 247 | 400 | 269 | 22 |
| 377 (292 + 85 link frames) | 200 | 399 | 22 |

The sample contains 1,000 exchanges from five retained native loopback captures
at DNP3_obf commit afbea5a528d1884964b6f6a21dbca8dabd83195c, under
`full_read_01/evidence/native_*`. Each experiment requested 200 READs. Class-0
and integrity on the base database both contribute 247-byte responses. These
are controlled fixture frequencies, not estimates of deployment frequencies.
The hypothetical 157-byte example is not included as an observation.

## Rule and comparison

Minimize frequency-weighted added bytes, with complete exact coverage and
strictly positive padding for every sample, using the generalized software
prefix encoder, pad indices 16..4095 and a 2048-byte application capacity.
Choose the smallest reachable target at runtime. Enumerate attainable encodings
within that capacity; targets with identical size coverage are dominated by the
smallest one. Compare one-, two- and three-target solutions. The chosen three
targets retain one bucket that merges different observed native sizes.

| Target count | Best target set | Mean added bytes/response | Added/native DNP3 bytes |
|---|---|---:|---:|
| 1 | 399 | 186.8 | 88.03% |
| 2 | 269, 399 | 82.8 | 39.02% |
| 3 | 163, 269, 399 | 40.4 | 19.04% |

For three targets the native total is 212,200 bytes; the output total is
252,600 bytes. This saves 42,400 added bytes (51.2%) versus the two-target
alternative. The 49-byte shape still incurs 114 bytes of padding: the cost of
grouping it with the 141-byte shape. A small dedicated bucket would lower its
cost but retain a separately identifiable size class or shift overhead to
another shape.

Base-database sensitivity (800 exchanges, excluding large database): two targets
163/269 add 45 bytes per response on average (26.32%). Three targets 71/163/269
would add only 22 bytes each, but each observed native size would have its own
target, merging no observed size classes. That is why simply choosing a close
target for every native size is not the preferred size-grouping policy.

## Validation and limits

The selected encoder was applied to every captured request/response pair:
**1,000/1,000 exact outputs**, with CRC validation, transport reassembly,
original application-header/object-byte preservation and decoded-point equality.
The exchange ledger contains source run/index, lengths, frame sizes, padding
counts and hashes. No observations were excluded or invented.

The newly selected 163-byte target also passed 16 live range READs and 16 live
analog READs, each compared against 16 native polls. Every original point value
and flag was preserved, tasks succeeded, and IIN sets/counts were unchanged.
These endpoint tests used upstream OpenDNP3 3.1.2 at
c1dc7165a79cc08edbf4b6f6a21dbca8dabd83195c, not the deployment's pinned fork.

Sizes are aggregate encoded DNP3 response bytes, not guaranteed individual TCP
packet sizes. Added-byte percentages exclude Ethernet/IP/TCP overhead and do
not establish physical-link bandwidth savings. Original link-frame boundaries
remain visible. Three target classes and other protocol features still leak
information; no indistinguishability or classifier-resistance result is claimed.

The policy is conditional on this sample and encoding profile. If an unseen
response cannot reach any selected target, return `unreachable` explicitly;
do not force the size, silently leave it native as a success, or retune using
held-out evaluation data. No P4 source, timing settings or hardware was changed.

## Reproduce

```sh
python3 select_targets.py
```

This re-decodes the retained captures and regenerates `selection.json` and
`exchange_ledger.json`. Dependencies are bundled under `source/`; no new capture
or simulator is required. Input hashes are in the selection manifest.

To repeat the focused endpoint check, build the included FullReadGate.cpp against
the upstream OpenDNP3 commit above, then:

```sh
LD_LIBRARY_PATH=/path/to/opendnp3/build/cpp/lib python3 check_selected_live.py --binary /path/to/full_read_gate --output ./new-live-results
```

The proxy uses two TCP connections, so it does not test switch sequence mapping,
timing/J or hardware recovery. Existing `selected_live_01` evidence is immutable;
use a new output directory. No repository commit or push was made.
