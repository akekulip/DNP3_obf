# Device indistinguishability — the actual obfuscation goal

Classifying each device is not obfuscation. The goal is that **SEL-751, ION7550 and AB1400 look
identical on the wire after normalization**, so a passive observer cannot tell them apart. The
device fingerprint lives in the **outstation's SYN-ACK** option layout (Experiment 1). This is the
test that matters, and `tests/indistinguishability.py` measures it against the real device layouts.

## The gap in the first (conservative) design — measured

The original safe normalizer only canonicalized an **already-minimal** SYN-ACK and failed open on a
full-option one. Measured result (`tests/indistinguishability.py`):

| device | SYN-ACK layout | outcome | result |
|---|---|---|---|
| SEL751 | MSS,NOP,WScale,…,SAckOK,…,TS (do=11) | **fail open** | fingerprint SURVIVES |
| ION7550 | MSS only (do=6) | normalized | canonical |
| AB1400 | MSS,NOP,NOP,NOP,EOL (do=7) | **fail open** | fingerprint SURVIVES |

Residual fields that still distinguished the devices: `data_offset`, `opt_bytes`, `window`, `mss`.
**Not indistinguishable** — obfuscation not achieved. (This depended on the endpoint honoring the
SYN-strip fallback, an unverified Experiment-3 assumption.)

## The fix — symmetric aggressive normalization

The normalizer now strips the SYN-ACK options too, exactly as it strips the SYN, and this is **safe
because it is symmetric**: the master's SYN was already stripped, so both ends consistently
negotiate no options — there is no window-scale desync (the reason a one-sided SYN-ACK strip was
avoided). Concretely, an MSS-first SYN-ACK with a safe second option is rewritten to canonical
`[MSS]`, `data_offset=6`, MSS clamped to ≤1460, and the **handshake window canonicalized** to a
public constant (8192); MD5/AO second options still fail open. Same `canon` action, applied to both
directions.

## Measured result after the fix — indistinguishable

`evidence/indistinguishability.txt`:

| device | normalized SYN-ACK |
|---|---|
| SEL751 | `do=6 ttl=64 ip.id=0 win=8192 mss=1460 opt=020405b4` |
| ION7550 | `do=6 ttl=64 ip.id=0 win=8192 mss=1460 opt=020405b4` |
| AB1400 | `do=6 ttl=64 ip.id=0 win=8192 mss=1460 opt=020405b4` |

**COLLAPSED (identical across devices): `data_offset, opt_bytes, ttl, ip_id, window, mss`.
RESIDUAL: none. Devices indistinguishable: YES — obfuscation achieved** (over the observable
handshake header fields; the 5-tuple, seq and ack legitimately vary per connection and are not
device identity).

The analysis also caught a real oracle bug: scapy keeps a concrete `data_offset` after reparse, so
the golden packet emitted 4 option bytes but a stale `data_offset`; the P4 explicitly sets
`data_offset=6` (correct), and the oracle now does too, with a check that every normalized output is
exactly canonical `[MSS]/do=6`.

## Bounds

- This is the **handshake** header axis (SYN/SYN-ACK), the Experiment-1 fingerprint. Established
  segments' window and any application-layer size/timing are separate axes (size probe / Defense 4).
- The **window canonicalization** clamps the *handshake* window only; established segments carry the
  real window. For DNP3 (tiny requests, fast ACKs) a fixed initial window is safe; it is a
  deliberate choice recorded here, not silent.
- Verified **offline** (byte-identical golden outputs) and the normalize path is **confirmed on
  silicon** by the ASIC classification matrix. Byte-level output capture on the ASIC (to observe the
  identical bytes leaving the chip) still needs an egress capture path.
