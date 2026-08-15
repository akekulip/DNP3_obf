# One-Sided Impossibility of Total-Length Hiding

Gate: S0
Status: adversarially reviewed S0 proof boundary

## Claim

With an unmodified DNP3 master, an unmodified relay, only one transparent in-path switch, and a passive TCP-aware observer that sees the master-side stream, a byte-preserving middlebox cannot hide total application byte count by segmentation, fragmentation, padding outside the accepted stream, or filterable cover traffic.

This does not say all traffic-analysis resistance is impossible. A trusted encapsulation boundary on each side of the observed link changes the premise.

## Assumptions

1. The master must receive the original ordered DNP3 byte stream `B(m)`.
2. Master and relay are not modified to remove padding or decode a new record layer.
3. The observer sees every packet on the same master-facing flow and understands IP/TCP sequence and ACK semantics.
4. The switch remains transparent to endpoint application semantics.
5. Traffic outside the accepted byte stream is distinguishable by flow, sequence validity, checksum, retransmission identity, or protocol parsing.

## Proof sketch

Let `L(m)=|B(m)|`. From the TCP transcript, let `N` be the number of previously unseen response-direction sequence-space bytes after removing SYN/FIN sequence consumption and duplicate retransmissions.

Because the unmodified master receives the original stream exactly:

\[
N=|B(m)|=L(m).
\]

Segmentation changes only the partition of those bytes. For payload intervals `[seq_i,seq_i+p_i)`, sequence-aware reassembly gives:

\[
N=\left|\bigcup_i[seq_i,seq_i+p_i)\right|.
\]

Two messages with different lengths therefore produce different `N`, regardless of partition, order, duplication, or retransmission. If both directions are visible, ACK progression supplies a second byte-count signal.

Adding bytes inside accepted sequence space changes the unmodified master's application stream. Adding bytes outside it makes them invalid, duplicate, out of window, or unrelated cover. Link padding and IP fragmentation do not change reassembled TCP payload total. Clear DNP3 padding remains parseable and still needs a trusted remover.

Therefore a one-sided transparent switch cannot make observed total-new-byte count independent of `L` while preserving the original endpoint stream.

## Why common workarounds fail

| Transform | Observer recovery |
| --- | --- |
| `[49] -> [28,21]` | Novel TCP sequence intervals total 49 bytes. |
| Other segmentation | Partition changes; union length does not. |
| IP fragmentation | Reassembled payload length remains visible. |
| Ethernet padding | IP total length identifies non-IP padding. |
| TCP options | Application byte count and ACK deltas are unchanged. |
| Invalid checksums | Invalid packets are excluded from the accepted transcript. |
| Out-of-window segments | Sequence validity identifies rejected bytes. |
| Retransmission chaff | Repeated intervals are duplicates. |
| Another port/flow | It is filterable from the protected flow. |
| Clear application padding | DNP3 framing exposes it and the master cannot remove it. |
| Ordinary encrypted tunnel | Without fixed padded records, ciphertext length tracks plaintext length. |

## Persistent-stream and ACK objections

A long TCP stream does not help while DNP3 framing remains clear: the observer parses message boundaries and lengths. Encrypting framing and mixing messages across fixed records would require the missing trusted decoder and leave the one-sided premise. ACK normalization can change timing or ACK shape, not the number of novel response bytes accepted.

## Required escape from the proof

Real total-length hiding requires:

1. an encoder mapping variable cleartext to a fixed-volume authenticated encrypted transcript;
2. a trusted decoder removing cover/padding and restoring exact original bytes before endpoint delivery.

If S1 cannot verify both boundaries on the current testbed, the result is **blocked by topology**, not a semantic workaround.

## Evidence anchors

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/scripts/size_reconstruct.py`
