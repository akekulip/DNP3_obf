# Physical relay loss: identity targeting

## Why

The occurrence chain in `loss.py` drops the Nth packet of a class: N-1 `ACCEPT` rules and then `LOG`+`DROP`.
Each rule is `-m limit --limit 1/hour --limit-burst 1` and matches IP length, TCP flags and ports. A TCP
retransmission is a packet of the same class, so it shifts the count. In
`rc01_hw_c52_20261024_26_loss_full_950` trial t0 (`request_full:3`), the master retransmitted READ #1
(SEQ 2394027613) about 210 ms after the first copy. The chain therefore dropped READ #2 (SEQ 2394027640)
instead of READ #3 (SEQ 2394027667). `relay_loss.target_checks` caught the miss after the run.

Identity targeting drops the intended transaction, identified by its exact TCP sequence or acknowledgment
number, so retransmissions cannot shift it.

## Selecting it

A config loss preset entry gets `"target": "identity"`, for example
`{"class": "request_full", "n": 3, "target": "identity"}`. `campaign.drop_text` then passes
`--drop request_full:3:identity` to `vision_run.py`. Identity targeting is accepted only with the `sel751`
endpoint profile. An entry without `target` and the drop text `CLASS:N` keep the occurrence behaviour
exactly as before: `relay_loss.parse_drop` returns the same spec dict, so retained configs, frozen evidence and
pending ownership files still parse.

## How the target is resolved

An identity spec carries `operation`, `index` (the ordinal among the master's own requests of that
operation, which are first transmissions by construction), `frontier` and `match`. The master harness
(`relay_master.workload(loss_target=RelayLoss)`) does two things:

1. Right after connecting, `RelayLoss.on_connect` reads the relay's SYN-ACK from the live receive capture
   (`in.pcap`, `syn_ack_isns`). The SYN-ACK's SEQ is the relay ISN, and its ACK minus 1 is the master ISN.
2. Before every request, `RelayLoss.before_send(operation, frame, sock)` feeds `IdentityTarget` with the
   operation, the request length and the bytes the kernel has accepted in order (`tcp_info.tcpi_bytes_received`,
   offset 128). Octets sent are summed from the master's own frames.

| frontier | presets | chain | match | value |
|---|---|---|---|---|
| request | `request_mixed`, `request_full`, `select_req`, `operate_req` | OUTPUT | SEQ | master ISN + 1 + octets sent before the request |
| request_ack | `ack_sep` | INPUT | ACK | that + request length (relay's separate pure ACK) |
| response | `read_resp_padded`, `select_resp_padded`, `operate_resp_padded` | INPUT | SEQ | relay ISN + 1 + octets received before the response |
| response_ack | `master_ack_of_padded_data` | OUTPUT | ACK | that + padded READ image (141 mixed, 158 full) |

All values are taken modulo 2^32. All nine physical presets are converted. Response-side presets were
already dropped on the master's INPUT chain, and they now match the exact response SEQ in the master's
(post-switch, padded) sequence space.

## The u32 expressions

    SEQ:  -m u32 --u32 0>>22&0x3C@4=0x<SEQ, 8 hex digits>
    ACK:  -m u32 --u32 0>>22&0x3C@8=0x<ACK, 8 hex digits>

`0>>22&0x3C` takes the first IPv4 word, shifts it right by 22 and masks it with 0x3C. The result is IHL x 4,
which is the TCP header offset with any IP options included. `@4` and `@8` then read the TCP sequence and
acknowledgment words. The u32 match comes before `-m limit` in each rule. Matches are evaluated in order, so
a class packet with another SEQ or ACK fails the u32 test and never spends the one-shot token. The kernel
renders the rule as `"0x0>>0x16&0x3c@0x4=0x..."` in `iptables -S`, and `iptables -C` accepts the form above.

## One-shot semantics

Two rules are armed: `LOG` (prefix `D4R<16 hex>`, `--log-tcp-sequence`) and `DROP`. Both keep the existing
length, flags and port matches plus the u32 match and `--limit 1/hour --limit-burst 1`. Each rule matches
exactly once. The first packet with the identity is logged and dropped. Its own retransmission finds both
tokens spent and passes. Earlier transactions and their retransmissions carry other SEQ/ACK values and never
match. For ACK presets, the master's ACK of a FIN carries frontier + 1, and a FIN or a data segment with the
same ACK differs in flags or length, so none of them can match.

**Precondition.** One-shot depends on each rule's `xt_limit` token staying spent from the drop until the trial
ends. Nothing in `RelayLoss` changes the table in that window: `arm` inserts the rules before the target is
sent, and the next table change is the removal in `finish()`. Another process could still change the table
during the trial. On the legacy iptables backend, such a change replaces the whole table, which may
re-initialise the limit state and refill the token. The rule could then also drop the target's retransmission.
This is inferred from the local test failure described below and has not been confirmed in the kernel source.
This workstation runs `iptables v1.8.4 (legacy)`; Vision's backend has not been checked from here.

A second drop does not pass silently. `LossRule.record()` requires the DROP counter to be exactly 1 packet,
`RelayLoss.finish()` requires the LOG counter to be exactly 1, and the trial is then not `exact`. The loss
report records `iptables -V` as `iptables_version`, so the backend that ran each trial is on file.

This failure was seen in the first version of the netns test. Its forcing rule, length plus limit with no u32,
had dropped request 1 earlier. When `arm` later inserted request 3's rules, the forcing rule's token was
refilled, so the forcing rule dropped request 3's retransmission too (2 packets, about 645 ms). The test now
selects request 1 with its own u32 SEQ and deletes the forcing rule before request 3 is armed.

## Fail-closed behaviour

- `install()` records ownership (the state file, with `identity: null`) and inserts nothing.
- `on_connect` raises if no single SYN-ACK of the connection appears in the capture within 2 s.
- `arm` runs immediately before the target request is handed to the socket. It checks that the rules are
  absent, rewrites the state file with `identity: [key, value]` (so `restore_owned` can rebuild the exact
  rules after a crash), inserts the rules and confirms each one with `iptables -C`. Any failure raises
  inside the master before the send. The run records the error and `master_rc=1`, and the target is never
  sent unarmed.
- `finish()` always removes the rules and verifies the chain against the pre-loss baseline.
  `report['identity']` records `armed`, `key`, `value`, both ISNs, any error and `arm_ns`, the time
  `arm` took before the target request was released (about 90 ms in the unprivileged test: six iptables
  calls plus an fsync of the state file). `exact` requires `armed`.
- When the master stops before traffic, `relay_wire.json` is never written. `campaign.verdict_loss` records a
  missing or unreadable `result.json` or `relay_wire.json` as a trial failure, adds the trial to the soft
  failures and lets the block go on. A Vision run that returns anything other than 0 or 1 still stops the
  block.
- `relay_loss.target_checks` remains the post-run gate. The kernel LOG SEQ or ACK must equal the
  `relay_wire.json` frontier of the intended transaction. In identity mode the armed value must also equal
  the logged one.

## Tests

`tests/test_loss_identity.py` covers resolution on the retained t0 and t6 captures, the exact rule strings,
the u32 semantics (an independent interpreter, with IP options and on every retained frame), lifecycle,
crash restoration, fail-closed arming, the master hook, FIN-adjacent ACKs and campaign compatibility.

`tests/test_loss_identity_netns.py` runs a kernel scenario (`tests/netns_identity_scenario.py`) on veth plus a
nested netns at the production addresses, in three modes:

- `request` (OUTPUT, SEQ `@4`): a u32 forcing rule makes request 1 retransmit, then the identity rule targets
  request 3.
- `response` (INPUT, SEQ `@4`): the target is response 2, located from the relay ISN plus
  `tcpi_bytes_received`.
- `response_ack` (OUTPUT, ACK `@8`): the target is the master's pure ACK of response 2.

Each mode asserts that the intended segment was dropped exactly once (LOG and DROP counters both 1, with the
expected identity) and that its retransmission passed within one RTO (150 to 400 ms). For the pure ACK, the
next request's cumulative ACK must pass and the relay must not retransmit. The root variant also asserts the
dmesg LOG line:
`sudo -v && python3 -m pytest -q -rs tests/test_loss_identity_netns.py`.
The unprivileged user-namespace variant cannot assert the LOG line, because the kernel does not emit LOG lines
from a non-initial netns unless `nf_log_all_netns` is set. That root-only test is marked `privileged`, and
test_markers' nested runs leave it out.

Vision note: the rules need the `xt_u32` module. If it is missing, the insert fails and the trial fails
closed.
