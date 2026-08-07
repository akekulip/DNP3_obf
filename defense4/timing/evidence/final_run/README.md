# Immutable evidence root for the final Defense 4 run

This directory is the single root for the FINAL, accepted evidence. It is created now (Phase 1) and
filled only by the later phases, one immutable timestamped subdirectory per campaign:

```
final_run/
  <UTC-timestamp>_<phase>/     e.g. 20260808T0300Z_campaignA/
    block_*.json ev_pre_*.json ev_post_*.json  (raw per-block)
    blocks.jsonl                                (fail-closed scorer output, one line/block)
    pcaps/blk_*.pcap                            (full-Ethernet master-facing captures)
    pcaps_relay/blk_*.pcap                      (paired relay-facing captures, when byte identity is claimed)
    intended/*.jsonl                            (intended bytes for controlled software-outstation traffic)
    pair_bytes_*.json                           (paired ingress-vs-egress reports)
    analysis.json                               (session-aware distributions)
    run.log finalize.out manifest.out manifest_verify.out
    SHA256SUMS                                  (generated LAST; sha256sum -c must pass)
```

Rules (from the Prompt 0 charter):

- **Immutable.** Once a subdirectory's `SHA256SUMS` is written and verified, nothing in it is edited.
  A correction is a NEW subdirectory, never an overwrite.
- **No silent deletion.** Failed and invalid trials stay in place with their exclusion reason. They
  remain in the denominator.
- **Pre-fix vs post-fix separated.** The pre-fix defective campaigns stay in their own
  `../campaign_*` directories and are never mixed in here.
- **Every conclusion traces here.** No number in any canonical document or in the paper is accepted
  unless it is re-derivable from a subdirectory of this root by the fail-closed pipeline.

The fail-closed pipeline that writes and checks this root is under `../../control/deploy/`:
`run_campaign.sh` (orchestrator), `score_campaign.py` (scenario-aware scorer), `pair_bytes.py`
(paired byte comparator), `analyze_campaign.py` (session-aware statistics), `make_manifest.sh`
(SHA256 manifest). Its fail-closed behavior is proven by `../../control/deploy/fixtures/run_tests.sh`.

This root is empty until Phase 4 (the final physical + controlled campaigns) writes into it.
