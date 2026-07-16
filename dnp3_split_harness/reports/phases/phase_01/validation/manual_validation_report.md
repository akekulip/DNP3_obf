# Phase 01 — Transaction Validation Report

**Method:** automated, frame-targeted re-extraction and cross-derivation (an independent second tshark read of each transaction's request / pure-ACK / response frames), NOT human visual inspection. Sample seed: `20250716` (numpy default_rng). Timestamp tolerance: 0.02 ms.

Sample size: **60** transactions (20 per device where available: {'SEL751': 20, 'AB1400': 20, 'ION7550': 20}).

Agreement (re-read fields + ACK relationship + re-derived class): **60/60**.

Selected transaction frames are enumerated in `manual_validation_sample.csv` (capture, req/pure-ACK/resp frame numbers, automated vs re-derived class).

## Result

Every sampled transaction re-verified: the frame-targeted re-read reproduces the recorded sizes and timestamps, the TCP acknowledgement acknowledges the request bytes, and the re-derived ACK mode matches the automated classification.

