# Phase 01 — Base vs L Capture Comparison

Two-sample distributional comparison of each device's base capture vs its longer `L` capture (device-specific outstation). KS = Kolmogorov-Smirnov statistic; W1 = 1-D Wasserstein distance; Cliff's delta and Cohen's d are effect sizes. Computed with numpy (no scipy).

| device | metric | n(base) | n(L) | med(base) | med(L) | KS | W1 | Cliff's d | Cohen's d |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SEL-751 | req_to_first_rev_ms | 299 | 3999 | 3.695 | 3.673 | 0.123 | 0.077 | 0.087 | 0.065 |
| SEL-751 | req_to_pure_ack_ms | 299 | 3999 | 3.695 | 3.673 | 0.123 | 0.077 | 0.087 | 0.065 |
| SEL-751 | pure_ack_to_resp_ms | 299 | 3999 | 12.898 | 12.178 | 0.218 | 1.241 | 0.205 | 0.178 |
| SEL-751 | req_to_resp_ms | 299 | 3999 | 16.985 | 16.104 | 0.236 | 1.280 | 0.218 | 0.187 |
| SEL-751 | req_tcp_len | 299 | 3999 | 35.000 | 35.000 | 0.169 | 2.194 | 0.169 | 0.339 |
| SEL-751 | resp_tcp_len | 299 | 3999 | 37.000 | 37.000 | 0.169 | 2.869 | -0.169 | -0.339 |
| SEL-751 | packet_count | 299 | 3999 | 3.000 | 3.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| SEL-751 | transaction_ip_bytes | 299 | 3999 | 270.000 | 270.000 | 0.169 | 0.675 | -0.169 | -0.339 |
| AB1400 | req_to_first_rev_ms | 399 | 1999 | 16.620 | 16.247 | 0.232 | 0.617 | 0.339 | 0.322 |
| AB1400 | req_to_pure_ack_ms | 0 | 0 | n/a | n/a | n/a | n/a | n/a | n/a |
| AB1400 | pure_ack_to_resp_ms | 0 | 0 | n/a | n/a | n/a | n/a | n/a | n/a |
| AB1400 | req_to_resp_ms | 399 | 1999 | 16.620 | 16.247 | 0.232 | 0.617 | 0.339 | 0.322 |
| AB1400 | req_tcp_len | 399 | 1999 | 35.000 | 35.000 | 0.001 | 0.013 | 0.001 | 0.002 |
| AB1400 | resp_tcp_len | 399 | 1999 | 37.000 | 37.000 | 0.001 | 0.017 | -0.001 | -0.002 |
| AB1400 | packet_count | 399 | 1999 | 2.000 | 2.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| AB1400 | transaction_ip_bytes | 399 | 1999 | 180.000 | 180.000 | 0.001 | 0.004 | -0.001 | -0.002 |
| ION7550 | req_to_first_rev_ms | 799 | 3999 | 16.055 | 15.984 | 0.141 | 0.468 | 0.155 | 0.222 |
| ION7550 | req_to_pure_ack_ms | 0 | 1 | n/a | 43.304 | n/a | n/a | n/a | n/a |
| ION7550 | pure_ack_to_resp_ms | 0 | 1 | n/a | 28.754 | n/a | n/a | n/a | n/a |
| ION7550 | req_to_resp_ms | 799 | 3999 | 16.055 | 15.984 | 0.141 | 0.475 | 0.155 | 0.198 |
| ION7550 | req_tcp_len | 799 | 3999 | 35.000 | 35.000 | 0.001 | 0.007 | 0.001 | 0.001 |
| ION7550 | resp_tcp_len | 799 | 3999 | 37.000 | 37.000 | 0.001 | 0.012 | -0.001 | -0.001 |
| ION7550 | packet_count | 799 | 3999 | 2.000 | 2.000 | 0.000 | 0.000 | -0.000 | -0.017 |
| ION7550 | transaction_ip_bytes | 799 | 3999 | 180.000 | 191.000 | 0.001 | 0.021 | -0.001 | -0.004 |

> These compare only the captured base vs L traces; they do not imply temporal stability beyond the captured data. Effect sizes accompany the distances; no p-value-only claims are made.

