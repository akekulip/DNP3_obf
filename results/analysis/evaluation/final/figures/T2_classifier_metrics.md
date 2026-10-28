| d_ms | arm | feature | k | attacker | classifier | test_windows | ba_pooled | ba_block_mean | ci_lower | ci_upper | mean_accuracy | min_accuracy | mean_precision | min_precision | mean_recall | min_recall | note |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5 | off | clrt | 8 | retrained | nb | 192 | 0.474 | 0.474 | 0.438 | 0.516 | 0.649 | 0.562 | 0.476 | 0.357 | 0.474 | 0.391 |  |
| 5 | off | clrt | 8 | retrained | ff_ann | 96 | 0.479 |  |  |  | 0.653 | 0.604 | 0.487 | 0.417 | 0.479 | 0.438 | random 75/25 (Formby) |
| 5 | off | clrt | 8 | retrained | gmm | 192 | 0.333 | 0.333 | 0.302 | 0.365 | 0.556 | 0.432 | 0.212 | 0.000 | 0.333 | 0.000 |  |
| 5 | off | clrt | 8 | pre_deployment | nb | 192 | 0.474 | 0.474 | 0.438 | 0.516 | 0.649 | 0.562 | 0.476 | 0.357 | 0.474 | 0.391 |  |
| 5 | off | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.302 | 0.365 | 0.556 | 0.432 | 0.212 | 0.000 | 0.333 | 0.000 |  |
| 5 | off | clrt | 32 | retrained | nb | 48 | 0.500 | 0.500 | 0.417 | 0.583 | 0.667 | 0.500 | 0.537 | 0.300 | 0.500 | 0.375 |  |
| 5 | off | clrt | 32 | retrained | ff_ann | 24 | 0.750 |  |  |  | 0.833 | 0.750 | 0.778 | 0.667 | 0.750 | 0.500 | random 75/25 (Formby) |
| 5 | off | clrt | 32 | retrained | gmm | 48 | 0.396 | 0.396 | 0.292 | 0.500 | 0.597 | 0.542 | 0.256 | 0.000 | 0.396 | 0.000 |  |
| 5 | off | clrt | 32 | pre_deployment | nb | 48 | 0.500 | 0.500 | 0.417 | 0.583 | 0.667 | 0.500 | 0.537 | 0.300 | 0.500 | 0.375 |  |
| 5 | off | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | clrt | 32 | pre_deployment | gmm | 48 | 0.396 | 0.396 | 0.292 | 0.500 | 0.597 | 0.542 | 0.256 | 0.000 | 0.396 | 0.000 |  |
| 5 | off | clrt | 64 | retrained | nb | 24 | 0.625 | 0.625 | 0.500 | 0.750 | 0.750 | 0.625 | 0.648 | 0.444 | 0.625 | 0.500 |  |
| 5 | off | clrt | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.567 | 0.400 | 0.583 | 0.250 | random 75/25 (Formby) |
| 5 | off | clrt | 64 | retrained | gmm | 24 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.458 | 0.238 | 0.000 | 0.375 | 0.000 |  |
| 5 | off | clrt | 64 | pre_deployment | nb | 24 | 0.625 | 0.625 | 0.500 | 0.750 | 0.750 | 0.625 | 0.648 | 0.444 | 0.625 | 0.500 |  |
| 5 | off | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | clrt | 64 | pre_deployment | gmm | 24 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.458 | 0.238 | 0.000 | 0.375 | 0.000 |  |
| 5 | off | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | off | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | off | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | off | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | joint | 8 | retrained | nb | 192 | 0.844 | 0.844 | 0.823 | 0.865 | 0.896 | 0.844 | 0.847 | 0.736 | 0.844 | 0.703 |  |
| 5 | off | joint | 8 | retrained | ff_ann | 96 | 0.812 |  |  |  | 0.875 | 0.812 | 0.812 | 0.719 | 0.812 | 0.719 | random 75/25 (Formby) |
| 5 | off | joint | 8 | retrained | gmm | 192 | 0.625 | 0.625 | 0.568 | 0.677 | 0.750 | 0.625 | 0.617 | 0.395 | 0.625 | 0.234 |  |
| 5 | off | joint | 8 | pre_deployment | nb | 192 | 0.844 | 0.844 | 0.823 | 0.865 | 0.896 | 0.844 | 0.847 | 0.736 | 0.844 | 0.703 |  |
| 5 | off | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | joint | 8 | pre_deployment | gmm | 192 | 0.625 | 0.625 | 0.568 | 0.677 | 0.750 | 0.625 | 0.617 | 0.395 | 0.625 | 0.234 |  |
| 5 | off | joint | 32 | retrained | nb | 48 | 0.979 | 0.979 | 0.938 | 1.000 | 0.986 | 0.979 | 0.980 | 0.941 | 0.979 | 0.938 |  |
| 5 | off | joint | 32 | retrained | ff_ann | 24 | 0.958 |  |  |  | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 | random 75/25 (Formby) |
| 5 | off | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | joint | 32 | pre_deployment | nb | 48 | 0.979 | 0.979 | 0.938 | 1.000 | 0.986 | 0.979 | 0.980 | 0.941 | 0.979 | 0.938 |  |
| 5 | off | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 5 | off | joint | 64 | retrained | ff_ann | 12 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 5 | off | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | off | joint | 64 | pre_deployment | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 5 | off | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | off | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | clrt | 8 | retrained | nb | 192 | 0.323 | 0.323 | 0.271 | 0.370 | 0.549 | 0.516 | 0.319 | 0.284 | 0.323 | 0.234 |  |
| 5 | timing_only | clrt | 8 | retrained | ff_ann | 96 | 0.250 |  |  |  | 0.500 | 0.490 | 0.250 | 0.241 | 0.250 | 0.219 | random 75/25 (Formby) |
| 5 | timing_only | clrt | 8 | retrained | gmm | 192 | 0.417 | 0.417 | 0.380 | 0.453 | 0.611 | 0.557 | 0.412 | 0.324 | 0.417 | 0.172 |  |
| 5 | timing_only | clrt | 8 | pre_deployment | nb | 192 | 0.297 | 0.297 | 0.260 | 0.339 | 0.531 | 0.391 | 0.201 | 0.000 | 0.297 | 0.000 |  |
| 5 | timing_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | clrt | 8 | pre_deployment | gmm | 192 | 0.339 | 0.339 | 0.333 | 0.349 | 0.559 | 0.339 | 0.445 | 0.000 | 0.339 | 0.000 |  |
| 5 | timing_only | clrt | 32 | retrained | nb | 48 | 0.417 | 0.417 | 0.354 | 0.479 | 0.611 | 0.562 | 0.417 | 0.381 | 0.417 | 0.250 |  |
| 5 | timing_only | clrt | 32 | retrained | ff_ann | 24 | 0.250 |  |  |  | 0.500 | 0.417 | 0.264 | 0.143 | 0.250 | 0.125 | random 75/25 (Formby) |
| 5 | timing_only | clrt | 32 | retrained | gmm | 48 | 0.250 | 0.250 | 0.167 | 0.312 | 0.500 | 0.417 | 0.208 | 0.125 | 0.250 | 0.062 |  |
| 5 | timing_only | clrt | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.250 | 0.417 | 0.556 | 0.396 | 0.234 | 0.000 | 0.333 | 0.000 |  |
| 5 | timing_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | timing_only | clrt | 64 | retrained | nb | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.500 | 0.350 | 0.250 | 0.375 | 0.125 |  |
| 5 | timing_only | clrt | 64 | retrained | ff_ann | 12 | 0.250 |  |  |  | 0.500 | 0.417 | 0.261 | 0.200 | 0.250 | 0.250 | random 75/25 (Formby) |
| 5 | timing_only | clrt | 64 | retrained | gmm | 24 | 0.292 | 0.292 | 0.167 | 0.417 | 0.528 | 0.458 | 0.239 | 0.000 | 0.292 | 0.000 |  |
| 5 | timing_only | clrt | 64 | pre_deployment | nb | 24 | 0.292 | 0.292 | 0.167 | 0.417 | 0.528 | 0.333 | 0.208 | 0.000 | 0.292 | 0.000 |  |
| 5 | timing_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | timing_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | timing_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | timing_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | timing_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 8 | retrained | nb | 192 | 0.682 | 0.682 | 0.641 | 0.734 | 0.788 | 0.682 | 0.683 | 0.520 | 0.682 | 0.438 |  |
| 5 | timing_only | joint | 8 | retrained | ff_ann | 96 | 0.635 |  |  |  | 0.757 | 0.635 | 0.635 | 0.452 | 0.635 | 0.438 | random 75/25 (Formby) |
| 5 | timing_only | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.635 | 0.693 | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.266 |  |
| 5 | timing_only | joint | 8 | pre_deployment | nb | 192 | 0.672 | 0.672 | 0.651 | 0.693 | 0.781 | 0.672 | 0.692 | 0.504 | 0.672 | 0.062 |  |
| 5 | timing_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 32 | retrained | nb | 48 | 0.688 | 0.688 | 0.562 | 0.812 | 0.792 | 0.688 | 0.690 | 0.524 | 0.688 | 0.375 |  |
| 5 | timing_only | joint | 32 | retrained | ff_ann | 24 | 0.750 |  |  |  | 0.833 | 0.750 | 0.750 | 0.625 | 0.750 | 0.625 | random 75/25 (Formby) |
| 5 | timing_only | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 64 | retrained | nb | 24 | 0.750 | 0.750 | 0.583 | 0.917 | 0.833 | 0.750 | 0.778 | 0.583 | 0.750 | 0.375 |  |
| 5 | timing_only | joint | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.578 | 0.333 | 0.583 | 0.250 | random 75/25 (Formby) |
| 5 | timing_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | timing_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | timing_only | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | clrt | 8 | retrained | nb | 192 | 0.547 | 0.547 | 0.484 | 0.599 | 0.698 | 0.651 | 0.541 | 0.469 | 0.547 | 0.359 |  |
| 5 | size_only | clrt | 8 | retrained | ff_ann | 96 | 0.417 |  |  |  | 0.611 | 0.521 | 0.421 | 0.294 | 0.417 | 0.312 | random 75/25 (Formby) |
| 5 | size_only | clrt | 8 | retrained | gmm | 192 | 0.328 | 0.328 | 0.281 | 0.375 | 0.552 | 0.422 | 0.214 | 0.000 | 0.328 | 0.000 |  |
| 5 | size_only | clrt | 8 | pre_deployment | nb | 192 | 0.443 | 0.443 | 0.417 | 0.469 | 0.628 | 0.557 | 0.439 | 0.328 | 0.443 | 0.312 |  |
| 5 | size_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | clrt | 8 | pre_deployment | gmm | 192 | 0.344 | 0.344 | 0.307 | 0.396 | 0.562 | 0.432 | 0.231 | 0.000 | 0.344 | 0.000 |  |
| 5 | size_only | clrt | 32 | retrained | nb | 48 | 0.729 | 0.729 | 0.604 | 0.833 | 0.819 | 0.771 | 0.736 | 0.650 | 0.729 | 0.562 |  |
| 5 | size_only | clrt | 32 | retrained | ff_ann | 24 | 0.542 |  |  |  | 0.694 | 0.542 | 0.548 | 0.286 | 0.542 | 0.250 | random 75/25 (Formby) |
| 5 | size_only | clrt | 32 | retrained | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | clrt | 32 | pre_deployment | nb | 48 | 0.604 | 0.604 | 0.521 | 0.708 | 0.736 | 0.646 | 0.603 | 0.467 | 0.604 | 0.438 |  |
| 5 | size_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | clrt | 32 | pre_deployment | gmm | 48 | 0.354 | 0.354 | 0.271 | 0.438 | 0.569 | 0.458 | 0.231 | 0.000 | 0.354 | 0.000 |  |
| 5 | size_only | clrt | 64 | retrained | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.854 | 0.727 | 0.833 | 0.625 |  |
| 5 | size_only | clrt | 64 | retrained | ff_ann | 12 | 0.833 |  |  |  | 0.889 | 0.833 | 0.833 | 0.750 | 0.833 | 0.750 | random 75/25 (Formby) |
| 5 | size_only | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | clrt | 64 | pre_deployment | nb | 24 | 0.792 | 0.792 | 0.625 | 0.958 | 0.861 | 0.792 | 0.800 | 0.667 | 0.792 | 0.750 |  |
| 5 | size_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.208 | 0.458 | 0.556 | 0.375 | 0.222 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | size_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | size_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | size_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | joint | 8 | retrained | nb | 192 | 0.849 | 0.849 | 0.823 | 0.875 | 0.899 | 0.849 | 0.849 | 0.769 | 0.849 | 0.766 |  |
| 5 | size_only | joint | 8 | retrained | ff_ann | 96 | 0.875 |  |  |  | 0.917 | 0.875 | 0.876 | 0.794 | 0.875 | 0.781 | random 75/25 (Formby) |
| 5 | size_only | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | joint | 8 | pre_deployment | nb | 192 | 0.443 | 0.443 | 0.417 | 0.469 | 0.628 | 0.557 | 0.439 | 0.328 | 0.443 | 0.312 |  |
| 5 | size_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | joint | 8 | pre_deployment | gmm | 192 | 0.349 | 0.349 | 0.292 | 0.406 | 0.566 | 0.443 | 0.235 | 0.000 | 0.349 | 0.000 |  |
| 5 | size_only | joint | 32 | retrained | nb | 48 | 0.958 | 0.958 | 0.896 | 1.000 | 0.972 | 0.958 | 0.958 | 0.938 | 0.958 | 0.938 |  |
| 5 | size_only | joint | 32 | retrained | ff_ann | 24 | 0.958 |  |  |  | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 | random 75/25 (Formby) |
| 5 | size_only | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | joint | 32 | pre_deployment | nb | 48 | 0.604 | 0.604 | 0.521 | 0.708 | 0.736 | 0.646 | 0.603 | 0.467 | 0.604 | 0.438 |  |
| 5 | size_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | size_only | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 5 | size_only | joint | 64 | retrained | ff_ann | 12 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 5 | size_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | size_only | joint | 64 | pre_deployment | nb | 24 | 0.792 | 0.792 | 0.625 | 0.958 | 0.861 | 0.792 | 0.800 | 0.667 | 0.792 | 0.750 |  |
| 5 | size_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | size_only | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | clrt | 8 | retrained | nb | 192 | 0.385 | 0.385 | 0.333 | 0.443 | 0.590 | 0.583 | 0.384 | 0.364 | 0.385 | 0.312 |  |
| 5 | combined | clrt | 8 | retrained | ff_ann | 96 | 0.312 |  |  |  | 0.542 | 0.510 | 0.307 | 0.222 | 0.312 | 0.188 | random 75/25 (Formby) |
| 5 | combined | clrt | 8 | retrained | gmm | 192 | 0.344 | 0.344 | 0.255 | 0.453 | 0.562 | 0.521 | 0.355 | 0.321 | 0.344 | 0.234 |  |
| 5 | combined | clrt | 8 | pre_deployment | nb | 192 | 0.380 | 0.380 | 0.333 | 0.422 | 0.587 | 0.484 | 0.259 | 0.000 | 0.380 | 0.000 |  |
| 5 | combined | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | clrt | 32 | retrained | nb | 48 | 0.354 | 0.354 | 0.229 | 0.521 | 0.569 | 0.542 | 0.341 | 0.250 | 0.354 | 0.188 |  |
| 5 | combined | clrt | 32 | retrained | ff_ann | 24 | 0.292 |  |  |  | 0.528 | 0.500 | 0.290 | 0.286 | 0.292 | 0.250 | random 75/25 (Formby) |
| 5 | combined | clrt | 32 | retrained | gmm | 48 | 0.250 | 0.250 | 0.167 | 0.312 | 0.500 | 0.396 | 0.201 | 0.100 | 0.250 | 0.062 |  |
| 5 | combined | clrt | 32 | pre_deployment | nb | 48 | 0.354 | 0.354 | 0.292 | 0.417 | 0.569 | 0.458 | 0.237 | 0.000 | 0.354 | 0.000 |  |
| 5 | combined | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | clrt | 64 | retrained | nb | 24 | 0.375 | 0.375 | 0.167 | 0.583 | 0.583 | 0.542 | 0.379 | 0.333 | 0.375 | 0.375 |  |
| 5 | combined | clrt | 64 | retrained | ff_ann | 12 | 0.250 |  |  |  | 0.500 | 0.417 | 0.222 | 0.000 | 0.250 | 0.000 | random 75/25 (Formby) |
| 5 | combined | clrt | 64 | retrained | gmm | 24 | 0.292 | 0.292 | 0.208 | 0.333 | 0.528 | 0.333 | 0.106 | 0.000 | 0.292 | 0.000 |  |
| 5 | combined | clrt | 64 | pre_deployment | nb | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.417 | 0.283 | 0.000 | 0.375 | 0.000 |  |
| 5 | combined | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | combined | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | combined | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 5 | combined | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | joint | 8 | retrained | nb | 192 | 0.729 | 0.729 | 0.667 | 0.792 | 0.819 | 0.729 | 0.729 | 0.588 | 0.729 | 0.562 |  |
| 5 | combined | joint | 8 | retrained | ff_ann | 96 | 0.677 |  |  |  | 0.785 | 0.677 | 0.682 | 0.515 | 0.677 | 0.531 | random 75/25 (Formby) |
| 5 | combined | joint | 8 | retrained | gmm | 192 | 0.625 | 0.625 | 0.599 | 0.656 | 0.750 | 0.625 | 0.560 | 0.214 | 0.625 | 0.047 |  |
| 5 | combined | joint | 8 | pre_deployment | nb | 192 | 0.380 | 0.380 | 0.333 | 0.422 | 0.587 | 0.484 | 0.259 | 0.000 | 0.380 | 0.000 |  |
| 5 | combined | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | joint | 8 | pre_deployment | gmm | 192 | 0.339 | 0.339 | 0.333 | 0.349 | 0.559 | 0.349 | 0.224 | 0.000 | 0.339 | 0.000 |  |
| 5 | combined | joint | 32 | retrained | nb | 48 | 0.771 | 0.771 | 0.667 | 0.876 | 0.847 | 0.771 | 0.771 | 0.647 | 0.771 | 0.625 |  |
| 5 | combined | joint | 32 | retrained | ff_ann | 24 | 0.708 |  |  |  | 0.806 | 0.708 | 0.709 | 0.556 | 0.708 | 0.500 | random 75/25 (Formby) |
| 5 | combined | joint | 32 | retrained | gmm | 48 | 0.688 | 0.688 | 0.667 | 0.729 | 0.792 | 0.688 | 0.839 | 0.516 | 0.688 | 0.062 |  |
| 5 | combined | joint | 32 | pre_deployment | nb | 48 | 0.354 | 0.354 | 0.292 | 0.417 | 0.569 | 0.458 | 0.237 | 0.000 | 0.354 | 0.000 |  |
| 5 | combined | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 5 | combined | joint | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.500 | 0.833 | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.500 |  |
| 5 | combined | joint | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.476 | 0.000 | 0.583 | 0.000 | random 75/25 (Formby) |
| 5 | combined | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 5 | combined | joint | 64 | pre_deployment | nb | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.417 | 0.283 | 0.000 | 0.375 | 0.000 |  |
| 5 | combined | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 5 | combined | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | off | clrt | 8 | retrained | nb | 192 | 0.526 | 0.526 | 0.458 | 0.594 | 0.684 | 0.615 | 0.515 | 0.404 | 0.526 | 0.328 |  |
| 10 | off | clrt | 8 | retrained | ff_ann | 96 | 0.427 |  |  |  | 0.618 | 0.573 | 0.425 | 0.320 | 0.427 | 0.250 | random 75/25 (Formby) |
| 10 | off | clrt | 8 | retrained | gmm | 192 | 0.349 | 0.349 | 0.297 | 0.396 | 0.566 | 0.396 | 0.474 | 0.329 | 0.349 | 0.094 |  |
| 10 | off | clrt | 8 | pre_deployment | nb | 192 | 0.526 | 0.526 | 0.458 | 0.594 | 0.684 | 0.615 | 0.515 | 0.404 | 0.526 | 0.328 |  |
| 10 | off | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | clrt | 8 | pre_deployment | gmm | 192 | 0.349 | 0.349 | 0.297 | 0.396 | 0.566 | 0.396 | 0.474 | 0.329 | 0.349 | 0.094 |  |
| 10 | off | clrt | 32 | retrained | nb | 48 | 0.646 | 0.646 | 0.479 | 0.792 | 0.764 | 0.667 | 0.656 | 0.500 | 0.646 | 0.562 |  |
| 10 | off | clrt | 32 | retrained | ff_ann | 24 | 0.542 |  |  |  | 0.694 | 0.583 | 0.596 | 0.417 | 0.542 | 0.500 | random 75/25 (Formby) |
| 10 | off | clrt | 32 | retrained | gmm | 48 | 0.417 | 0.417 | 0.354 | 0.500 | 0.611 | 0.521 | 0.494 | 0.333 | 0.417 | 0.188 |  |
| 10 | off | clrt | 32 | pre_deployment | nb | 48 | 0.646 | 0.646 | 0.479 | 0.792 | 0.764 | 0.667 | 0.656 | 0.500 | 0.646 | 0.562 |  |
| 10 | off | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | clrt | 32 | pre_deployment | gmm | 48 | 0.417 | 0.417 | 0.354 | 0.500 | 0.611 | 0.521 | 0.494 | 0.333 | 0.417 | 0.188 |  |
| 10 | off | clrt | 64 | retrained | nb | 24 | 0.708 | 0.708 | 0.583 | 0.833 | 0.806 | 0.708 | 0.704 | 0.571 | 0.708 | 0.500 |  |
| 10 | off | clrt | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.700 | 0.500 | 0.667 | 0.500 | random 75/25 (Formby) |
| 10 | off | clrt | 64 | retrained | gmm | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.500 | 0.333 | 0.000 | 0.375 | 0.000 |  |
| 10 | off | clrt | 64 | pre_deployment | nb | 24 | 0.708 | 0.708 | 0.583 | 0.833 | 0.806 | 0.708 | 0.704 | 0.571 | 0.708 | 0.500 |  |
| 10 | off | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | clrt | 64 | pre_deployment | gmm | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.500 | 0.333 | 0.000 | 0.375 | 0.000 |  |
| 10 | off | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | off | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | off | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | off | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | off | joint | 8 | retrained | nb | 192 | 0.849 | 0.849 | 0.807 | 0.896 | 0.899 | 0.849 | 0.849 | 0.769 | 0.849 | 0.766 |  |
| 10 | off | joint | 8 | retrained | ff_ann | 96 | 0.781 |  |  |  | 0.854 | 0.781 | 0.781 | 0.667 | 0.781 | 0.656 | random 75/25 (Formby) |
| 10 | off | joint | 8 | retrained | gmm | 192 | 0.693 | 0.693 | 0.651 | 0.734 | 0.795 | 0.693 | 0.708 | 0.524 | 0.693 | 0.234 |  |
| 10 | off | joint | 8 | pre_deployment | nb | 192 | 0.849 | 0.849 | 0.807 | 0.896 | 0.899 | 0.849 | 0.849 | 0.769 | 0.849 | 0.766 |  |
| 10 | off | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | joint | 8 | pre_deployment | gmm | 192 | 0.693 | 0.693 | 0.651 | 0.734 | 0.795 | 0.693 | 0.708 | 0.524 | 0.693 | 0.234 |  |
| 10 | off | joint | 32 | retrained | nb | 48 | 0.938 | 0.938 | 0.875 | 0.979 | 0.958 | 0.938 | 0.947 | 0.842 | 0.938 | 0.812 |  |
| 10 | off | joint | 32 | retrained | ff_ann | 24 | 0.958 |  |  |  | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 | random 75/25 (Formby) |
| 10 | off | joint | 32 | retrained | gmm | 48 | 0.729 | 0.729 | 0.646 | 0.812 | 0.819 | 0.729 | 0.758 | 0.560 | 0.729 | 0.312 |  |
| 10 | off | joint | 32 | pre_deployment | nb | 48 | 0.938 | 0.938 | 0.875 | 0.979 | 0.958 | 0.938 | 0.947 | 0.842 | 0.938 | 0.812 |  |
| 10 | off | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | joint | 32 | pre_deployment | gmm | 48 | 0.729 | 0.729 | 0.646 | 0.812 | 0.819 | 0.729 | 0.758 | 0.560 | 0.729 | 0.312 |  |
| 10 | off | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 10 | off | joint | 64 | retrained | ff_ann | 12 | 0.917 |  |  |  | 0.944 | 0.917 | 0.933 | 0.800 | 0.917 | 0.750 | random 75/25 (Formby) |
| 10 | off | joint | 64 | retrained | gmm | 24 | 0.708 | 0.708 | 0.667 | 0.792 | 0.806 | 0.708 | 0.844 | 0.533 | 0.708 | 0.125 |  |
| 10 | off | joint | 64 | pre_deployment | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 10 | off | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | off | joint | 64 | pre_deployment | gmm | 24 | 0.708 | 0.708 | 0.667 | 0.792 | 0.806 | 0.708 | 0.844 | 0.533 | 0.708 | 0.125 |  |
| 10 | timing_only | clrt | 8 | retrained | nb | 192 | 0.312 | 0.312 | 0.266 | 0.359 | 0.542 | 0.510 | 0.313 | 0.266 | 0.312 | 0.266 |  |
| 10 | timing_only | clrt | 8 | retrained | ff_ann | 96 | 0.344 |  |  |  | 0.562 | 0.542 | 0.344 | 0.323 | 0.344 | 0.312 | random 75/25 (Formby) |
| 10 | timing_only | clrt | 8 | retrained | gmm | 192 | 0.354 | 0.354 | 0.323 | 0.385 | 0.569 | 0.422 | 0.242 | 0.000 | 0.354 | 0.000 |  |
| 10 | timing_only | clrt | 8 | pre_deployment | nb | 192 | 0.271 | 0.271 | 0.208 | 0.349 | 0.514 | 0.406 | 0.253 | 0.167 | 0.271 | 0.078 |  |
| 10 | timing_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | timing_only | clrt | 32 | retrained | nb | 48 | 0.375 | 0.375 | 0.229 | 0.500 | 0.583 | 0.479 | 0.394 | 0.320 | 0.375 | 0.250 |  |
| 10 | timing_only | clrt | 32 | retrained | ff_ann | 24 | 0.458 |  |  |  | 0.639 | 0.583 | 0.444 | 0.333 | 0.458 | 0.250 | random 75/25 (Formby) |
| 10 | timing_only | clrt | 32 | retrained | gmm | 48 | 0.292 | 0.292 | 0.229 | 0.375 | 0.528 | 0.312 | 0.193 | 0.000 | 0.292 | 0.000 |  |
| 10 | timing_only | clrt | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.208 | 0.438 | 0.556 | 0.396 | 0.236 | 0.000 | 0.333 | 0.000 |  |
| 10 | timing_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | timing_only | clrt | 64 | retrained | nb | 24 | 0.375 | 0.375 | 0.167 | 0.542 | 0.583 | 0.458 | 0.411 | 0.333 | 0.375 | 0.250 |  |
| 10 | timing_only | clrt | 64 | retrained | ff_ann | 12 | 0.417 |  |  |  | 0.611 | 0.500 | 0.365 | 0.000 | 0.417 | 0.000 | random 75/25 (Formby) |
| 10 | timing_only | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.167 | 0.500 | 0.556 | 0.417 | 0.229 | 0.000 | 0.333 | 0.000 |  |
| 10 | timing_only | clrt | 64 | pre_deployment | nb | 24 | 0.292 | 0.292 | 0.167 | 0.417 | 0.528 | 0.292 | 0.206 | 0.000 | 0.292 | 0.000 |  |
| 10 | timing_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | timing_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | timing_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | timing_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | timing_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 8 | retrained | nb | 192 | 0.651 | 0.651 | 0.589 | 0.719 | 0.767 | 0.651 | 0.651 | 0.474 | 0.651 | 0.422 |  |
| 10 | timing_only | joint | 8 | retrained | ff_ann | 96 | 0.656 |  |  |  | 0.771 | 0.656 | 0.656 | 0.484 | 0.656 | 0.469 | random 75/25 (Formby) |
| 10 | timing_only | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 8 | pre_deployment | nb | 192 | 0.646 | 0.646 | 0.578 | 0.714 | 0.764 | 0.646 | 0.642 | 0.450 | 0.646 | 0.281 |  |
| 10 | timing_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.562 | 0.771 | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.438 |  |
| 10 | timing_only | joint | 32 | retrained | ff_ann | 24 | 0.625 |  |  |  | 0.750 | 0.625 | 0.618 | 0.400 | 0.625 | 0.250 | random 75/25 (Formby) |
| 10 | timing_only | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.542 | 0.771 | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.188 |  |
| 10 | timing_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 64 | retrained | nb | 24 | 0.708 | 0.708 | 0.542 | 0.875 | 0.806 | 0.708 | 0.715 | 0.545 | 0.708 | 0.375 |  |
| 10 | timing_only | joint | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.476 | 0.000 | 0.583 | 0.000 | random 75/25 (Formby) |
| 10 | timing_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | timing_only | joint | 64 | pre_deployment | nb | 24 | 0.625 | 0.625 | 0.500 | 0.750 | 0.750 | 0.625 | 0.598 | 0.333 | 0.625 | 0.125 |  |
| 10 | timing_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | timing_only | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | clrt | 8 | retrained | nb | 192 | 0.464 | 0.464 | 0.396 | 0.531 | 0.642 | 0.542 | 0.469 | 0.329 | 0.464 | 0.359 |  |
| 10 | size_only | clrt | 8 | retrained | ff_ann | 96 | 0.479 |  |  |  | 0.653 | 0.594 | 0.480 | 0.394 | 0.479 | 0.406 | random 75/25 (Formby) |
| 10 | size_only | clrt | 8 | retrained | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | clrt | 8 | pre_deployment | nb | 192 | 0.448 | 0.448 | 0.380 | 0.510 | 0.632 | 0.547 | 0.458 | 0.333 | 0.448 | 0.359 |  |
| 10 | size_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | clrt | 8 | pre_deployment | gmm | 192 | 0.380 | 0.380 | 0.344 | 0.417 | 0.587 | 0.422 | 0.578 | 0.346 | 0.380 | 0.125 |  |
| 10 | size_only | clrt | 32 | retrained | nb | 48 | 0.562 | 0.562 | 0.417 | 0.688 | 0.708 | 0.583 | 0.556 | 0.375 | 0.562 | 0.375 |  |
| 10 | size_only | clrt | 32 | retrained | ff_ann | 24 | 0.625 |  |  |  | 0.750 | 0.625 | 0.615 | 0.429 | 0.625 | 0.375 | random 75/25 (Formby) |
| 10 | size_only | clrt | 32 | retrained | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | clrt | 32 | pre_deployment | nb | 48 | 0.583 | 0.583 | 0.417 | 0.750 | 0.722 | 0.625 | 0.616 | 0.455 | 0.583 | 0.562 |  |
| 10 | size_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | clrt | 32 | pre_deployment | gmm | 48 | 0.438 | 0.438 | 0.333 | 0.542 | 0.625 | 0.458 | 0.546 | 0.286 | 0.438 | 0.125 |  |
| 10 | size_only | clrt | 64 | retrained | nb | 24 | 0.625 | 0.625 | 0.417 | 0.833 | 0.750 | 0.625 | 0.642 | 0.444 | 0.625 | 0.500 |  |
| 10 | size_only | clrt | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.633 | 0.400 | 0.583 | 0.500 | random 75/25 (Formby) |
| 10 | size_only | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | clrt | 64 | pre_deployment | nb | 24 | 0.625 | 0.625 | 0.375 | 0.875 | 0.750 | 0.625 | 0.698 | 0.462 | 0.625 | 0.500 |  |
| 10 | size_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | clrt | 64 | pre_deployment | gmm | 24 | 0.167 | 0.167 | 0.042 | 0.292 | 0.444 | 0.333 | 0.103 | 0.000 | 0.167 | 0.000 |  |
| 10 | size_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | size_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | size_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | size_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | size_only | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | joint | 8 | retrained | nb | 192 | 0.839 | 0.839 | 0.818 | 0.859 | 0.892 | 0.839 | 0.842 | 0.726 | 0.839 | 0.688 |  |
| 10 | size_only | joint | 8 | retrained | ff_ann | 96 | 0.823 |  |  |  | 0.882 | 0.823 | 0.824 | 0.714 | 0.823 | 0.688 | random 75/25 (Formby) |
| 10 | size_only | joint | 8 | retrained | gmm | 192 | 0.656 | 0.656 | 0.641 | 0.667 | 0.771 | 0.656 | 0.500 | 0.000 | 0.656 | 0.000 |  |
| 10 | size_only | joint | 8 | pre_deployment | nb | 192 | 0.448 | 0.448 | 0.380 | 0.510 | 0.632 | 0.547 | 0.458 | 0.333 | 0.448 | 0.359 |  |
| 10 | size_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.297 | 0.375 | 0.556 | 0.411 | 0.213 | 0.000 | 0.333 | 0.000 |  |
| 10 | size_only | joint | 32 | retrained | nb | 48 | 0.958 | 0.958 | 0.896 | 1.000 | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 |  |
| 10 | size_only | joint | 32 | retrained | ff_ann | 24 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 10 | size_only | joint | 32 | retrained | gmm | 48 | 0.604 | 0.604 | 0.542 | 0.646 | 0.736 | 0.604 | 0.500 | 0.000 | 0.604 | 0.000 |  |
| 10 | size_only | joint | 32 | pre_deployment | nb | 48 | 0.583 | 0.583 | 0.417 | 0.750 | 0.722 | 0.625 | 0.616 | 0.455 | 0.583 | 0.562 |  |
| 10 | size_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | joint | 32 | pre_deployment | gmm | 48 | 0.292 | 0.292 | 0.229 | 0.375 | 0.528 | 0.458 | 0.165 | 0.000 | 0.292 | 0.000 |  |
| 10 | size_only | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 10 | size_only | joint | 64 | retrained | ff_ann | 12 | 0.917 |  |  |  | 0.944 | 0.917 | 0.933 | 0.800 | 0.917 | 0.750 | random 75/25 (Formby) |
| 10 | size_only | joint | 64 | retrained | gmm | 24 | 0.458 | 0.458 | 0.375 | 0.583 | 0.639 | 0.458 | 0.500 | 0.000 | 0.458 | 0.000 |  |
| 10 | size_only | joint | 64 | pre_deployment | nb | 24 | 0.625 | 0.625 | 0.375 | 0.875 | 0.750 | 0.625 | 0.698 | 0.462 | 0.625 | 0.500 |  |
| 10 | size_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | size_only | joint | 64 | pre_deployment | gmm | 24 | 0.417 | 0.417 | 0.333 | 0.500 | 0.611 | 0.417 | 0.455 | 0.000 | 0.417 | 0.000 |  |
| 10 | combined | clrt | 8 | retrained | nb | 192 | 0.385 | 0.385 | 0.344 | 0.427 | 0.590 | 0.557 | 0.392 | 0.352 | 0.385 | 0.375 |  |
| 10 | combined | clrt | 8 | retrained | ff_ann | 96 | 0.323 |  |  |  | 0.549 | 0.510 | 0.316 | 0.222 | 0.323 | 0.188 | random 75/25 (Formby) |
| 10 | combined | clrt | 8 | retrained | gmm | 192 | 0.344 | 0.344 | 0.302 | 0.385 | 0.562 | 0.552 | 0.333 | 0.280 | 0.344 | 0.219 |  |
| 10 | combined | clrt | 8 | pre_deployment | nb | 192 | 0.292 | 0.292 | 0.240 | 0.359 | 0.528 | 0.448 | 0.256 | 0.167 | 0.292 | 0.062 |  |
| 10 | combined | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | clrt | 32 | retrained | nb | 48 | 0.375 | 0.375 | 0.292 | 0.438 | 0.583 | 0.521 | 0.395 | 0.333 | 0.375 | 0.312 |  |
| 10 | combined | clrt | 32 | retrained | ff_ann | 24 | 0.292 |  |  |  | 0.528 | 0.458 | 0.280 | 0.200 | 0.292 | 0.125 | random 75/25 (Formby) |
| 10 | combined | clrt | 32 | retrained | gmm | 48 | 0.250 | 0.250 | 0.083 | 0.458 | 0.500 | 0.375 | 0.291 | 0.182 | 0.250 | 0.188 |  |
| 10 | combined | clrt | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.250 | 0.417 | 0.556 | 0.417 | 0.244 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | clrt | 64 | retrained | nb | 24 | 0.458 | 0.458 | 0.333 | 0.583 | 0.639 | 0.583 | 0.453 | 0.375 | 0.458 | 0.375 |  |
| 10 | combined | clrt | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.698 | 0.429 | 0.583 | 0.500 | random 75/25 (Formby) |
| 10 | combined | clrt | 64 | retrained | gmm | 24 | 0.250 | 0.250 | 0.125 | 0.333 | 0.500 | 0.292 | 0.095 | 0.000 | 0.250 | 0.000 |  |
| 10 | combined | clrt | 64 | pre_deployment | nb | 24 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.458 | 0.294 | 0.000 | 0.375 | 0.000 |  |
| 10 | combined | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | combined | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | combined | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 10 | combined | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 10 | combined | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | joint | 8 | retrained | nb | 192 | 0.682 | 0.682 | 0.646 | 0.724 | 0.788 | 0.682 | 0.682 | 0.522 | 0.682 | 0.500 |  |
| 10 | combined | joint | 8 | retrained | ff_ann | 96 | 0.688 |  |  |  | 0.792 | 0.688 | 0.688 | 0.528 | 0.688 | 0.469 | random 75/25 (Formby) |
| 10 | combined | joint | 8 | retrained | gmm | 192 | 0.688 | 0.688 | 0.641 | 0.734 | 0.792 | 0.688 | 0.688 | 0.526 | 0.688 | 0.438 |  |
| 10 | combined | joint | 8 | pre_deployment | nb | 192 | 0.312 | 0.312 | 0.266 | 0.375 | 0.542 | 0.469 | 0.274 | 0.167 | 0.312 | 0.062 |  |
| 10 | combined | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | joint | 32 | retrained | nb | 48 | 0.688 | 0.688 | 0.604 | 0.792 | 0.792 | 0.688 | 0.688 | 0.529 | 0.688 | 0.500 |  |
| 10 | combined | joint | 32 | retrained | ff_ann | 24 | 0.750 |  |  |  | 0.833 | 0.750 | 0.750 | 0.625 | 0.750 | 0.625 | random 75/25 (Formby) |
| 10 | combined | joint | 32 | retrained | gmm | 48 | 0.646 | 0.646 | 0.604 | 0.667 | 0.764 | 0.646 | 0.495 | 0.000 | 0.646 | 0.000 |  |
| 10 | combined | joint | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.250 | 0.417 | 0.556 | 0.417 | 0.244 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 10 | combined | joint | 64 | retrained | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.833 | 0.750 | 0.833 | 0.750 |  |
| 10 | combined | joint | 64 | retrained | ff_ann | 12 | 0.750 |  |  |  | 0.833 | 0.750 | 0.756 | 0.600 | 0.750 | 0.500 | random 75/25 (Formby) |
| 10 | combined | joint | 64 | retrained | gmm | 24 | 0.500 | 0.500 | 0.375 | 0.625 | 0.667 | 0.500 | 0.500 | 0.000 | 0.500 | 0.000 |  |
| 10 | combined | joint | 64 | pre_deployment | nb | 24 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.458 | 0.294 | 0.000 | 0.375 | 0.000 |  |
| 10 | combined | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 10 | combined | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | off | clrt | 8 | retrained | nb | 192 | 0.536 | 0.536 | 0.458 | 0.620 | 0.691 | 0.609 | 0.533 | 0.410 | 0.536 | 0.391 |  |
| 15 | off | clrt | 8 | retrained | ff_ann | 96 | 0.510 |  |  |  | 0.674 | 0.615 | 0.503 | 0.407 | 0.510 | 0.344 | random 75/25 (Formby) |
| 15 | off | clrt | 8 | retrained | gmm | 192 | 0.328 | 0.328 | 0.292 | 0.375 | 0.552 | 0.411 | 0.222 | 0.000 | 0.328 | 0.000 |  |
| 15 | off | clrt | 8 | pre_deployment | nb | 192 | 0.536 | 0.536 | 0.458 | 0.620 | 0.691 | 0.609 | 0.533 | 0.410 | 0.536 | 0.391 |  |
| 15 | off | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | clrt | 8 | pre_deployment | gmm | 192 | 0.328 | 0.328 | 0.292 | 0.375 | 0.552 | 0.411 | 0.222 | 0.000 | 0.328 | 0.000 |  |
| 15 | off | clrt | 32 | retrained | nb | 48 | 0.708 | 0.708 | 0.583 | 0.812 | 0.806 | 0.708 | 0.697 | 0.571 | 0.708 | 0.500 |  |
| 15 | off | clrt | 32 | retrained | ff_ann | 24 | 0.625 |  |  |  | 0.750 | 0.625 | 0.675 | 0.455 | 0.625 | 0.500 | random 75/25 (Formby) |
| 15 | off | clrt | 32 | retrained | gmm | 48 | 0.333 | 0.333 | 0.250 | 0.417 | 0.556 | 0.479 | 0.210 | 0.000 | 0.333 | 0.000 |  |
| 15 | off | clrt | 32 | pre_deployment | nb | 48 | 0.708 | 0.708 | 0.583 | 0.812 | 0.806 | 0.708 | 0.697 | 0.571 | 0.708 | 0.500 |  |
| 15 | off | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.250 | 0.417 | 0.556 | 0.479 | 0.210 | 0.000 | 0.333 | 0.000 |  |
| 15 | off | clrt | 64 | retrained | nb | 24 | 0.750 | 0.750 | 0.583 | 0.917 | 0.833 | 0.750 | 0.758 | 0.636 | 0.750 | 0.375 |  |
| 15 | off | clrt | 64 | retrained | ff_ann | 12 | 0.750 |  |  |  | 0.833 | 0.750 | 0.739 | 0.667 | 0.750 | 0.500 | random 75/25 (Formby) |
| 15 | off | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | off | clrt | 64 | pre_deployment | nb | 24 | 0.750 | 0.750 | 0.583 | 0.917 | 0.833 | 0.750 | 0.758 | 0.636 | 0.750 | 0.375 |  |
| 15 | off | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | off | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | off | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | off | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | off | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 8 | retrained | nb | 192 | 0.870 | 0.870 | 0.833 | 0.906 | 0.913 | 0.870 | 0.870 | 0.800 | 0.870 | 0.797 |  |
| 15 | off | joint | 8 | retrained | ff_ann | 96 | 0.896 |  |  |  | 0.931 | 0.896 | 0.899 | 0.806 | 0.896 | 0.781 | random 75/25 (Formby) |
| 15 | off | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 8 | pre_deployment | nb | 192 | 0.870 | 0.870 | 0.833 | 0.906 | 0.913 | 0.870 | 0.870 | 0.800 | 0.870 | 0.797 |  |
| 15 | off | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 32 | retrained | nb | 48 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 15 | off | joint | 32 | retrained | ff_ann | 24 | 0.958 |  |  |  | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 | random 75/25 (Formby) |
| 15 | off | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 32 | pre_deployment | nb | 48 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 15 | off | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 15 | off | joint | 64 | retrained | ff_ann | 12 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 15 | off | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | off | joint | 64 | pre_deployment | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 15 | off | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | off | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | clrt | 8 | retrained | nb | 192 | 0.375 | 0.375 | 0.312 | 0.448 | 0.583 | 0.568 | 0.371 | 0.327 | 0.375 | 0.266 |  |
| 15 | timing_only | clrt | 8 | retrained | ff_ann | 96 | 0.312 |  |  |  | 0.542 | 0.490 | 0.316 | 0.270 | 0.312 | 0.312 | random 75/25 (Formby) |
| 15 | timing_only | clrt | 8 | retrained | gmm | 192 | 0.333 | 0.333 | 0.286 | 0.385 | 0.556 | 0.406 | 0.224 | 0.000 | 0.333 | 0.000 |  |
| 15 | timing_only | clrt | 8 | pre_deployment | nb | 192 | 0.328 | 0.328 | 0.260 | 0.396 | 0.552 | 0.526 | 0.317 | 0.224 | 0.328 | 0.172 |  |
| 15 | timing_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | timing_only | clrt | 32 | retrained | nb | 48 | 0.333 | 0.333 | 0.229 | 0.458 | 0.556 | 0.500 | 0.296 | 0.100 | 0.333 | 0.062 |  |
| 15 | timing_only | clrt | 32 | retrained | ff_ann | 24 | 0.583 |  |  |  | 0.722 | 0.667 | 0.619 | 0.500 | 0.583 | 0.500 | random 75/25 (Formby) |
| 15 | timing_only | clrt | 32 | retrained | gmm | 48 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.500 | 0.247 | 0.000 | 0.375 | 0.000 |  |
| 15 | timing_only | clrt | 32 | pre_deployment | nb | 48 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.521 | 0.318 | 0.182 | 0.375 | 0.125 |  |
| 15 | timing_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | timing_only | clrt | 64 | retrained | nb | 24 | 0.375 | 0.375 | 0.250 | 0.500 | 0.583 | 0.542 | 0.285 | 0.000 | 0.375 | 0.000 |  |
| 15 | timing_only | clrt | 64 | retrained | ff_ann | 12 | 0.333 |  |  |  | 0.556 | 0.500 | 0.278 | 0.000 | 0.333 | 0.000 | random 75/25 (Formby) |
| 15 | timing_only | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | timing_only | clrt | 64 | pre_deployment | nb | 24 | 0.417 | 0.417 | 0.333 | 0.542 | 0.611 | 0.583 | 0.361 | 0.250 | 0.417 | 0.125 |  |
| 15 | timing_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | timing_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | timing_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | timing_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | timing_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 8 | retrained | nb | 192 | 0.677 | 0.677 | 0.615 | 0.740 | 0.785 | 0.677 | 0.677 | 0.513 | 0.677 | 0.422 |  |
| 15 | timing_only | joint | 8 | retrained | ff_ann | 96 | 0.646 |  |  |  | 0.764 | 0.646 | 0.645 | 0.462 | 0.646 | 0.375 | random 75/25 (Formby) |
| 15 | timing_only | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 8 | pre_deployment | nb | 192 | 0.698 | 0.698 | 0.656 | 0.740 | 0.799 | 0.698 | 0.699 | 0.539 | 0.698 | 0.453 |  |
| 15 | timing_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 32 | retrained | nb | 48 | 0.625 | 0.625 | 0.500 | 0.750 | 0.750 | 0.625 | 0.622 | 0.417 | 0.625 | 0.312 |  |
| 15 | timing_only | joint | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.500 | random 75/25 (Formby) |
| 15 | timing_only | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 32 | pre_deployment | nb | 48 | 0.688 | 0.688 | 0.667 | 0.729 | 0.792 | 0.688 | 0.706 | 0.519 | 0.688 | 0.188 |  |
| 15 | timing_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 64 | retrained | nb | 24 | 0.542 | 0.542 | 0.417 | 0.625 | 0.694 | 0.542 | 0.462 | 0.000 | 0.542 | 0.000 |  |
| 15 | timing_only | joint | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.500 | random 75/25 (Formby) |
| 15 | timing_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | timing_only | joint | 64 | pre_deployment | nb | 24 | 0.708 | 0.708 | 0.667 | 0.792 | 0.806 | 0.708 | 0.735 | 0.538 | 0.708 | 0.250 |  |
| 15 | timing_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | timing_only | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | clrt | 8 | retrained | nb | 192 | 0.484 | 0.484 | 0.427 | 0.547 | 0.656 | 0.557 | 0.494 | 0.364 | 0.484 | 0.406 |  |
| 15 | size_only | clrt | 8 | retrained | ff_ann | 96 | 0.479 |  |  |  | 0.653 | 0.594 | 0.480 | 0.400 | 0.479 | 0.406 | random 75/25 (Formby) |
| 15 | size_only | clrt | 8 | retrained | gmm | 192 | 0.349 | 0.349 | 0.323 | 0.375 | 0.566 | 0.443 | 0.232 | 0.000 | 0.349 | 0.000 |  |
| 15 | size_only | clrt | 8 | pre_deployment | nb | 192 | 0.547 | 0.547 | 0.469 | 0.635 | 0.698 | 0.661 | 0.542 | 0.490 | 0.547 | 0.391 |  |
| 15 | size_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.312 | 0.354 | 0.556 | 0.438 | 0.220 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | clrt | 32 | retrained | nb | 48 | 0.604 | 0.604 | 0.479 | 0.708 | 0.736 | 0.646 | 0.602 | 0.471 | 0.604 | 0.500 |  |
| 15 | size_only | clrt | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.667 | 0.500 | 0.667 | 0.500 | random 75/25 (Formby) |
| 15 | size_only | clrt | 32 | retrained | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | clrt | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.542 | 0.771 | 0.778 | 0.750 | 0.667 | 0.611 | 0.667 | 0.500 |  |
| 15 | size_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | clrt | 32 | pre_deployment | gmm | 48 | 0.312 | 0.312 | 0.229 | 0.396 | 0.542 | 0.458 | 0.204 | 0.000 | 0.312 | 0.000 |  |
| 15 | size_only | clrt | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.690 | 0.500 | 0.667 | 0.500 |  |
| 15 | size_only | clrt | 64 | retrained | ff_ann | 12 | 0.750 |  |  |  | 0.833 | 0.750 | 0.783 | 0.600 | 0.750 | 0.750 | random 75/25 (Formby) |
| 15 | size_only | clrt | 64 | retrained | gmm | 24 | 0.375 | 0.375 | 0.333 | 0.458 | 0.583 | 0.458 | 0.238 | 0.000 | 0.375 | 0.000 |  |
| 15 | size_only | clrt | 64 | pre_deployment | nb | 24 | 0.792 | 0.792 | 0.667 | 0.917 | 0.861 | 0.792 | 0.794 | 0.667 | 0.792 | 0.625 |  |
| 15 | size_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | size_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | size_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | size_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | joint | 8 | retrained | nb | 192 | 0.854 | 0.854 | 0.786 | 0.917 | 0.903 | 0.854 | 0.855 | 0.765 | 0.854 | 0.750 |  |
| 15 | size_only | joint | 8 | retrained | ff_ann | 96 | 0.781 |  |  |  | 0.854 | 0.781 | 0.784 | 0.649 | 0.781 | 0.594 | random 75/25 (Formby) |
| 15 | size_only | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | joint | 8 | pre_deployment | nb | 192 | 0.547 | 0.547 | 0.469 | 0.635 | 0.698 | 0.661 | 0.542 | 0.490 | 0.547 | 0.391 |  |
| 15 | size_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | joint | 32 | retrained | nb | 48 | 0.896 | 0.896 | 0.792 | 0.979 | 0.931 | 0.896 | 0.897 | 0.824 | 0.896 | 0.812 |  |
| 15 | size_only | joint | 32 | retrained | ff_ann | 24 | 0.917 |  |  |  | 0.944 | 0.917 | 0.917 | 0.875 | 0.917 | 0.875 | random 75/25 (Formby) |
| 15 | size_only | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | joint | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.542 | 0.771 | 0.778 | 0.750 | 0.667 | 0.611 | 0.667 | 0.500 |  |
| 15 | size_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | size_only | joint | 64 | retrained | nb | 24 | 0.958 | 0.958 | 0.875 | 1.000 | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 |  |
| 15 | size_only | joint | 64 | retrained | ff_ann | 12 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 15 | size_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | size_only | joint | 64 | pre_deployment | nb | 24 | 0.792 | 0.792 | 0.667 | 0.917 | 0.861 | 0.792 | 0.794 | 0.667 | 0.792 | 0.625 |  |
| 15 | size_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | size_only | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | clrt | 8 | retrained | nb | 192 | 0.391 | 0.391 | 0.339 | 0.448 | 0.594 | 0.589 | 0.385 | 0.348 | 0.391 | 0.250 |  |
| 15 | combined | clrt | 8 | retrained | ff_ann | 96 | 0.312 |  |  |  | 0.542 | 0.510 | 0.313 | 0.286 | 0.312 | 0.250 | random 75/25 (Formby) |
| 15 | combined | clrt | 8 | retrained | gmm | 192 | 0.333 | 0.333 | 0.271 | 0.417 | 0.556 | 0.505 | 0.316 | 0.250 | 0.333 | 0.172 |  |
| 15 | combined | clrt | 8 | pre_deployment | nb | 192 | 0.370 | 0.370 | 0.266 | 0.469 | 0.580 | 0.557 | 0.369 | 0.343 | 0.370 | 0.312 |  |
| 15 | combined | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | clrt | 32 | retrained | nb | 48 | 0.417 | 0.417 | 0.333 | 0.500 | 0.611 | 0.562 | 0.382 | 0.222 | 0.417 | 0.125 |  |
| 15 | combined | clrt | 32 | retrained | ff_ann | 24 | 0.500 |  |  |  | 0.667 | 0.583 | 0.511 | 0.375 | 0.500 | 0.375 | random 75/25 (Formby) |
| 15 | combined | clrt | 32 | retrained | gmm | 48 | 0.375 | 0.375 | 0.292 | 0.479 | 0.583 | 0.479 | 0.383 | 0.286 | 0.375 | 0.125 |  |
| 15 | combined | clrt | 32 | pre_deployment | nb | 48 | 0.438 | 0.438 | 0.271 | 0.604 | 0.625 | 0.583 | 0.444 | 0.400 | 0.438 | 0.250 |  |
| 15 | combined | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | clrt | 64 | retrained | nb | 24 | 0.458 | 0.458 | 0.375 | 0.583 | 0.639 | 0.583 | 0.453 | 0.333 | 0.458 | 0.250 |  |
| 15 | combined | clrt | 64 | retrained | ff_ann | 12 | 0.333 |  |  |  | 0.556 | 0.417 | 0.372 | 0.200 | 0.333 | 0.250 | random 75/25 (Formby) |
| 15 | combined | clrt | 64 | retrained | gmm | 24 | 0.292 | 0.292 | 0.125 | 0.458 | 0.528 | 0.375 | 0.193 | 0.000 | 0.292 | 0.000 |  |
| 15 | combined | clrt | 64 | pre_deployment | nb | 24 | 0.458 | 0.458 | 0.250 | 0.667 | 0.639 | 0.583 | 0.501 | 0.400 | 0.458 | 0.250 |  |
| 15 | combined | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | combined | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | combined | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 15 | combined | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 15 | combined | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | joint | 8 | retrained | nb | 192 | 0.734 | 0.734 | 0.667 | 0.792 | 0.823 | 0.734 | 0.735 | 0.592 | 0.734 | 0.547 |  |
| 15 | combined | joint | 8 | retrained | ff_ann | 96 | 0.615 |  |  |  | 0.743 | 0.615 | 0.614 | 0.414 | 0.615 | 0.375 | random 75/25 (Formby) |
| 15 | combined | joint | 8 | retrained | gmm | 192 | 0.719 | 0.719 | 0.651 | 0.786 | 0.812 | 0.719 | 0.721 | 0.564 | 0.719 | 0.469 |  |
| 15 | combined | joint | 8 | pre_deployment | nb | 192 | 0.370 | 0.370 | 0.266 | 0.469 | 0.580 | 0.562 | 0.368 | 0.348 | 0.370 | 0.297 |  |
| 15 | combined | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | joint | 32 | retrained | nb | 48 | 0.812 | 0.812 | 0.729 | 0.896 | 0.875 | 0.812 | 0.818 | 0.684 | 0.812 | 0.625 |  |
| 15 | combined | joint | 32 | retrained | ff_ann | 24 | 0.750 |  |  |  | 0.833 | 0.750 | 0.750 | 0.625 | 0.750 | 0.625 | random 75/25 (Formby) |
| 15 | combined | joint | 32 | retrained | gmm | 48 | 0.708 | 0.708 | 0.625 | 0.771 | 0.806 | 0.708 | 0.762 | 0.536 | 0.708 | 0.188 |  |
| 15 | combined | joint | 32 | pre_deployment | nb | 48 | 0.438 | 0.438 | 0.271 | 0.604 | 0.625 | 0.583 | 0.444 | 0.400 | 0.438 | 0.250 |  |
| 15 | combined | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 15 | combined | joint | 64 | retrained | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.833 | 0.750 | 0.833 | 0.750 |  |
| 15 | combined | joint | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.578 | 0.333 | 0.583 | 0.250 | random 75/25 (Formby) |
| 15 | combined | joint | 64 | retrained | gmm | 24 | 0.708 | 0.708 | 0.542 | 0.875 | 0.806 | 0.708 | 0.715 | 0.545 | 0.708 | 0.375 |  |
| 15 | combined | joint | 64 | pre_deployment | nb | 24 | 0.458 | 0.458 | 0.250 | 0.667 | 0.639 | 0.583 | 0.501 | 0.400 | 0.458 | 0.250 |  |
| 15 | combined | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 15 | combined | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | off | clrt | 8 | retrained | nb | 192 | 0.490 | 0.490 | 0.443 | 0.531 | 0.660 | 0.625 | 0.483 | 0.429 | 0.490 | 0.375 |  |
| 20 | off | clrt | 8 | retrained | ff_ann | 96 | 0.385 |  |  |  | 0.590 | 0.552 | 0.379 | 0.296 | 0.385 | 0.250 | random 75/25 (Formby) |
| 20 | off | clrt | 8 | retrained | gmm | 192 | 0.349 | 0.349 | 0.333 | 0.365 | 0.566 | 0.354 | 0.363 | 0.000 | 0.349 | 0.000 |  |
| 20 | off | clrt | 8 | pre_deployment | nb | 192 | 0.490 | 0.490 | 0.443 | 0.531 | 0.660 | 0.625 | 0.483 | 0.429 | 0.490 | 0.375 |  |
| 20 | off | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | clrt | 8 | pre_deployment | gmm | 192 | 0.349 | 0.349 | 0.333 | 0.365 | 0.566 | 0.354 | 0.363 | 0.000 | 0.349 | 0.000 |  |
| 20 | off | clrt | 32 | retrained | nb | 48 | 0.688 | 0.688 | 0.625 | 0.750 | 0.792 | 0.708 | 0.704 | 0.556 | 0.688 | 0.562 |  |
| 20 | off | clrt | 32 | retrained | ff_ann | 24 | 0.500 |  |  |  | 0.667 | 0.500 | 0.528 | 0.250 | 0.500 | 0.250 | random 75/25 (Formby) |
| 20 | off | clrt | 32 | retrained | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | off | clrt | 32 | pre_deployment | nb | 48 | 0.688 | 0.688 | 0.625 | 0.750 | 0.792 | 0.708 | 0.704 | 0.556 | 0.688 | 0.562 |  |
| 20 | off | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | off | clrt | 64 | retrained | nb | 24 | 0.750 | 0.750 | 0.583 | 0.875 | 0.833 | 0.750 | 0.793 | 0.600 | 0.750 | 0.625 |  |
| 20 | off | clrt | 64 | retrained | ff_ann | 12 | 0.750 |  |  |  | 0.833 | 0.750 | 0.800 | 0.600 | 0.750 | 0.500 | random 75/25 (Formby) |
| 20 | off | clrt | 64 | retrained | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | off | clrt | 64 | pre_deployment | nb | 24 | 0.750 | 0.750 | 0.583 | 0.875 | 0.833 | 0.750 | 0.793 | 0.600 | 0.750 | 0.625 |  |
| 20 | off | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | off | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | off | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | off | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | off | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 8 | retrained | nb | 192 | 0.786 | 0.786 | 0.734 | 0.823 | 0.858 | 0.786 | 0.786 | 0.677 | 0.786 | 0.672 |  |
| 20 | off | joint | 8 | retrained | ff_ann | 96 | 0.781 |  |  |  | 0.854 | 0.781 | 0.782 | 0.657 | 0.781 | 0.625 | random 75/25 (Formby) |
| 20 | off | joint | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 8 | pre_deployment | nb | 192 | 0.786 | 0.786 | 0.734 | 0.823 | 0.858 | 0.786 | 0.786 | 0.677 | 0.786 | 0.672 |  |
| 20 | off | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 32 | retrained | nb | 48 | 0.896 | 0.896 | 0.812 | 0.979 | 0.931 | 0.896 | 0.904 | 0.789 | 0.896 | 0.750 |  |
| 20 | off | joint | 32 | retrained | ff_ann | 24 | 0.958 |  |  |  | 0.972 | 0.958 | 0.963 | 0.889 | 0.958 | 0.875 | random 75/25 (Formby) |
| 20 | off | joint | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 32 | pre_deployment | nb | 48 | 0.896 | 0.896 | 0.812 | 0.979 | 0.931 | 0.896 | 0.904 | 0.789 | 0.896 | 0.750 |  |
| 20 | off | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 20 | off | joint | 64 | retrained | ff_ann | 12 | 0.917 |  |  |  | 0.944 | 0.917 | 0.933 | 0.800 | 0.917 | 0.750 | random 75/25 (Formby) |
| 20 | off | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | off | joint | 64 | pre_deployment | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 20 | off | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | off | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | clrt | 8 | retrained | nb | 192 | 0.380 | 0.380 | 0.333 | 0.427 | 0.587 | 0.562 | 0.378 | 0.321 | 0.380 | 0.281 |  |
| 20 | timing_only | clrt | 8 | retrained | ff_ann | 96 | 0.385 |  |  |  | 0.590 | 0.521 | 0.373 | 0.250 | 0.385 | 0.219 | random 75/25 (Formby) |
| 20 | timing_only | clrt | 8 | retrained | gmm | 192 | 0.391 | 0.391 | 0.297 | 0.484 | 0.594 | 0.521 | 0.401 | 0.348 | 0.391 | 0.266 |  |
| 20 | timing_only | clrt | 8 | pre_deployment | nb | 192 | 0.339 | 0.339 | 0.307 | 0.359 | 0.559 | 0.365 | 0.251 | 0.000 | 0.339 | 0.000 |  |
| 20 | timing_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | timing_only | clrt | 32 | retrained | nb | 48 | 0.375 | 0.375 | 0.271 | 0.458 | 0.583 | 0.500 | 0.381 | 0.267 | 0.375 | 0.250 |  |
| 20 | timing_only | clrt | 32 | retrained | ff_ann | 24 | 0.417 |  |  |  | 0.611 | 0.583 | 0.378 | 0.333 | 0.417 | 0.125 | random 75/25 (Formby) |
| 20 | timing_only | clrt | 32 | retrained | gmm | 48 | 0.292 | 0.292 | 0.187 | 0.396 | 0.528 | 0.438 | 0.298 | 0.261 | 0.292 | 0.188 |  |
| 20 | timing_only | clrt | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | timing_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | timing_only | clrt | 64 | retrained | nb | 24 | 0.417 | 0.417 | 0.250 | 0.625 | 0.611 | 0.500 | 0.383 | 0.250 | 0.417 | 0.125 |  |
| 20 | timing_only | clrt | 64 | retrained | ff_ann | 12 | 0.583 |  |  |  | 0.722 | 0.583 | 0.544 | 0.333 | 0.583 | 0.250 | random 75/25 (Formby) |
| 20 | timing_only | clrt | 64 | retrained | gmm | 24 | 0.417 | 0.417 | 0.250 | 0.625 | 0.611 | 0.500 | 0.435 | 0.250 | 0.417 | 0.250 |  |
| 20 | timing_only | clrt | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | timing_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | timing_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | timing_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 8 | pre_deployment | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | size | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | timing_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | size | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | timing_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 64 | pre_deployment | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | size | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | joint | 8 | retrained | nb | 192 | 0.719 | 0.719 | 0.667 | 0.781 | 0.812 | 0.719 | 0.719 | 0.578 | 0.719 | 0.578 |  |
| 20 | timing_only | joint | 8 | retrained | ff_ann | 96 | 0.760 |  |  |  | 0.840 | 0.760 | 0.763 | 0.622 | 0.760 | 0.562 | random 75/25 (Formby) |
| 20 | timing_only | joint | 8 | retrained | gmm | 192 | 0.698 | 0.698 | 0.630 | 0.766 | 0.799 | 0.698 | 0.699 | 0.541 | 0.698 | 0.469 |  |
| 20 | timing_only | joint | 8 | pre_deployment | nb | 192 | 0.661 | 0.661 | 0.651 | 0.667 | 0.774 | 0.661 | 0.499 | 0.000 | 0.661 | 0.000 |  |
| 20 | timing_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | joint | 8 | pre_deployment | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | joint | 32 | retrained | nb | 48 | 0.750 | 0.750 | 0.646 | 0.875 | 0.833 | 0.750 | 0.750 | 0.625 | 0.750 | 0.625 |  |
| 20 | timing_only | joint | 32 | retrained | ff_ann | 24 | 0.750 |  |  |  | 0.833 | 0.750 | 0.778 | 0.583 | 0.750 | 0.375 | random 75/25 (Formby) |
| 20 | timing_only | joint | 32 | retrained | gmm | 48 | 0.500 | 0.500 | 0.438 | 0.562 | 0.667 | 0.500 | 0.500 | 0.000 | 0.500 | 0.000 |  |
| 20 | timing_only | joint | 32 | pre_deployment | nb | 48 | 0.646 | 0.646 | 0.604 | 0.667 | 0.764 | 0.646 | 0.495 | 0.000 | 0.646 | 0.000 |  |
| 20 | timing_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | joint | 32 | pre_deployment | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | joint | 64 | retrained | nb | 24 | 0.792 | 0.792 | 0.625 | 0.958 | 0.861 | 0.792 | 0.794 | 0.667 | 0.792 | 0.625 |  |
| 20 | timing_only | joint | 64 | retrained | ff_ann | 12 | 0.917 |  |  |  | 0.944 | 0.917 | 0.933 | 0.800 | 0.917 | 0.750 | random 75/25 (Formby) |
| 20 | timing_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | timing_only | joint | 64 | pre_deployment | nb | 24 | 0.625 | 0.625 | 0.542 | 0.667 | 0.750 | 0.625 | 0.489 | 0.000 | 0.625 | 0.000 |  |
| 20 | timing_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | timing_only | joint | 64 | pre_deployment | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | clrt | 8 | retrained | nb | 192 | 0.521 | 0.521 | 0.464 | 0.578 | 0.681 | 0.630 | 0.514 | 0.436 | 0.521 | 0.375 |  |
| 20 | size_only | clrt | 8 | retrained | ff_ann | 96 | 0.427 |  |  |  | 0.618 | 0.552 | 0.433 | 0.323 | 0.427 | 0.312 | random 75/25 (Formby) |
| 20 | size_only | clrt | 8 | retrained | gmm | 192 | 0.401 | 0.401 | 0.333 | 0.469 | 0.601 | 0.443 | 0.622 | 0.354 | 0.401 | 0.062 |  |
| 20 | size_only | clrt | 8 | pre_deployment | nb | 192 | 0.484 | 0.484 | 0.417 | 0.557 | 0.656 | 0.589 | 0.466 | 0.333 | 0.484 | 0.234 |  |
| 20 | size_only | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | clrt | 8 | pre_deployment | gmm | 192 | 0.359 | 0.359 | 0.339 | 0.380 | 0.573 | 0.365 | 0.392 | 0.000 | 0.359 | 0.000 |  |
| 20 | size_only | clrt | 32 | retrained | nb | 48 | 0.625 | 0.625 | 0.521 | 0.729 | 0.750 | 0.646 | 0.629 | 0.474 | 0.625 | 0.438 |  |
| 20 | size_only | clrt | 32 | retrained | ff_ann | 24 | 0.875 |  |  |  | 0.917 | 0.875 | 0.884 | 0.778 | 0.875 | 0.875 | random 75/25 (Formby) |
| 20 | size_only | clrt | 32 | retrained | gmm | 48 | 0.458 | 0.458 | 0.375 | 0.542 | 0.639 | 0.479 | 0.540 | 0.333 | 0.458 | 0.312 |  |
| 20 | size_only | clrt | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.542 | 0.771 | 0.778 | 0.688 | 0.663 | 0.538 | 0.667 | 0.438 |  |
| 20 | size_only | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | clrt | 64 | retrained | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.844 | 0.700 | 0.833 | 0.625 |  |
| 20 | size_only | clrt | 64 | retrained | ff_ann | 12 | 0.750 |  |  |  | 0.833 | 0.750 | 0.857 | 0.571 | 0.750 | 0.500 | random 75/25 (Formby) |
| 20 | size_only | clrt | 64 | retrained | gmm | 24 | 0.500 | 0.500 | 0.375 | 0.667 | 0.667 | 0.583 | 0.514 | 0.400 | 0.500 | 0.375 |  |
| 20 | size_only | clrt | 64 | pre_deployment | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.836 | 0.800 | 0.833 | 0.625 |  |
| 20 | size_only | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | size_only | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | size_only | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | size_only | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | joint | 8 | retrained | nb | 192 | 0.849 | 0.849 | 0.797 | 0.896 | 0.899 | 0.849 | 0.849 | 0.761 | 0.849 | 0.750 |  |
| 20 | size_only | joint | 8 | retrained | ff_ann | 96 | 0.781 |  |  |  | 0.854 | 0.781 | 0.781 | 0.667 | 0.781 | 0.656 | random 75/25 (Formby) |
| 20 | size_only | joint | 8 | retrained | gmm | 192 | 0.661 | 0.661 | 0.651 | 0.667 | 0.774 | 0.661 | 0.500 | 0.000 | 0.661 | 0.000 |  |
| 20 | size_only | joint | 8 | pre_deployment | nb | 192 | 0.484 | 0.484 | 0.417 | 0.557 | 0.656 | 0.589 | 0.466 | 0.333 | 0.484 | 0.234 |  |
| 20 | size_only | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | joint | 32 | retrained | nb | 48 | 0.979 | 0.979 | 0.938 | 1.000 | 0.986 | 0.979 | 0.980 | 0.941 | 0.979 | 0.938 |  |
| 20 | size_only | joint | 32 | retrained | ff_ann | 24 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 20 | size_only | joint | 32 | retrained | gmm | 48 | 0.583 | 0.583 | 0.521 | 0.646 | 0.722 | 0.583 | 0.500 | 0.000 | 0.583 | 0.000 |  |
| 20 | size_only | joint | 32 | pre_deployment | nb | 48 | 0.667 | 0.667 | 0.542 | 0.771 | 0.778 | 0.688 | 0.663 | 0.538 | 0.667 | 0.438 |  |
| 20 | size_only | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | size_only | joint | 64 | retrained | nb | 24 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |  |
| 20 | size_only | joint | 64 | retrained | ff_ann | 12 | 1.000 |  |  |  | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | random 75/25 (Formby) |
| 20 | size_only | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | size_only | joint | 64 | pre_deployment | nb | 24 | 0.833 | 0.833 | 0.708 | 0.958 | 0.889 | 0.833 | 0.836 | 0.800 | 0.833 | 0.625 |  |
| 20 | size_only | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | size_only | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | clrt | 8 | retrained | nb | 192 | 0.328 | 0.328 | 0.286 | 0.370 | 0.552 | 0.505 | 0.331 | 0.282 | 0.328 | 0.312 |  |
| 20 | combined | clrt | 8 | retrained | ff_ann | 96 | 0.365 |  |  |  | 0.576 | 0.542 | 0.376 | 0.324 | 0.365 | 0.312 | random 75/25 (Formby) |
| 20 | combined | clrt | 8 | retrained | gmm | 192 | 0.391 | 0.391 | 0.333 | 0.453 | 0.594 | 0.552 | 0.395 | 0.372 | 0.391 | 0.172 |  |
| 20 | combined | clrt | 8 | pre_deployment | nb | 192 | 0.339 | 0.339 | 0.286 | 0.385 | 0.559 | 0.370 | 0.235 | 0.000 | 0.339 | 0.000 |  |
| 20 | combined | clrt | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | clrt | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | clrt | 32 | retrained | nb | 48 | 0.229 | 0.229 | 0.145 | 0.333 | 0.486 | 0.312 | 0.255 | 0.053 | 0.229 | 0.062 |  |
| 20 | combined | clrt | 32 | retrained | ff_ann | 24 | 0.292 |  |  |  | 0.528 | 0.500 | 0.272 | 0.167 | 0.292 | 0.125 | random 75/25 (Formby) |
| 20 | combined | clrt | 32 | retrained | gmm | 48 | 0.375 | 0.375 | 0.333 | 0.438 | 0.583 | 0.479 | 0.241 | 0.000 | 0.375 | 0.000 |  |
| 20 | combined | clrt | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | clrt | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | clrt | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | clrt | 64 | retrained | nb | 24 | 0.250 | 0.250 | 0.125 | 0.417 | 0.500 | 0.333 | 0.283 | 0.100 | 0.250 | 0.125 |  |
| 20 | combined | clrt | 64 | retrained | ff_ann | 12 | 0.500 |  |  |  | 0.667 | 0.500 | 0.644 | 0.333 | 0.500 | 0.250 | random 75/25 (Formby) |
| 20 | combined | clrt | 64 | retrained | gmm | 24 | 0.292 | 0.292 | 0.083 | 0.500 | 0.528 | 0.375 | 0.200 | 0.000 | 0.292 | 0.000 |  |
| 20 | combined | clrt | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | clrt | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | clrt | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 8 | retrained | nb | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 8 | retrained | ff_ann | 96 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | combined | size | 8 | retrained | gmm | 192 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 8 | pre_deployment | nb | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | size | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 32 | retrained | nb | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 32 | retrained | ff_ann | 24 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | combined | size | 32 | retrained | gmm | 48 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | size | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 64 | retrained | nb | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 64 | retrained | ff_ann | 12 | 0.667 |  |  |  | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 | random 75/25 (Formby) |
| 20 | combined | size | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | size | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | size | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | size | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | joint | 8 | retrained | nb | 192 | 0.672 | 0.672 | 0.641 | 0.698 | 0.781 | 0.672 | 0.672 | 0.508 | 0.672 | 0.500 |  |
| 20 | combined | joint | 8 | retrained | ff_ann | 96 | 0.677 |  |  |  | 0.785 | 0.677 | 0.677 | 0.515 | 0.677 | 0.500 | random 75/25 (Formby) |
| 20 | combined | joint | 8 | retrained | gmm | 192 | 0.688 | 0.688 | 0.672 | 0.708 | 0.792 | 0.688 | 0.703 | 0.519 | 0.688 | 0.203 |  |
| 20 | combined | joint | 8 | pre_deployment | nb | 192 | 0.339 | 0.339 | 0.286 | 0.385 | 0.559 | 0.370 | 0.235 | 0.000 | 0.339 | 0.000 |  |
| 20 | combined | joint | 8 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | joint | 8 | pre_deployment | gmm | 192 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | joint | 32 | retrained | nb | 48 | 0.792 | 0.792 | 0.729 | 0.833 | 0.861 | 0.792 | 0.800 | 0.650 | 0.792 | 0.562 |  |
| 20 | combined | joint | 32 | retrained | ff_ann | 24 | 0.625 |  |  |  | 0.750 | 0.625 | 0.624 | 0.429 | 0.625 | 0.375 | random 75/25 (Formby) |
| 20 | combined | joint | 32 | retrained | gmm | 48 | 0.458 | 0.458 | 0.417 | 0.500 | 0.639 | 0.458 | 0.500 | 0.000 | 0.458 | 0.000 |  |
| 20 | combined | joint | 32 | pre_deployment | nb | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | joint | 32 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | joint | 32 | pre_deployment | gmm | 48 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | joint | 64 | retrained | nb | 24 | 0.875 | 0.875 | 0.750 | 1.000 | 0.917 | 0.875 | 0.878 | 0.778 | 0.875 | 0.750 |  |
| 20 | combined | joint | 64 | retrained | ff_ann | 12 | 0.917 |  |  |  | 0.944 | 0.917 | 0.933 | 0.800 | 0.917 | 0.750 | random 75/25 (Formby) |
| 20 | combined | joint | 64 | retrained | gmm | 24 | 0.667 | 0.667 | 0.667 | 0.667 | 0.778 | 0.667 | 0.500 | 0.000 | 0.667 | 0.000 |  |
| 20 | combined | joint | 64 | pre_deployment | nb | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
| 20 | combined | joint | 64 | pre_deployment | ff_ann |  |  |  |  |  |  |  |  |  |  |  | Formby's FF-ANN protocol is a random 75/25 split within one arm, so it has no pre-deployment form |
| 20 | combined | joint | 64 | pre_deployment | gmm | 24 | 0.333 | 0.333 | 0.333 | 0.333 | 0.556 | 0.333 | 0.111 | 0.000 | 0.333 | 0.000 |  |
