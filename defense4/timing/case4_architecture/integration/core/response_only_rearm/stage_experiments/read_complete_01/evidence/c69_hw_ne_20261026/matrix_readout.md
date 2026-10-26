| run | D ms | planned | observed | OK outcomes | block rc | restored | all trials ok |
|---|---:|---:|---:|---:|---:|---|---|
| rc01_hw_c69_20261026_01_smoke | 5 | 4 | 4 | 4 | 1 | True | False |
| rc01_hw_c69_20261026_11_smoke | 5 | 4 | 4 | 4 | 0 | True | True |
| rc01_hw_c69_20261026_12_reference | 5 | 772 | 772 | 772 | 0 | True | True |
| rc01_hw_c69_20261026_13_reference_rest | 10 | 386 | 386 | 386 | 0 | True | True |
| rc01_hw_c69_20261026_14_reference_rest | 15 | 386 | 386 | 386 | 0 | True | True |
| rc01_hw_c69_20261026_15_reference_rest | 20 | 386 | 386 | 386 | 0 | True | True |
| rc01_hw_c69_20261026_16_persistence_graceful_950 | 20 | 66 | 66 | 66 | 0 | True | True |
| rc01_hw_c69_20261026_17_persistence_rst_950 | 20 | 66 | 66 | 66 | 0 | True | True |
| rc01_hw_c69_20261026_18_reconnect_950 | 20 | 66 | 66 | 66 | 0 | True | True |
| rc01_hw_c69_20261026_19_loss_mixed_950 | 20 | 154 | 154 | 154 | 0 | True | True |
| rc01_hw_c69_20261026_20_loss_full_950 | 20 | 154 | 154 | 154 | 0 | True | True |

| run | arm | class | n | piggyback | min ms | median ms | max ms | response bytes |
|---|---|---|---:|---:|---:|---:|---:|---|
| 01_smoke | combined | READ mixed | 1 | 0 | 5.964 | 5.964 | 5.964 | [141] |
| 01_smoke | combined | READ integrity | 1 | 0 | 4.623 | 4.623 | 4.623 | [158] |
| 01_smoke | combined | SELECT | 1 | 0 | 6.408 | 6.408 | 6.408 | [60] |
| 01_smoke | combined | OPERATE | 1 | 0 | 5.319 | 5.319 | 5.319 | [60] |
| 11_smoke | combined | READ mixed | 1 | 0 | 5.658 | 5.658 | 5.658 | [141] |
| 11_smoke | combined | READ integrity | 1 | 0 | 5.021 | 5.021 | 5.021 | [158] |
| 11_smoke | combined | SELECT | 1 | 0 | 5.358 | 5.358 | 5.358 | [60] |
| 11_smoke | combined | OPERATE | 1 | 0 | 4.989 | 4.989 | 4.989 | [60] |
| 12_reference | combined | READ mixed | 33 | 0 | 3.071 | 4.985 | 7.187 | [141] |
| 12_reference | combined | READ integrity | 32 | 0 | 2.993 | 4.842 | 6.949 | [158] |
| 12_reference | combined | SELECT | 64 | 0 | 2.905 | 5.002 | 6.988 | [60] |
| 12_reference | combined | OPERATE | 64 | 0 | 2.996 | 4.981 | 6.994 | [60] |
| 12_reference | off | READ mixed | 33 | 0 | 0.049 | 2.364 | 21.929 | [91] |
| 12_reference | off | READ integrity | 32 | 0 | 0.011 | 4.13 | 13.445 | [134] |
| 12_reference | off | SELECT | 64 | 0 | 0.011 | 2.066 | 14.104 | [49] |
| 12_reference | off | OPERATE | 64 | 0 | 0.05 | 2.998 | 17.54 | [49] |
| 12_reference | size_only | READ mixed | 33 | 0 | 0.006 | 2.392 | 24.699 | [141] |
| 12_reference | size_only | READ integrity | 32 | 0 | 0.045 | 2.556 | 13.975 | [158] |
| 12_reference | size_only | SELECT | 64 | 0 | 0.006 | 2.267 | 12.342 | [60] |
| 12_reference | size_only | OPERATE | 64 | 0 | 0.044 | 2.566 | 9.352 | [60] |
| 12_reference | timing_only | READ mixed | 33 | 0 | 3.535 | 4.913 | 6.872 | [91] |
| 12_reference | timing_only | READ integrity | 32 | 0 | 3.02 | 4.963 | 6.964 | [134] |
| 12_reference | timing_only | SELECT | 64 | 0 | 3.005 | 4.981 | 6.909 | [49] |
| 12_reference | timing_only | OPERATE | 64 | 0 | 3.085 | 4.947 | 7.024 | [49] |
| 13_reference_rest | combined | READ mixed | 33 | 0 | 8.325 | 10.258 | 12.092 | [141] |
| 13_reference_rest | combined | READ integrity | 32 | 0 | 7.131 | 9.299 | 12.007 | [158] |
| 13_reference_rest | combined | SELECT | 64 | 0 | 8.006 | 9.851 | 11.809 | [60] |
| 13_reference_rest | combined | OPERATE | 64 | 0 | 8.183 | 10.04 | 11.809 | [60] |
| 13_reference_rest | timing_only | READ mixed | 33 | 0 | 8.128 | 10.016 | 11.765 | [91] |
| 13_reference_rest | timing_only | READ integrity | 32 | 0 | 7.964 | 9.77 | 11.869 | [134] |
| 13_reference_rest | timing_only | SELECT | 64 | 0 | 8.151 | 9.984 | 11.972 | [49] |
| 13_reference_rest | timing_only | OPERATE | 64 | 0 | 8.298 | 10.033 | 11.86 | [49] |
| 14_reference_rest | combined | READ mixed | 33 | 0 | 13.09 | 15.28 | 16.974 | [141] |
| 14_reference_rest | combined | READ integrity | 32 | 0 | 12.993 | 15.023 | 16.995 | [158] |
| 14_reference_rest | combined | SELECT | 64 | 0 | 13.146 | 14.988 | 18.104 | [60] |
| 14_reference_rest | combined | OPERATE | 64 | 0 | 11.956 | 15.043 | 16.918 | [60] |
| 14_reference_rest | timing_only | READ mixed | 33 | 0 | 13.193 | 14.916 | 16.919 | [91] |
| 14_reference_rest | timing_only | READ integrity | 32 | 0 | 13.076 | 14.889 | 16.414 | [134] |
| 14_reference_rest | timing_only | SELECT | 64 | 0 | 12.961 | 15.038 | 16.954 | [49] |
| 14_reference_rest | timing_only | OPERATE | 64 | 0 | 12.928 | 14.755 | 16.841 | [49] |
| 15_reference_rest | combined | READ mixed | 33 | 0 | 18.163 | 20.309 | 21.97 | [141] |
| 15_reference_rest | combined | READ integrity | 32 | 0 | 17.744 | 19.831 | 22.256 | [158] |
| 15_reference_rest | combined | SELECT | 64 | 0 | 17.953 | 20.047 | 23.657 | [60] |
| 15_reference_rest | combined | OPERATE | 64 | 0 | 18.131 | 20.045 | 21.93 | [60] |
| 15_reference_rest | timing_only | READ mixed | 33 | 0 | 18.416 | 20.105 | 21.98 | [91] |
| 15_reference_rest | timing_only | READ integrity | 32 | 0 | 18.38 | 20.721 | 23.877 | [134] |
| 15_reference_rest | timing_only | SELECT | 64 | 0 | 15.579 | 20.127 | 21.857 | [49] |
| 15_reference_rest | timing_only | OPERATE | 64 | 0 | 16.429 | 19.944 | 23.082 | [49] |
| 16_persistence_graceful_950 | combined | READ mixed | 30 | 0 | 17.538 | 20.308 | 21.693 | [141] |
| 16_persistence_graceful_950 | combined | READ integrity | 30 | 0 | 17.952 | 19.864 | 21.983 | [158] |
| 16_persistence_graceful_950 | combined | SELECT | 3 | 0 | 19.836 | 20.636 | 21.511 | [60] |
| 16_persistence_graceful_950 | combined | OPERATE | 3 | 0 | 20.006 | 20.246 | 20.548 | [60] |
| 17_persistence_rst_950 | combined | READ mixed | 30 | 0 | 18.718 | 20.427 | 21.804 | [141] |
| 17_persistence_rst_950 | combined | READ integrity | 30 | 0 | 18.162 | 19.745 | 21.686 | [158] |
| 17_persistence_rst_950 | combined | SELECT | 3 | 0 | 18.984 | 21.444 | 21.778 | [60] |
| 17_persistence_rst_950 | combined | OPERATE | 3 | 0 | 19.19 | 19.768 | 20.378 | [60] |
| 18_reconnect_950 | combined | READ mixed | 30 | 0 | 0.048 | 19.713 | 26.056 | [91, 141] |
| 18_reconnect_950 | combined | READ integrity | 30 | 0 | 0.153 | 19.062 | 21.838 | [134, 158] |
| 18_reconnect_950 | combined | SELECT | 3 | 0 | 0.011 | 18.761 | 19.179 | [49, 60] |
| 18_reconnect_950 | combined | OPERATE | 3 | 0 | 5.102 | 19.314 | 20.402 | [49, 60] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.507 | 20.931 | 21.934 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.473 | 19.935 | 21.648 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.395 | 20.011 | 21.687 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.135 | 19.973 | 21.878 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.292 | 19.889 | 21.721 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 17.992 | 19.92 | 21.786 | [141] |
| 19_loss_mixed_950 | combined | READ mixed | 20 | 0 | 18.071 | 19.96 | 21.626 | [141] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 20.688 | 20.688 | 20.688 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 21.093 | 21.093 | 21.093 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 19.85 | 19.85 | 19.85 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 21.941 | 21.941 | 21.941 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 20.552 | 20.552 | 20.552 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 18.765 | 18.765 | 18.765 | [60] |
| 19_loss_mixed_950 | combined | SELECT | 1 | 0 | 19.195 | 19.195 | 19.195 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 18.996 | 18.996 | 18.996 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 20.324 | 20.324 | 20.324 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 19.959 | 19.959 | 19.959 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 20.076 | 20.076 | 20.076 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 20.009 | 20.009 | 20.009 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 21.82 | 21.82 | 21.82 | [60] |
| 19_loss_mixed_950 | combined | OPERATE | 1 | 0 | 18.361 | 18.361 | 18.361 | [60] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.746 | 20.18 | 21.932 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 17.534 | 20.062 | 21.887 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.056 | 20.023 | 21.388 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.613 | 20.608 | 22.056 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.025 | 19.982 | 21.845 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.137 | 19.987 | 21.583 | [158] |
| 20_loss_full_950 | combined | READ integrity | 20 | 0 | 18.753 | 20.442 | 23.909 | [158] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 21.239 | 21.239 | 21.239 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 19.907 | 19.907 | 19.907 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 20.102 | 20.102 | 20.102 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 19.823 | 19.823 | 19.823 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 19.853 | 19.853 | 19.853 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 20.384 | 20.384 | 20.384 | [60] |
| 20_loss_full_950 | combined | SELECT | 1 | 0 | 18.277 | 18.277 | 18.277 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 21.525 | 21.525 | 21.525 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 20.02 | 20.02 | 20.02 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 19.628 | 19.628 | 19.628 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 20.602 | 20.602 | 20.602 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 21.996 | 21.996 | 21.996 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 22.006 | 22.006 | 22.006 | [60] |
| 20_loss_full_950 | combined | OPERATE | 1 | 0 | 19.992 | 19.992 | 19.992 | [60] |
