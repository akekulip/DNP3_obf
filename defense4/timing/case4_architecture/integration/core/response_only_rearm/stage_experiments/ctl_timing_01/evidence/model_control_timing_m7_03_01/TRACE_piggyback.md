# model_control_timing_m7_03_01: 138/141, the three `*_piggyback_not_before_t0_plus_pb` checks (2026-10-16)

The run's result stays 138/141.

**What the driver measured.** The driver turns `pb` (1 s of model time) into wall time with a clock estimate: `op_j`
divided by the median wall-clock J hold seen so far. The J samples were 0.288 s, 0.432 s and 0.270 s. With the first
two samples the median gives 555M model ns per wall second, so `pb` converts to 1.80 s, and the 0.6× threshold is
1.08 s. The piggybacked responses were released 0.91–0.94 s after the request. That is the same as the passing m6_07
run (0.92–0.94 s, with consistent J samples of 0.27–0.28 s and a 1.37 s bound).

**What T decided, from the retained model log.** At the three piggyback releases (`release_response_counted` with
`md.pb_delta` sign 0) the values are `pb_delta` = 0xd1cc, 0x1908a and 0x17d76, in 256 ns units. So T released each one
13.7 ms, 26.2 ms and 24.9 ms (model time) after the `pb` bound on its own clock: none was early. The releases with a
negative `pb_delta` are committed releases, to which `pb` does not apply.

**Cause of the failed check.** The wall-clock calibration was biased by one long J sample. A host stall can only
lengthen a sample. Another agent ran short tests on this machine while the run was in progress (inference: the
timing matches, but it is not proven). The driver now estimates the clock from the shortest J hold.
