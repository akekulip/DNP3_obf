### fig_release_tail

Release tail of the framework, measured on campaign_v2. (a) The tail against the acknowledgment hold, one series per transaction class. It is flat at about 0.10 ms across every hold the switch can sustain. Past the dashed line the acknowledgment leaves at 31.07 ms whatever the setting, so the hold is not achieved and no tail is defined. (b) Its distribution at the shipped policy. READ and SELECT coincide; OPERATE sits about six microseconds higher because it arrives at a different point in the blocker cycle, not because the outstation did anything different.

**Statistics.** Tail = the measured request-to-acknowledgment median minus the acknowledgment hold as the switch stores it, whole 256 ns ticks rounded down. Panel (a) uses the sweep's per-point per-class medians at a configured interval of 4 ms; panel (b) uses every obfuscated exchange of the campaign at D_A = 20 ms. Medians: READ 0.101070, SELECT 0.100832, OPERATE 0.107031 ms.
