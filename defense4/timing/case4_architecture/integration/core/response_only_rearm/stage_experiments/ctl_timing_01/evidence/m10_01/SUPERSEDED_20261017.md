# m10_01 is superseded by m10_02 (2026-10-17)

m10_01 (source `4b1be793…`) compiled on both SDKs at N12/E12/T11 with the mirror guard passing. No model driver
and no hardware ran on it.

The code review of m10_01 found that its restart rows did not key on TCP flags, so a FIN|ACK whose owner state moved
under its close also restarted. That was a behaviour change beyond the reset fix, and nothing documented or tested
it. m10_02 adds `hdr.tcp.flags` to `reset_boundary` and requires the RST bit on the restart rows; FIN|ACK keeps m9's
abort (`tests/test_reset_race.py::test_m10_fin_ack_does_not_restart`). Its docstring also corrects the generation
guarantee, which rests on the epoch.

Kept unchanged as the record of what compiled.
