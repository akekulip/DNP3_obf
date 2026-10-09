import os, sys
from queue_sim import QueueSim, T0, DA, READINESS, CAP, GAP, OP_J, ACK_FRAME, RSP_FRAME, OP_FRAME, RELAY, FORWARD, q
def outs(s, *names):
    c = s.consts(); return {n: s.counter(c[n]) for n in names}
K = ('OUT_ACK_COMMIT','OUT_ACK_FALLBACK','OUT_RESP_RELEASE','OUT_RESP_FALLBACK','OUT_OP_RELEASE','OUT_HELD_STALE_FLUSH','OUT_TOKEN_STALE','OUT_UNMATCHED')
# 1 fallback ACK then a response after readiness
s = QueueSim(); s.request(T0); s.ack(T0 + 50_000); rsp_t = T0 + READINESS + 400_000; s.response(rsp_t); s.run(T0 + CAP + 3_000_000)
print('1 fallback', 'ack', s.emissions(ACK_FRAME), 'rsp', s.emissions(RSP_FRAME), 'rsp_t', rsp_t, outs(s, *K))
# 2 genuine commit gen1, fallback gen2, response
s = QueueSim(); s.read(T0); b = T0 + CAP + 1_000_000; s.request(b); s.ack(b + 50_000); r2 = b + READINESS + 400_000; s.response(r2); s.run(b + CAP + 3_000_000)
print('2 stale', 'ack', s.emissions(ACK_FRAME), 'rsp', s.emissions(RSP_FRAME), 'r2', r2, outs(s, *K))
# 3 RESET with a held OPERATE
s = QueueSim(); s.operate(T0); s.reset(T0 + 20_000); s.run(T0 + 3_000_000)
print('3 reset-op', 'relay', [t - T0 for t in s.emissions(OP_FRAME, RELAY)], 'op_gen', s.cell('op_gen_alloc_reg'), outs(s, *K))
# 4 RESET then new OPERATE and new-epoch READ
s = QueueSim(); s.operate(T0); s.read(T0, epoch=1); s.reset(T0 + 200_000, epoch=1)
n = T0 + 1_000_000; s.operate(n, epoch=2); s.read(n, epoch=2); s.run(n + CAP + 3_000_000)
a = s.emissions(ACK_FRAME); r = s.emissions(RSP_FRAME)
print('4 after', 'relay', [t - T0 for t in s.emissions(OP_FRAME, RELAY)], 'n+OPJ', q(n) + OP_J - T0, 'ack', [x - T0 for x in a], 'rsp', [x - T0 for x in r], 'n', n - T0, outs(s, *K))
