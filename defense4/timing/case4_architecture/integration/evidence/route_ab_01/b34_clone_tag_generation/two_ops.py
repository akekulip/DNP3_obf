from queue_sim import QueueSim, T0, OP_FRAME, RELAY, OP_J, q
for d in (1_000, 2_000, 4_000):
    s = QueueSim(); s.operate(T0); s.operate(T0 + d); s.run(T0 + 3_000_000); c = s.consts()
    print('d=%d relay=%s STALE_FLUSH=%d OP_RELEASE=%d UNMATCHED=%d op_gen=%d' % (d, [t - T0 for t in s.emissions(OP_FRAME, RELAY)], s.counter(c['OUT_HELD_STALE_FLUSH']), s.counter(c['OUT_OP_RELEASE']), s.counter(c['OUT_UNMATCHED']), s.cell('op_gen_alloc_reg')))
