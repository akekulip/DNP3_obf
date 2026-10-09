from queue_sim import QueueSim, T0, OP_FRAME, RELAY
for dt in (1_000, 3_000, 4_000, 5_000, 6_000, 20_000, 200_000):
    s = QueueSim(); s.operate(T0); s.reset(T0 + dt); s.run(T0 + 3_000_000)
    c = s.consts()
    print('dt=%7d relay_after_reset=%s STALE_FLUSH=%d OP_RELEASE=%d' % (dt, [t - T0 - dt for t in s.emissions(OP_FRAME, RELAY)], s.counter(c['OUT_HELD_STALE_FLUSH']), s.counter(c['OUT_OP_RELEASE'])))
