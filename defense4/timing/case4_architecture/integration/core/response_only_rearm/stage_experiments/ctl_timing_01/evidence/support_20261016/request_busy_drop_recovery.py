import sys; sys.path.insert(0, '.')
import contention_source as cs
import test_m6_lifecycle as lc
import test_t_time_base as tb
V = cs.vectors
def run(src, ack_lag_ns):
    p = cs.LapPipeline(src).handshake()
    rq, ak, rp = cs.transaction('SELECT'); t = p.now + 100_000
    p.at(t, rq, master=True); p.at(t + 200_000, ak); p.at(t + 400_000, rp); p.now = t; p.settle()
    orq, oak, orp = cs.transaction('OPERATE'); t = p.now + 100_000
    p.at(t, orq, master=True)                     # OPERATE request
    p.at(t + ack_lag_ns, oak); p.at(t + ack_lag_ns + 1, oak)      # outstation ACK twice (dupack), possibly early
    p.at(t + ack_lag_ns + 400_000, orp)
    p.now = t; p.settle(horizon=40_000_000)
    seen = len(p.to_master()); relayed_before = len([1 for tm, port, raw in p.wire if port == cs.RELAY_PORT])
    # the master retransmits the OPERATE request later (a real TCP does after its RTO)
    t = p.now + 5_000_000
    p.at(t, orq, master=True); p.now = t; p.settle(horizon=40_000_000)
    relayed_after = len([1 for tm, port, raw in p.wire if port == cs.RELAY_PORT])
    return dict(owner=hex(lc.owner_state(p)), work=p.n.state()['work'], busy=[p.busy(i) for i in range(5)],
                relay_frames_added_by_retransmit=relayed_after - relayed_before)
for name, src in (('m6', lc.M6), ('m7', tb.M7)):
    for lag in (1_000, 14_000, 200_000, 2_000_000):
        print(name, 'ack lag %d ns' % lag, run(src, lag))
