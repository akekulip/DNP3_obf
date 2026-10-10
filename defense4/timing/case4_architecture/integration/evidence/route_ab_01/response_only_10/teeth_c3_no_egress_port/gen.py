"""Scratch teeth source: the composite WITHOUT make_e's conn egress_port binding (review C3, E side)."""
import sys
RO = '/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only'
sys.path.insert(0, RO)
import make_e
make_e.CONN_NEW = make_e.CONN_OLD
import compose
src, _ = compose.generate()
open(sys.argv[1], 'w').write(src)
