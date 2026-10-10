"""Scratch teeth driver: model_drive_composite with E conn rows carrying no egress_port key."""
import sys
RO = '/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only'
sys.path.insert(0, RO)
import model_drive_composite as d
orig = d.cp.e_conn_rows
d.cp.e_conn_rows = lambda *a, **k: [(t, tuple(x for x in key if x[0] != 'eg.egress_port'), act, data, pr)
                                    for t, key, act, data, pr in orig(*a, **k)]
sys.exit(d.main())
