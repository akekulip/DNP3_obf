"""Isolate the checksum witness in retained E_emit03.

The separate strict Mirror witness already rejects its invalid-header capture.
For this witness only, retain the old evaluator's invalid-header-value semantics
so actual packet_out can expose the independent cached-image checksum defect.
"""
import sys,unittest
from pathlib import Path
ordinary=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ordinary/'tests'))
import test_e_prepare as ep,test_e_emit as ee
from source_wire import WireSource
from interp_ext import ExtSource
snapshot=(ordinary/'evidence/e_emit_03/source/e.p4').read_text()
original=ep.e_source
WireSource.ev=ExtSource.ev
# Other actual source stages remain current; this is an isolated retained E defect.
ep.e_source=lambda:original(snapshot)
print('Retained E_emit03 cached-image replacement without TCP checksum regeneration')
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([ee.EEmit('test_cached_read_overwrites_different_incoming_words_including_low24_tail')]))
sys.exit(0 if result.wasSuccessful() else 1)
