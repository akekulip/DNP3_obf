"""PTF functional test for the handshake normalizer (Experiment 2B), full matrix.

Drives every case from the shared oracle (`tests/oracle.py`): for each input packet it
computes the oracle's expected output, injects the input on port 0, and verifies the exact
expected bytes leave on port 1 (the program forwards egress = ingress ^ 1). The tables use
compile-time const entries, so loading the program is enough — no runtime programming.

Run under the SDE harness with the model + switchd up (see ../../MODEL_BLOCKER.md):
    sudo -E $SDE/run_p4_tests.sh -p handshake_normalizer -t tests/ptf
"""
import os
import sys

import ptf
from ptf import testutils as tu
from ptf.base_tests import BaseTest
from scapy.all import Ether, IP, TCP

# make the sibling oracle importable (tests/ is one level up from tests/ptf/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import oracle  # noqa: E402  -- shared case list + transform()

SND, RCV = 0, 1


class HandshakeNormMatrix(BaseTest):
    """One PTF test method per oracle case, generated from oracle.CASES."""

    def setUp(self):
        BaseTest.setUp(self)
        self.dp = ptf.dataplane_instance

    def runTest(self):
        passed, failed = 0, []
        for name, pkt_in, expect_outcome, expect_tcp_identical in oracle.CASES:
            exp_out, outcome, _l3 = oracle.transform(pkt_in)
            tu.send_packet(self, SND, bytes(pkt_in))
            # capture whatever the pipeline emits on the paired port
            rc = tu.dp_poll(self, port_number=RCV, timeout=2)
            got = getattr(rc, "packet", None) if rc else None
            if got is None:
                failed.append(f"{name}: no output packet"); continue
            got_pkt = Ether(got)
            exp_pkt = Ether(bytes(exp_out))
            ok = True
            # exact bytes for transformed packets; for fail-open verify TCP byte-identity
            if bytes(got_pkt) != bytes(exp_pkt):
                # allow trailing MAC pad differences: compare up to the IP total length
                if IP in got_pkt and IP in exp_pkt:
                    gl = got_pkt[IP].len; el = exp_pkt[IP].len
                    gcore = bytes(got_pkt[IP])[:gl]; ecore = bytes(exp_pkt[IP])[:el]
                    if gcore != ecore:
                        ok = False
                else:
                    ok = False
            if expect_tcp_identical and TCP in got_pkt and TCP in Ether(bytes(pkt_in)):
                if bytes(got_pkt[TCP]) != bytes(Ether(bytes(pkt_in))[TCP]):
                    ok = False
            if ok:
                passed += 1
            else:
                failed.append(f"{name}: outcome={outcome} bytes mismatch")
        print(f"[handshake-normalizer PTF] {passed}/{len(oracle.CASES)} cases pass")
        for f in failed:
            print("  FAIL:", f)
        self.assertEqual(failed, [], f"{len(failed)} case(s) failed on the model")
