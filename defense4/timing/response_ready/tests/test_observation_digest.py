"""Offline learn-record decoding, never a hardware acquisition test."""
import importlib.util
import struct
import unittest
from pathlib import Path

PATH=Path(__file__).resolve().parents[1]/'observation_digest.py'

class DigestDecode(unittest.TestCase):
    def decoder(self):
        spec=importlib.util.spec_from_file_location('observation_digest',PATH)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def raw(self,event=4,profile=0x00010305,tuple_fields=(0xc0a80a07,0xc0a80a01,20000,40000)):
        return struct.pack('!HHIIIII IHHHH'.replace(' ',''),1,event,0x80000001,2,0xfffffff0,profile,*tuple_fields,3,30)

    def test_exact_raw_digest_maps_observed_internal_event(self):
        record=self.decoder().decode(self.raw(),clock_domain='ingress_mac')
        self.assertEqual(record['event'],'ack_commit')
        self.assertEqual(record['owner_cookie'],0x80000001)
        self.assertEqual(record['connection_cookie'],2)
        self.assertEqual(record['operation'],'SELECT')
        self.assertEqual(record['app_seq'],5)
        self.assertEqual(record['marker_mask'],0)
        self.assertEqual(record['src_ipv4'],0xc0a80a07)
        self.assertEqual(record['evidence_kind'],'observed')

    def test_pulse_zero_tuple_is_retained_without_inference(self):
        record=self.decoder().decode(self.raw(event=6,tuple_fields=(0,0,0,0)),clock_domain='ingress_mac')
        self.assertEqual(record['event'],'readiness_expiry_service')
        self.assertEqual((record['src_ipv4'],record['dst_ipv4'],record['sport'],record['dport']),(0,0,0,0))
        self.assertNotIn('wire_departure',record)

    def test_truncated_unknown_event_or_identity_alias_refused(self):
        for raw in (self.raw()[:-1],self.raw(event=99),self.raw(profile=0x00020305)):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):self.decoder().decode(raw,clock_domain='ingress_mac')

if __name__=='__main__':unittest.main()
