"""Isolated BMv2 emulator acceptance, never physical-switch evidence."""
import unittest
import struct
import sys
from pathlib import Path
from test_bmv2_artifact import available, lab, MS, TOL_ACK_NS, TOL_GAP_NS
from test_rrc_split import packet

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / "size"))
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / "bmv2" / "lab"))
import rrc
from case4_padding import Decoy, build_frame, decode_frame
from case4_transport import ControlConnection
from master import control_frame


def master_packet(payload,seq,flags=0x18):
    raw=bytearray(packet(payload,seq=seq,flags=flags,sport=40000))
    raw[:6]=bytes.fromhex("020000000002"); raw[6:12]=bytes.fromhex("020000000001")
    struct.pack_into(">H",raw,36,20000)
    return rrc._build(rrc.parse(bytes(raw)),payload,seq,flags)


def outstation_packet(ack,window,payload=b"",seq=77):
    raw=bytearray(packet(payload,seq=seq,flags=0x18 if payload else 0x10))
    raw[:6]=bytes.fromhex("020000000001"); raw[6:12]=bytes.fromhex("020000000002")
    raw[26:30],raw[30:34]=raw[30:34],raw[26:30]
    struct.pack_into(">I",raw,42,ack); struct.pack_into(">H",raw,48,window)
    return rrc._build(rrc.parse(bytes(raw)),payload,seq,0x18 if payload else 0x10)


@unittest.skipUnless(available(), "BMv2 toolchain unavailable")
class Case4BMv2(unittest.TestCase):
    def test_actual_response_association_rejects_wrong_profile_flow_app_position_and_crc(self):
        from outstation import response
        user=bytes.fromhex("c0c0010a02000016")
        request=build_frame(bytes.fromhex("056400c40a000100"),user)
        valid=response(user)
        _,control_user=decode_frame(control_frame(0,3))
        wrong_operation=response(control_user)
        wrong_app=response(bytes([0xc0,0xc1])+user[2:])
        wrong_flow=bytearray(outstation_packet(1020,4096,valid))
        struct.pack_into(">H",wrong_flow,36,40001)
        wrong_flow=rrc._build(rrc.parse(bytes(wrong_flow)),valid,77,0x18)
        bad_crc=bytearray(valid);bad_crc[-1]^=1
        rejected=[outstation_packet(1020,4096,wrong_operation),outstation_packet(1020,4096,wrong_app),
                  outstation_packet(1020,4096,valid,seq=78),wrong_flow,
                  outstation_packet(1020,4096,bytes(bad_crc))]
        fixtures=[dict(raw=master_packet(b"",999,2).hex()),dict(raw=master_packet(request,1000).hex())]
        fixtures += [dict(sender="o",raw=raw.hex()) for raw in rejected]
        fixtures += [dict(sender="o",raw=outstation_packet(1020,4096,valid).hex())]
        run=lab("raw_profile",frames=fixtures,padding=0,mode=4)
        # This predicate fixture deliberately disables the heartbeat; timing is
        # covered by step5. With no ACK, only the valid response remains held.
        self.assertFalse(run["service_enabled"])
        observed=[rrc.parse(bytes.fromhex(raw)).payload for raw in run["reverse"]]
        self.assertEqual(observed,[rrc.parse(raw).payload for raw in rejected])
        self.assertEqual(run["outcome_counters"]["7"],1)

    def test_invalid_ack_checksum_cannot_acquire_the_owner_hold(self):
        request=build_frame(bytes.fromhex("056400c40a000100"),bytes.fromhex("c0c0010a02000016"))
        ack=bytearray(outstation_packet(1020,4096));ack[50]^=1
        fixtures=[dict(raw=master_packet(b"",999,2).hex()),dict(raw=master_packet(request,1000).hex()),
                  dict(sender="o",raw=bytes(ack).hex())]
        run=lab("raw_profile",frames=fixtures,padding=0,mode=4)
        self.assertEqual(run["outcome_counters"]["5"],0)
        observed=rrc.parse(bytes.fromhex(run["reverse"][-1]))
        self.assertFalse(rrc.tcp_ok(observed))

    def test_every_transaction_has_its_own_switch_event_provenance(self):
        run = lab("step5", count=3, latency_ms=90, budget=250, loop_pps=20000)
        self.assertEqual(run["outcomes"], ["OK"] * 3)
        for index, txn in enumerate(run["txns"]):
            self.assertIn("switch_ev_us", txn, "final register snapshot cannot describe earlier transactions")
            self.assertEqual(txn["transaction_id"], index)
            self.assertGreater(txn["switch_ev_us"]["0"], 0)
            self.assertIn(txn["release_outcome"], ("normal", "fallback"))

    def test_absolute_readiness_does_not_depend_on_token_pass_budget(self):
        run = lab("step5", count=2, latency_ms=90, budget=1, loop_pps=20000)
        self.assertEqual(run["outcomes"], ["OK"] * 2)
        for txn in run["txns"]:
            expiry = txn["switch_ev_us"]["5"] - txn["switch_ev_us"]["0"]
            self.assertGreaterEqual(expiry, 30_000)
            self.assertLessEqual(expiry, 32_000, "software heartbeat detection tolerance is unchanged")
            self.assertEqual(txn["release_outcome"], "fallback")

    def test_late_readiness_keeps_the_full_configured_gap(self):
        run = lab("step5", count=2, latency_ms=25, gap_us=8000, budget=1, loop_pps=20000)
        self.assertEqual(run["outcomes"], ["OK"] * 2)
        for txn in run["txns"]:
            self.assertEqual(txn["release_outcome"], "normal")
            readiness=txn["switch_ev_us"]["4"]-txn["switch_ev_us"]["0"]
            self.assertGreater(readiness,18_000,"response follows the old absolute response deadline")
            self.assertLess(readiness,30_000,"normal-path stimulus must arrive before readiness expiry")
            self.assertLessEqual(abs(txn["e_R"] - txn["e_A"] - 8 * MS), TOL_GAP_NS)

    def test_select_and_operate_are_timed_and_padded_in_the_p4_switch(self):
        run = lab("step5", count=1, operation="SBO", padding=1, shape=1,
                  latency_ms=2, budget=1000, loop_pps=20000)
        self.assertEqual(run["outcomes"], ["OK", "OK"])
        self.assertEqual([p["wire_length"] for p in run["request_padding"]], [55, 55])
        self.assertTrue(all(p["equals_software_oracle"] for p in run["request_padding"]))
        self.assertTrue(all(p["native_length"] == 35 for p in run["request_padding"]))
        self.assertEqual([p["seq_order"] for p in run["split"]], [[28, 29], [28, 29]])
        self.assertTrue(all(p["checksums_ok"] and p["dnp3_ok"] and p["reassembled_equal"] for p in run["split"]))
        self.assertTrue(all(p["equals_software_carve_after_ack_translation"] for p in run["split"]))
        for txn in run["txns"]:
            self.assertEqual(txn["release_outcome"], "normal")
            self.assertLessEqual(abs(txn["e_R"] - txn["e_A"] - MS), TOL_GAP_NS)

    def test_both_lost_tokens_expire_and_the_next_transaction_recovers(self):
        run = lab("step5", count=2, latency_ms=90, token_loss=3, wait_fallback=True)
        self.assertEqual(run["outcomes"], ["OK"] * 2)
        for txn in run["txns"]:
            self.assertEqual(txn["release_outcome"], "fallback")
            expiry = txn["switch_ev_us"]["5"] - txn["switch_ev_us"]["0"]
            self.assertGreaterEqual(expiry, 30_000)
            self.assertLessEqual(expiry, 32_000)
        service = run["artifact"]["heartbeat_observed"]
        self.assertGreater(service["r_hb_count"], 0)
        self.assertGreater(service["r_hb_max_gap"], 0)

    def test_actual_partial_overlap_replay_and_tcp_wrap_preserve_committed_stream(self):
        base=0xfffffff0
        select=control_frame(0,3); operate=control_frame(1,4)
        native=select+operate
        connection=ControlConnection(base,Decoy(201,bytes.fromhex("0101640000006400000000")))
        first=connection.forward(base,select); second=connection.forward((base+35)&0xffffffff,operate)
        stream=first.payload+second.payload
        slices=[(7,17),(29,35),(40,55),(25,50)]
        fixtures=[master_packet(b"",(base-1)&0xffffffff,0x02),master_packet(select,base),
                  master_packet(operate,(base+35)&0xffffffff)]
        fixtures += [master_packet(native[start:end],(base+start)&0xffffffff) for start,end in slices]
        run=lab("raw_profile",frames=[dict(raw=raw.hex()) for raw in fixtures])
        packets=[rrc.parse(bytes.fromhex(raw)) for raw in run["forwarded"]]
        self.assertEqual(len(packets),len(fixtures))
        self.assertEqual([p.payload for p in packets[1:3]],[first.payload,second.payload])
        for observed,(start,end) in zip(packets[3:],slices):
            expected=connection.forward((base+start)&0xffffffff,native[start:end])
            left=(observed.seq-base)&0xffffffff; wanted=(expected.seq-base)&0xffffffff
            self.assertLessEqual(left,wanted)
            self.assertGreaterEqual(left+len(observed.payload),wanted+len(expected.payload))
            self.assertEqual(observed.payload,stream[left:left+len(observed.payload)])
            self.assertTrue(rrc.ip_ok(observed) and rrc.tcp_ok(observed))

    def test_invalid_crc_bypasses_before_insertion_and_valid_next_packet_recovers(self):
        good=control_frame(0,3); damaged=bytearray(good); damaged[-1]^=1
        fixtures=[master_packet(b"",999,0x02),master_packet(bytes(damaged),1000),master_packet(good,1035)]
        run=lab("raw_profile",frames=[dict(raw=raw.hex()) for raw in fixtures])
        packets=[rrc.parse(bytes.fromhex(raw)) for raw in run["forwarded"]]
        self.assertEqual(packets[1].payload,bytes(damaged))
        self.assertEqual(len(packets[2].payload),55)
        self.assertTrue(rrc.dnp3_frame_ok(packets[2].payload))

    def test_invalid_tcp_checksum_cannot_acquire_an_insertion(self):
        native=control_frame(0,3)
        damaged=bytearray(master_packet(native,1000)); damaged[50]^=1
        run=lab("raw_profile",frames=[dict(raw=master_packet(b"",999,2).hex()),dict(raw=bytes(damaged).hex())])
        packet=rrc.parse(bytes.fromhex(run["forwarded"][-1]))
        self.assertEqual(packet.payload,native)
        self.assertFalse(rrc.tcp_ok(packet))

    def test_timestamp_negotiation_excludes_insertion_before_first_boundary(self):
        from test_rrc_split import TS_OPT
        syn=bytearray(packet(b"",seq=999,flags=2,sport=40000,options=TS_OPT))
        syn[:6]=bytes.fromhex("020000000002"); syn[6:12]=bytes.fromhex("020000000001")
        struct.pack_into(">H",syn,36,20000)
        syn=rrc._build(rrc.parse(bytes(syn)),b"",999,2)
        native=control_frame(0,3)
        run=lab("raw_profile",frames=[dict(raw=syn.hex()),dict(raw=master_packet(native,1000).hex())])
        packets=[rrc.parse(bytes.fromhex(raw)) for raw in run["forwarded"]]
        self.assertEqual(packets[1].payload,native)
        self.assertEqual(packets[1].seq,1000)

    def test_tuple_reuse_after_fin_starts_a_new_translation_epoch(self):
        select=control_frame(0,3); operate=control_frame(1,4)
        fixtures=[master_packet(b"",999,2),master_packet(select,1000),master_packet(operate,1035),
                  master_packet(b"",1070,0x11),master_packet(b"",5000,2),master_packet(select,5001)]
        run=lab("raw_profile",frames=[dict(raw=raw.hex()) for raw in fixtures])
        packets=[rrc.parse(bytes.fromhex(raw)) for raw in run["forwarded"]]
        self.assertEqual(packets[3].seq,1110,"FIN must be translated before retirement")
        self.assertEqual((packets[-1].seq,len(packets[-1].payload)),(5001,55))

    def test_actual_partial_cumulative_acks_and_window_edges_match_oracle(self):
        base=0xfffffff0; select=control_frame(0,3); operate=control_frame(1,4)
        oracle=ControlConnection(base,Decoy(201,bytes.fromhex("0101640000006400000000")))
        oracle.forward(base,select); oracle.forward((base+35)&0xffffffff,operate)
        points=[(34,9),(35,20),(45,51),(55,10),(90,9),(100,20),(110,65535)]
        frames=[dict(raw=master_packet(b"",(base-1)&0xffffffff,2).hex()),
                dict(raw=master_packet(select,base).hex()),dict(raw=master_packet(operate,(base+35)&0xffffffff).hex())]
        frames += [dict(sender="o",raw=outstation_packet((base+ack)&0xffffffff,window).hex()) for ack,window in points]
        run=lab("raw_profile",frames=frames)
        packets=[rrc.parse(bytes.fromhex(raw)) for raw in run["reverse"]]
        self.assertEqual(len(packets),len(points))
        for observed,(ack,window) in zip(packets,points):
            self.assertEqual((observed.ack,struct.unpack_from(">H",observed.raw,48)[0]),
                             oracle.ledger.reverse((base+ack)&0xffffffff,window))
            self.assertTrue(rrc.tcp_ok(observed) and rrc.ip_ok(observed))

    def test_inserted_tail_loss_withholds_native_byte_until_replay_completes(self):
        """Raw wire ACK/retransmission proof, not autonomous kernel loss recovery."""
        from case4_padding import expand_control
        decoy=Decoy(201,bytes.fromhex("0101640000006400000000"))
        select=control_frame(0,3); operate=control_frame(1,4)
        for base in (1000,0xfffffff0):
            with self.subTest(base=base):
                def m(payload,offset,flags=0x18):
                    return dict(raw=master_packet(payload,(base+offset)&0xffffffff,flags).hex())
                def o(offset,window):
                    return dict(sender="o",raw=outstation_packet((base+offset)&0xffffffff,window).hex())
                frames=[m(b"",-1,2),m(select,0),o(35,0),o(35,20),o(54,0),o(54,1),m(select[-1:],34),o(55,0),
                        m(operate,35),o(90,0),o(90,20),o(109,0),o(109,1),m(operate[-1:],69),o(110,0)]
                run=lab("raw_profile",frames=frames)
                forward=[rrc.parse(bytes.fromhex(raw)) for raw in run["forwarded"]]
                reverse=[rrc.parse(bytes.fromhex(raw)) for raw in run["reverse"]]
                self.assertEqual(len(forward),5)
                self.assertEqual(len(reverse),10)
                expected=[(34,0),(34,1),(34,0),(34,1),(35,0),
                          (69,0),(69,1),(69,0),(69,1),(70,0)]
                for observed,(ack,window) in zip(reverse,expected):
                    self.assertEqual((observed.ack,struct.unpack_from(">H",observed.raw,48)[0]),
                                     ((base+ack)&0xffffffff,window),
                                     "missing inserted tail must leave one native byte unacknowledged")
                for original,replay,native,start in ((forward[1],forward[2],select,0),
                                                     (forward[3],forward[4],operate,55)):
                    image=expand_control(native,decoy)[0]
                    self.assertEqual((original.seq,original.payload),((base+start)&0xffffffff,image))
                    # The P4 cache sends its complete image; receiver duplicate trimming
                    # accepts the missing suffix, including both CRC bytes.
                    left=(replay.seq-original.seq)&0xffffffff
                    self.assertLessEqual(left,34)
                    self.assertGreaterEqual(left+len(replay.payload),55)
                    self.assertEqual(replay.payload,image[left:left+len(replay.payload)])
                    repaired=image[:35]+replay.payload[35-left:55-left]
                    self.assertEqual(repaired,image)
                    self.assertTrue(rrc.dnp3_frame_ok(repaired))
                self.assertTrue(all(rrc.ip_ok(p) and rrc.tcp_ok(p) for p in forward+reverse))


if __name__ == "__main__":
    unittest.main()
