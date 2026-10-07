"""Task1 acceptance defects exercised through the whole source program."""
import struct
import unittest
import read_support as rs
import vectors
import importlib.util


class Task1Safety(unittest.TestCase):
    def test_read_close_forwards_once_and_emits_current_epoch_reset(self):
        read=rs.ARCH/'integration/read'
        spec=importlib.util.spec_from_file_location('task1_t_whole',read/'tests/whole_program.py')
        w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
        for phase in (13,14,15):
            for flags in (17,20,4):
              for reverse in (False,True):
                with self.subTest(phase=phase,flags=flags,reverse=reverse):
                    raw=vectors.frame(flags,2000 if reverse else 1020,1020 if reverse else 2000,reverse)
                    pipe=rs.ReadPipeline().start(phase<<16|1,1020,2000)
                    out=pipe.inject(rs.IN_SERVER if reverse else rs.IN_CLIENT,raw)
                    self.assertEqual(pipe.state()['owner'],0x70001)
                    self.assertFalse(out.dropped)
                    self.assertEqual(len(out.emitted),1)
                    port,data=out.emitted[0]
                    self.assertEqual(port,rs.handoff_port())
                    self.assertEqual(data[:16],struct.pack('>IIIBBH',17,17,0,4,2 if reverse else 1,0))
                    self.assertEqual(data[16:],raw)
                    self.assertEqual(pipe.state()['work']['phase'],4)
                    sim=w.Sim((read/'read_timing.p4').read_text(),read)
                    sim.at(1000,port,data);sim.run(1000)
                    self.assertEqual(sim.cell('quarantined_epoch'),17)
                    self.assertEqual(sim.emitted,[(1000,w.PORTS['FORWARD_PORT'] if reverse else w.PORTS['RELAY_PORT'],raw)])

    def test_stale_duplicate_and_busy_close_never_debit_a_current_writer(self):
        raw=vectors.frame(17,1020,2000)
        owner=0xe0001
        prefix=struct.pack('>IIIHH',17,17,owner,0x104,0)
        pipe=rs.ReadPipeline().start(owner,1020,2000,work=(29,2))
        out=pipe.inject(68,prefix+raw)
        self.assertFalse(out.dropped)
        self.assertEqual(pipe.state()['owner'],0x60001)
        self.assertEqual(pipe.state()['work'],{'generation':29,'phase':2})
        again=pipe.inject(68,prefix+raw)
        self.assertTrue(again.dropped);self.assertEqual(again.emitted,[])
        stale=pipe.inject(68,struct.pack('>IIIHH',18,18,0x60001,0x104,0)+raw)
        self.assertTrue(stale.dropped);self.assertEqual(stale.emitted,[])
        self.assertEqual(pipe.state()['owner'],0x60001)
        self.assertEqual(pipe.state()['work'],{'generation':29,'phase':2})

    def test_foreign_private_epoch_never_writes_banks_or_emits_terminal(self):
        packets={2:vectors.frame(18,900,101,True,1500),
            6:vectors.packet(24,2000,1075,reverse=True,payload=vectors.native_response()),
            9:rs.request_packet(),10:rs.ack_packet(),11:rs.response_packet(),
            16:vectors.packet(24,2000,1075,reverse=True,payload=vectors.native_response())}
        for kind,raw in packets.items():
            with self.subTest(kind=kind):
                owner=0xe0001
                pipe=rs.ReadPipeline().start(owner,1000,2000,work=(1,1))
                before=pipe.state();banks=pipe.banks()
                event=struct.pack('>IIIHH',18,1,owner,0x100|kind,0)
                if kind in (9,10,11):event+=struct.pack('>I',rs.T0_BASE&0xffffff00)
                out=pipe.inject(68,event+raw)
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted,[])
                after=pipe.state()
                for name in ('owner','epoch','client','server'):
                    self.assertEqual(after[name],before[name],name)
                self.assertEqual(pipe.banks(),banks)
                self.assertEqual(after['work']['phase'],4)

    def test_late_configuration_removal_quarantines_the_committed_owner(self):
        for removed in (3,4):
            for table in ('connection','read_connection'):
                with self.subTest(removed=removed,table=table):
                    pipe=rs.ReadPipeline().start(0x50001,1000,2000)
                    before=pipe.state();banks=pipe.banks();raw=rs.request_packet()
                    pipe.mutate[removed]=lambda p,t=table:rs.drop_runtime(p,t)
                    out=pipe.inject(rs.IN_CLIENT,raw)
                    self.assertTrue(out.dropped)
                    self.assertEqual(out.emitted,[])
                    after=pipe.state()
                    self.assertEqual(after['owner'],0x60001)
                    self.assertEqual(after['epoch'],before['epoch'])
                    self.assertEqual((after['client'],after['server']),(1020,2000))
                    self.assertEqual(pipe.banks(),banks)
                    self.assertEqual(after['work']['phase'],4)


if __name__=='__main__':unittest.main()
