"""A counter-only reset is not authority to reuse stale timing cells."""
import unittest
from read_scenario import new_sim,request,T,L
from test_read_admit import counters,pin_phase


class PartialRearm(unittest.TestCase):
    def test_common_selector_qualifies_policy_off_terminal_without_second_selector(self):
        for kind in (1,2,3):
            sim=new_sim();src=sim.src;src.begin_pass(327)
            src.env.update({'m.role':5,'m.kind':kind,'m.credit_word':0x10101,
                'hdr.envelope.stage':4,'hdr.envelope.expected_credit':0x10101})
            src.apply_table('successful_admission')
            self.assertEqual(src.env.get('m.credit_op',0),2)
            self.assertEqual(src.env['m.desired'],0x10100)
            src.env.update({'m.credit_word':0x10100,'hdr.envelope.expected_credit':0x10100})
            src.apply_table('successful_admission')
            self.assertEqual(src.env['m.credit_op'],0)

    def test_counter_only_reset_is_counted_refusal_without_stale_binding(self):
        sim=new_sim();request(sim,T);sim.run(T+10*L)
        before={name:dict(sim.cell(name)) for name in ('timing_binding','admission_anchor',
            'observations','releases','committed_response_deadline','ready_response')}
        sim.src.cells[('', 'cookie_counter')][0]={'cookie':0,'word':0}
        request(sim,T+1_000_000);sim.run(T+2_000_000)
        self.assertEqual(counters(sim)[1],1)
        self.assertEqual({name:dict(sim.cell(name)) for name in before},before)
        self.assertEqual(pin_phase(sim),4)
        for reset in ({'cookie':0,'word':0x10000},{'cookie':1,'word':0}):
            sim=new_sim();request(sim,T);sim.run(T+10*L)
            before={name:dict(sim.cell(name)) for name in ('timing_binding','admission_anchor','observations','releases','committed_response_deadline','ready_response')}
            sim.src.cells[('', 'cookie_counter')][0]=reset
            request(sim,T+1_000_000);sim.run(T+2_000_000)
            self.assertEqual(counters(sim)[1],1)
            self.assertEqual({name:dict(sim.cell(name)) for name in before},before)
            self.assertEqual(pin_phase(sim),4)


if __name__=='__main__':unittest.main()
