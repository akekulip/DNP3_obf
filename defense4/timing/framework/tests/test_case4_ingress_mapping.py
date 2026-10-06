"""Private processing source arithmetic; no target execution or activation proof."""
import re
import sys
import unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'p4'))
import fixed_layout
from make_joint_processing_probe import block


def source_mapping(text, work):
    """Execute only the component's pure arithmetic/constant-table fragments.

    CP register values are supplied explicitly. This deliberately does not model
    queues, SALU runtime, trust, validation, or physical loopback service.
    """
    def integer(value):
        return int(re.sub(r'^\d+w', '', value.strip()), 0)

    def operand(expression):
        match=re.fullmatch(r'hdr.work.(\w+)(?:\[(\d+):(\d+)\])?',expression.strip())
        if not match:return integer(expression)
        value=work[match[1]]
        if match[2]:value=(value>>int(match[3]))&((1<<(int(match[2])-int(match[3])+1))-1)
        return value

    def action(name):
        if name=='NoAction':return
        if name=='reject':
            work['rejected']=True
            return
        body=block(text,'action '+name+'()').partition('{')[2][:-1]
        for statement in body.split(';'):
            if not statement.strip():continue
            match=re.fullmatch(r'\s*hdr.work.(\w+)\s*=\s*(.+)',statement)
            if not match:raise AssertionError('not a pure source arithmetic fragment: '+statement)
            terms=re.split(r'\s*([+-])\s*',match[2])
            value=operand(terms[0])
            if len(terms)==3:
                value=value+operand(terms[2]) if terms[1]=='+' else value-operand(terms[2])
            elif len(terms)!=1:raise AssertionError('unsupported arithmetic expression')
            work[match[1]]=value&0xffffffff

    def table(name):
        body=block(text,'table '+name+' ')
        keys=re.findall(r'(hdr.work.\w+(?:\[\d+:\d+\])?):(exact|range|ternary);',body)
        rows=re.findall(r'\(([^()]*)\):\s*(\w+)\(\);',body)
        for row,name in rows:
            matches=row.split(',')
            if len(matches)!=len(keys):raise AssertionError('source row/key mismatch')
            accepted=True
            for (key,kind),item in zip(keys,matches):
                got=operand(key)
                if '..' in item:
                    low,high=map(integer,item.split('..'));accepted &= low<=got<=high
                elif '&&&' in item:
                    value,mask=map(integer,item.split('&&&'));accepted &= got&mask==value
                else:accepted &= got==integer(item)
            if accepted:
                action(name);return
        action(re.search(r'default_action\s*=\s*(\w+)\(\)',body)[1])

    # Phase zero reads/init are not inferred. Supply the declared seeded state,
    # then interpret each actual phase's pure action/table calls from the source.
    for phase in range(1,15):
        branch=block(text,'else if(hdr.work.phase==8w'+str(phase)+')')
        for name in re.findall(r'(\w+)\.apply\(\)',branch):table(name)
    return work

class IngressMapping(unittest.TestCase):
    def test_half_range_window_cannot_be_inflated_by_independent_wrapping(self):
        text=(BASE/'p4/case4_ingress_mapping.p4').read_text()
        ack=(35+0x7ffffff6)&0xffffffff
        observed=source_mapping(text,dict(first_start=0,second_start=35,
            first_valid=1,second_valid=2,seq_native=0,seq_wire=0,
            ack_wire=ack,window=20,left_native=ack,right_native=ack,offset=0))
        self.assertTrue(observed.get('rejected'), 'wrapped right edge advertises 60 instead of 20 bytes')
        with self.assertRaises(ValueError):
            fixed_layout.map_ack_window(ack,20,0,35)
        with self.assertRaises(ValueError):
            fixed_layout.map_ack_window(0x7ffffff6,20,0,35)

    def test_component_exists_with_explicit_bounds_and_disabled_completion(self):
        source=BASE/'p4/case4_ingress_mapping.p4'
        self.assertTrue(source.exists(), 'ingress arithmetic implementation missing')
        text=source.read_text()
        for fragment in ('MAX_PASSES = 8w16','WORK_TYPE = 16w0x88CA',
                         'Register<bit<32>, bit<1>>','first_valid',
                         'second_valid','cookie_read','tm.qid = 5w0',
                         'No validation proof'):
            self.assertIn(fragment,text)
        self.assertRegex(text,r'default_action\s*=\s*reject\(\)')
        self.assertNotIn('0xFFFFFFFF',text)

    def test_each_source_inverse_action_matches_independent_edges(self):
        source=BASE/'p4/case4_ingress_mapping.p4'
        self.assertTrue(source.exists(), 'ingress arithmetic implementation missing')
        text=source.read_text()
        for edge in ('left','right'):
            for which,base_field,expected in ((1,'first_start',34),(2,'second_start',34)):
                match=re.search(r'action '+edge+'_clamp_'+str(which)+r'\(\)\s*\{\s*hdr.work.'+edge+r'_native\s*=\s*hdr.work.'+base_field+r'\s*\+\s*32w(\d+);',text)
                self.assertIsNotNone(match)
                self.assertEqual(int(match[1]),expected)
        # The second boundary uses native coordinates: the first insertion has
        # already added twenty bytes before the second wire tail starts.
        for base in (1000,0xfffffff0):
            second=(base+35)&0xffffffff
            for offset in range(-2,151):
                def inverse(n):
                    if n<35:return n
                    if n<55:return 34
                    if n<90:return n-20
                    if n<110:return 69
                    return n-40
                for window in (0,1,20,40,65535):
                    ack,win=fixed_layout.map_ack_window((base+offset)&0xffffffff,window,base,second)
                    self.assertEqual((ack,win),((base+inverse(offset))&0xffffffff,inverse(offset+window)-inverse(offset)))

    def test_source_phases_map_both_window_edges_and_sequence_independently(self):
        text=(BASE/'p4/case4_ingress_mapping.p4').read_text()
        for base in (1000,0xfffffff0):
            for offset in (-2,0,34,35,54,55,69,70,89,90,109,110,127,128,500):
                for window in (0,1,20,40,65535):
                    seq=(base+offset)&0xffffffff
                    work=dict(first_start=base,second_start=(base+35)&0xffffffff,
                        first_valid=1,second_valid=2,seq_native=seq,seq_wire=seq,
                        ack_wire=seq,window=window,left_native=seq,right_native=seq,offset=0)
                    observed=source_mapping(text,work)
                    self.assertFalse(observed.get('rejected',False))
                    ack,win=fixed_layout.map_ack_window(seq,window,base,(base+35)&0xffffffff)
                    self.assertEqual((observed['left_native'],observed['window']), (ack,win))
                    self.assertEqual(observed['seq_wire'],fixed_layout.map_seq(seq,base,(base+35)&0xffffffff))

    def test_uncommitted_boundaries_do_not_translate_even_zero_sequence_start(self):
        text=(BASE/'p4/case4_ingress_mapping.p4').read_text()
        for window in (0,65535):
            observed=source_mapping(text,dict(first_start=0,second_start=0,
                first_valid=0,second_valid=0,seq_native=35,seq_wire=35,
                ack_wire=55,window=window,left_native=55,right_native=55,offset=0))
            self.assertFalse(observed.get('rejected',False))
            self.assertEqual((observed['seq_wire'],observed['left_native'],observed['window']),(35,55,window))

if __name__=='__main__':unittest.main()
