"""Regress the supporting evaluator's dropped common branch suffix."""
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'protocol'))
from source_control import Source


class CommonSuffix(unittest.TestCase):
    def execute(self,kind,text):
        source=Source('struct headers_t{}\nstruct meta_t{bit<8> kind;bit<32> result;}',
                      {'m.kind':kind,'m.result':0})
        source.run(text)
        return source.env['m.result']

    def test_suffix_runs_for_first_second_and_neither_branch(self):
        text='if(m.kind==8w1){m.result=32w11;}else if(m.kind==8w2){m.result=32w22;}m.result=m.result+32w1;'
        for kind,expected in ((1,12),(2,23),(3,1)):
            self.assertEqual(self.execute(kind,text),expected)

    def test_nested_else_chain_preserves_outer_and_inner_suffix(self):
        text=('if(m.kind==8w1){m.result=32w10;}else if(m.kind==8w2){'
            'if(m.kind==8w2){m.result=32w20;}else if(m.kind==8w3){m.result=32w30;}'
            'm.result=m.result+32w2;}else{m.result=32w40;}m.result=m.result+32w1;')
        for kind,expected in ((1,11),(2,23),(3,41)):
            self.assertEqual(self.execute(kind,text),expected)

    def test_supplied_parser_error_controls_the_actual_guard(self):
        for error,expected in ((0,1),(1,0),(65535,0)):
            source=Source('struct headers_t{}\nstruct meta_t{bit<8> result;}',{'p.parser_err':error,'m.result':0})
            source.run('if(p.parser_err==16w0){m.result=8w1;}')
            self.assertEqual(source.env['m.result'],expected)

    def test_scalar_const_table_rows_execute_declared_actions(self):
        text=('struct headers_t{} struct meta_t{bit<8> operation;bit<8> result;}'
            'action chosen(){m.result=8w9;}'
            'table choice{key={m.operation:exact;}actions={chosen;NoAction;}'
            'const default_action=NoAction();const entries={8w2:chosen();}}')
        for operation,expected in ((0,0),(2,9),(3,0)):
            source=Source(text,{'m.operation':operation,'m.result':0})
            source.table('choice')
            self.assertEqual(source.env['m.result'],expected)
