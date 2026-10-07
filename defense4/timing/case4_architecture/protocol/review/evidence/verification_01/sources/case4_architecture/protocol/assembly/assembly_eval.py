"""Source control evaluator extension for actual constant range table entries."""
from source_eval import Source as Base,block
import re
class Source(Base):
    def expr(self,s):
        s=re.sub(r"\(bit<(\d+)>\)((?:m\.\w+|hdr\.\w+\.\w+))",lambda x:str(self.env.get(x[2],0)&((1<<int(x[1]))-1)),s)
        s=s.replace("(bit<32>)p.global_tstamp",str(self.env.get("p.global_tstamp",0)&0xffffffff))
        if "^" in s:
            a,b=s.split("^",1);return self.expr(a)^self.expr(b)
        return super().expr(s)
    def table(self,name):
        body=block(self.text,'table '+name+'{')
        keys=re.findall(r'((?:hdr\.\w+\.\w+|m\.\w+)(?:\[\d+:\d+\])?):(?:exact|ternary|range);',body)
        if ':range;' not in body and len(keys)!=1:return super().table(name)
        rows=re.findall(r'\(([^()]+)\):(\w+)\(\);',body)
        if len(keys)==1:rows+=re.findall(r'(?<![\w(])(\d+w(?:0x[0-9a-fA-F]+|\d+)):(\w+)\(\);',body)
        for values,action in rows:
            terms=values.split(',');yes=True
            if len(keys)!=len(terms):raise ValueError('key mismatch')
            for key,term in zip(keys,terms):
                got=self.expr(key)
                if '..' in term:
                    low,high=map(self.expr,term.split('..'));yes&=low<=got<=high
                elif '&&&' in term:
                    value,mask=map(self.expr,term.split('&&&'));yes&=got&mask==value
                else:yes&=got==self.expr(term)
            if yes:self.action(action);return
        default=re.search(r'default_action=(\w+)\(\)',body);self.action(default[1])
