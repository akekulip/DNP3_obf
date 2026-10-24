"""Restricted P4 control-fragment evaluator; explicitly not target/parser execution.

Executes source assignments, tables, nested predicates and field-order rendering.
Custom CRC hash semantics are modeled from the declared polynomial parameters.
"""
import re

def block(text,marker):
    at=text.index('{',text.index(marker));depth=1;end=at+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[at+1:end-1]

class Source:
    def __init__(self,text,fields=None,runtime=None,registers=None):
        self.text=re.sub(r'/\*.*?\*/|//[^\n]*','',text,flags=re.S)
        self.env=dict(fields or {});self.runtime=runtime or {};self.registers=registers or {}
        self.valid={};self.width={}
        types={name:dict((field,int(width)) for width,field in re.findall(r'bit<(\d+)>\s+(\w+);',body)) for name,body in re.findall(r'header\s+(\w+)\s*\{([^}]+)\}',self.text)}
        for typename,field in re.findall(r'(\w+)\s+(\w+);',block(self.text,'struct headers_t')):
            for sub,width in types[typename].items():self.width['hdr.'+field+'.'+sub]=width
        self.types=types
        for width,name in re.findall(r'bit<(\d+)>\s+(\w+);',block(self.text,'struct meta_t')):self.width['m.'+name]=int(width)
    def expr(self,s):
        s=s.strip()
        s=re.sub(r'\(([^()]*\+\+[^()]*)\)',lambda x:str(self.expr(x[1])),s)
        if '++' in s:
            total=0
            for term in s.split('++'):
                term=term.strip();width=self.width.get(term)
                if width is None:
                    match=re.fullmatch(r'(.+)\[(\d+):(\d+)\]',term)
                    width=int(match[2])-int(match[3])+1 if match else int(re.match(r'(\d+)w',term)[1])
                total=(total<<width)|self.expr(term)
            return total
        cast=re.match(r'^\(bit<(\d+)>\)(.+)',s)
        if cast:return self.expr(cast[2])&((1<<int(cast[1]))-1)
        hashed=re.fullmatch(r'hash_\w+\.get\(\{(.+)\}\)',s)
        if hashed:
            bits=''.join(format(self.expr(f.strip()),'0'+str(self.width[f.strip()])+'b') for f in hashed[1].split(','))
            data=int(bits,2).to_bytes(len(bits)//8,'big')
            poly=int(re.search(r'CRCPolynomial<bit<16>>\(16w(0x\w+)',self.text)[1],16)
            reverse=int(format(poly,'016b')[::-1],2)
            v=0
            for byte in data:
                v^=byte
                for _ in range(8):v=(v>>1)^(reverse if v&1 else 0)
            return v^0xffff
        read=re.fullmatch(r'(\w+)\.execute\((.+)\)',s)
        if read:return self.register(read[1],self.expr(read[2]))
        s=re.sub(r'(hdr\.\w+\.\w+|m\.\w+)\[(\d+):(\d+)\]',lambda x:str((self.env.get(x[1],0)>>int(x[3]))&((1<<(int(x[2])-int(x[3])+1))-1)),s)
        s=re.sub(r'\bv\.\w+\b',lambda x:str(self.env.get(x[0],0)),s)
        s=re.sub(r'\b(v|rv)\b',lambda x:str(self.env.get(x[1],0)),s)
        s=re.sub(r'\b(hdr\.\w+\.\w+|m\.\w+|md\.drop_ctl|tm\.\w+)\b',lambda x:str(self.env.get(x[1],0)),s)
        s=re.sub(r'\b\d+w(0x[0-9a-fA-F]+|\d+)',r'\1',s)
        s=s.replace('&&',' and ').replace('||',' or ').replace('false','False').replace('true','True')
        s=re.sub(r'!(?!=)',' not ',s)
        if not re.fullmatch(r'[\dabcdefxABCDEF\s()+<>=!&|\-*/orandtFlsu]+',s):raise ValueError('unsupported expression '+s)
        return eval(s,{'__builtins__':{}},{})
    def register(self,name,index):
        bound=re.search(r'RegisterAction<[^;]+>\((\w+)\)\s*'+name+r'=',self.text)[1]
        key=(bound,index);old=self.registers.get(key,self.registers.get((name,index),0))
        paired=isinstance(old,dict)
        if paired:
            for field,value in old.items():self.env['v.'+field]=value;self.width['v.'+field]=32
        else:self.env['v']=old;self.width['v']=32
        self.env['rv']=0;self.width['rv']=32
        body=block(block(self.text,name+'='),'void apply')
        self.run(body);self.registers[key]={field:self.env['v.'+field] for field in old} if paired else self.env['v']
        return self.env['rv']
    def action(self,name,args=()):
        if name=='NoAction':return
        opening=self.text.index('action '+name+'(');end=self.text.index(')',opening)
        params=re.findall(r'bit<\d+>\s+(\w+)|PortId_t\s+(\w+)',self.text[opening:end])
        body=block(self.text,'action '+name+'(')
        for (a,b),arg in zip(params,args):body=re.sub(r'(?<![\w.])'+(a or b)+r'\b',str(arg),body)
        self.run(body)
    def table(self,name):
        if name in self.runtime:
            entry=self.runtime[name]
            if isinstance(entry,dict):
                declared=re.findall(r'((?:hdr\.\w+\.\w+|m\.\w+)(?:\[\d+:\d+\])?):exact;',block(self.text,'table '+name+'{'))
                if set(declared)!=set(entry['keys']):raise ValueError('runtime key schema mismatch')
                if all(self.expr(key)==value for key,value in entry['keys'].items()):self.action(entry['action'],entry.get('args',()));return
            else:
                action,args=entry;self.action(action,args);return
        body=block(self.text,'table '+name+'{')
        keys=re.findall(r'((?:hdr\.\w+\.\w+|m\.\w+)(?:\[\d+:\d+\])?):(?:exact|ternary|range);',body)
        for values,action in re.findall(r'\(([^()]+)\):(\w+)\(\);',body):
            terms=values.split(',')
            if len(terms)!=len(keys):raise ValueError('key mismatch')
            yes=True
            for key,term in zip(keys,terms):
                got=self.expr(key)
                if '&&&' in term:
                    value,mask=map(self.expr,term.split('&&&'));yes&=got&mask==value
                else:yes&=got==self.expr(term)
            if yes:self.action(action);return
        default=re.search(r'default_action=(\w+)\(\)',body)
        self.action(default[1])
    def run(self,text):
        while text.strip():
            text=text.lstrip()
            if text.startswith('{'):
                nested=block(text,'');self.run(nested);text=text[len(nested)+2:];continue
            if text.startswith('if(') or text.startswith('if ('):
                at=text.index('(');end=at+1;depth=1
                while depth:
                    depth+=(text[end]=='(')-(text[end]==')');end+=1
                predicate=text[at+1:end-1];branch=block(text,'if');start=text.index('{',end)
                after=text[start+len(branch)+2:].lstrip();other=None
                if after.startswith('else if'):
                    other=after[5:];after=''
                elif after.startswith('else{') or after.startswith('else {'):
                    other=block(after,'else');after=after[after.index('{')+len(other)+2:]
                if self.expr(predicate):self.run(branch)
                elif other is not None:self.run(other)
                text=after;continue
            end=text.index(';');statement=text[:end].strip();text=text[end+1:]
            if not statement:continue
            applied=re.fullmatch(r'(\w+)\.apply\(\)',statement)
            valid=re.fullmatch(r'hdr\.(\w+)\.(setValid|setInvalid)\(\)',statement)
            bare=re.fullmatch(r'(\w+)\(\)',statement)
            called=re.fullmatch(r'(\w+)\.execute\((.+)\)',statement)
            assignment=re.fullmatch(r'((?:v\.\w+|v|rv|hdr\.\w+\.\w+|m\.\w+|md\.\w+|tm\.\w+))=(.+)',statement)
            if applied:self.table(applied[1])
            elif bare:self.action(bare[1])
            elif called:self.register(called[1],self.expr(called[2]))
            elif valid:self.valid[valid[1]]=valid[2]=='setValid'
            elif assignment:
                field=assignment[1];self.env[field]=self.expr(assignment[2])&((1<<self.width.get(field,32))-1)
            else:raise ValueError('unsupported statement '+statement)
    def render(self,header):
        fields=[(field,width) for field,width in self.width.items() if field.startswith('hdr.'+header+'.')]
        bits=''.join(format(self.env.get(field,0),'0'+str(width)+'b') for field,width in fields)
        return int(bits,2).to_bytes(len(bits)//8,'big')
