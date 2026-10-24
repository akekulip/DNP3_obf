"""Restricted parser/control/deparser evaluator, supporting evidence only.

Executes the candidate's actual state selectors/extractions/checksum commands.
Not a switch model; intrinsic/parser error metadata and TM behavior are not modeled.
"""
import re
from pathlib import Path
import sys
ARCH=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ARCH/'tests'),str(ARCH/'protocol')]
from source_control import Source as ControlSource
from source_eval import block


def folded(data):
 if len(data)%2:data+=b'\0'
 value=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
 while value>>16:value=(value&65535)+(value>>16)
 return value

def checksum(data):return folded(data)^65535

class Source(ControlSource):
 def bytes_expr(self,text):
  if text.startswith('{'):
   fields=text[1:-1].split(',')
   bits=''
   for field in fields:
    field=field.strip();literal=re.fullmatch(r'(\d+)w.+',field)
    width=int(literal[1]) if literal else self.width[field]
    bits+=format(self.expr(field),f'0{width}b')
   return int(bits,2).to_bytes(len(bits)//8,'big')
  return self.render(text[4:] if text.startswith('hdr.') else text)
 def expr(self,text):
  match=re.fullmatch(r'(?:ic|tc)\.update\((\{.*\})\)',text.strip())
  if match:return checksum(self.bytes_expr(match[1]))
  return super().expr(text)
 def packet_parser(self,raw,parser='IgParser'):
  states=block(self.text,'parser '+parser+'(');state='start';cursor=0;checksums={'ic':bytearray(),'tc':bytearray()}
  for _ in range(32):
   if state in ('accept','reject'):return state=='accept',cursor
   body=block(states,'state '+state+'{');commands,transition=body.split('transition',1)
   for command in commands.split(';'):
    command=command.strip()
    if not command:continue
    extract=re.fullmatch(r'pkt.extract\(hdr\.(\w+)\)',command)
    if extract:
     header=extract[1];fields=[(k,w) for k,w in self.width.items() if k.startswith('hdr.'+header+'.')];size=sum(w for _,w in fields)//8
     if cursor+size>len(raw):return False,cursor
     value=int.from_bytes(raw[cursor:cursor+size],'big');remaining=size*8
     for key,width in fields:remaining-=width;self.env[key]=(value>>remaining)&((1<<width)-1)
     self.valid[header]=True;cursor+=size;continue
    if command.startswith(('pkt.extract(ig)','pkt.extract(eg)','pkt.advance(')):continue
    added=re.fullmatch(r'(ic|tc)\.(add|subtract)\((.*)\)',command)
    if added:checksums[added[1]].extend(self.bytes_expr(added[3]));continue
    verify=re.fullmatch(r'(m\.\w+)=(ic|tc)\.(verify|get)\(\)',command)
    if verify:
     value=folded(bytes(checksums[verify[2]]))
     self.env[verify[1]]=int(value!=65535) if verify[3]=='verify' else checksum(bytes(checksums[verify[2]]));continue
    self.run(command+';')
   transition=transition.strip().rstrip(';').strip()
   if transition.startswith('select('):
    closing=transition.index(')');keys=[self.expr(k.strip()) for k in transition[7:closing].split(',')]
    choices=block(transition,'select');target=None
    for values,name in re.findall(r'(\([^()]+\)|\d+w(?:0x[0-9A-Fa-f]+|\d+)|default)\s*:\s*(\w+)\s*;',choices):
     if values=='default':
      if target is None:target=name
      continue
     terms=values.strip('()').split(',')
     if len(terms)==len(keys) and all(value==self.expr(term.strip()) for value,term in zip(keys,terms)):target=name;break
    if target is None:raise ValueError('unsupported parser selector '+transition)
    state=target
   else:state=transition
  raise ValueError('parser exceeded bounded states')
 def apply_control(self,name):self.run(block(block(self.text,'control '+name+'('),' apply{'))
 def deparse(self,name,headers):
  text=block(block(self.text,'control '+name+'('),'apply{');self.run(text.split('pkt.emit(')[0])
  return b''.join(self.render(h) for h in headers if self.valid.get(h,False))
