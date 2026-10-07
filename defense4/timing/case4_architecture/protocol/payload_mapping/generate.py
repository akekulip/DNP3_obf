"""A real private extra pass: preserve arbitrary payload and incrementally repair TCP.

The private16B WorkRef is an identity reference, never an asserted validation flag.
Upstream validation and actual current WorkRecord/epoch authority are required seams.
"""
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent

def generate(direction):
 s=(HERE.parent/f'mapping_{"forward" if direction==1 else "reverse"}.p4').read_text()
 s=s[s.index('#include'):]
 s='/* Private payload mapping primitive; no autonomous ledger or WorkRecord authority. */\n'+s
 s=s.replace('struct headers_t {','header work_h{bit<32> epoch;bit<32> generation;bit<32> expected_cell;bit<16> event;bit<16> reserved;}\nstruct headers_t {work_h work;')
 s=s.replace('struct meta_t {','struct meta_t {bit<16> inverse_checksum;bit<32> inverse_seq;bit<32> inverse_ack;bit<16> inverse_window;bit<32> geometry;')
 start=s.index('parser IgParser(');end=s.index('@pa_container_size',start)
 s=s[:start]+'''parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){Checksum() ipcheck;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;transition select(ig.ingress_port){9w68:work;default:reject;}}
 state work{pkt.extract(hdr.work);transition select(hdr.work.reserved){16w0:eth;default:reject;}}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:reject;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):ip_flags;default:reject;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:reject;}}
 state tcp{pkt.extract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):eligible;(4w5,4w0,8w0x18,16w0):eligible;default:reject;}}
 state eligible{m.parsed=8w1;transition accept;}
}
'''+s[end:]
 if direction==2:
  extra=''.join('@pa_container_size("ingress", "m.'+field+'", 32)\n' for field in ('inverse_ack','inverse_seq','geometry','inverse_window'))
  s=s.replace('control Ingress(',extra+'control Ingress(',1)
 # Epoch keys static connection configuration; no per-packet validity entry exists.
 s=s.replace('hdr.tcp.dport:exact;}actions={configure;', 'hdr.tcp.dport:exact;hdr.work.epoch:exact;}actions={configure;')
 # RFC1624: HC' = ~(~HC + ~old seq/ACK/window + new seq/ACK/window).
 start=s.index(' apply{forwarding.apply();');end=s.index('\ncontrol IgDeparser',start)
 body=s[start:end]
 operations='seq1.apply();seq2.apply();hdr.tcp.seq=m.seq_result;m.changed=1w1;' if direction==1 else 'left1.apply();left2.apply();right1.apply();right2.apply();difference_t.apply();growth_t.apply();window_guard.apply();if(md.drop_ctl==3w0){window_narrow_t.apply();complete_t.apply();}'
 s=s[:start]+''' action snapshot(){m.inverse_checksum=hdr.tcp.checksum^16w0xffff;m.inverse_seq=hdr.tcp.seq^32w0xffffffff;m.inverse_ack=hdr.tcp.ack^32w0xffffffff;m.inverse_window=hdr.tcp.window^16w0xffff;m.geometry=m.second-m.first;}
 table snapshot_t{actions={snapshot;}size=1;const default_action=snapshot();}
 table network_gate{key={m.parsed:exact;m.ip_error:exact;hdr.ip.len:range;hdr.ip.ttl:range;}actions={NoAction;deny;}size=1;const default_action=deny();const entries={(8w1,false,16w40..16w65535,8w1..8w255):NoAction();}}
 apply{forwarding.apply();if(ig.ingress_port==9w68&&p.parser_err==16w0&&md.drop_ctl==3w0){if(hdr.work.generation!=32w0){network_gate.apply();if(md.drop_ctl==3w0){
 connection.apply();if(m.direction==8w'''+str(direction)+'''){if(m.valid==8w0||m.valid==8w1||m.valid==8w3){snapshot_t.apply();if(m.valid!=8w3||m.geometry==32w35){prepare_window_t.apply();edges_t.apply();offsets_t.apply();'''+operations+'''}else{deny();}}else{deny();}}else{deny();}
 }else{deny();}}else{deny();}}else{deny();}}
}
'''+s[end:]
 start=s.index('control IgDeparser(')
 s=s[:start]+'''control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;
 apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({m.inverse_checksum,m.inverse_seq,hdr.tcp.seq,m.inverse_ack,hdr.tcp.ack,m.inverse_window,hdr.tcp.window});}pkt.emit(hdr.work);pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
 if direction==2:
  # Fold the OLD checksum/sequence/ACK/window in the parser checksum engine.
  # This is algebraically the RFC1624 base, without MAU inverseACK copies.
  s=s.replace('Checksum() ipcheck;', 'Checksum() ipcheck;Checksum() repaircheck;',1)
  s=s.replace('state tcp{pkt.extract(hdr.tcp);', 'state tcp{pkt.extract(hdr.tcp);repaircheck.subtract({hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.checksum,16w0});m.repair_sum=repaircheck.get();',1)
  s=s.replace('struct meta_t {','struct meta_t {bit<16> repair_sum;',1)
  for field in ('inverse_checksum','inverse_seq','inverse_ack','inverse_window'):
   s=re.sub(r'bit<\d+> '+field+r';','',s)
   s=re.sub(r'@pa_container_size\("ingress", "m\.'+field+r'", 32\)\n','',s)
  s=re.sub(r'action snapshot\(\)\{[^}]+\}', 'action snapshot(){m.geometry=m.second-m.first;}',s)
  s=s.replace('m.inverse_checksum,m.inverse_seq,hdr.tcp.seq,m.inverse_ack,hdr.tcp.ack,m.inverse_window,hdr.tcp.window','hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,m.repair_sum,16w0')
 if direction==2:
  # Preserve the actual control16 wire word as one field. Its byte slices still
  # check offset/reserved/ACK|PSH and leave the16-bit urgent PMR available.
  s=s.replace('bit<4> offset;bit<4> reserved;bit<8> flags;','bit<16> control_word;')
  s=s.replace('hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent','hdr.tcp.control_word[15:8],hdr.tcp.control_word[7:0],hdr.tcp.urgent')
  s=s.replace('(4w5,4w0,8w0x10,16w0)', '(8w0x50,8w0x10,16w0)').replace('(4w5,4w0,8w0x18,16w0)', '(8w0x50,8w0x18,16w0)')
  s=s.replace('hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags','hdr.tcp.control_word')
 if direction==2:
  # Keep control/window as its real32-bit TCP wireword through all MAU work.
  # This removes the16-bit narrowing/header packing constraint on the ACK graph.
  s=s.replace('bit<16> control_word;bit<16> window;','bit<32> control_window;')
  s=s.replace('struct meta_t {','struct meta_t {bit<32> control_high;bit<32> window_word;',1)
  s=s.replace('hdr.tcp.control_word[15:8]','hdr.tcp.control_window[31:24]').replace('hdr.tcp.control_word[7:0]','hdr.tcp.control_window[23:16]')
  s=s.replace('hdr.tcp.control_word,hdr.tcp.window','hdr.tcp.control_window')
  s=s.replace('m.full_window=16w0++hdr.tcp.window;', 'm.full_window=hdr.tcp.control_window&32w0xffff;')
  s=s.replace('m.original_window=hdr.tcp.window;','')
  s=s.replace('m.output_window=(bit<16>)m.window_after;', 'm.window_word=m.window_after&32w0xffff;m.control_high=hdr.tcp.control_window&32w0xffff0000;')
  s=s.replace('hdr.tcp.window=m.output_window;', 'hdr.tcp.control_window=m.control_high|m.window_word;')
  s=s.replace('control Ingress(', '@pa_container_size("ingress", "hdr.tcp.control_window", 32)\ncontrol Ingress(',1)
 if direction==2:
  # Reuse exhausted scratch words: rightedge is dead after difference; the
  # native advertised window is dead after growth guard. No32-bit edge shrinks.
  s=s.replace('m.growth=m.native_right-m.left;m.window_after=m.native_right-m.left;', 'm.window_after=m.native_right-m.left;')
  s=s.replace('m.growth=m.growth-m.full_window;', 'm.native_right=m.window_after-m.full_window;')
  s=s.replace('key={m.growth:ternary;}', 'key={m.native_right:ternary;}')
  s=s.replace('m.window_word=m.window_after&32w0xffff;m.control_high=hdr.tcp.control_window&32w0xffff0000;', 'm.window_after=m.window_after&32w0xffff;m.full_window=hdr.tcp.control_window&32w0xffff0000;')
  s=s.replace('hdr.tcp.control_window=m.control_high|m.window_word;', 'hdr.tcp.control_window=m.full_window|m.window_after;')
 if direction==2:
  # Parallel scratch preparation with geometry, then mask dead inputs in the
  # same growth action. All ACK/window edges retain their original32-bit widths.
  s=s.replace('snapshot_t.apply();if(m.valid!=8w3||m.geometry==32w35){prepare_window_t.apply();', 'snapshot_t.apply();prepare_window_t.apply();if(m.valid!=8w3||m.geometry==32w35){')
  s=s.replace('action growth(){m.native_right=m.window_after-m.full_window;}', 'action growth(){m.native_right=m.window_after-m.full_window;m.window_after=m.window_after&32w0xffff;m.full_window=hdr.tcp.control_window&32w0xffff0000;}')
  s=s.replace('window_narrow_t.apply();complete_t.apply();', 'complete_t.apply();')
 if direction==2:
  # Independent, read-only admission lookups run in parallel. No ledger/cache
  # mutation exists here; the combined route/network/identity guard precedes
  # every packet header edit. A missing route cannot be rescued by network OK.
  s=s.replace('struct meta_t {', 'struct meta_t {bit<8> network_allowed;',1)
  s=s.replace('m.valid=8w0;transition select(ig.ingress_port)', 'm.valid=8w0;m.network_allowed=8w0;transition select(ig.ingress_port)',1)
  s=s.replace('table network_gate{', 'action network_allow(){m.network_allowed=8w1;}\n table network_gate{',1)
  s=s.replace('actions={NoAction;deny;}size=1;const default_action=deny();const entries={(8w1,false,16w40..16w65535,8w1..8w255):NoAction();}', 'actions={network_allow;NoAction;}size=1;const default_action=NoAction();const entries={(8w1,false,16w40..16w65535,8w1..8w255):network_allow();}')
  s=s.replace('apply{forwarding.apply();if(ig.ingress_port==9w68&&p.parser_err==16w0&&md.drop_ctl==3w0){if(hdr.work.generation!=32w0){network_gate.apply();if(md.drop_ctl==3w0){\n connection.apply();', 'apply{forwarding.apply();network_gate.apply();connection.apply();if(ig.ingress_port==9w68&&p.parser_err==16w0&&md.drop_ctl==3w0){if(hdr.work.generation!=32w0){if(m.network_allowed==8w1){\n ')
 return s

if __name__=='__main__':
 for direction,name in ((1,'forward'),(2,'reverse')):(HERE/f'{name}.p4').write_text(generate(direction))
