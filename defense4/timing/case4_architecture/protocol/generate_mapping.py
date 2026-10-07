"""Generate a new grouped, one-pass fixed-header TCP arithmetic component."""
from pathlib import Path

def generate():
 s='''/* Grouped TCP mapping primitive. CP-seeded two-boundary state only; no handshake/producer.
 * One ingress pass completes a real pure-ACK packet; no internal placeholder completion.
 * Default forwarding/profile tables deny. No hardware qualification. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
struct headers_t {eth_h eth;ip_h ip;tcp_h tcp;}
struct meta_t {bit<32> first;bit<32> second;bit<8> valid;bit<8> direction;PortId_t output_port;
 bit<32> right;bit<32> left;bit<32> native_right;bit<32> so1;bit<32> so2;bit<32> ao1;bit<32> ao2;bit<32> ro1;bit<32> ro2;
 bit<32> seq_result;bit<16> output_window;bit<32> full_window;bit<32> window_after;bit<32> original_seq;bit<32> original_ack;bit<32> growth;bit<16> original_window;bit<16> tcp_len;bit<16> tcp_sum;bool ip_error;bit<8> parsed;bit<1> changed;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 Checksum() ipcheck;Checksum() tcpcheck;
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);m.parsed=8w0;m.changed=1w0;m.direction=8w0;m.valid=8w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();tcpcheck.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});
 transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.len){(4w4,4w5,8w6,16w40):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);tcpcheck.subtract(hdr.tcp);m.tcp_sum=tcpcheck.get();transition select(hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.urgent){(4w5,4w0,8w0x10,16w0):eligible;default:accept;} }
 state eligible{m.parsed=8w1;transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){m.output_port=port;tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 action configure(bit<32> first,bit<32> second,bit<8> valid,bit<8> direction){m.first=first;m.second=second;m.valid=valid;m.direction=direction;}
 table connection{key={hdr.ip.src:exact;hdr.ip.dst:exact;hdr.tcp.sport:exact;hdr.tcp.dport:exact;}actions={configure;NoAction;}size=2;default_action=NoAction();}
 action prepare_window(){m.full_window=16w0++hdr.tcp.window;}
 table prepare_window_t{actions={prepare_window;}size=1;const default_action=prepare_window();}
 action edges(){m.right=hdr.tcp.ack+m.full_window;m.left=hdr.tcp.ack;m.original_ack=hdr.tcp.ack;m.original_seq=hdr.tcp.seq;m.seq_result=hdr.tcp.seq;m.original_window=hdr.tcp.window;m.tcp_len=16w20;}
 table edges_t{actions={edges;}size=1;const default_action=edges();}
 action offsets(){m.so1=m.original_seq-m.first;m.so2=m.original_seq-m.second;m.ao1=m.original_ack-m.first;m.ao2=m.original_ack-m.second;m.ro1=m.right-m.first;m.ro2=m.right-m.second;m.native_right=m.right;}
 table offsets_t{actions={offsets;}size=1;const default_action=offsets();}
'''
 s=s.replace('control Ingress(', '\n'.join('@pa_container_size("ingress", "'+name+'", 32)' for name in ['hdr.tcp.seq','hdr.tcp.ack']+['m.'+f for f in ['first','second','right','left','native_right','so1','so2','ao1','ao2','ro1','ro2','original_seq','original_ack','growth','full_window','window_after','seq_result']])+'\ncontrol Ingress(')
 for kind,field,base,which,delta,low,high in [('seq','so1','first',1,20,35,35),('seq','so2','second',2,40,35,35),('left','ao1','first',1,20,35,55),('left','ao2','second',2,40,55,75),('right','ro1','first',1,20,35,55),('right','ro2','second',2,40,55,75)]:
  name=kind+str(which)
  valid=1 if which==1 else 2
  direction=1 if kind=='seq' else 2
  out='m.seq_result' if kind=='seq' else 'm.left' if kind=='left' else 'm.native_right'
  original='m.original_seq' if kind=='seq' else 'm.original_ack' if kind=='left' else 'm.right'
  op='+' if kind=='seq' else '-'
  s+=f'action {name}_shift(){{{out}={original}{op}32w{delta};}}\n'
  actions=f'{name}_shift;NoAction;'
  if kind!='seq':
   s+=f'action {name}_clamp(){{{out}=m.{base}+32w34;}}\n';actions+=f'{name}_clamp;'
  def cover(a,b):
   while a<=b:
    size=(a & -a) if a else 1<<32
    while size>b-a+1:size>>=1
    yield a,(0xffffffff^(size-1))
    a+=size
  mask=1 if which==1 else 2
  rows=[]
  if kind!='seq':rows += [(v,m,name+'_clamp') for v,m in cover(low,high-1)]
  rows += [(v,m,name+'_shift') for v,m in cover(high,0x7fffffff)]
  s+=f'table {name}{{key={{m.direction:exact;m.valid:ternary;m.{field}:ternary;}}actions={{{actions}}}size=128;const default_action=NoAction();const entries={{\n'
  for value,bits,action in rows:s+=f'(8w{direction},8w{valid}&&&8w{mask},32w{hex(value)}&&&32w{hex(bits)}):{action}();\n'
  s+='}}\n'
 s+='''action difference(){m.growth=m.native_right-m.left;m.window_after=m.native_right-m.left;}
 table difference_t{actions={difference;}size=1;const default_action=difference();}
 action growth(){m.growth=m.growth-m.full_window;}
 table growth_t{actions={growth;}size=1;const default_action=growth();}
 table window_guard{key={m.growth:ternary;}actions={deny;NoAction;}size=32;const default_action=NoAction();const entries={
(32w0x1&&&32w0xffffffff):deny();
(32w0x2&&&32w0xfffffffe):deny();
(32w0x4&&&32w0xfffffffc):deny();
(32w0x8&&&32w0xfffffff8):deny();
(32w0x10&&&32w0xfffffff0):deny();
(32w0x20&&&32w0xffffffe0):deny();
(32w0x40&&&32w0xffffffc0):deny();
(32w0x80&&&32w0xffffff80):deny();
(32w0x100&&&32w0xffffff00):deny();
(32w0x200&&&32w0xfffffe00):deny();
(32w0x400&&&32w0xfffffc00):deny();
(32w0x800&&&32w0xfffff800):deny();
(32w0x1000&&&32w0xfffff000):deny();
(32w0x2000&&&32w0xffffe000):deny();
(32w0x4000&&&32w0xffffc000):deny();
(32w0x8000&&&32w0xffff8000):deny();
(32w0x10000&&&32w0xffff0000):deny();
(32w0x20000&&&32w0xfffe0000):deny();
(32w0x40000&&&32w0xfffc0000):deny();
(32w0x80000&&&32w0xfff80000):deny();
(32w0x100000&&&32w0xfff00000):deny();
(32w0x200000&&&32w0xffe00000):deny();
(32w0x400000&&&32w0xffc00000):deny();
(32w0x800000&&&32w0xff800000):deny();
(32w0x1000000&&&32w0xff000000):deny();
(32w0x2000000&&&32w0xfe000000):deny();
(32w0x4000000&&&32w0xfc000000):deny();
(32w0x8000000&&&32w0xf8000000):deny();
(32w0x10000000&&&32w0xf0000000):deny();
(32w0x20000000&&&32w0xe0000000):deny();
(32w0x40000000&&&32w0xc0000000):deny();
}}
 action window_narrow(){m.output_window=(bit<16>)m.window_after;}
 table window_narrow_t{actions={window_narrow;}size=1;const default_action=window_narrow();}
 action complete(){hdr.tcp.seq=m.seq_result;hdr.tcp.ack=m.left;hdr.tcp.window=m.output_window;m.changed=1w1;tm.ucast_egress_port=m.output_port;}
 table complete_t{actions={complete;}size=1;const default_action=complete();}
 apply{forwarding.apply();if(m.parsed==8w1 && !m.ip_error && m.tcp_sum==16w0xFFEB){
 connection.apply();if(m.direction!=8w0){prepare_window_t.apply();edges_t.apply();offsets_t.apply();seq1.apply();seq2.apply();left1.apply();left2.apply();right1.apply();right2.apply();
 if(m.direction==8w2){difference_t.apply();growth_t.apply();window_guard.apply();window_narrow_t.apply();complete_t.apply();}else{hdr.tcp.seq=m.seq_result;m.changed=1w1;}}}}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){Checksum() tcpcheck;apply{if(m.changed==1w1){hdr.tcp.checksum=tcpcheck.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_len,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent});}pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition eth;}state eth{pkt.extract(hdr.eth);transition ip;}state ip{pkt.extract(hdr.ip);transition tcp;}state tcp{pkt.extract(hdr.tcp);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
'''
 return s
if __name__=='__main__':Path(__file__).with_name('mapping.p4').write_text(generate())
