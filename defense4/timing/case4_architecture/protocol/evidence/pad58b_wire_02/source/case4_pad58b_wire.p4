/* Egress-resident realization of case4_pad58b.py's whitelisted-qualifier 58-byte pad. Byte constants
   (fillers, length bytes, CRCs) verified against a live run of the real codec and cross-checked against
   rrc.dnp3_crc before being written here (see LEDGER.md 2026-10-08 Phase D entry). No PRE/multicast: one
   packet in, one (larger) packet out, so all work fits in egress -- required anyway since pipe 0's
   ingress is already saturated 12/12 by installed_nf_05. Ingress here is a bare forwarding stub for a
   standalone compile; integration into the real pipe-0 ingress is a separate, later step. */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;bit<16> checksum;bit<16> urgent;}
header dl_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header read_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<8> g_start;bit<8> g_stop;bit<48> data_mid;bit<16> crc0;}
header read_b1_h{bit<128> data;bit<16> crc1;}
header read_tail_n_h{bit<8> data_last;bit<16> crc2;}
header read_tail_p_h{bit<8> data_last;bit<72> filler;bit<16> crc2;}
header ctl_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<16> g_count;bit<16> index;bit<8> crob_code;bit<8> crob_count;bit<16> on_hi;bit<16> crc0;}
header ctl_tail_n_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<16> crc1;}
header ctl_tail_p1_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<72> filler_a;bit<16> crc1;}
header ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}
struct headers_t{eth_h eth;ip_h ip;tcp_h tcp;dl_h dl;read_b0_h rb0;read_b1_h rb1;read_tail_n_h rtn;read_tail_p_h rtp;ctl_b0_h cb0;ctl_tail_n_h ctn;ctl_tail_p1_h ctp1;ctl_tail_p2_h ctp2;}
struct meta_t{bit<1> changed;bit<16> tcp_length;bit<16> dlcrc;bit<16> rtcrc;bit<16> ctcrc1;
 bit<1> read_shape;bit<1> ctl_shape;
 bit<16> in_dl;bit<16> in_rb0;bit<16> in_rb1;bit<16> in_rt;bit<16> in_cb0;bit<16> in_ct;
 bit<1> badh;bit<1> rbad0;bit<1> rbad1;bit<1> rbadt;bit<1> cbad0;bit<1> cbadt;}
/* Each shape/bad-CRC flag is written by a different table. Packed into one container (bf-p4c's default),
   every writer becomes an action dependency of the previous one ("due to PHV allocation" in
   table_placement_*.log) and egress grew 6 -> 10 stages; one container per flag removes that. */
@pa_solitary("egress","m.read_shape") @pa_solitary("egress","m.ctl_shape")
@pa_solitary("egress","m.badh") @pa_solitary("egress","m.rbad0") @pa_solitary("egress","m.rbad1")
@pa_solitary("egress","m.rbadt") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,out ingress_intrinsic_metadata_t ig){
 state start{pkt.extract(ig);pkt.advance(PORT_METADATA_SIZE);transition eth;}
 state eth{pkt.extract(hdr.eth);transition accept;}
}
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t p,inout ingress_intrinsic_metadata_for_deparser_t md,inout ingress_intrinsic_metadata_for_tm_t tm){
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;}
 table forwarding{key={ig.ingress_port:exact;}actions={route;deny;}size=4;default_action=deny();}
 apply{forwarding.apply();}
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr.eth);}}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,out egress_intrinsic_metadata_t eg){
 state start{pkt.extract(eg);m.changed=1w0;m.read_shape=1w0;m.ctl_shape=1w0;
  m.badh=1w0;m.rbad0=1w0;m.rbad1=1w0;m.rbadt=1w0;m.cbad0=1w0;m.cbadt=1w0;transition eth;}
 state eth{pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip{pkt.extract(hdr.ip);transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto){(4w4,4w5,8w6):ip_flags;default:accept;}}
 state ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):tcp;(13w0,3w2):tcp;default:accept;}}
 state tcp{pkt.extract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved){(4w5,4w0):dl;default:accept;}}
 state dl{pkt.extract(hdr.dl);transition select(hdr.ip.len){16w89:read_b0;16w77:ctl_b0;default:accept;}}
 state read_b0{pkt.extract(hdr.rb0);transition read_b1;}
 state read_b1{pkt.extract(hdr.rb1);transition read_tail;}
 state read_tail{pkt.extract(hdr.rtn);transition accept;}
 state ctl_b0{pkt.extract(hdr.cb0);transition ctl_tail;}
 state ctl_tail{pkt.extract(hdr.ctn);transition accept;}
}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,inout egress_intrinsic_metadata_for_output_port_t port){
 /* Eligibility: byte-for-byte the same checks as case4_pad58b.py's own pad_read_response/
    pad_control_response, plus a dl.start/dl.len sanity match (link sync bytes and the exact native
    link length) that the software codec gets for free from decode_frame's own strict length check.
    The profile tables only record the shape; the transform runs later, and only if every native link
    CRC also checks (case4_padding.decode_frame -> rrc.dnp3_frame_ok: a bad CRC returns the frame unchanged). */
 action read_shape(){m.read_shape=1w1;}
 table read_profile{key={hdr.dl.start:exact;hdr.dl.len:exact;hdr.rb0.tpctrl:ternary;hdr.rb0.appctrl:ternary;hdr.rb0.func:exact;hdr.rb0.g_group:exact;hdr.rb0.g_var:exact;hdr.rb0.g_qual:exact;hdr.rb0.g_start:exact;hdr.rb0.g_stop:exact;}
  actions={read_shape;NoAction;}size=1;const default_action=NoAction();
  const entries={(16w0x0564,8w0x26,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0a,8w0x02,8w0x00,8w0x00,8w0x16):read_shape();}}
 action ctl_shape(){m.ctl_shape=1w1;}
 table ctl_profile{key={hdr.dl.start:exact;hdr.dl.len:exact;hdr.cb0.tpctrl:ternary;hdr.cb0.appctrl:ternary;hdr.cb0.func:exact;hdr.cb0.g_group:exact;hdr.cb0.g_var:exact;hdr.cb0.g_qual:exact;hdr.cb0.g_count:exact;hdr.ctn.status:exact;}
  actions={ctl_shape;NoAction;}size=1;const default_action=NoAction();
  const entries={(16w0x0564,8w0x1c,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):ctl_shape();}}
 action read_eligible(){hdr.rtp.setValid();hdr.rtp.data_last=hdr.rtn.data_last;hdr.rtp.filler=72w0x290106290206290306;hdr.rtn.setInvalid();hdr.dl.len=8w0x2f;hdr.ip.len=16w98;m.changed=1w1;}
 table read_pad_t{actions={read_eligible;}size=1;const default_action=read_eligible();}
 action ctl_eligible(){hdr.ctp1.setValid();hdr.ctp1.on_lo=hdr.ctn.on_lo;hdr.ctp1.off=hdr.ctn.off;hdr.ctp1.status=hdr.ctn.status;hdr.ctp1.filler_a=72w0x29032802002d010000;hdr.ctp2.setValid();hdr.ctp2.filler_b=80w0x2041002e010000a04100;hdr.ctp2.crc2=16w0xf995;hdr.ctn.setInvalid();hdr.dl.len=8w0x2f;hdr.ip.len=16w98;m.changed=1w1;}
 table ctl_pad_t{actions={ctl_eligible;}size=1;const default_action=ctl_eligible();}
 CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
 /* Native-CRC validation: one Hash instance per computation site (padding.p4 precedent), all computed
    over the NATIVE fields before any mutation. The link header is validated once for both roles: its
    CRC covers whatever len byte is on the wire, and the profile tables' exact dl.len match already pins
    that byte to 0x26 (READ) or 0x1c (CONTROL), so a role-specific second header path would add nothing. */
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_dl;
 action in_dl(){m.in_dl=hash_in_dl.get({hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table in_dl_t{actions={in_dl;}size=1;const default_action=in_dl();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb0;
 action in_rb0(){m.in_rb0=hash_in_rb0.get({hdr.rb0.tpctrl,hdr.rb0.appctrl,hdr.rb0.func,hdr.rb0.iin,hdr.rb0.g_group,hdr.rb0.g_var,hdr.rb0.g_qual,hdr.rb0.g_start,hdr.rb0.g_stop,hdr.rb0.data_mid});}
 table in_rb0_t{actions={in_rb0;}size=1;const default_action=in_rb0();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb1;
 action in_rb1(){m.in_rb1=hash_in_rb1.get({hdr.rb1.data});}
 table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rt;
 action in_rt(){m.in_rt=hash_in_rt.get({hdr.rtn.data_last});}
 table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_cb0;
 action in_cb0(){m.in_cb0=hash_in_cb0.get({hdr.cb0.tpctrl,hdr.cb0.appctrl,hdr.cb0.func,hdr.cb0.iin,hdr.cb0.g_group,hdr.cb0.g_var,hdr.cb0.g_qual,hdr.cb0.g_count,hdr.cb0.index,hdr.cb0.crob_code,hdr.cb0.crob_count,hdr.cb0.on_hi});}
 table in_cb0_t{actions={in_cb0;}size=1;const default_action=in_cb0();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;
 action in_ct(){m.in_ct=hash_in_ct.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status});}
 table in_ct_t{actions={in_ct;}size=1;const default_action=in_ct();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_dl;
 action crc_dl(){m.dlcrc=hash_dl.get({hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
 table crc_dl_t{actions={crc_dl;}size=1;const default_action=crc_dl();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_tail;
 action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.rtp.data_last,hdr.rtp.filler});}
 table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}
 Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail1;
 action crc_ctl_tail1(){m.ctcrc1=hash_ctl_tail1.get({hdr.ctp1.on_lo,hdr.ctp1.off,hdr.ctp1.status,hdr.ctp1.filler_a});}
 table crc_ctl_tail1_t{actions={crc_ctl_tail1;}size=1;const default_action=crc_ctl_tail1();}
 action render_dl_crc(){hdr.dl.crc=m.dlcrc[7:0]++m.dlcrc[15:8];}
 table render_dl_crc_t{actions={render_dl_crc;}size=1;const default_action=render_dl_crc();}
 action render_read_crc(){hdr.rtp.crc2=m.rtcrc[7:0]++m.rtcrc[15:8];}
 table render_read_crc_t{actions={render_read_crc;}size=1;const default_action=render_read_crc();}
 action render_ctl_crc(){hdr.ctp1.crc1=m.ctcrc1[7:0]++m.ctcrc1[15:8];}
 table render_ctl_crc_t{actions={render_ctl_crc;}size=1;const default_action=render_ctl_crc();}
 apply{
  /* 1. shape match and native-CRC hashes, all on the unmodified frame */
  if(hdr.dl.isValid()){in_dl_t.apply();}
  if(hdr.rb0.isValid()){read_profile.apply();in_rb0_t.apply();in_rb1_t.apply();in_rt_t.apply();}
  if(hdr.cb0.isValid()){ctl_profile.apply();in_cb0_t.apply();in_ct_t.apply();}
  /* 2. compare each wire CRC (little-endian on the wire) against its recomputation */
  if(hdr.dl.crc!=(m.in_dl[7:0]++m.in_dl[15:8])){m.badh=1w1;}
  if(hdr.rb0.crc0!=(m.in_rb0[7:0]++m.in_rb0[15:8])){m.rbad0=1w1;}
  if(hdr.rb1.crc1!=(m.in_rb1[7:0]++m.in_rb1[15:8])){m.rbad1=1w1;}
  if(hdr.rtn.crc2!=(m.in_rt[7:0]++m.in_rt[15:8])){m.rbadt=1w1;}
  if(hdr.cb0.crc0!=(m.in_cb0[7:0]++m.in_cb0[15:8])){m.cbad0=1w1;}
  if(hdr.ctn.crc1!=(m.in_ct[7:0]++m.in_ct[15:8])){m.cbadt=1w1;}
  /* 3. transform only a matched shape whose every native CRC checked; otherwise nothing is written */
  if(m.read_shape==1w1&&m.badh==1w0&&m.rbad0==1w0&&m.rbad1==1w0&&m.rbadt==1w0){read_pad_t.apply();}
  if(m.ctl_shape==1w1&&m.badh==1w0&&m.cbad0==1w0&&m.cbadt==1w0){ctl_pad_t.apply();}
  if(m.changed==1w1){
   crc_dl_t.apply();render_dl_crc_t.apply();
   if(hdr.rtp.isValid()){crc_read_tail_t.apply();render_read_crc_t.apply();}
   if(hdr.ctp1.isValid()){crc_ctl_tail1_t.apply();render_ctl_crc_t.apply();}
  }
  m.tcp_length=hdr.ip.len-16w20;
 }
}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in egress_intrinsic_metadata_for_deparser_t md){
 Checksum() ic;Checksum() tc;
 apply{
  if(m.changed==1w1){
   hdr.ip.checksum=ic.update({hdr.ip.version,hdr.ip.ihl,hdr.ip.tos,hdr.ip.len,hdr.ip.id,hdr.ip.flags,hdr.ip.frag,hdr.ip.ttl,hdr.ip.proto,hdr.ip.src,hdr.ip.dst});
   hdr.tcp.checksum=tc.update({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,m.tcp_length,hdr.tcp.sport,hdr.tcp.dport,hdr.tcp.seq,hdr.tcp.ack,hdr.tcp.offset,hdr.tcp.reserved,hdr.tcp.flags,hdr.tcp.window,hdr.tcp.urgent,
    hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src,hdr.dl.crc,
    hdr.rb0.tpctrl,hdr.rb0.appctrl,hdr.rb0.func,hdr.rb0.iin,hdr.rb0.g_group,hdr.rb0.g_var,hdr.rb0.g_qual,hdr.rb0.g_start,hdr.rb0.g_stop,hdr.rb0.data_mid,hdr.rb0.crc0,
    hdr.rb1.data,hdr.rb1.crc1,hdr.rtp.data_last,hdr.rtp.filler,hdr.rtp.crc2,
    hdr.cb0.tpctrl,hdr.cb0.appctrl,hdr.cb0.func,hdr.cb0.iin,hdr.cb0.g_group,hdr.cb0.g_var,hdr.cb0.g_qual,hdr.cb0.g_count,hdr.cb0.index,hdr.cb0.crob_code,hdr.cb0.crob_count,hdr.cb0.on_hi,hdr.cb0.crc0,
    hdr.ctp1.on_lo,hdr.ctp1.off,hdr.ctp1.status,hdr.ctp1.filler_a,hdr.ctp1.crc1,hdr.ctp2.filler_b,hdr.ctp2.crc2});
  }
  pkt.emit(hdr.eth);pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.dl);
  pkt.emit(hdr.rb0);pkt.emit(hdr.rb1);pkt.emit(hdr.rtn);pkt.emit(hdr.rtp);
  pkt.emit(hdr.cb0);pkt.emit(hdr.ctn);pkt.emit(hdr.ctp1);pkt.emit(hdr.ctp2);
 }
}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;Switch(pipe) main;
