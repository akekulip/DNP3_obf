/* Actual MSS-only TCP handshake producer experiment, never deploy standalone.
 * One configured full tuple, first-SYN epoch allocation, protected two-pass
 * publication. Writes are claimed BEFORE mutation; phase1/3 pins the record
 * until its exact 8-byte resubmit returns. Close during production changes
 * phase6; only actual producer return terminates it. Closed isn't reusable.
 * No timing, insertion, stream translation or connection-retirement evidence.
 */
#include <core.p4>
#include <tna.p4>
header eth_h {bit<48> dst;bit<48> src;bit<16> type;}
header ip_h {bit<4> version;bit<4> ihl;bit<8> tos;bit<16> len;
 bit<16> id;bit<3> flags;bit<13> frag;bit<8> ttl;bit<8> proto;
 bit<16> checksum;bit<32> src;bit<32> dst;}
header tcp_h {bit<16> sport;bit<16> dport;bit<32> seq;bit<32> ack;
 bit<4> offset;bit<4> reserved;bit<8> flags;bit<16> window;
 bit<16> checksum;bit<16> urgent;}
header mss_h {bit<8> kind;bit<8> len;bit<16> value;}
header work_h {bit<32> epoch;bit<32> generation;}
struct headers_t {eth_h eth;ip_h ip;tcp_h tcp;mss_h mss;}
struct meta_t {work_h work;bit<8> parsed;bit<8> direction;
 bool ip_error;bit<16> tcp_sum;bit<32> expected;bit<32> desired;
 bit<32> previous;bit<32> epoch;bit<32> client;bit<32> server;
 bit<32> new_seq;bit<32> phase;bit<1> resubmit;}
parser IgParser(packet_in pkt,out headers_t hdr,out meta_t m,
 out ingress_intrinsic_metadata_t ig) {
 Checksum() ipcheck;Checksum() tcpcheck;
 state start {pkt.extract(ig);m.parsed=8w0;m.direction=8w0;
  m.resubmit=1w0;transition select(ig.resubmit_flag){1:work;default:port;}}
 state port {pkt.advance(PORT_METADATA_SIZE);transition eth;}
 state work {pkt.extract(m.work);transition eth;}
 state eth {pkt.extract(hdr.eth);transition select(hdr.eth.type){16w0x0800:ip;default:accept;}}
 state ip {pkt.extract(hdr.ip);ipcheck.add(hdr.ip);m.ip_error=ipcheck.verify();
  tcpcheck.subtract({hdr.ip.src,hdr.ip.dst,8w0,hdr.ip.proto,hdr.ip.len});
  transition select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags,hdr.ip.len){
   (4w4,4w5,8w6,13w0,3w0,16w40):tcp;
   (4w4,4w5,8w6,13w0,3w2,16w40):tcp;
   (4w4,4w5,8w6,13w0,3w0,16w44):tcp;
   (4w4,4w5,8w6,13w0,3w2,16w44):tcp;default:accept;}}
 state tcp {pkt.extract(hdr.tcp);tcpcheck.subtract(hdr.tcp);
  transition select(hdr.tcp.offset,hdr.ip.len){(4w6,16w44):mss;
   (4w5,16w40):ack;default:accept;}}
 state mss {pkt.extract(hdr.mss);tcpcheck.subtract(hdr.mss);
  m.tcp_sum=tcpcheck.get();m.parsed=8w1;transition accept;}
 state ack {m.tcp_sum=tcpcheck.get();m.parsed=8w1;transition accept;}
}
@pa_container_size("ingress","m.work.epoch",32)
@pa_container_size("ingress","m.work.generation",32)
@pa_container_size("ingress","m.expected",32)
@pa_container_size("ingress","m.desired",32)
control Ingress(inout headers_t hdr,inout meta_t m,in ingress_intrinsic_metadata_t ig,
 in ingress_intrinsic_metadata_from_parser_t parser_md,
 inout ingress_intrinsic_metadata_for_deparser_t md,
 inout ingress_intrinsic_metadata_for_tm_t tm) {
 Register<bit<32>,bit<1>>(1,0) lifecycle;
 Register<bit<32>,bit<1>>(1,0) incarnation;
 Register<bit<32>,bit<1>>(1,0) client_next;
 Register<bit<32>,bit<1>>(1,0) server_next;
 RegisterAction<bit<32>,bit<1>,bit<32>>(lifecycle) read_phase={
  void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(lifecycle) transition_phase={
  void apply(inout bit<32> v,out bit<32> r){r=v;if(v==m.expected){v=m.desired;}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(incarnation) allocate_epoch={
  void apply(inout bit<32> v,out bit<32> r){r=32w0;if(v!=32w0xffffffff){v=v+32w1;r=v;}}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(incarnation) read_epoch={
  void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(client_next) write_client={
  void apply(inout bit<32> v,out bit<32> r){v=m.new_seq;r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(client_next) read_client={
  void apply(inout bit<32> v,out bit<32> r){r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(server_next) write_server={
  void apply(inout bit<32> v,out bit<32> r){v=m.new_seq;r=v;}};
 RegisterAction<bit<32>,bit<1>,bit<32>>(server_next) read_server={
  void apply(inout bit<32> v,out bit<32> r){r=v;}};
 action deny(){md.drop_ctl=3w1;}
 action route(PortId_t port){tm.ucast_egress_port=port;tm.bypass_egress=1w1;}
 table forwarding {key={ig.ingress_port:exact;}actions={route;deny;}
  size=4;default_action=deny();}
 action forward_flow(){m.direction=8w1;}
 action reverse_flow(){m.direction=8w2;}
 table connection {key={hdr.ip.src:exact;hdr.ip.dst:exact;
  hdr.tcp.sport:exact;hdr.tcp.dport:exact;}
  actions={forward_flow;reverse_flow;NoAction;}size=2;default_action=NoAction();}
 action phase_load(){m.phase=read_phase.execute(1w0);}
 table phase_load_t {actions={phase_load;}size=1;const default_action=phase_load();}
 action epoch_load(){m.epoch=read_epoch.execute(1w0);}
 table epoch_load_t {actions={epoch_load;}size=1;const default_action=epoch_load();}
 action client_load(){m.client=read_client.execute(1w0);}
 table client_load_t {actions={client_load;}size=1;const default_action=client_load();}
 action server_load(){m.server=read_server.execute(1w0);}
 table server_load_t {actions={server_load;}size=1;const default_action=server_load();}
 action claim_syn(){m.expected=32w0;m.desired=32w1;}
 action claim_synack(){m.expected=32w2;m.desired=32w3;}
 action verified(){m.expected=32w4;m.desired=32w5;}
 action publish_syn(){m.expected=32w1;m.desired=32w2;}
 action publish_synack(){m.expected=32w3;m.desired=32w4;}
 action close_work(){m.expected=m.phase;m.desired=32w6;}
 action close_idle(){m.expected=m.phase;m.desired=32w7;}
 action terminate_work(){m.expected=32w6;m.desired=32w7;}
 table event {key={m.direction:exact;hdr.tcp.flags:exact;}
  actions={claim_syn;claim_synack;verified;NoAction;}size=4;
  const default_action=NoAction();const entries={
   (8w1,8w2):claim_syn();(8w2,8w18):claim_synack();
   (8w1,8w16):verified();}}
 action transition_owner(){m.previous=transition_phase.execute(1w0);}
 table transition_owner_t {actions={transition_owner;}size=1;
  const default_action=transition_owner();}
 action next_sequence(){m.new_seq=hdr.tcp.seq+32w1;}
 table next_sequence_t {actions={next_sequence;}size=1;
  const default_action=next_sequence();}
 action epoch_allocate(){m.epoch=allocate_epoch.execute(1w0);}
 table epoch_allocate_t {actions={epoch_allocate;}size=1;
  const default_action=epoch_allocate();}
 action client_store(){m.client=write_client.execute(1w0);}
 table client_store_t {actions={client_store;}size=1;
  const default_action=client_store();}
 action server_store(){m.server=write_server.execute(1w0);}
 table server_store_t {actions={server_store;}size=1;
  const default_action=server_store();}
 action return_work(){m.work.setValid();m.work.epoch=m.epoch;
  m.work.generation=m.desired;m.resubmit=1w1;md.resubmit_type=3w1;}
 table return_work_t {actions={return_work;}size=1;
  const default_action=return_work();}
 apply {
  forwarding.apply();
  if(m.parsed==8w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&
   hdr.ip.ttl!=8w0&&hdr.tcp.reserved==4w0&&hdr.tcp.urgent==16w0){
   connection.apply();
   if(m.direction!=8w0){
    phase_load_t.apply();epoch_load_t.apply();client_load_t.apply();server_load_t.apply();
    if(ig.resubmit_flag==1w1){
     if(m.work.epoch==m.epoch&&m.epoch!=32w0&&
      (m.work.generation==32w1||m.work.generation==32w3)){
      if(m.phase==32w6){terminate_work();}
      else if(m.work.generation==32w1){publish_syn();}
      else{publish_synack();}
      transition_owner_t.apply();
      if(m.previous!=m.expected){deny();}
     }else{deny();}
    }else if((hdr.tcp.flags&8w5)!=8w0){
     if(m.phase==32w1||m.phase==32w3){close_work();}else{close_idle();}
     transition_owner_t.apply();
    }else if(hdr.mss.isValid()&&hdr.mss.kind==8w2&&hdr.mss.len==8w4&&hdr.mss.value>=16w57){
     if((m.direction==8w1&&hdr.tcp.flags==8w2&&m.phase==32w0)||
       (m.direction==8w2&&hdr.tcp.flags==8w18&&m.phase==32w2&&hdr.tcp.ack==m.client)){
      event.apply();transition_owner_t.apply();
      if(m.previous==m.expected){
       next_sequence_t.apply();
       if(m.direction==8w1){epoch_allocate_t.apply();client_store_t.apply();}
       else{server_store_t.apply();}
       if(m.epoch!=32w0){return_work_t.apply();}else{deny();}
      }
     }
    }else if(!hdr.mss.isValid()&&m.direction==8w1&&hdr.tcp.flags==8w16&&
      m.phase==32w4&&hdr.tcp.seq==m.client&&hdr.tcp.ack==m.server){
     event.apply();transition_owner_t.apply();
    }
   }
  }
 }
}
control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,
 in ingress_intrinsic_metadata_for_deparser_t md){
 Resubmit() resub;
 apply{if(m.resubmit==1w1){resub.emit(m.work);}pkt.emit(hdr.eth);
  pkt.emit(hdr.ip);pkt.emit(hdr.tcp);pkt.emit(hdr.mss);}
}
parser EgParser(packet_in pkt,out headers_t hdr,out meta_t m,
 out egress_intrinsic_metadata_t eg){state start{pkt.extract(eg);transition accept;}}
control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,
 in egress_intrinsic_metadata_from_parser_t p,inout egress_intrinsic_metadata_for_deparser_t md,
 inout egress_intrinsic_metadata_for_output_port_t port){apply{}}
control EgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,
 in egress_intrinsic_metadata_for_deparser_t md){apply{}}
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) pipe;
Switch(pipe) main;
