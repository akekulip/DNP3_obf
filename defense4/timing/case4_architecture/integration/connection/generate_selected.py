"""Autonomous actual SELECT record experiment; not a connection-qualified target.

Reuses frozen native35 parser/profile/three-CRC algorithms, not a supplied proof
flag or expected-object table. Connection epoch authority and response publisher
composition remain separate required work. No hardware interface.
"""
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PROTOCOL=ROOT.parents[1]/'protocol'


def generate():
    text=(PROTOCOL/'padding.p4').read_text()
    text=text.replace('/* Actual native35 validation/padding wire primitive. Default profile disabled. No lifecycle or assembly. */',
        '/* Autonomous actual native35 SELECT context publisher experiment.\n * Four processing passes; full network/profile/all3CRC validation precedes work.\n * Transaction epoch equals nonwrapping allocated work generation; it is NOT\n * yet the live connection epoch. No verified reset/reuse or RESPONSE/OP target\n * association. Stored REAL object and frozen configured decoy are distinct.\n */')
    text=text.replace('#include <tna.p4>','#include <tna.p4>\n#include "work_record.p4"\nconst PortId_t RETURN_PORT=9w68;')
    mark=text.index('header appended_h');end=text.index('struct headers_t',mark)
    text=text[:mark]+'''header epoch_h{bit<32> epoch;}
header generation_h{bit<32> generation;}
header expected_h{bit<32> expected;}
header event_h{bit<16> event;bit<16> reserved;}
'''+text[end:]
    text=text.replace('struct headers_t{eth_h eth;',
        'struct headers_t{epoch_h epoch;generation_h generation;expected_h expected;event_h event;eth_h eth;')
    text=text.replace('appended_h appended;final_h last;','')
    text=text.replace('struct meta_t{',
        'struct meta_t{bit<1> port_valid;bit<8> stage;bit<8> kind;bit<8> work_op;bit<32> generation;bit<32> work_phase;bit<32> context_generation;bit<32> native_end;')
    text=text.replace('m.parsed=1w0;', 'm.parsed=1w0;m.port_valid=1w0;m.stage=8w0;m.kind=8w0;')
    text=text.replace('transition eth;}','transition select(ig.ingress_port){RETURN_PORT:epoch;default:eth;}}',1)
    mark=text.index(' state eth{')
    text=text[:mark]+''' state epoch{pkt.extract(hdr.epoch);transition select(hdr.epoch.epoch){32w0:accept;default:generation;}}
 state generation{pkt.extract(hdr.generation);transition select(hdr.generation.generation){32w0:accept;default:expected;}}
 state expected{pkt.extract(hdr.expected);pkt.extract(hdr.event);m.stage=hdr.event.event[15:8];m.kind=hdr.event.event[7:0];transition reserved;}
 state reserved{transition select(hdr.event.reserved){16w0:events;default:accept;}}
 state events{transition select(hdr.event.event){16w0x0101:eth;16w0x0201:eth;16w0x0301:eth;16w0x01ff:eth;16w0x02ff:eth;16w0x03ff:eth;default:accept;}}
'''+text[mark:]
    text=text.replace('tm.ucast_egress_port=port;tm.bypass_egress=1w1;',
        'm.port_valid=1w1;tm.ucast_egress_port=port;tm.bypass_egress=1w1;')
    # Only SELECT creates this context; OPERATE cannot overwrite it.
    text=text.replace('size=2;const default_action=NoAction();const entries=',
        'size=1;const default_action=NoAction();const entries=')
    start=text.index('(16w0x0564,8w26,8w0xC4',text.index('table profile'))
    end=text.index('}}',start)
    text=text[:start]+text[start:end].split(';')[0]+';'+text[end:]
    start=text.index('Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_newhead;')
    end=text.index('action input_head()',start)
    text=text[:start]+text[end:]
    start=text.index('action construct()');end=text.index('\n}',start)
    # Publication is monotone until verified retirement exists. No new SELECT
    # can overwrite an already-published immutable record; busy work stays pinned.
    body='''WorkRecord() work;
Register<bit<32>,bit<1>>(1,0) counter;
RegisterAction<bit<32>,bit<1>,bit<32>>(counter) allocate={void apply(inout bit<32> v,out bit<32> r){r=32w0;if((int<32>)v!=-1){v=v+32w1;r=v;}}};
action mint(){m.generation=allocate.execute(1w0);m.work_op=8w1;}
table mint_t{actions={mint;}size=1;const default_action=mint();}
Register<bit<32>,bit<1>>(1,0) published;
RegisterAction<bit<32>,bit<1>,bit<32>>(published) read_published={void apply(inout bit<32> v,out bit<32> r){r=v;}};
RegisterAction<bit<32>,bit<1>,bit<32>>(published) publish={void apply(inout bit<32> v,out bit<32> r){if(v==0){v=hdr.generation.generation;}r=v;}};
action load_published(){m.context_generation=read_published.execute(1w0);}
action commit_published(){m.context_generation=publish.execute(1w0);}
table published_t{key={m.stage:exact;m.kind:exact;m.work_op:exact;m.work_phase:exact;}actions={load_published;commit_published;}size=1;const entries={(8w1,8w1,8w2,32w1):commit_published();}const default_action=load_published();}
action calculate_native_end(){m.native_end=hdr.tcp.seq+32w35;}
table calculate_native_end_t{actions={calculate_native_end;}size=1;const default_action=calculate_native_end();}
'''
    fields={
        'real_links':'hdr.dl.dst++hdr.dl.src','real_tcp_src':'hdr.ip.src',
        'real_tcp_dst':'hdr.ip.dst','real_tcp_ports':'hdr.tcp.sport++hdr.tcp.dport',
        'real_object':'hdr.native.index++hdr.native.code++hdr.native.repeat','real_on':'hdr.native.on',
        'real_off':'hdr.tail.off','native_start':'hdr.tcp.seq','native_end':'m.native_end',
        'server_start':'hdr.tcp.ack','application':'hdr.native.app',
        'frozen_decoy_object':'m.decoy_index++m.decoy_code++m.decoy_repeat',
        'frozen_decoy_on':'m.decoy_on','frozen_decoy_off':'m.decoy_off'}
    for name,value in fields.items():
        body+=f'''Register<bit<32>,bit<1>>(1,0) {name};
RegisterAction<bit<32>,bit<1>,bit<32>>({name}) write_{name}={{void apply(inout bit<32> v,out bit<32> r){{v=(bit<32>)({value});r=v;}}}};
action store_{name}(){{write_{name}.execute(1w0);}}
table {name}_t{{key={{m.stage:exact;m.work_op:exact;m.work_phase:exact;m.context_generation:exact;}}actions={{store_{name};NoAction;}}size=1;const entries={{(8w0,8w1,32w4,32w0):store_{name}();}}const default_action=NoAction();}}
'''
    body+='''action start_work(){hdr.epoch.setValid();hdr.generation.setValid();hdr.expected.setValid();hdr.event.setValid();hdr.epoch.epoch=m.generation;hdr.generation.generation=m.generation;hdr.expected.expected=32w0;hdr.event.event=16w0x0101;hdr.event.reserved=16w0;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table start_work_t{actions={start_work;}size=1;const default_action=start_work();}
action abort_work(){hdr.event.event=16w0x01ff;}
table abort_t{actions={abort_work;}size=1;const default_action=abort_work();}
action next_work(){hdr.event.event=hdr.event.event+16w0x100;tm.ucast_egress_port=RETURN_PORT;tm.bypass_egress=1w1;}
table next_work_t{actions={next_work;}size=1;const default_action=next_work();}
apply{m.work_op=8w0;m.generation=32w0;forwarding.apply();
 if(m.port_valid==1w1&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
 connection.apply();profile.apply();if(m.enabled==1w1&&m.profile==1w1){
 input_head_t.apply();input_body_t.apply();input_tail_t.apply();
 if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
 if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
 if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
 if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=m.decoy_index){
 if(m.stage==8w0){mint_t.apply();}else{m.generation=hdr.generation.generation;m.work_op=8w2;}
 work.apply(m.work_op,m.generation,m.work_phase);published_t.apply();calculate_native_end_t.apply();
'''
    body+=''.join(name+'_t.apply();' for name in fields)
    body+='''
 if(m.stage==8w0){if(m.work_phase==32w4){start_work_t.apply();if(m.context_generation!=32w0){abort_t.apply();}}}
 else if(m.work_phase==32w1||m.work_phase==32w2){next_work_t.apply();}
 else if(m.work_phase==32w3){hdr.epoch.setInvalid();hdr.generation.setInvalid();hdr.expected.setInvalid();hdr.event.setInvalid();}
 else{deny();}
 }}
 }else if(m.stage!=8w0){deny();}
}
'''
    text=text[:start]+body+text[end:]
    start=text.index('control IgDeparser(');end=text.index('parser EgParser(',start)
    text=text[:start]+'''control IgDeparser(packet_out pkt,inout headers_t hdr,in meta_t m,in ingress_intrinsic_metadata_for_deparser_t md){apply{pkt.emit(hdr);}}
'''+text[end:]
    from selected_association import extend, common_first_block, compact_bank_dispatch, parser_role_paths
    from selected_compact import compact
    return compact(parser_role_paths(compact_bank_dispatch(common_first_block(extend(text)))))

if __name__=='__main__':(ROOT/'selected.p4').write_text(generate())
