"""Concrete two-pipeline native-validation/authority experiment.

Private physical ingress ports are requirements, not configured topology. No
shared registers or cross-pipe metadata are assumed: the original packet is the
validation handoff, and the authority emits its own protected return envelope.
The complete target remains unqualified.
"""
from pathlib import Path
import re
from generate import generate, braced

HERE=Path(__file__).resolve().parent


def split_source():
    text=generate()
    declarations=text[:text.index('control Ingress(')]
    declarations=declarations.replace('const PortId_t RETURN_PORT=9w68;',
        'const PortId_t RETURN_PORT=9w68;\nconst PortId_t VALIDATION_RETURN_PORT=9w70;')
    # Validation never parses a supplied protected envelope. The authority
    # parser alone interprets the private return port; raw packets arrive70.
    parser_start=declarations.index('parser IgParser(')
    validation_parser=declarations[parser_start:].replace('parser IgParser(', 'parser ValidationParser(')
    validation_parser=validation_parser.replace('RETURN_PORT:envelope;', '9w511:accept;')
    ingress=text[text.index('control Ingress('):text.index('control IgDeparser(')]
    head=ingress[:ingress.index(' WorkRecord() work;')] if ' WorkRecord() work;' in ingress else ingress[:ingress.index(' ExpectedWorkRecord() work;')]
    # Reuse the exact source algorithms, but none of the authority registers.
    keep=[]
    for name in ('deny','route','forward_flow','reverse_flow','network_accept'):
        at=ingress.index(' action '+name+'(')
        keep.append(ingress[at:ingress.index('\n',at)])
    for name in ('ports','connection','network'):
        at=ingress.index(' table '+name+'{')
        body=braced(ingress,' table '+name+'{')
        keep.append(' table '+name+'{'+body+'}')
    start=ingress.index(' action configure(')
    end=ingress.index(' action mint()')
    validation_algorithms=ingress[start:end]
    start=ingress.index('action data_ok()')
    end=ingress.index('action invalid_kind()',start)
    data_guard=ingress[start:end]
    start=ingress.index('   if(m.packet_kind==8w5||')
    end=ingress.index('   if(m.stage!=8w0)',start)
    validation_apply=ingress[start:end]
    validator=head.replace('control Ingress(', 'control ValidationIngress(')+'\n'.join(keep)+validation_algorithms+data_guard+'''
 action handoff(){tm.ucast_egress_port=VALIDATION_RETURN_PORT;tm.bypass_egress=1w1;}
 table handoff_t{actions={handoff;}size=1;const default_action=handoff();}
 apply{ports.apply();network.apply();connection.apply();
  if(m.port_valid==8w1&&m.network_valid==8w1&&m.direction!=8w0){
'''+validation_apply+'''
   if(m.data_valid==8w1){handoff_t.apply();}else{deny();}
  }else{deny();}
 }
}
'''
    authority=ingress.replace(validation_apply, '   m.data_valid=8w1;data_connection.apply();\n')
    # Raw authority admission is physically restricted, independent of a
    # caller-configurable ports entry. No external wire valid flag is accepted.
    authority=authority.replace('  ports.apply();network.apply();',
        '  ports.apply();network.apply();authority_port_guard.apply();')
    before=authority.index(' apply{\n  m.work_op=')
    authority=authority[:before]+'''
 action trusted_authority(){m.authority_trusted=8w1;}
 table authority_port_guard{key={ig.ingress_port:exact;}actions={trusted_authority;NoAction;}size=2;
 const entries={RETURN_PORT:trusted_authority();VALIDATION_RETURN_PORT:trusted_authority();}const default_action=NoAction();}
'''+authority[before:]
    declarations=declarations.replace('struct meta_t{','struct meta_t{bit<8> authority_trusted;')
    declarations=declarations.replace('m.parsed=8w0;','m.authority_trusted=8w0;m.parsed=8w0;')
    authority=authority.replace('if(m.port_valid==8w1&&m.network_valid==8w1&&',
        'if(m.authority_trusted==8w1&&m.port_valid==8w1&&m.network_valid==8w1&&')
    # Canonical decoded operands are packet-derived and do not depend on Work
    # grant. Decode them before the lifetime barrier to avoid the late-stage
    # owner-to-object-write chain of the monolithic18-stage attempt.
    decode='     calculate_native_end_t.apply();if(m.response==8w1){compare_response_inputs_t.apply();}else{if(m.packet_kind==8w5){compare_select_inputs_t.apply();}else{compare_operate_inputs_t.apply();}}\n'
    authority=authority.replace(decode,'')
    mark=authority.index('    if(m.stage==8w0){')
    authority=authority[:mark]+'    if(m.packet_kind>=8w5){\n'+decode+'    }\n'+authority[mark:]
    # Object comparison/publication banks are independent of the subsequent
    # sequence/owner admission. Keep their guarded access immediately after
    # Work/epoch, rather than forcing it through the sequence arithmetic chain.
    start=authority.index('    if(m.packet_kind>=8w5){',authority.index('work.apply(m.work_op'))
    end=authority.index('    owner_t.apply();',start)
    objects=authority[start:end].replace('     if(m.stage==8w0){m.epoch_diff=32w0;}\n','')
    authority=authority[:start]+authority[end:]
    mark=authority.index('    if(m.stage==8w0){if(m.packet_kind>=8w5)')
    authority=authority[:mark]+'    epoch_diff_t.apply();\n'+objects+authority[mark:]
    authority=authority.replace('else{epoch_diff_t.apply();owner_command.apply();}', 'else{owner_command.apply();}')
    authority=authority.replace('m.epoch_diff:exact;}actions={binding_store;', 'm.epoch_diff:ternary;}actions={binding_store;')
    authority=authority.replace('(8w0,8w6,32w4,32w0):binding_response()', '(8w0,8w6,32w4,_):binding_response()')
    authority=authority.replace('(8w0,8w7,32w4,32w0):binding_op()', '(8w0,8w7,32w4,_):binding_op()')
    suffix=text[text.index('control IgDeparser('):text.index('Pipeline(')]
    return declarations+validation_parser+validator+authority+suffix+'''
Pipeline(ValidationParser(),ValidationIngress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) validation;
Pipeline(IgParser(),Ingress(),IgDeparser(),EgParser(),Egress(),EgDeparser()) authority;
Switch(validation,authority) main;
'''


if __name__=='__main__':
    (HERE/'split_binding.p4').write_text(split_source())
