"""Compose recovery timing, ingress arithmetic and size rendering for resource proof.

This probe deliberately refuses completed processing packets. It has no complete
validation/image producer, connection admission, or physical service proof. A
compiler PASS is component coexistence, never complete Case4 qualification.
"""
import hashlib
import json
import re
from pathlib import Path

HERE=Path(__file__).resolve().parent
TIMING=HERE.parents[1]/'response_ready/src/defense4_response_ready.p4'
MAPPING=HERE/'case4_ingress_mapping.p4'
WIRE=HERE/'case4_wire_only.p4'
OUT=HERE/'case4_joint_processing_probe.p4'


def sha(data):return hashlib.sha256(data).hexdigest()


def block(text, marker):
    start=text.index(marker)
    opening=text.index('{',start)
    depth=1
    end=opening+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}')
        end+=1
    return text[start:end]


def generate():
    timing_bytes=TIMING.read_bytes();mapping_bytes=MAPPING.read_bytes();wire_bytes=WIRE.read_bytes()
    timing=timing_bytes.decode();mapping=mapping_bytes.decode();wire=wire_bytes.decode()
    timing=timing[:timing.index('\nstruct eg_meta_t')]
    declarations='\n'+mapping[mapping.index('const bit<16> WORK_TYPE'):mapping.index('parser IgParser')]
    # Preserve the real timing header/parser/control; add only a distinct private
    # work header. Mapping metadata is local to the ingress wrapper.
    declarations=declarations.replace(block(declarations,'header eth_h'),'')
    declarations=declarations.replace(block(declarations,'struct headers_t'),'')
    declarations=re.sub(r'\bmetadata_t\b','mapping_meta_t',declarations)
    timing=timing.replace('struct headers_t {',declarations+'\nstruct headers_t {\n    work_h work;',1)
    selector='ETHERTYPE_CASE4_VALIDATED : extract_validated; default : reject;'
    if timing.count(selector)!=1:raise ValueError('current validated-parser seam changed')
    timing=timing.replace(selector,'ETHERTYPE_CASE4_VALIDATED : extract_validated; WORK_TYPE : extract_mapping; default : reject;',1)
    timing=timing.replace('    state extract_validated',
        '    state extract_mapping {pkt.extract(hdr.work); transition select(hdr.work.version,hdr.work.reserved) {(8w1,16w0):accept;default:reject;}}\n    state extract_validated',1)
    deparser=timing.index('control IgDeparser')
    timing=timing[:deparser]+timing[deparser:].replace('pkt.emit(hdr.eth);','pkt.emit(hdr.eth);\n        pkt.emit(hdr.work);',1)
    map_control=block(mapping,'control Ingress').replace('control Ingress','control MappingIngress',1).replace('inout metadata_t m','inout mapping_meta_t m')
    annotations=mapping[mapping.index('@pa_container_size'):mapping.index('control Ingress')]
    wrapper="""
control JointIngress(inout headers_t hdr,inout ig_meta_t meta,
 in ingress_intrinsic_metadata_t ig,in ingress_intrinsic_metadata_from_parser_t parser_md,
 inout ingress_intrinsic_metadata_for_deparser_t deparser_md,
 inout ingress_intrinsic_metadata_for_tm_t tm) {
 Ingress() timing;
 MappingIngress() mapping;
 mapping_meta_t m;
 apply {
  if(hdr.work.isValid()) {
   m.allowed=8w0;m.valid=8w0;m.cookie=32w0;m.first=32w0;m.second=32w0;
   mapping.apply(hdr,m,ig,parser_md,deparser_md,tm);
  } else {timing.apply(hdr,meta,ig,parser_md,deparser_md,tm);}
 }
}
"""
    size_declarations=wire[wire.index('const bit<16> RRC_49'):wire.index('parser IgParser')]
    size_egress=wire[wire.index('parser EgParser'):wire.index('Pipeline(')]
    names=re.findall(r'^(?:header|struct) (\w+)',size_declarations,re.M)+['RRC_49','RRC_57','EgParser','Egress','EgDeparser']
    renames={name:'size_'+name for name in names}
    tokens=re.compile(r'\b(?:'+'|'.join(map(re.escape,renames))+r')\b')
    size=tokens.sub(lambda match:renames[match[0]],size_declarations+size_egress)
    result=('/* NON-DEPLOYABLE joint recovery/mapping/rendering resource probe.\n'
            ' * No complete CRC/image producer or new connection admission.\n'
            ' * Processing completion drops; no full joint capability is claimed.\n */\n'+
            timing+'\n'+annotations+map_control+'\n'+wrapper+size+'\n'+
            'Pipeline(IgParser(),JointIngress(),IgDeparser(),size_EgParser(),size_Egress(),size_EgDeparser()) pipe;\nSwitch(pipe) main;\n')
    OUT.write_text(result)
    inputs={'sources':{str(path):sha(data) for path,data in ((TIMING,timing_bytes),(MAPPING,mapping_bytes),(WIRE,wire_bytes))},
            'output_sha256':sha(result.encode()),'scope':'component integration resource proof only; incomplete producer/cache/lifecycle',
            'software_only':True,'joint_mechanism_verified':False,'deployment_permitted':False}
    OUT.with_suffix('.inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    return inputs


if __name__=='__main__':print(json.dumps(generate(),indent=2))
