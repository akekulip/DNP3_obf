"""Independent source-interpreter and capture-checker counterexamples. No ASIC simulation."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, struct, subprocess, sys, types

ROOT = Path(__file__).resolve().parent
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--repo', type=Path, default=ROOT / 'repo')
ap.add_argument('--out', type=Path, default=ROOT / 'reproductions')
args = ap.parse_args()
REPO = args.repo.resolve()
ARCH = REPO / 'defense4/timing/case4_architecture'
INTEG = ARCH / 'integration'
BASE = INTEG / 'core/response_only_rearm'
STAGE = BASE / 'stage_experiments'
P4 = STAGE / 'ctl_timing_01/evidence/m12p_b08/response_only.p4'
OUT = args.out.resolve()
OUT.mkdir(parents=True, exist_ok=True)

def module(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m

shim = types.ModuleType('baseline'); shim.INTEG = INTEG
sys.modules['baseline'] = shim
interp = module('audit_interpreter', BASE / 'interpreter.py')
combined = module('audit_segments', STAGE / 'combined_nt_01/generate.py')
text = P4.read_text()
assert hashlib.sha256(text.encode()).hexdigest() == '7b1281bc4aa73950b33088adc9d9ae5bbd827422ec702c71d1d3b791f352214f', 'This audit is pinned to the d531918e2 b08 source'

def role(text, name):
    prefix = {'N': 'n', 'E': 'r', 'T': 't'}[name]
    result = re.sub(r'\b' + prefix + r'_(\w+)', r'\1', combined.segment(text, name))
    if name == 'E': result += '\nPipeline() source_adapter_marker;\n'
    return result

report = {'commit': 'd531918e2197df404401847f0c8244bb8d61a8b7',
          'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
          'tier': 'repository source interpreter and Python checker; NOT compiled model or hardware'}
baseline = (STAGE / 'ctl_timing_01/evidence/m11_09/response_only.p4').read_text()
reverse = []
for source_name, source in [('b08', text), ('m11_09', baseline)]:
    e = interp.ESource(role(source, 'E'))
    for d in (0, 1, 61, 62, 100, 141, 142):
        e.begin_pass(0); e.valid['tcp'] = True
        e.env.update({'m.r': (-d) & 0xffffffff, 'm.p': 901, 'm.q': 938,
                      'm.s_end': 4133, 'hdr.tcp.window': 4096})
        e.table('classify_rev')
        reverse.append({'source': source_name, 'committed_SBO_image': 61,
                        'distance_before_wire_end': d, 'result': e.env.get('m.result'),
                        'drop': e.env.get('md.drop_ctl', 0), 'events': list(e.events)})
report['SBO_boundary'] = reverse
assert next(x for x in reverse if x['source']=='b08' and x['distance_before_wire_end']==62)['result']==10
assert next(x for x in reverse if x['source']=='m11_09' and x['distance_before_wire_end']==62)['drop']==1

# Actual integrity request from retained pinned-stack software capture.
fr = module('audit_fullread', STAGE / 'read_complete_01/software/source/full_read_01/fullread.py')
caps = sorted((STAGE / 'read_complete_01/evidence').rglob('*.pcap'))
request = None
for cap in caps:
    try:
        for r in fr.capture.tcp_records(cap):
            p = r['payload']
            if r['dst'][1] == 20000 and len(p)==27 and p[:2]==b'\x05\x64':
                request = p; request_cap = cap; break
    except (ValueError, struct.error):
        continue
    if request is not None: break
if request is None:
    # Valid canonical integrity request with class 1/2/3/0 objects.
    std = fr.std
    app = bytes.fromhex('c0013c02063c03063c04063c0106')
    user = b'\xc0' + app
    request = std.frame(bytes.fromhex('0564') + bytes([5+len(user)]) + bytes.fromhex('c40a000100'), user)
    request_cap = 'constructed canonical integrity request'

def packet(payload):
    from source_packets import checksum
    src,dst=0x0a000001,0x0a000002
    tcp=struct.pack('!HHIIBBHHH',30000,20000,1001,901,0x50,0x18,4096,0,0)
    pseudo=struct.pack('!IIBBH',src,dst,0,6,len(tcp)+len(payload))
    tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp+payload))+tcp[18:]
    ip=struct.pack('!BBHHHBBHII',0x45,0,40+len(payload),0,0,64,6,0,src,dst)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800')+ip+tcp+payload

n=interp.ExtSource(interp.source_text(role(text,'N')).replace('p.global_tstamp','ig.global_tstamp'),INTEG)
n.begin_pass(9)
accepted,cursor=n.packet_parser(packet(request))
report['integrity_request_parser']={'request_origin':str(request_cap),'request_hex':request.hex(),
    'payload_len':len(request),'accepted_by_parser':accepted,'cursor':cursor,
    'protected_parsed_flag':n.env.get('m.parsed'),'tcp_extracted':n.valid.get('tcp',False),
    'states':n.parser_states}
assert len(request)==27 and not n.valid.get('tcp',False) and n.env.get('m.parsed')==0

# Readout false pass: valid empty captures, and deletion of the last response
# packet from a COPY of a retained off-arm capture. Never alter original evidence.
readout=STAGE/'read_complete_01/analysis/hw_read_readout.py'
hardware=STAGE/'read_complete_01/evidence/hw_blocks/rc01_hw_b08_20261021_01_reference'
original=next((hardware/'separate_ack/off').rglob('in.pcap')).parent
def run_readout(root):
    out=root/'audit_readout.json'
    r=subprocess.run([sys.executable,str(readout),str(root),'--native','--out',str(out)],capture_output=True,text=True)
    j=json.loads(out.read_text())
    return {'exit':r.returncode,'ok':j['ok'],'connections':[{'summary':x.get('summary'),'failures':x['failures']} for x in j['connections']]}
empty=OUT/'empty_capture';empty.mkdir(exist_ok=True)
header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
for name in ('in.pcap','out.pcap'):(empty/name).write_bytes(header)
report['empty_capture_checker']=run_readout(empty)
assert report['empty_capture_checker']['ok'] is True
partial=OUT/'missing_final_response';partial.mkdir(exist_ok=True)
data=(original/'in.pcap').read_bytes(); records=[]; matches=[]; pos=24
while pos+16<=len(data):
    incl=struct.unpack_from('<I',data,pos+8)[0]; rec=data[pos:pos+16+incl]; f=rec[16:]
    if len(f)>=54 and f[26:30]==bytes([192,168,10,62]) and f[30:34]==bytes([192,168,10,61]) and f[23]==6:
        ihl=(f[14]&15)*4; off=14+ihl; doff=(f[off+12]>>4)*4
        if int.from_bytes(f[16:18],'big')>ihl+doff:matches.append(len(records))
    records.append(rec);pos+=16+incl
assert matches
(partial/'in.pcap').write_bytes(data[:24]+b''.join(rec for i,rec in enumerate(records) if i!=matches[-1]))
(partial/'out.pcap').write_bytes((original/'out.pcap').read_bytes())
report['missing_final_response_checker']=run_readout(partial)
assert report['missing_final_response_checker']['ok'] is True
report['original_off_checker']={'note':'original evidence unmodified; source capture used only as read input'}
(OUT/'findings.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
