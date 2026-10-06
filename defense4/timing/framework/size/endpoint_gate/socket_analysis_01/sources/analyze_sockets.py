"""Independent pcap acceptance: bytes, partial ACKs and kernel replay packets.

No bridge event or codec-emulator success flags settle this check. Endpoint
callback records still supply configured-point/application outcomes; captures
independently supply every TCP byte and ACK boundary below.
"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rrc
from case4_padding import decode_frame

MASK = 0xffffffff
MASTER = bytes.fromhex('020000000001')


def packets(path):
    result = []
    for timestamp, raw in rrc.read_records(path):
        packet = rrc.parse(raw)
        if packet is None: continue
        if not rrc.ip_ok(packet) or not rrc.tcp_ok(packet): raise ValueError('invalid captured network checksum')
        result.append((timestamp, raw[6:12] == MASTER, packet))
    return result


def reconstruct(rows, base, start, size, direction=True):
    image = {}
    for _, forward, packet in rows:
        if forward != direction: continue
        offset = (packet.seq-base)&MASK
        if offset >= 0x80000000: offset -= 0x100000000
        for index, value in enumerate(packet.payload):
            position=offset+index
            if not start <= position < start+size: continue
            if position in image and image[position] != value: raise ValueError('conflicting TCP overlap')
            image[position]=value
    missing=[index for index in range(start,start+size) if index not in image]
    if missing: raise ValueError('missing captured stream bytes: '+str(missing))
    return bytes(image[index] for index in range(start,start+size))


def analyze(work):
    work=Path(work); native=packets(work/'master_side.pcap'); wire=packets(work/'outstation_side.pcap')
    originals=[p for _,forward,p in native if forward and len(p.payload)==35]
    if len(originals)!=2: raise ValueError('exactly two native full command frames required')
    base=originals[0].seq
    selected=[]; phases=[]
    for index in range(2):
        original=reconstruct(native,base,index*35,35)
        transformed=reconstruct(wire,base,index*55,55)
        head,user=decode_frame(original); expanded_head,expanded_user=decode_frame(transformed)
        if len(user)!=21 or len(expanded_user)!=39 or user[2]!=3+index or expanded_user[2]!=3+index:
            raise ValueError('native/select/operate lengths or functions')
        if head[3:]!=expanded_head[3:] or expanded_user[:21]!=user:
            raise ValueError('native fields were changed')
        if expanded_user[21:28]!=bytes.fromhex('0c01280100c900'):
            raise ValueError('configured decoy header/index mismatch')
        selected.append(expanded_user[3:])
        native_prefix=index*35+34; native_end=index*35+35
        wire_prefix=index*55+35; wire_end=index*55+55
        prefixes=[timestamp for timestamp,forward,p in wire if forward and ((p.seq-base)&MASK)==index*55 and len(p.payload)==35]
        retransmissions=[timestamp for timestamp,forward,p in native if forward and ((p.seq-base)&MASK)==native_prefix and len(p.payload)==1]
        replays=[timestamp for timestamp,forward,p in wire if forward and ((p.seq-base)&MASK)==index*55+34 and len(p.payload)==21]
        if len(prefixes)!=1 or len(retransmissions)!=1 or len(replays)!=1: raise ValueError('one deliberate prefix and one real last-byte retransmission/replay required per phase')
        if not prefixes[0]<retransmissions[0]<=replays[0]: raise ValueError('kernel replay ordering')
        acknowledgments=lambda rows: {(p.ack-base)&MASK for _,forward,p in rows if not forward and p.flags&16}
        if not {native_prefix,native_end} <= acknowledgments(native): raise ValueError('missing native partial/completion ACKs')
        if not {wire_prefix,wire_end} <= acknowledgments(wire): raise ValueError('missing wire partial/completion ACKs')
        # While inserted bytes are outstanding, no captured native ACK may
        # retire the whole original before the corresponding full wire ACK.
        complete_times=[timestamp for timestamp,forward,p in wire if not forward and ((p.ack-base)&MASK)==wire_end]
        premature=[timestamp for timestamp,forward,p in native if not forward and ((p.ack-base)&MASK)==native_end and timestamp<min(complete_times)]
        if premature: raise ValueError('premature native completion ACK')
        responses=[p for _,forward,p in wire if not forward and len(p.payload)==57 and ((p.ack-base)&MASK)==wire_end]
        if len(responses)!=1: raise ValueError('exactly one complete 57-byte response per phase')
        _,echo=decode_frame(responses[0].payload)
        if len(echo)!=41 or echo[2]!=129 or echo[1]&15!=user[1]&15 or echo[5:]!=expanded_user[3:]:
            raise ValueError('echoed selected objects/statuses/app sequence differ')
        if echo[-1]!=0 or echo[22]!=0: raise ValueError('echoed CROB status is not SUCCESS')
        master_echo=[p for _,forward,p in native if not forward and p.payload==responses[0].payload]
        if len(master_echo)!=1: raise ValueError('master did not receive exact echoed response')
        phases.append(dict(native_size=35,wire_size=55,prefix_ack=native_prefix,complete_ack=native_end,
                           kernel_retransmission_size=1,replay_size=21,response_size=57,
                           retransmission_interval_ns=retransmissions[0]-prefixes[0]))
    if selected[0]!=selected[1]: raise ValueError('SELECT/OPERATE selected sets differ')
    result=json.loads((work/'socket_result.json').read_text())
    if not result.get('passed'): raise ValueError('endpoint callback/application acceptance gate failed')
    return dict(passed=True,scope='independent raw pcaps + production endpoint callbacks',phases=phases,
                connection_id=result['connection_id'],native_tcp_packets=len(native),wire_tcp_packets=len(wire))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('capture',type=Path); parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv)
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
    from runner.evidence import reserve_run,sha256
    run=reserve_run(args.output,{'scope':'independent production-socket pcap analysis','capture':str(args.capture.absolute())})
    with run:
        run.snapshot(Path(__file__))
        run.snapshot(Path(__file__).resolve().parents[1]/'rrc.py')
        run.snapshot(Path(__file__).resolve().parents[1]/'case4_padding.py')
        run.write_json('input_hashes.json',{name:sha256(args.capture/name) for name in ('master_side.pcap','outstation_side.pcap','socket_result.json','manifest.json','completion.json')})
        result=analyze(args.capture);run.write_json('result.json',result);run.finish('passed',result)
    print(json.dumps(result));return 0

if __name__=='__main__': raise SystemExit(main())
