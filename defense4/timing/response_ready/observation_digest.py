#!/usr/bin/env python3
"""Decode retained Case4 management learn records; this does not acquire hardware data.

Raw BFRT learn-field dictionaries or the exact 36-byte network-order wire layout
are accepted. A record cannot establish physical departure, physical drain, CRC
validation, or endpoint command acceptance. Pulse records retain their zero tuple.
"""
import argparse
import json
from pathlib import Path
import struct

LAYOUT=struct.Struct('!HHIIIIIIHHHH')
FIELDS=('version','event','owner_cookie','connection_cookie','timestamp_ns32',
        'association_profile','src_ipv4','dst_ipv4','sport','dport','originals_pre_mask','outcome')
EVENTS={1:'request_ingress',2:'ack_ingress',3:'response_complete_ingress',
        4:'ack_commit',5:'response_commit',6:'readiness_expiry_service',
        7:'blocker_termination',8:'reset_abort',9:'quarantine_complete'}
OPERATIONS={1:'READ',3:'SELECT',4:'OPERATE'}


def decode(raw, *, clock_domain):
    if not isinstance(clock_domain,str) or not clock_domain.strip():
        raise ValueError('declared ingress clock domain is required')
    if isinstance(raw,(bytes,bytearray)):
        if len(raw)!=LAYOUT.size:
            raise ValueError('learn record must be exactly 36 bytes')
        fields=dict(zip(FIELDS,LAYOUT.unpack(raw)))
    elif isinstance(raw,dict):
        try: fields={name:raw[name] for name in FIELDS}
        except KeyError as exc: raise ValueError('missing raw learn field: '+str(exc)) from exc
    else:
        raise ValueError('expected bytes or raw BFRT learn fields')
    for name,value in fields.items():
        width=32 if name in FIELDS[2:8] else 16
        if type(value) is not int or not 0<=value<1<<width:
            raise ValueError('invalid raw field '+name)
    owner,profile=fields['owner_cookie'],fields['association_profile']
    if (fields['version']!=1 or fields['event'] not in EVENTS
            or not 0x80000001<=owner<=0x8000ffff or fields['connection_cookie']==0
            or profile>>16 != owner&0xffff or (profile&255)>15
            or (profile>>8)&255 not in OPERATIONS or fields['originals_pre_mask']>7):
        raise ValueError('unsupported event or association identity mismatch')
    return dict(transaction_id=f"{fields['connection_cookie']:08x}:{owner&0xffff:04x}",
                owner_cookie=owner,connection_cookie=fields['connection_cookie'],
                operation=OPERATIONS[(profile>>8)&255],app_seq=profile&255,
                event=EVENTS[fields['event']],timestamp_ns=fields['timestamp_ns32'],
                clock_domain=clock_domain,clock_width_bits=32,marker_mask=0,
                endpoint='ingress',evidence_kind='observed',
                src_ipv4=fields['src_ipv4'],dst_ipv4=fields['dst_ipv4'],
                sport=fields['sport'],dport=fields['dport'],
                originals_pre_mask=fields['originals_pre_mask'],outcome=fields['outcome'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path,help='retained JSONL raw BFRT learn dictionaries')
    parser.add_argument('output',type=Path,help='fresh output JSONL; existing files are refused')
    parser.add_argument('--clock-domain',required=True)
    args=parser.parse_args()
    records=[decode(json.loads(line),clock_domain=args.clock_domain)
             for line in args.input.read_text().splitlines() if line.strip()]
    with args.output.open('x') as handle:
        for record in records:handle.write(json.dumps(record,sort_keys=True)+'\n')

if __name__=='__main__':main()
