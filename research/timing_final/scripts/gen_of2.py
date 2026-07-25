#!/usr/bin/env python3
# gen byte = DNP3 app-control of transaction i's READ, read from the self-contained frames file.
import json,sys,struct
i=int(sys.argv[1])
fr=json.load(open('/tmp/claude-1002/-home-philip-Projects-DNP3/dfaf5646-3039-4b11-b811-41243ad16b5a/scratchpad/relay_frames_live.json'))['frames_list']
reads=[f for f in fr if f['role']=='READ']
b=bytes.fromhex(reads[i]['hex']); ihl=(b[14]&0xf)*4; tcp=14+ihl; doff=((b[tcp+12]>>4)&0xf)*4
pl=b[14+ihl+doff:]; print(hex(pl[11]))
