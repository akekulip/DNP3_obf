#!/usr/bin/env python3
"""Prepare candidate config and launcher; does not restart the switch."""
import hashlib
import json
from pathlib import Path
root=Path('/home/decps/dnp3_latency_random_20260926')
build=root/'build_digest_init_sde9132'
m=json.loads((build/'manifest.json').read_text())
assert m['source_sha256']=='8e6d0ad983acfceadae447aa7b5b4614193604b6cd87b902b1d567eaa5696478'
assert m['ingress_stages']==7 and m['egress_stages']==0
for name,want in m['artifact_sha256'].items():
    assert hashlib.sha256((build/'out'/name).read_bytes()).hexdigest()==want
conf=json.loads(Path('/home/decps/dnp3_timing7_20260925/defense4_timing.conf').read_text())
p=conf['p4_devices'][0]['p4_programs'][0]
p['bfrt-config']=str(build/'out/bfrt.json')
pipe=p['p4_pipelines'][0]
pipe['context']=str(build/'out/pipe/context.json')
pipe['config']=str(build/'out/pipe/tofino.bin')
pipe['path']=str(build/'out')
(root/'defense4_timing_randomized.conf').write_text(json.dumps(conf,indent=2)+'\n')
launcher='#!/bin/bash\nset -e\nexport SDE=/home/decps/Downloads/bf-sde-9.13.2\nexport SDE_INSTALL=$SDE/install\nexport LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}\ncd /home/decps/dnp3_latency_random_20260926\ntail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" --install-dir "$SDE_INSTALL" --conf-file /home/decps/dnp3_latency_random_20260926/defense4_timing_randomized.conf --init-mode=cold --status-port 7777\n'
(root/'launch_randomized.sh').write_text(launcher)
(root/'launch_randomized.sh').chmod(0o755)
print('Candidate configuration prepared; no daemon changed')
