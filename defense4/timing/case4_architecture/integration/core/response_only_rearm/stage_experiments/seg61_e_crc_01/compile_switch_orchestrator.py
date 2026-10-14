from pathlib import Path
import hashlib, json, shlex, subprocess, sys
ARCH=Path('/home/philip/Projects/DNP3/defense4/timing/case4_architecture')
SOURCE=ARCH/'integration/core/response_only_rearm/stage_experiments/seg61_e_crc_01/evidence/full_01/response_only.p4'
OUT=SOURCE.parent/'compile_switch_9132'
EXPECTED='1789b5cbac30fab3fe68543ea3f5fa013c4536ef332c33eb32106a56765d19e3'
HOST='decps@10.10.54.81'
COMPILER='/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==EXPECTED
OUT.mkdir(exist_ok=True)
assert not (OUT/'manifest.json').exists(), 'completed evidence already exists'
(OUT/'orchestrator.py').write_bytes(Path(__file__).read_bytes())
def run(command, **kw):
    return subprocess.run(command, check=True, text=True, **kw)
remote=run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',HOST,'mktemp -d /tmp/case4_compile_crc61_XXXXXXXX'],capture_output=True).stdout.strip()
assert remote.startswith('/tmp/case4_compile_crc61_') and '/' not in remote[5:]
run(['ssh',HOST,'mkdir '+shlex.quote(remote+'/inputs')])
run(['scp','-q',str(ARCH/'build.py'),HOST+':'+remote+'/build.py'])
run(['scp','-q',str(SOURCE),HOST+':'+remote+'/inputs/response_only.p4'])
command=['python3',remote+'/build.py',remote+'/inputs/response_only.p4',remote+'/evidence','--compiler',COMPILER,'--timeout','420']
(OUT/'remote_command.json').write_text(json.dumps(dict(host=HOST,command=command,remote_directory=remote,activation=False,sdk_updates=False,source_sha256=EXPECTED),indent=2)+'\n')
with (OUT/'session.log').open('w') as log:
    completed=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',HOST,shlex.join(command)],stdout=log,stderr=subprocess.STDOUT,text=True,timeout=450)
run(['rsync','-a',HOST+':'+remote+'/evidence/',str(OUT)+'/'])
report=json.loads((OUT/'manifest.json').read_text())
(OUT/'remote_manifest.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
report.update(compiler_host=HOST,source=str(SOURCE),remote_source=remote+'/inputs/response_only.p4')
(OUT/'manifest.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(exit_code=completed.returncode,elapsed_seconds=report['elapsed_seconds'],compiler=report['compiler'],source_sha256=report['source_sha256'],evidence=str(OUT))))
sys.exit(completed.returncode)
