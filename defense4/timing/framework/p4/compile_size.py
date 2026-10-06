#!/usr/bin/env python3
"""Source-bound local9.13.1 compiler probe; no loading or hardware access."""
import hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
compiler=Path('/home/philip/bf-sde-9.13.1/install/bin/bf-p4c')
source=HERE/(sys.argv[2] if len(sys.argv)>2 else 'case4_size_kernel.p4')
if source.parent.resolve()!=HERE or source.suffix!='.p4':raise ValueError('local P4 source required')
name=sys.argv[1] if len(sys.argv)>1 else 'build_01'
if not name.startswith('build_') or '/' in name: raise ValueError('build name required')
build=HERE/'evidence'/name;build.mkdir(parents=True,exist_ok=False)
snapshot=build/source.name;snapshot.write_bytes(source.read_bytes())
inputs=source.with_suffix('.inputs.json')
if inputs.exists():
    (build/'inputs.json').write_bytes(inputs.read_bytes())
command=[str(compiler),'--target','tofino','--arch','tna']
if source.name=='case4_joint_component_probe.p4':
    command+=['-g','-DU_BOR']
command+=['-o',str(build/'out'),str(snapshot)]
with (build/'compile.log').open('w') as log:
    run=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
artifacts={str(p.relative_to(build)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (build/'out').rglob('*') if p.is_file()}
manifest={'source':source.name,'source_sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest(),
 'command':command,'compiler':subprocess.check_output([str(compiler),'--version'],text=True).strip(),
 'exit_code':run.returncode,'software_only':True,'sde':'9.13.1','deployment_gate':'requires9.13.2+transportcompletion+hardwareadmission',
 'artifact_sha256':artifacts}
if inputs.exists():
    manifest['inputs_sha256']=hashlib.sha256((build/'inputs.json').read_bytes()).hexdigest()
(build/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({k:v for k,v in manifest.items() if k!='artifact_sha256'},indent=2))
raise SystemExit(run.returncode)
