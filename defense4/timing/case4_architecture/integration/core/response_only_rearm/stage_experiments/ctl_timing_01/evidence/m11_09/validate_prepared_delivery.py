from pathlib import Path
import csv,hashlib,json
b=Path(__file__).resolve().parent
ct=b.parents[1]
repo=ct.parents[7]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
load=lambda p:json.loads(p.read_text())
record=load(b/'configs/prepared_configs.json')
assert len(record['configs'])==55
assert record['source_sha256']==sha(b/'response_only.p4')
assert record['supported_profile_sha256']==sha(b/'supported_profile.json')
assert record['inputs_sha256']==sha(b/'response_only.inputs.json')
assert record['compile_manifests']=={n:sha(b/n/'manifest.json') for n in ('compile_local','compile_switch_9132')}
templates=ct.parent/'seg61_02/hw/config'
for name,binding in record['configs'].items():
 p=b/'configs'/name;t=templates/binding['template']
 assert sha(p)==binding['sha256'] and sha(t)==binding['template_sha256']
 actual,original=load(p),load(t)
 assert actual['ctl_timing_identity']['source_sha256']==record['source_sha256']
 assert actual['ctl_timing_identity']['supported_profile_sha256']==record['supported_profile_sha256']
 for build in actual['builds'].values(): assert build['source_sha256']==record['source_sha256']
 actual.pop('ctl_timing_identity',None);original.pop('ctl_timing_identity',None)
 actual.pop('builds');original.pop('builds')
 for arm in actual['arms']: arm.pop('build')
 for arm in original['arms']: arm.pop('build')
 if 'candidate61_label' in original['evaluation']:
  actual['evaluation']['candidate61_label']=original['evaluation']['candidate61_label']
 assert actual==original,name
reports={p.stem:load(p) for p in (b/'compiler_reports').glob('*.json')}
rows=list(csv.DictReader((b/'compiler_table.csv').open()))
expected=[]
for name,r in reports.items():
 assert r['candidate_sha256']==sha(ct/'evidence'/name/'response_only.p4')
 for sdk,compiled in r['compiles'].items():
  if compiled.get('present') is False: continue
  assert compiled['exit_code']==0 and compiled['mirror_guard'].startswith('PASS')
  assert compiled['source_sha256']==r['candidate_sha256']
  for role,(pipe,direction) in {'N':('p0','ingress'),'E':('p0','egress'),'T':('p1','ingress')}.items():
   matches=[row for row in rows if (row['build'],row['sdk'],row['role'])==(name,sdk,role)]
   assert len(matches)==1
   row=matches[0];placement=compiled['placement'][role]
   assert row['occupied_indices']==' '.join(map(str,placement['occupied_indices']))
   for k in ('occupied_count','stage_span'): assert int(row[k])==placement[k]
   assert int(row['maximum_stage'])==placement['maximum_occupied_stage']
   for k,v in dict(compiled['resources'][pipe]['attributed'][direction],**compiled['resources'][pipe]['phv'][direction]).items(): assert int(row[k])==v
   expected.append((name,sdk,role))
assert len(rows)==len(expected)
comparison=load(b/'compiler_comparison.json')
assert comparison['candidate_build']=='m11_09' and comparison['candidate_source_sha256']==record['source_sha256']
assert comparison['exporter_sha256']==sha(b/'export_comparison.py')
m=load(b/'reproduction_commands.json')
def validate_command_metadata(manifest, reference):
 offline=manifest['offline_reproduction']
 assert [step['order'] for step in offline]==list(range(1,26))
 assert all(type(step['order']) is int for step in offline)
 assert [step['order'] for step in manifest['hardware_proposal']['commands']]==list(range(1,8))
 assert all(step['model_only'] is True for step in offline[5:14])
 assert type(offline[15]['expected_configuration_count']) is int
 assert offline[15]['expected_configuration_count']==55
 assert manifest['hardware_proposal']['physical_relay'] is False
 actual=manifest['hardware_proposal']['comparison']
 expected={'reads_per_arm':reference['trials']['reads_per_trial'],
           'sbo_cycles_per_arm':reference['traffic']['sbo_cycles'],
           'trials_per_arm':reference['trials']['trials_per_arm']}
 for key,value in expected.items():
  assert type(actual[key]) is int and actual[key]==value,key
 assert actual['fixture']=={'mode':reference['fixture']['modes'][0],
                           'delay_ms':reference['fixture']['delay_ms'],
                           'jitter_ms':reference['fixture']['jitter_ms']}
 assert all(type(actual['fixture'][key]) is int for key in ('delay_ms','jitter_ms'))
 assert actual['timing_ns']==reference['timing_params_ns']
 assert all(type(value) is int for value in actual['timing_ns'].values())
 assert 'parser_err==16w0' not in manifest['provenance']['m11_05']['finding']
validate_command_metadata(m,load(b/'configs/part2_m11_09_ref_r30_b1.json'))
assert m['current_candidate']['source_sha256']==record['source_sha256']
assert len(m['hardware_proposal']['commands'])==7
commands=[s['argv'] for s in m['offline_reproduction']]+m['selected_candidate_pre_hardware_commands']+[s['argv'] for s in m['hardware_proposal']['commands']]+[s['argv'] for s in m['analysis_reproduction']['commands']]
assert len(commands)==39
for argv in commands:
 for a in argv: assert not a.startswith('defense4/'),a
 script=argv[1] if argv[0] in ('python3','bash') else argv[1]
 assert Path(script).is_file(),script
 if Path(script).name in ('run_model.py','model_summary.py'): assert Path(argv[2]).is_absolute()
assert m['generator_identity']['sha256']==sha(ct/'efficiency_candidates.py')
assert m['generator_identity']['selected_build_generator_sha256']==sha(b/'generate.py')
assert m['delivery_validator']['sha256']==sha(Path(__file__))
assert m['offline_reproduction'][24]['validator_sha256']==sha(Path(__file__))
print(json.dumps({'configs':55,'template_policy_equal':True,'compiler_reports':len(reports),'compiler_rows':len(rows),'commands':len(commands),'hardware_proposal_blocks':7,'candidate_source_sha256':record['source_sha256']},indent=2))
