"""Seal fresh source-bound supporting byte checks, preserving every prior record."""
from pathlib import Path
import json
import subprocess
import sys
HERE=Path(__file__).resolve().parent;ARCH=HERE.parents[1]
sys.path[:0]=[str(ARCH),str(ARCH.parent/'framework'),str(HERE/'tests')]
from runner.evidence import reserve_run,sha256
from build import verify_evidence
from generate_shared import generate
from test_packets import TEXT,fixtures,codec,packet,ingress,output,expected_packet


def verify(destination):
 with reserve_run(destination,{'scope':'source parser/control/deparser fragments, independent Scapy expected serialization; no target/model/physical execution','full_target':False}) as run:
  inputs=list(HERE.glob('*.py'))+list((HERE/'tests').glob('*.py'))+[HERE/'shared_egress.p4',HERE/'tagged_probe.p4',ARCH/'tests/source_control.py',ARCH/'protocol/source_eval.py',ARCH/'protocol/generate_padding.py',ARCH/'protocol/generate_images.py',ARCH/'protocol/tests/test_protocol.py',ARCH.parent/'framework/size/case4_padding.py']
  hashes={str(path.relative_to(ARCH.parent)):sha256(path) for path in inputs}
  for path in inputs:run.snapshot(path,str(path.relative_to(ARCH.parent)))
  generated_matches=(HERE/'shared_egress.p4').read_text()==generate()
  completed=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(HERE/'tests'),'-v'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  run.write_bytes('tests.log',completed.stdout)
  vectors=[];banks={}
  for fc in (3,4):
   native=fixtures.ExactImages().native(fc);expected=codec.expand_control(native,codec.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
   transformed,eg,internal=output(ingress(packet(native)),banks);banks=eg.registers
   replayed,eg,replay_internal=output(ingress(packet(native[-1:],seq=18,ack=987654,window=0,flags=0x10),replay=(2,0xfffffff0,native[-1],fc-3)),banks)
   vectors.append({'function':fc,'native_packet':packet(native).hex(),'internal_write_packet':internal.hex(),'transformed_packet':transformed.hex(),'independent_expected_packet':expected_packet(expected).hex(),'native_tail_packet':packet(native[-1:],seq=18,ack=987654,window=0,flags=0x10).hex(),'internal_read_packet':replay_internal.hex(),'replayed_packet':replayed.hex(),'independent_expected_replay':expected_packet(expected,ack=987654,window=0,flags=0x10).hex(),'cache_words':[banks[(f'image_{i}',fc-3)] for i in range(14)]})
  run.write_json('exact_vectors.json',vectors)
  compile_verified=verify_evidence(HERE/'evidence/shared_03')
  result={'generated_matches':generated_matches,'source_sha256':hashes,'tests_exit_code':completed.returncode,'tests':11,'compiled_candidate':compile_verified,'full_target':False}
  run.write_json('manifest.json',result)
  run.finish('passed' if completed.returncode==0 and generated_matches and compile_verified['compiled_artifacts_verified'] else 'failed',result)
  return result

if __name__=='__main__':print(json.dumps(verify(Path(sys.argv[1])),indent=2))
