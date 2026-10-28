#!/usr/bin/env python3
"""Derive a private model config from verified original compiler artifacts."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def prepare(out, destination):
    out, destination = Path(out).resolve(), Path(destination).resolve()
    spec = importlib.util.spec_from_file_location('current_compile_evidence', ROOT / 'scripts/build.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    compiled, build = out.parent, out.parent.parent
    if not compiler.verify_evidence(compiled, source_root=build)['compiled_artifacts_verified']:
        raise ValueError('model config requires verified original compiler artifacts')
    manifest_path = compiled / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    confs = [out / name for name in manifest['artifact_sha256'] if name.endswith('.conf')]
    if len(confs) != 1:
        raise ValueError('model requires one original compiler configuration')
    original = confs[0]
    content = original.read_bytes()
    if compiler.sha(original) != manifest['artifact_sha256'][str(original.relative_to(out))]:
        raise ValueError('original compiler configuration hash differs')
    config = json.loads(content)
    inventory = compiler.pipeline_contexts(out)
    observed = set()
    for device in config['p4_devices']:
        device.pop('agent0', None)
        for program in device['p4_programs']:
            program['bfrt-config'] = str(out / 'bfrt.json')
            if 'model_json_path' in program:
                program['model_json_path'] = str(out / 'share' / program['program-name'] / 'aug_model.json')
            for pipe in program['p4_pipelines']:
                name = pipe['p4_pipeline_name']
                if name not in inventory or name in observed:
                    raise ValueError('model config pipeline differs from verified inventory')
                observed.add(name)
                context = inventory[name]
                pipe['context'] = str(out / context)
                pipe['config'] = str(out / context.parent / 'tofino.bin')
                pipe['path'] = str(out)
    if observed != set(inventory):
        raise ValueError('model config omits a verified pipeline')
    destination.write_text(json.dumps(config, indent=2) + '\n')
    binding = dict(schema='private-model-config-v1', source_sha256=manifest['source_sha256'],
        compile_manifest_sha256=compiler.sha(manifest_path), selected_out=str(out),
        original_config=str(original.relative_to(out)), original_config_sha256=compiler.sha(original),
        derived_config=destination.name, derived_config_sha256=compiler.sha(destination))
    destination.with_name('model_config_binding.json').write_text(json.dumps(binding, indent=2) + '\n')
    if original.read_bytes() != content:
        raise ValueError('original compiler config was changed')
    return binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare(args.out, args.destination)


if __name__ == '__main__':
    main()
