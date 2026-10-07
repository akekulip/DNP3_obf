#!/usr/bin/env python3
"""Reproduce source-bound primitive resource evidence, without target contact."""
from collections import Counter
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = (
    'owner_cas_05', 'protected_pair_04', 'protected_recirc_06',
    'association_binding_01', 'deadline_service_01', 'timing_service_02',
    'timing_bound_01', 'held_original_04', 'original_credit_native_04',
    'held_timing_snapshot_02', 'held_timing_expected_02',
)


def collect(name, builder):
    directory = ROOT / 'evidence' / name
    manifest = json.loads((directory / 'manifest.json').read_text())
    verified = builder.verify_evidence(directory)
    if not verified['compiled_artifacts_verified']:
        raise RuntimeError(f'{name}: current source/artifact evidence is inconsistent')
    phv = json.loads((directory / 'out/pipe/logs/phv.json').read_text())
    containers = Counter()
    footprint = Counter()
    span = {'ingress': [0] * 12, 'egress': [0] * 12}
    for container in phv['containers']:
        gress, width = container['gress'], container['bit_width']
        containers[(gress, container['container_type'], width)] += 1
        footprint[gress] += width
        # Each slice's actual read/write endpoints bound its conservative span.
        # Parser=-1 and deparser=12; only actual MAU stages0..11 are counted.
        # Aliased disjoint slices are unioned; each container counts once/stage.
        active = set()
        for field_slice in container['slices']:
            endpoints = []
            for mode in ('reads', 'writes'):
                for access in field_slice[mode]:
                    location = access['location']
                    if location['type'] == 'parser':
                        endpoints.append(-1)
                    elif location['type'] == 'deparser':
                        endpoints.append(12)
                    elif location['type'] == 'mau':
                        endpoints.append(location['stage'])
                    else:
                        raise ValueError(f'unknown PHV location: {location}')
            if endpoints:
                active.update(range(max(0, min(endpoints)), min(11, max(endpoints)) + 1))
        for stage in active:
            span[gress][stage] += width
    return {
        'manifest_sha256': builder.sha(directory / 'manifest.json'),
        'source_sha256': manifest['source_sha256'],
        'verification': verified,
        'resources': manifest['resources'],
        'allocated_phv_containers': [
            {'gress': gress, 'type': kind, 'width_bits': width, 'count': count}
            for (gress, kind, width), count in sorted(containers.items())],
        'allocated_phv_footprint_bits': dict(footprint),
        'conservative_endpoint_span_bits_by_stage': span,
        'conservative_endpoint_span_max_bits': {gress: max(bits) for gress, bits in span.items()},
        'pressure_note': 'Endpoint-span container footprint is a conservative derived allocation proxy, '
                         'not compiler-reported simultaneous live-field pressure or full-target headroom.',
    }


def main():
    spec = importlib.util.spec_from_file_location('case4_builder', ROOT.parent / 'build.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    results = {name: collect(name, builder) for name in EVIDENCE}
    (ROOT / 'resources.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(json.dumps({name: {'stages': result['resources']['stages'],
                            'critical_path': result['resources']['critical_path'],
                            'allocated_ingress_bits': result['allocated_phv_footprint_bits']['ingress'],
                            'endpoint_span_max_ingress_bits': result['conservative_endpoint_span_max_bits']['ingress']}
                      for name, result in results.items()}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
