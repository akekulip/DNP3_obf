"""Select complete captured READ vectors for exactly the build's admitted shapes."""
import json
from pathlib import Path


def select_templates(vdir, shapes):
    expected = set(map(int, shapes))
    for name in ('two_read_templates_relay.json', 'two_read_templates.json'):
        path = Path(vdir) / name
        if not path.is_file():
            continue
        try:
            variants = json.loads(path.read_text())['variants']
            if set(variants) != {'v0', 'v1'}:
                continue
            lengths = set()
            for variant in variants.values():
                classes = variant['classes']
                if set(classes) != {'mixed', 'integrity'}:
                    raise ValueError('incomplete classes')
                for item in classes.values():
                    request, native = bytes.fromhex(item['request']), bytes.fromhex(item['native'])
                    if not request or not native:
                        raise ValueError('empty capture')
                    lengths.add(len(native))
            if lengths == expected:
                return variants, path
        except (KeyError, TypeError, ValueError):
            continue
    raise AssertionError('no two-READ template set matches this build SHAPES %s' % sorted(expected))
