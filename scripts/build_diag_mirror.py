#!/usr/bin/env python3
"""Derive and package the c72_diag_mirror diagnostic candidate from the canonical P4.

  python3 scripts/build_diag_mirror.py results/builds/c72_diag_mirror [--compile]

The derived source is p4/response_only.p4 plus the INSERTIONS listed in HUNKS, nothing else:
  * pipe-0 ingress (N): every frame received on dev64 is copied AS RECEIVED to session SESSION_RX;
  * pipe-0 egress (E): every frame that leaves on dev64 (not dropped) is copied AS EMITTED to session SESSION_TX.
The TNA header (tofino1_base.p4) defines the copy contents: the ingress deparser copies the original ingress
packet, the egress deparser copies the constructed output packet. Both sessions point at dev10, which
r_EgParser does not parse (default: accept), so a copy crosses pipe-0 egress untouched and leaves.
T (pipe 1), its clone session 7 and scripts/hardware/t_config.py are not touched.

The canonical source and results/builds/c72 are only read. The derived source exists only inside the new
build directory (packaged with scripts/profile.py, compiled with scripts/build.py, SDK 9.13.2, c72's flags).
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / 'p4/response_only.p4'
BUILD_NAME = 'c72_diag_mirror'
SCHEMA = 'c72-diag-mirror-v1'
MIRROR_TYPE = 1
RELAY_PORT = 64
COPY_PORT = 10
SESSION_RX = 101       # ingress copy: frames ARRIVING from the relay on dev64
SESSION_TX = 102       # egress copy: frames LEAVING toward the relay on dev64
MAX_PKT_LEN = 16384    # no truncation; TF1 jumbo is 9216
TAG = 'DIAG MIRROR'

# (name, anchor in the canonical source, 'before'|'after', inserted text). Each anchor occurs exactly once.
HUNKS = (
    ('n_constants', "const PortId_t n_READ_HANDOFF_PORT=9w180; /* N-to-T handoff at dev180; matches t_T_IN. */\n", 'after',
     "/* %s (c72_diag_mirror only; scripts/build_diag_mirror.py, never in p4/response_only.p4): every frame received on\n"
     "   n_DIAG_RELAY_PORT is copied as received (TNA ingress mirror) to session n_DIAG_SESSION_RX. */\n"
     "const MirrorType_t n_DIAG_MIRROR_TYPE=%d;\n"
     "const PortId_t n_DIAG_RELAY_PORT=9w%d;\n"
     "const MirrorId_t n_DIAG_SESSION_RX=10w%d;\n"
     "const MirrorId_t n_DIAG_NO_SESSION=10w0;\n" % (TAG, MIRROR_TYPE, RELAY_PORT, SESSION_RX)),
    ('n_meta_field', "bit<32> owner_diff;bit<2> retry;", 'after', "MirrorId_t diag_ses;"),
    ('n_pragmas', "control n_Ingress(", 'before',
     '@pa_no_overlay("ingress", "ig_intr_md_for_dprsr.mirror_type")   /* %s: unwritten value must stay 0 */\n'
     '@pa_no_overlay("ingress", "m.diag_ses")\n' % TAG),
    ('n_ingress_select', "  m.return_abort=(bit<1>)(8w0);m.work_op=8w0;", 'before',
     "  /* %s: always select mirror entry 1, never bf-p4c's type-0 entry (see t_NO_MIRROR_SESSION); session 0 = no copy. */\n"
     "  md.mirror_type=n_DIAG_MIRROR_TYPE;m.diag_ses=n_DIAG_NO_SESSION;\n"
     "  if(ig.ingress_port==n_DIAG_RELAY_PORT){m.diag_ses=n_DIAG_SESSION_RX;}\n" % TAG),
    ('n_deparser_mirror', "in ingress_intrinsic_metadata_for_deparser_t md){", 'after', "Mirror() n_diag_mirror;"),
    ('n_deparser_emit', "pkt.emit(hdr);}}\nparser n_EgParser(", 'before',
     "if(md.mirror_type==n_DIAG_MIRROR_TYPE){n_diag_mirror.emit(m.diag_ses);}"),
    ('r_constants', "const bit<32> r_IMAGE_LEN = 61;\n", 'after',
     "/* %s (c72_diag_mirror only): every frame that leaves on r_DIAG_RELAY_PORT and is not dropped is copied as\n"
     "   emitted (TNA egress mirror) to session r_DIAG_SESSION_TX. Both diagnostic sessions send their copies to\n"
     "   r_DIAG_COPY_PORT, which r_EgParser does not parse (default: accept): no header, register or mirror there. */\n"
     "const MirrorType_t r_DIAG_MIRROR_TYPE = %d;\n"
     "const PortId_t r_DIAG_RELAY_PORT = 9w%d;\n"
     "const PortId_t r_DIAG_COPY_PORT = 9w%d;\n"
     "const MirrorId_t r_DIAG_SESSION_TX = 10w%d;\n"
     "const MirrorId_t r_DIAG_NO_SESSION = 10w0;\n" % (TAG, MIRROR_TYPE, RELAY_PORT, COPY_PORT, SESSION_TX)),
    ('r_meta_field', "bit<1> cbad0; bit<1> cbadt;\n", 'after', "    MirrorId_t diag_ses;   /* %s */\n" % TAG),
    ('r_pragmas', "control r_Egress(", 'before',
     '@pa_no_overlay("egress", "eg_intr_md_for_dprsr.mirror_type")   /* %s: unwritten value must stay 0 */\n'
     '@pa_no_overlay("egress", "m.diag_ses")\n' % TAG),
    ('r_egress_select', "        /* stage 0 */\n        conn.apply();", 'before',
     "        /* %s: always select mirror entry 1 (session 0 = no copy); the session is chosen at the end. */\n"
     "        md.mirror_type = r_DIAG_MIRROR_TYPE;\n" % TAG),
    ('r_egress_session', "            else { strip_provenance(); }\n        }\n", 'after',
     "        /* %s: copy only a frame that leaves on the relay port. drop_ctl bit 0 drops the frame but does not\n"
     "           stop an egress mirror copy (tofino1_base.p4: bit 2 does), so a dropped frame must not name a session. */\n"
     "        if (eg.egress_port == r_DIAG_RELAY_PORT && md.drop_ctl[0:0] == 1w0) { m.diag_ses = r_DIAG_SESSION_TX; }\n"
     "        else { m.diag_ses = r_DIAG_NO_SESSION; }\n" % TAG),
    ('r_deparser_mirror', "Checksum() ip_new; Checksum() tcp_plain; Checksum() tcp_read; Checksum() tcp_ctl;\n", 'after',
     "    Mirror() r_diag_mirror;   /* %s */\n" % TAG),
    ('r_deparser_emit', "Checksum() tcp_ctl;\n    apply {\n", 'after',
     "        if (md.mirror_type == r_DIAG_MIRROR_TYPE) { r_diag_mirror.emit(m.diag_ses); }   /* %s */\n" % TAG),
)


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def derive(canonical):
    """Canonical text -> (derived text, [(name, canonical offset, inserted text)]). Insertions only."""
    points = []
    for name, anchor, where, text in HUNKS:
        if canonical.count(anchor) != 1:
            raise ValueError('anchor for %s occurs %d times' % (name, canonical.count(anchor)))
        start = canonical.index(anchor)
        points.append((start + (len(anchor) if where == 'after' else 0), name, text))
    if len({p for p, _, _ in points}) != len(points):
        raise ValueError('two hunks insert at one offset')
    derived = canonical
    for offset, _name, text in sorted(points, reverse=True):
        derived = derived[:offset] + text + derived[offset:]
    return derived, [(name, offset, text) for offset, name, text in sorted(points)]


def insertions(canonical, derived):
    """Independent check: [(canonical line, inserted text)] or ValueError if anything was deleted or replaced."""
    a, b = canonical.splitlines(keepends=True), derived.splitlines(keepends=True)
    found = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == 'equal':
            continue
        if tag == 'delete':
            raise ValueError('derived source deletes canonical lines %d-%d' % (i1 + 1, i2))
        old, new = ''.join(a[i1:i2]), ''.join(b[j1:j2])
        for op, k1, k2, m1, m2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
            if op in ('delete', 'replace'):
                raise ValueError('derived source changes canonical text near line %d: %r' % (i1 + 1, old[k1:k2]))
            if op == 'insert':
                found.append((i1 + 1, new[m1:m2]))
    return found


def unified_diff(canonical, derived):
    return ''.join(difflib.unified_diff(canonical.splitlines(keepends=True), derived.splitlines(keepends=True),
                                        'a/p4/response_only.p4', 'b/results/builds/%s/response_only.p4' % BUILD_NAME))


def constants(text):
    """Diagnostic constants as declared in a derived source (the single source for the session script)."""
    found = {}
    for name in ('n_DIAG_MIRROR_TYPE', 'n_DIAG_RELAY_PORT', 'n_DIAG_SESSION_RX', 'n_DIAG_NO_SESSION',
                 'r_DIAG_MIRROR_TYPE', 'r_DIAG_RELAY_PORT', 'r_DIAG_COPY_PORT', 'r_DIAG_SESSION_TX', 'r_DIAG_NO_SESSION'):
        values = re.findall(r'const\s+\w+\s+%s\s*=\s*(?:\d+w)?(\d+)\s*;' % name, text)
        if len(values) != 1:
            raise ValueError('derived source must declare %s exactly once' % name)
        found[name] = int(values[0])
    return found


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def identity(canonical, derived):
    found = insertions(canonical, derived)
    return dict(schema=SCHEMA, build=BUILD_NAME, purpose='diagnostic relay-leg mirror; not the c72 binary',
                canonical_source='p4/response_only.p4', canonical_sha256=sha(canonical), source_sha256=sha(derived),
                generator='scripts/build_diag_mirror.py', generator_sha256=sha(Path(__file__).read_bytes()),
                hunks=[name for name, _a, _w, _t in HUNKS], inserted_fragments=len(found),
                inserted_lines=sum(text.count('\n') for _l, text in found), deleted_or_replaced=0,
                mirror=dict(type=MIRROR_TYPE, relay_port=RELAY_PORT, copy_port=COPY_PORT,
                            session_rx=SESSION_RX, session_tx=SESSION_TX, max_pkt_len=MAX_PKT_LEN,
                            t_clone_session_untouched=7))


def generate(output, compile_=False):
    output = Path(output).resolve()
    if output.name != BUILD_NAME:
        raise ValueError('the diagnostic build directory must be named ' + BUILD_NAME)
    canonical = CANONICAL.read_text()
    derived, _points = derive(canonical)
    meta = identity(canonical, derived)
    profile = module('current_profile', ROOT / 'scripts/profile.py')
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'response_only.p4'
        source.write_text(derived)
        profile.package(output, source=source)          # exclusive: refuses an existing directory
    if sha((output / 'response_only.p4').read_bytes()) != meta['source_sha256']:
        raise ValueError('packaged source differs from the derived source')
    (output / 'diag_mirror.json').write_text(json.dumps(meta, indent=2) + '\n')
    (output / 'diag_mirror.diff').write_text(unified_diff(canonical, derived))
    if compile_:
        result = profile.compiler_module().compile_candidate(output / 'response_only.p4', output / 'compile_local')
        if result['exit_code'] != 0:
            return result['exit_code']
        profile.record_artifacts(output)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compile', action='store_true')
    args = parser.parse_args()
    code = generate(args.output, args.compile)
    print(json.dumps(dict(build=str(args.output), exit_code=code,
                          source_sha256=sha((args.output / 'response_only.p4').read_bytes()))))
    return code


if __name__ == '__main__':
    sys.exit(main())
