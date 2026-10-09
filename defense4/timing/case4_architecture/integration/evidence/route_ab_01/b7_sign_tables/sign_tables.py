"""Replace the four `(bit<8>)(~delta[31:31])` sign-bit slices with one-entry ternary tables."""
import sys
from pathlib import Path
t = Path(sys.argv[1]).read_text()
for name, delta in [('da', 'da_delta'), ('readiness', 'readiness_delta'), ('gap', 'gap_delta'), ('op', 'op_delta')]:
    old = '    action extract_%s_ready() { md.%s_ready = (bit<8>)(~md.%s[31:31]); }' % (name, name, delta)
    new = ('    action set_%s_ready(bit<8> v) { md.%s_ready = v; }\n'
           '    table %s_sign {\n'
           '        key = { md.%s : ternary; }\n'
           '        actions = { set_%s_ready; }\n'
           '        const entries = { 32w0 &&& 32w0x80000000 : set_%s_ready(1); }\n'
           '        default_action = set_%s_ready(0); size = 1;\n'
           '    }') % (name, name, name, delta, name, name, name)
    assert t.count(old) == 1, old; t = t.replace(old, new)
    call = 'extract_%s_ready();' % name
    assert t.count(call) == 1, call; t = t.replace(call, '%s_sign.apply();' % name)
Path(sys.argv[2]).write_text(t)
