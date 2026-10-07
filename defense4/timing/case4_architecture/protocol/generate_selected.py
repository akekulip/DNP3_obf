"""Immutable exact selected-object admission seam; CP installation is not SELECT publication."""
from pathlib import Path
from generate_padding import generate as padder
SELECTED_KEYS=('hdr.dl.dst','hdr.dl.src','hdr.native.index','hdr.native.code','hdr.native.repeat','hdr.native.on','hdr.tail.off','hdr.tail.status','hdr.native.func','hdr.native.app')
def generate():
    s=padder().replace('struct meta_t{','struct meta_t{bit<1> selected_match;')
    s=s.replace('m.parsed=1w0;','m.parsed=1w0;m.selected_match=1w0;')
    seam='action selected(){m.selected_match=1w1;}\ntable selected_objects{key={'+''.join(k+':exact;' for k in SELECTED_KEYS)+'}actions={selected;NoAction;}size=2;default_action=NoAction();}\n'
    s=s.replace(' action eligible()',seam+' action eligible()')
    s=s.replace('connection.apply();profile.apply();','connection.apply();profile.apply();selected_objects.apply();')
    s=s.replace('if(m.enabled==1w1&&m.profile==1w1){','if(m.enabled==1w1&&m.profile==1w1&&m.selected_match==1w1){')
    return s.replace('No lifecycle or assembly.', 'Exact selected object table is immutable externally installed; no lifecycle or assembly.')
if __name__=='__main__':Path(__file__).with_name('selected_padding.p4').write_text(generate())
