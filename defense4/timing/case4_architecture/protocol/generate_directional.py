"""Direction-separated projections of the grouped mapping arithmetic."""
from pathlib import Path
from generate_mapping import generate

def direction_source(direction):
    s=generate()
    if direction==1:
        for name in ('left1','left2','right1','right2','difference_t','growth_t','window_guard','window_narrow_t','complete_t'):
            s=s.replace(name+'.apply();','')
        s=s.replace('if(m.direction==8w2){}else{hdr.tcp.seq=m.seq_result;m.changed=1w1;}','hdr.tcp.seq=m.seq_result;m.changed=1w1;')
    else:
        for name in ('seq1','seq2'):s=s.replace(name+'.apply();','')
        s=s.replace('hdr.tcp.seq=m.seq_result;hdr.tcp.ack=m.left;','hdr.tcp.ack=m.left;')
        s=s.replace('if(m.direction==8w2){','{').replace('}else{hdr.tcp.seq=m.seq_result;m.changed=1w1;}','}')
    return s.replace('Grouped TCP mapping primitive.',f'Direction {direction} grouped TCP mapping primitive.')

if __name__=='__main__':
    for direction,name in ((1,'mapping_forward.p4'),(2,'mapping_reverse.p4')):Path(__file__).with_name(name).write_text(direction_source(direction))
