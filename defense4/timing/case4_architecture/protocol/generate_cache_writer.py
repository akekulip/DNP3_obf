"""Actual validated same-pass image writes; publication/lifecycle is separate.

This is never an enabled deployment: no atomic incarnation/publish owner yet.
"""
from pathlib import Path
from generate_padding import generate

def generate_writer():
    s=generate().replace('Default profile disabled. No lifecycle or assembly.','Default profile disabled. Actual image writes; NO protected publication/lifecycle or assembly.')
    fields='bit<1> image_slot;'+''.join(f'bit<32> image_word{i};' for i in range(14))
    s=s.replace('struct meta_t{','struct meta_t{'+fields)
    values=[
        'hdr.dl.magic++hdr.dl.len++hdr.dl.ctrl','hdr.dl.dst++hdr.dl.src',
        'hdr.dl.crc++hdr.native.tp++hdr.native.app','hdr.native.func++hdr.native.group++hdr.native.variation++hdr.native.qualifier',
        'hdr.native.count++hdr.native.index','hdr.native.code++hdr.native.repeat++hdr.native.on[31:16]',
        'hdr.native.on[15:0]++hdr.native.crc','hdr.appended.off',
        'hdr.appended.status++hdr.appended.group++hdr.appended.variation++hdr.appended.qualifier',
        'hdr.appended.count++hdr.appended.index','hdr.appended.code++hdr.appended.repeat++hdr.appended.on_first',
        'hdr.appended.crc++hdr.last.on_last','hdr.last.off','hdr.last.status++hdr.last.crc++8w0']
    declarations=''
    for i,value in enumerate(values):
        declarations+=f'Register<bit<32>,bit<1>>(2,0) image_{i};\nRegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout bit<32> v,out bit<32> rv){{v=m.image_word{i};rv=v;}}}};\n'
        declarations+=f'action candidate_{i}(){{m.image_word{i}={value};}}\ntable candidate_{i}_t{{actions={{candidate_{i};}}size=1;const default_action=candidate_{i}();}}\n'
        declarations+=f'action store_{i}(){{write_{i}.execute(m.image_slot);}}\ntable store_{i}_t{{actions={{store_{i};}}size=1;const default_action=store_{i}();}}\n'
    s=s.replace(' action deny()',declarations+' action deny()')
    stores='if(hdr.native.func==8w3){m.image_slot=1w0;}else{m.image_slot=1w1;}'
    stores+=''.join(f'candidate_{i}_t.apply();store_{i}_t.apply();' for i in range(14))
    s=s.replace('crc_render_t.apply();','crc_render_t.apply();'+stores)
    return s
if __name__=='__main__':Path(__file__).with_name('padding_cache_writer.p4').write_text(generate_writer())
