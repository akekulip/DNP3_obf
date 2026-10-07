"""Alternative atomic generation-tagged words; not a replacement for work pinning."""
from pathlib import Path
from generate_cache_writer import generate_writer

def generate():
    s=generate_writer().replace('NO protected publication/lifecycle','NO connection/work-slot publication/lifecycle')
    s=s.replace('struct meta_t{','struct cache_word_t{bit<32> generation;bit<32> data;}\nstruct meta_t{bit<32> work_generation;'+''.join(f'bit<32> status{i};' for i in range(14)))
    s=s.replace('bit<32> off){m.enabled','bit<32> off,bit<32> work_generation){m.work_generation=work_generation;m.enabled')
    s=s.replace('state start{pkt.extract(ig);','state start{pkt.extract(ig);m.work_generation=32w0;')
    for i in range(14):
        old=f'Register<bit<32>,bit<1>>(2,0) image_{i};\nRegisterAction<bit<32>,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout bit<32> v,out bit<32> rv){{v=m.image_word{i};rv=v;}}}};'
        new=f'''Register<cache_word_t,bit<1>>(2,{{32w0,32w0}}) image_{i};
RegisterAction<cache_word_t,bit<1>,bit<32>>(image_{i}) write_{i}={{void apply(inout cache_word_t v,out bit<32> rv){{
 if(v.generation<m.work_generation){{v.generation=m.work_generation;v.data=m.image_word{i};rv=v.generation;}}
 else {{if(v.data!=m.image_word{i}){{rv=32w0;}}else{{rv=v.generation;}}}}
}}}};'''
        if old not in s:raise ValueError('writer source schema changed')
        s=s.replace(old,new).replace(f'action store_{i}(){{write_{i}.execute(m.image_slot);}}',f'action store_{i}(){{m.status{i}=write_{i}.execute(m.image_slot);}}')
    checks=''.join(f'action check_{i}(){{m.status{i}=m.status{i}-m.work_generation;}}table check_{i}_t{{actions={{check_{i};}}size=1;const default_action=check_{i}();}}\n' for i in range(14))
    s=s.replace(' action deny()',checks+' action deny()')
    key=''.join(f'm.status{i}:exact;' for i in range(14))
    rows=','.join('32w0' for _ in range(14))
    gate=f'table cache_results{{key={{{key}}}actions={{deny;NoAction;}}size=1;const default_action=deny();const entries={{({rows}):NoAction();}}}}\n'
    s=s.replace(' action deny(){md.drop_ctl=3w1;}',' action deny(){md.drop_ctl=3w1;}\n'+gate)
    s=s.replace('store_13_t.apply();','store_13_t.apply();'+''.join(f'check_{i}_t.apply();' for i in range(14))+'cache_results.apply();')
    # Globally monotone generation reserves zero and must not wrap or reset.
    s=s.replace('if(m.enabled==1w1&&m.profile==1w1){','if(m.enabled==1w1&&m.profile==1w1&&m.work_generation!=32w0){')
    return s
if __name__=='__main__':Path(__file__).with_name('tagged_cache_writer.p4').write_text(generate())
