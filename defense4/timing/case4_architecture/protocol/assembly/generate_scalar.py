"""Two-input scalar CAS requires actual protected whole-work no-reuse authority."""
from pathlib import Path
from generate_buckets import generate as buckets
from generate_merge import generate as merge

def scalar(s):
    s=s.replace('// Internal executable bank primitive, not raw network admission or protected publication.','// Scalar CAS backend: caller must pin old work through all genuine terminal credits. Not a complete producer.')
    for i in range(12):
        start=s.index(f'Register<bucket_t,bit<1>>(1,');end=s.index(f'action read_{i}()',start)
        replacement=f'''Register<bit<32>,bit<1>>(1,32w0) bucket_{i};
RegisterAction<bit<32>,bit<1>,bit<32>>(bucket_{i}) snapshot_{i}={{void apply(inout bit<32> v,out bit<32> rv){{rv=v;}}}};
RegisterAction<bit<32>,bit<1>,bit<32>>(bucket_{i}) cas_{i}={{void apply(inout bit<32> v,out bit<32> rv){{
 if(v==hdr.expected.w{i}){{v=hdr.candidate.w{i};rv=32w0;}}else{{rv=32w1;}}
}}}};
'''
        s=s[:start]+replacement+s[end:]
    return s
if __name__=='__main__':
    for name,source in (('scalar_buckets.p4',buckets()),('merge_scalar.p4',merge())):Path(__file__).with_name(name).write_text(scalar(source))
