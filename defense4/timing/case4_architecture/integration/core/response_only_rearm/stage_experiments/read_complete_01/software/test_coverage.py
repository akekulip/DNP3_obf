"""Coverage of the declared <=377 encoded-byte, single-app-fragment profile."""
import sys,pathlib
sys.path.insert(0,str(pathlib.Path(__file__).parent/'source/full_read_01'))
import general_read_padding as gp
s=gp.std

def encode(app,chunks=None,seq=63,request=False):
    h=bytes.fromhex('056400c40a000100' if request else '056400c401000a00')
    if chunks is None:chunks=[len(app)] if len(app)<=249 else [len(app)//2,len(app)-len(app)//2]
    out=[];pos=0
    for i,n in enumerate(chunks):
        u=bytes([((seq+i)&63)|(s.FIR if i==0 else 0)|(s.FIN if i==len(chunks)-1 else 0)])+app[pos:pos+n];pos+=n
        out.append(s.frame(h[:2]+bytes([5+len(u)])+h[3:],u))
    assert pos==len(app)
    return b''.join(out)

Q=encode(bytes.fromhex('c3013c0106'),request=True)
def app_of_length(length):
    if length==4:return bytes.fromhex('c3810000')
    w=1 if length<=265 else 2;n=length-7-2*w
    return bytes.fromhex('c3810000')+bytes([10,2,0 if w==1 else 1])+bytes(w)+(n-1).to_bytes(w,'little')+bytes((i%2)*128+1 for i in range(n))

def test_all_application_lengths():
    for length in [4]+list(range(10,316)):
        app=app_of_length(length);raw=encode(app)
        assert len(app)==length and len(raw)<=377
        r=gp.pad_read(Q,raw,[163,269,399],pad_start=1024,pad_stop=4095)
        assert r.status in ('padded','already_at_target'),(length,len(raw),r)
        assert len(r.output) in (163,269,399)
        _,decoded=gp.one_fragment(r.output)
        assert decoded[:4]==app[:4] and decoded.endswith(app[4:])
        original=s.check_read_response(s.fragment_user(app))[1]
        points=s.check_read_response(s.fragment_user(decoded))[1]
        assert points[r.padding_points:]==original

def test_all_first_cut_positions():
    # Every two-frame cut of one 300-app-byte valid response, including a
    # cut inside the application header and transport sequence wraparound.
    app=app_of_length(300)
    for cut in range(1,250):
        remaining=300-cut;chunks=[cut]
        while remaining: n=min(remaining,249);chunks.append(n);remaining-=n
        raw=encode(app,chunks)
        if len(raw)>377:continue
        r=gp.pad_read(Q,raw,[163,269,399],pad_start=1024,pad_stop=4095)
        assert r.status=='padded' and len(r.output)==399
        assert gp.one_fragment(r.output)[1].endswith(app[4:])

def test_previously_unreachable_gap():
    # 308 app bytes -> 370 encoded bytes; 29-byte prefix addition is impossible
    # for the old encoder. Full serialization provides an exact 399-byte output.
    app=app_of_length(308);raw=encode(app)
    assert len(raw)==370
    r=gp.pad_read(Q,raw,[163,269,399],pad_start=1024,pad_stop=4095)
    assert r.status=='padded' and r.construction=='resegment' and len(r.output)==399
