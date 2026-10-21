import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'source/full_read_01'))
import general_read_padding as gp
import pytest
s=gp.std

def frame(app,seq=63,chunk=249,request=False):
    parts=[app[i:i+chunk] for i in range(0,len(app),chunk)]
    h=bytes.fromhex('056400c401000a00') if not request else bytes.fromhex('056400c40a000100')
    out=[]
    for i,p in enumerate(parts):
        u=bytes([((seq+i)&63)|(s.FIR if i==0 else 0)|(s.FIN if i==len(parts)-1 else 0)])+p
        out.append(s.frame(h[:2]+bytes([5+len(u)])+h[3:],u))
    return b''.join(out)

def native(g,v,n):
    width=1 if n<=256 else 2
    obj=bytes([g,v,0 if width==1 else 1])+bytes(width)+(n-1).to_bytes(width,'little')
    size=gp.fullread.MEASUREMENT_SIZE[g,v]
    return bytes.fromhex('c3810000')+obj+b''.join(bytes([1])+bytes([(i*17)%256])*(size-1) for i in range(n))

Q=frame(bytes.fromhex('c3013c0106'),request=True)
@pytest.mark.parametrize('g,v,n,chunk',[(1,2,1,249),(1,2,256,249),(10,2,23,249),(30,1,21,249),(30,5,42,31),(20,1,60,249),(30,1,100,249),(1,2,16,5)])
@pytest.mark.parametrize('padding,wide',[(4,False),(17,False),(240,False),(300,True)])
def test_construction(g,v,n,chunk,padding,wide):
    app=native(g,v,n); raw=frame(app,chunk=chunk)
    start=1024 if wide or g==1 else 16
    width=1 if start+padding-1<256 else 2
    target=len(raw)+gp.prefix_size(3+2*width+padding)
    r=gp.pad_read(Q,raw,[target+1,target],pad_start=start,pad_stop=4095)
    assert r.status=='padded' and len(r.output)==target
    _,encoded=gp.one_fragment(r.output)
    assert encoded[:4]==app[:4] and encoded.endswith(app[4:])
    pts=s.check_read_response(s.fragment_user(encoded))[1]
    assert pts[r.padding_points:]==s.check_read_response(s.fragment_user(app))[1]
    assert all(g==1 and v==2 and b==b'\0' for g,v,i,b in pts[:r.padding_points])
    for f in gp.split_frames(r.output):assert len(f)<=292

@pytest.mark.parametrize('mutation',['truncated','header_crc','tail_crc','missing_last','seq','address','control','unknown','collision','app_fragment','bad_request'])
def test_refusal(mutation):
    raw=frame(native(30,1,60)); q=Q; kwargs=dict(pad_start=16,pad_stop=255)
    if mutation=='truncated':raw=raw[:-1]
    elif mutation=='header_crc':raw=raw[:8]+bytes([raw[8]^1])+raw[9:]
    elif mutation=='tail_crc':raw=raw[:-1]+bytes([raw[-1]^1])
    elif mutation=='missing_last':raw=gp.split_frames(raw)[0]
    elif mutation=='seq':q=frame(bytes.fromhex('c2013c0106'),request=True)
    elif mutation=='address':q=frame(bytes.fromhex('c3013c0106'),request=False)
    elif mutation=='control':q=frame(bytes.fromhex('c3033c0106'),request=True)
    elif mutation=='unknown':raw=frame(bytes.fromhex('c3810000630100000000'))
    elif mutation=='collision':raw=frame(native(1,2,23))
    elif mutation=='app_fragment':raw=frame(bytes.fromhex('43810000')+native(30,1,60)[4:])
    elif mutation=='bad_request':q=frame(bytes.fromhex('c3013c01'),request=True)
    with pytest.raises(ValueError):gp.pad_read(q,raw,[800],**kwargs)

def test_targets_and_capacity():
    raw=frame(native(10,2,23))
    r=gp.pad_read(Q,raw,[len(raw)-1,len(raw)+1],pad_start=16,pad_stop=255)
    assert r.status=='unreachable' and r.target is None and r.output==raw
    r=gp.pad_read(Q,raw,[len(raw)],pad_start=16,pad_stop=255)
    assert r.status=='already_at_target' and r.padding_points==0
    r=gp.pad_read(Q,raw,[800],pad_start=16,pad_stop=255,max_app_bytes=100)
    assert r.status=='unreachable'

@pytest.mark.parametrize('mode,native_size,target', [('range',49,73),('integrity',247,269)])
def test_existing_prefix_parity(mode,native_size,target):
    # Retained wire records are optional outside the development workspace;
    # fixtures below recreate the same shapes without embedding capture values.
    import prepend
    if mode=='range':app=native(10,2,23)
    else:
        app=bytes.fromhex('c3810000')+b''.join(native(g,v,n)[4:] for g,v,n in [(1,2,16),(30,1,21),(20,1,8),(10,2,23)])
    raw=frame(app)
    assert len(raw)==native_size
    r=gp.pad_read(Q,raw,[target],pad_start=16,pad_stop=255)
    assert r.output==prepend.prepend_padding(raw,target,16)[0]

@pytest.mark.parametrize('g,v,n',[(10,2,23),(30,1,21)])
def test_exact_269_target(g,v,n):
    raw=frame(native(g,v,n))
    r=gp.pad_read(Q,raw,[269],pad_start=16,pad_stop=255)
    assert r.status=='padded' and len(r.output)==269
