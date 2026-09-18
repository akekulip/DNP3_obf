"""The adversary icon, as a draw.io custom stencil.

Neither draw.io's shape libraries nor the skill's catalog has an attacker icon; the closest is
a person at a desk, which reads as an ordinary user. This is a hooded figure with the face in
shadow, the usual shorthand for an adversary, encoded the way draw.io encodes an embedded
stencil: encodeURIComponent, raw deflate, base64, referenced as shape=stencil(...).
"""
import base64, zlib
from urllib.parse import quote

SHAPE = """<shape name="adversary" h="25" w="22" aspect="fixed" strokewidth="inherit">
<connections/><foreground>
<path><move x="0" y="24.5"/>
<curve x1="0" y1="17.6" x2="4.1" y2="15.6" x3="7.1" y3="15"/>
<curve x1="5.6" y1="13.5" x2="4.6" y2="11.5" x3="4.6" y3="8.9"/>
<curve x1="4.6" y1="3.9" x2="7.6" y2="0.8" x3="11" y3="0.8"/>
<curve x1="14.4" y1="0.8" x2="17.4" y2="3.9" x3="17.4" y3="8.9"/>
<curve x1="17.4" y1="11.5" x2="16.4" y2="13.5" x3="14.9" y3="15"/>
<curve x1="17.9" y1="15.6" x2="22" y2="17.6" x3="22" y3="24.5"/>
<close/></path><fill/>
<fillcolor color="#FFFFFF"/><ellipse x="7.6" y="5.2" w="6.8" h="8.4"/><fill/>
<fillcolor color="#1F2A36"/><rect x="7.2" y="8.0" w="7.6" h="2.1"/><fill/>
</foreground></shape>"""

def stencil_style(fill):
    packed = zlib.compressobj(9, zlib.DEFLATED, -15).copy()
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = c.compress(quote(SHAPE, safe="-_.!~*'()").encode()) + c.flush()
    return (f"shape=stencil({base64.b64encode(data).decode()});"
            f"html=1;fillColor={fill};strokeColor=none;pointerEvents=1;")

if __name__ == "__main__":
    print(stencil_style("#D55E00")[:90] + " ...")
