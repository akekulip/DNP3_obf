"""Independent fixed-block layout oracle; not a Tofino execution model."""
import struct

def crc(data):
    # Byte-independent polynomial long division against the wire's LSB order.
    value=0
    for byte in data:
        for bit in range(8):
            incoming=(byte>>bit)&1
            low=(value&1)^incoming
            value >>= 1
            if low: value ^= 0xa6bc
    return value ^ 0xffff

def block(data):
    return data+struct.pack('<H',crc(data))

def expand(frame,decoy):
    if len(frame)!=35: raise ValueError('fixed native frame is 35 bytes')
    header=bytearray(frame[:8]);header[2]=44
    first=frame[10:26]
    tail=frame[28:33]
    trailing=bytes.fromhex('0c01280100')+decoy.index.to_bytes(2,'little')+decoy.body
    return block(bytes(header))+block(first)+block(tail+trailing[:11])+block(trailing[11:])

def carve(frame):
    if len(frame) not in (49,57): raise ValueError('explicit profile required')
    return frame[:28],frame[28:]

MASK=0xffffffff

def offset(seq,base):
    v=(seq-base)&MASK
    return v if v<0x80000000 else v-0x100000000

def map_seq(seq,first,second=None):
    delta=20 if offset(seq,first)>=35 else 0
    if second is not None and offset(seq,second)>=35:delta=40
    return (seq+delta)&MASK

def inverse_delta(ack,first,second=None):
    o=offset(ack,first)
    # Hold the final native byte while any inserted tail remains outstanding.
    # This is the repaired software oracle; the inactive target prototype's
    # earlier native-end clamp is explicitly unsafe and remains unfitted.
    delta=max(0,min(20,o-34))
    if second is not None:
        o2=offset(ack,second)
        delta=max(delta,max(0,min(40,o2-34))) if o2>=55 else delta
    return delta

def map_ack_window(ack,win,first,second=None):
    left=inverse_delta(ack,first,second)
    right=inverse_delta((ack+win)&MASK,first,second)
    return (ack-left)&MASK,win+left-right

def tcp_subtract_residual(raw):
    """Arithmetic oracle for exclusive parser subtraction, not SDK execution.

    Fixed IHL=5 input uses extracted IPv4 total_len in the pseudo-header;
    it therefore subtracts twenty extra bytes from the valid TCP sum.
    """
    ip=raw[14:34]
    total=int.from_bytes(ip[2:4],'big')
    if ip[0]!=0x45 or ip[9]!=6 or len(raw)<14+total:
        raise ValueError('whole fixed IPv4/TCP packet required')
    data=ip[12:20]+bytes([0,ip[9]])+ip[2:4]+raw[34:14+total]
    if len(data)%2:data+=b'\0'
    value=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
    return (-value)%0xffff
