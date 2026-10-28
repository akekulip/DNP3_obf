"""Independent DNP3 stream framing helper for model output checks."""
import dnp3_std as std

def _split_frames(stream):
    out, p = [], 0
    while p < len(stream):
        n = std.frame_length(stream[p + 2] - 5)
        out.append(stream[p:p + n])
        p += n
    return out
