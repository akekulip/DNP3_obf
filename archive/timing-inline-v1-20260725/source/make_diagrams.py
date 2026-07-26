#!/usr/bin/env python3
"""make_diagrams.py: editable SVG schematics for the inline-live report.

Plain shapes and text (no rasterisation) so the diagrams stay hand-editable and print sharply.
Each is grounded in dnp3_timing_normalizer_inline.p4 and the measured lab topology.

Run:  python3 make_diagrams.py --out ../assets
"""
import argparse
import os

F = "font-family='Helvetica,Arial,sans-serif'"
CSS = ("<style>"
       "text{fill:#14202c}"
       ".t{%s;font-size:13px} .h{%s;font-size:15px;font-weight:bold}"
       ".s{%s;font-size:11px;fill:#5a6b7a} .m{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}"
       ".box{fill:#f2f5f9;stroke:#2f4a63;stroke-width:1.5}"
       ".sw{fill:#e7effa;stroke:#1e5f9e;stroke-width:2}"
       ".hold{fill:#fdf1e0;stroke:#b87514;stroke-width:1.6}"
       ".norm{fill:#e6f4f1;stroke:#1f7a6b;stroke-width:1.6}"
       ".bad{fill:#fbeaee;stroke:#a8324a;stroke-width:1.6}"
       ".ln{stroke:#2f4a63;stroke-width:1.6;fill:none}"
       ".dsh{stroke:#8496a6;stroke-width:1.2;stroke-dasharray:5 4;fill:none}"
       "@media(prefers-color-scheme:dark){text{fill:#e4eaf1}.s{fill:#8b9aaa}"
       ".box{fill:#1b232c;stroke:#7fa3c4}.sw{fill:#16283a;stroke:#5aa6e8}"
       ".hold{fill:#33260f;stroke:#e0a448}.norm{fill:#12302b;stroke:#4fbfa9}"
       ".bad{fill:#331a20;stroke:#e0697f}.ln{stroke:#9ab}.dsh{stroke:#7c8a99}}"
       "</style>" % (F, F, F))
DEFS = ("<defs><marker id='a' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>"
        "<path d='M0,0 L9,3 L0,6 Z' fill='#2f4a63'/></marker>"
        "<marker id='ah' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>"
        "<path d='M0,0 L9,3 L0,6 Z' fill='#b87514'/></marker></defs>")


def svg(w, h, body):
    """No intrinsic width/height, only a viewBox, so the diagram scales to whatever
    container it lands in. That keeps the text legible in the single-column PDF, where
    the print stylesheet removes the on-screen max-width."""
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 %d %d' "
            "preserveAspectRatio='xMidYMid meet'>%s%s%s</svg>" % (w, h, CSS, DEFS, body))


def box(x, y, w, h, cls="box", r=4):
    return "<rect x='%d' y='%d' width='%d' height='%d' rx='%d' class='%s'/>" % (x, y, w, h, r, cls)


def txt(x, y, s, cls="t", anchor="middle"):
    return "<text x='%d' y='%d' class='%s' text-anchor='%s'>%s</text>" % (x, y, cls, anchor, s)


def arrow(x1, y1, x2, y2, cls="ln", marker="a"):
    return "<path d='M%d,%d L%d,%d' class='%s' marker-end='url(#%s)'/>" % (x1, y1, x2, y2, cls, marker)


# ---------------------------------------------------------------- 1. topology
def topology():
    b = []
    b.append(txt(430, 24, "Inline bump-in-the-wire: every DNP3 packet transits the ASIC", "h"))
    b.append(box(20, 60, 150, 76, "box"))
    b.append(txt(95, 86, "MASTER (Vision)", "t")); b.append(txt(95, 104, "192.168.10.1", "m"))
    b.append(txt(95, 122, "enp59s0f0np0", "s"))

    b.append(box(250, 48, 260, 130, "sw"))
    b.append(txt(380, 72, "TOFINO-1", "h"))
    b.append(txt(380, 90, "dnp3_timing_normalizer_inline", "m"))
    b.append(box(268, 104, 106, 58, "hold"))
    b.append(txt(321, 124, "dp8 loopback", "s")); b.append(txt(321, 140, "Q_BLOCK  pri 7", "m"))
    b.append(txt(321, 156, "Q_RESP   pri 0", "m"))
    b.append(txt(452, 124, "dp9", "m")); b.append(txt(452, 140, "dev_port", "s"))
    b.append(txt(452, 156, "64", "m"))

    b.append(box(586, 60, 118, 76, "box"))
    b.append(txt(645, 86, "unmanaged", "t")); b.append(txt(645, 104, "switch", "t"))
    b.append(txt(645, 122, "p1 + p25 only", "s"))

    b.append(box(776, 60, 134, 76, "box"))
    b.append(txt(843, 86, "SEL-751", "t")); b.append(txt(843, 104, "192.168.10.7", "m"))
    b.append(txt(843, 122, "100M RJ45", "s"))

    b.append(arrow(170, 98, 248, 98)); b.append(txt(209, 90, "25G", "s"))
    b.append(arrow(510, 98, 584, 98)); b.append(txt(547, 90, "1G SFP", "s"))
    b.append(arrow(704, 98, 774, 98)); b.append(txt(739, 90, "100M", "s"))

    b.append(txt(430, 206, "The relay has exactly ONE route to the master. Proof: with dev_port 64 "
                           "disabled, ping is 0/3 (100% loss).", "s"))
    return svg(930, 224, "".join(b))


# ---------------------------------------------------------------- 2. sequence
def sequence():
    b = []
    b.append(txt(470, 22, "One transaction: native (left) versus protected (right)", "h"))
    for ox, title in ((30, "NATIVE: nothing holds the response"),
                      (500, "PROTECTED: response parked until t_ack + G")):
        b.append(txt(ox + 200, 46, title, "t"))
        for lx, lab in ((ox + 30, "master"), (ox + 200, "TOFINO"), (ox + 370, "relay")):
            b.append(txt(lx, 66, lab, "s"))
            b.append("<path d='M%d,74 L%d,300' class='dsh'/>" % (lx, lx))
        M, T, R = ox + 30, ox + 200, ox + 370
        b.append(arrow(M, 96, R - 4, 96)); b.append(txt(ox + 200, 90, "Class-0 READ", "s"))
        b.append(arrow(R, 130, M + 4, 130)); b.append(txt(ox + 200, 124, "pure TCP ACK", "s"))
        b.append("<circle cx='%d' cy='130' r='4' class='norm'/>" % T)
        if ox == 30:
            b.append(arrow(R, 172, M + 4, 172))
            b.append(txt(ox + 200, 166, "DNP3 response", "s"))
            b.append("<path d='M%d,130 L%d,172' class='ln'/>" % (M - 14, M - 14))
            b.append(txt(ox + 30, 200, "CLRT = 1-37 ms", "m", "middle"))
            b.append(txt(ox + 30, 218, "(device-specific)", "s"))
        else:
            b.append(arrow(R, 160, T + 6, 160)); b.append(txt(ox + 285, 154, "response", "s"))
            b.append(box(T - 62, 172, 124, 40, "hold"))
            b.append(txt(T, 188, "HELD on Q_RESP", "s")); b.append(txt(T, 204, "blockers starve it", "s"))
            b.append(arrow(T - 4, 246, M + 4, 246, "ln", "ah"))
            b.append(txt(ox + 118, 240, "released", "s"))
            b.append("<path d='M%d,130 L%d,246' class='ln'/>" % (M - 14, M - 14))
            b.append(txt(ox + 30, 274, "CLRT = G exactly", "m", "middle"))
            b.append(txt(ox + 30, 292, "sd 0.029 ms", "s"))
            b.append(txt(T, 230, "deadline t_ack + G", "s"))
    return svg(940, 314, "".join(b))


# ---------------------------------------------------------------- 3. queues
def queues():
    b = []
    b.append(txt(430, 24, "Why the response cannot leave: strict priority on the dp8 loopback", "h"))
    b.append(box(40, 52, 340, 150, "box"))
    b.append(txt(210, 74, "dp8: internal MAC-near loopback", "t"))
    b.append(box(60, 90, 300, 44, "hold"))
    b.append(txt(210, 108, "Q_BLOCK   qid 7   max_priority = 7", "m"))
    for i in range(9):
        b.append("<circle cx='%d' cy='124' r='4' class='hold'/>" % (78 + i * 33))
    b.append(txt(210, 150, "64 blocker tokens, circulating", "s"))
    b.append(box(60, 156, 300, 34, "norm"))
    b.append(txt(210, 177, "Q_RESP   qid 1   max_priority = 0", "m"))

    b.append(box(430, 52, 220, 150, "box"))
    b.append(txt(540, 74, "traffic manager", "t"))
    b.append(txt(540, 100, "serve highest non-empty", "s"))
    b.append(txt(540, 122, "Q_BLOCK occupied", "m"))
    b.append(txt(540, 142, "&#8595;", "t"))
    b.append(txt(540, 162, "Q_RESP never selected", "m"))
    b.append(txt(540, 186, "the response waits", "s"))

    b.append(box(700, 52, 200, 150, "bad"))
    b.append(txt(800, 74, "two ways to get it wrong", "t"))
    b.append(txt(800, 100, "min_priority only", "m"))
    b.append(txt(800, 118, "&#8594; fair share, leaks", "s"))
    b.append(txt(800, 146, "K &lt; 64 tokens", "m"))
    b.append(txt(800, 164, "&#8594; queue empties in", "s"))
    b.append(txt(800, 180, "flight, escapes ~540 ns", "s"))

    b.append(arrow(380, 127, 428, 127)); b.append(arrow(650, 127, 698, 127))
    b.append(txt(430, 226, "The gate is absolute only when max_priority is set AND enough tokens "
                           "are in flight to cover a full pipeline+loopback traversal.", "s"))
    return svg(930, 244, "".join(b))


# ---------------------------------------------------------------- 4. ingress flow
def stages():
    b = []
    b.append(txt(470, 24, "Ingress pipeline: role decides fate", "h"))
    b.append(box(20, 52, 128, 56, "box"))
    b.append(txt(84, 74, "parser", "t")); b.append(txt(84, 94, "ingress_port", "m"))
    b.append(arrow(148, 80, 194, 80))
    b.append(box(196, 52, 150, 56, "box"))
    b.append(txt(271, 74, "classify role", "t")); b.append(txt(271, 94, "0x88C1 &#8594; BLOCK", "m"))
    rows = [
        (140, "READ (master &#8594; relay)", "forward now; reg_gen := app-control byte", "norm"),
        (196, "ACK  (relay &#8594; master)", "forward now; reg_t_ack, reg_deadline := t_ack+G", "norm"),
        (252, "RESPONSE (relay)", "egress = dp8, qid = Q_RESP  &#8594;  HELD", "hold"),
        (308, "BLOCKER token", "early: requeue Q_BLOCK   late: drop &#8594; release", "hold"),
        (364, "anything else", "ROLE_BYPASS: forwarded untouched (ARP, ICMP)", "box"),
    ]
    for y, k, v, cls in rows:
        b.append(box(196, y, 150, 42, cls))
        b.append(txt(271, y + 26, k, "m"))
        b.append(arrow(346, y + 21, 392, y + 21))
        b.append(box(394, y, 520, 42, cls))
        b.append(txt(654, y + 26, v, "m"))
    b.append("<path d='M271,108 L271,140' class='ln' marker-end='url(#a)'/>")
    b.append(txt(470, 424, "10 of 12 ingress stages, 0 egress. The response is queued and later "
                           "dequeued, never rewritten.", "s"))
    return svg(930, 442, "".join(b))


DIAGRAMS = {"topology": topology, "sequence": sequence, "queues": queues, "stages": stages}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../assets")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for name, fn in DIAGRAMS.items():
        p = os.path.join(a.out, name + ".svg")
        with open(p, "w") as f:
            f.write(fn())
        print("wrote %s" % p)


if __name__ == "__main__":
    main()
