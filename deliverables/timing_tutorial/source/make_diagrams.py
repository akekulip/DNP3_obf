#!/usr/bin/env python3
"""make_diagrams.py — the 7 editable SVG diagrams for the timing tutorial (direcr2 §16).

Hand-built SVG via small helpers so the output stays human-editable (plain shapes + text, no
rasterization). Each diagram is grounded in dnp3_timing_normalizer.p4 and the lab topology.
Run: python3 make_diagrams.py [--out ../assets]
"""
import argparse
import os

FONT = "font-family='Helvetica,Arial,sans-serif'"
CSS = (
    "<style>"
    "text{fill:#111} .t{%s;font-size:13px} .h{%s;font-size:16px;font-weight:bold}"
    ".s{%s;font-size:11px;fill:#555} .box{fill:#f4f6f8;stroke:#345;stroke-width:1.5}"
    ".hi{fill:#e8f5e9;stroke:#2ca02c;stroke-width:1.5} .blk{fill:#fdecea;stroke:#d62728;stroke-width:1.5}"
    ".acc{fill:#e7effa;stroke:#1f77b4;stroke-width:1.5} .ln{stroke:#345;stroke-width:1.5;fill:none}"
    ".dsh{stroke:#888;stroke-width:1.2;stroke-dasharray:5 4;fill:none}"
    "@media(prefers-color-scheme:dark){text{fill:#e8e8e8}.s{fill:#aaa}"
    ".box{fill:#20272e;stroke:#7a9cc6}.hi{fill:#16321c;stroke:#4caf7d}.blk{fill:#3a1d1d;stroke:#e06666}"
    ".acc{fill:#1b2a3d;stroke:#6fa8dc}.ln{stroke:#9ab}.dsh{stroke:#999}}"
    "</style>" % (FONT, FONT, FONT)
)
DEFS = ("<defs><marker id='a' markerWidth='10' markerHeight='10' refX='8' refY='3' orient='auto'>"
        "<path d='M0,0 L9,3 L0,6 Z' fill='#345'/></marker>"
        "<marker id='ag' markerWidth='10' markerHeight='10' refX='8' refY='3' orient='auto'>"
        "<path d='M0,0 L9,3 L0,6 Z' fill='#2ca02c'/></marker></defs>")


def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def svg(w, h, body):
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 %d %d' width='%d' height='%d'>"
            % (w, h, w, h)) + CSS + DEFS + body + "</svg>"


def box(x, y, w, h, label, cls="box", sub=None, rx=6):
    s = "<rect x='%d' y='%d' width='%d' height='%d' rx='%d' class='%s'/>" % (x, y, w, h, rx, cls)
    lines = label.split("\n")
    n = len(lines) + (1 if sub else 0)
    y0 = y + h / 2 - (n - 1) * 8 + 5
    for i, ln in enumerate(lines):
        s += "<text x='%d' y='%.0f' text-anchor='middle' class='t'>%s</text>" % (x + w / 2, y0 + i * 16, esc(ln))
    if sub:
        s += "<text x='%d' y='%.0f' text-anchor='middle' class='s'>%s</text>" % (
            x + w / 2, y0 + len(lines) * 16, esc(sub))
    return s


def arrow(x1, y1, x2, y2, cls="ln", label=None, green=False):
    m = "url(#ag)" if green else "url(#a)"
    s = "<path d='M%d,%d L%d,%d' class='%s' marker-end='%s'/>" % (x1, y1, x2, y2, cls, m)
    if label:
        s += "<text x='%d' y='%d' text-anchor='middle' class='s'>%s</text>" % (
            (x1 + x2) / 2, (y1 + y2) / 2 - 4, esc(label))
    return s


def title(x, y, txt):
    return "<text x='%d' y='%d' class='h'>%s</text>" % (x, y, esc(txt))


# ---------- Diagram 1: lab topology ----------
def d_topology():
    b = title(20, 30, "Diagram 1 — Laboratory topology")
    b += box(60, 60, 200, 70, "Vision / master", sub="10.10.54.19 mgmt · 192.168.10.1 relay-net")
    b += box(340, 60, 200, 70, "Tofino-1 switch", cls="acc", sub="10.10.54.81")
    b += box(620, 60, 200, 70, "Hulk / outstation-side", sub="10.10.54.158")
    b += box(340, 210, 200, 56, "dp8 internal\nMAC-near loopback", cls="hi")
    # ports (below the horizontal arrows so they don't collide with the READ/ACK labels)
    b += "<text x='299' y='132' text-anchor='middle' class='s'>dp9</text>"
    b += "<text x='579' y='132' text-anchor='middle' class='s'>dp11</text>"
    b += arrow(260, 85, 338, 85, label="READ →")
    b += arrow(338, 110, 260, 110, label="← ACK, RESPONSE")
    b += arrow(540, 85, 618, 85)
    b += arrow(618, 110, 540, 110)
    b += arrow(440, 130, 440, 208, cls="dsh", green=True, label="blocker-token loop")
    b += arrow(415, 208, 415, 132, cls="dsh", green=True)
    b += box(590, 210, 230, 56, "SEL-751 relay", sub="192.168.10.7:20000 (READ-only)")
    b += arrow(700, 130, 700, 208, cls="dsh")
    b += "<text x='60' y='300' class='s'>Blocker tokens (EtherType 0x88c1) recirculate on dp8 only — they never egress to a host.</text>"
    return svg(860, 320, b)


# ---------- Diagram 2: packet path ----------
def d_packet_path():
    steps = ["READ arrives", "transaction state armed", "pure ACK arrives", "t_ack recorded",
             "deadline = t_ack + G", "RESPONSE arrives", "RESPONSE enters Q_RESP",
             "blocker reservoir keeps Q_RESP from draining", "deadline expires",
             "blockers terminate", "RESPONSE exits unchanged"]
    b = title(20, 30, "Diagram 2 — Packet path")
    y = 55
    for i, s in enumerate(steps):
        cls = "hi" if i == len(steps) - 1 else ("blk" if "blocker" in s.lower() else "box")
        b += box(230, y, 400, 34, s, cls=cls)
        if i < len(steps) - 1:
            b += arrow(430, y + 34, 430, y + 46)
        y += 46
    return svg(860, y + 10, b)


# ---------- Diagram 3: TM queues ----------
def d_queues():
    b = title(20, 30, "Diagram 3 — Traffic Manager queues (strict priority)")
    b += box(80, 70, 300, 60, "Q_BLOCK  (qid 7)  — HIGH priority", cls="blk",
             sub="holds recirculating blocker tokens")
    b += box(80, 170, 300, 60, "Q_RESP  (qid 1)  — LOW priority", cls="hi",
             sub="holds the ONE original response, unmodified")
    b += box(470, 110, 260, 70, "TM scheduler", cls="acc",
             sub="serves highest-priority non-empty queue")
    b += arrow(380, 100, 468, 125, label="served first (while non-empty)")
    b += arrow(380, 200, 468, 165, label="starved while Q_BLOCK non-empty")
    b += "<text x='80' y='280' class='s'>While ANY blocker token is eligible in Q_BLOCK, strict priority serves it first and Q_RESP is</text>"
    b += "<text x='80' y='298' class='s'>starved — so the response is held. The response is enqueued ONCE; it does not recirculate.</text>"
    return svg(780, 320, b)


# ---------- Diagram 4: transaction timeline ----------
def d_timeline():
    b = title(20, 30, "Diagram 4 — Transaction timeline")
    # Case A
    b += "<text x='20' y='70' class='t'>A. native RESPONSE before deadline — protection applied</text>"
    ax, ay, aw = 60, 90, 720
    b += "<line x1='%d' y1='%d' x2='%d' y2='%d' class='ln'/>" % (ax, ay + 30, ax + aw, ay + 30)
    for frac, lab, c in [(0.02, "READ", "#345"), (0.14, "ACK\n(t_ack)", "#345"),
                         (0.20, "native RESP\narrives", "#345"), (0.80, "deadline\nt_ack+G", "#2ca02c"),
                         (0.83, "release\n(+~1.7µs tail)", "#2ca02c")]:
        x = ax + aw * frac
        b += "<line x1='%.0f' y1='%d' x2='%.0f' y2='%d' class='ln'/>" % (x, ay + 22, x, ay + 38)
        for j, t in enumerate(lab.split("\n")):
            b += "<text x='%.0f' y='%d' text-anchor='middle' class='s' fill='%s'>%s</text>" % (
                x, ay + (10 - j * 12 if frac < 0.5 else 55 + j * 12), c, t)
    b += "<rect x='%.0f' y='%d' width='%.0f' height='10' class='hi'/>" % (
        ax + aw * 0.20, ay + 25, aw * 0.60, )
    b += "<text x='%.0f' y='%d' text-anchor='middle' class='s'>effective hold</text>" % (ax + aw * 0.5, ay + 33)
    # Case B
    b += "<text x='20' y='210' class='t'>B. native RESPONSE after deadline — zero hold, low-G warning</text>"
    by = 230
    b += "<line x1='%d' y1='%d' x2='%d' y2='%d' class='ln'/>" % (ax, by + 30, ax + aw, by + 30)
    for frac, lab, c in [(0.02, "READ", "#345"), (0.10, "ACK", "#345"),
                         (0.30, "deadline\nt_ack+G (small)", "#d62728"),
                         (0.55, "native RESP\narrives late", "#d62728")]:
        x = ax + aw * frac
        b += "<line x1='%.0f' y1='%d' x2='%.0f' y2='%d' class='ln'/>" % (x, by + 22, x, by + 38)
        for j, t in enumerate(lab.split("\n")):
            b += "<text x='%.0f' y='%d' text-anchor='middle' class='s' fill='%s'>%s</text>" % (
                x, by + (10 - j * 12 if frac < 0.4 else 55 + j * 12), c, t)
    b += "<text x='%.0f' y='%d' text-anchor='middle' class='s' fill='#d62728'>G below native CLRT ⇒ nothing to hold</text>" % (ax + aw * 0.5, by + 33)
    return svg(820, 320, b)


# ---------- Diagram 5: state machine ----------
def d_state():
    b = title(20, 30, "Diagram 5 — Transaction state machine")
    nodes = [("IDLE", 60, 70, "box"), ("ARMED", 250, 70, "box"), ("ACK_QUALIFIED", 450, 70, "acc"),
             ("RESPONSE_HELD", 450, 180, "hi"), ("DEADLINE_RELEASE", 250, 180, "hi"),
             ("FAIL_OPEN", 60, 180, "blk"), ("CLEANUP", 60, 290, "box")]
    pos = {}
    for name, x, y, c in nodes:
        b += box(x, y, 150, 46, name, cls=c)
        pos[name] = (x, y)
    def edge(a, bn, lab):
        (x1, y1), (x2, y2) = pos[a], pos[bn]
        return arrow(x1 + 75, y1 + 46, x2 + 75, y2, label=lab) if y2 > y1 + 46 else (
            arrow(x1 + 150, y1 + 23, x2, y2 + 23, label=lab) if x2 > x1 else
            arrow(x1, y1 + 23, x2 + 150, y2 + 23, label=lab))
    b += edge("IDLE", "ARMED", "READ")
    b += edge("ARMED", "ACK_QUALIFIED", "pure ACK")
    b += arrow(525, 116, 525, 178, label="RESPONSE")
    b += arrow(450, 203, 400, 203, label="deadline expires")
    b += arrow(250, 203, 210, 203, label="budget=0")
    b += arrow(135, 226, 135, 288, label="drop tokens")
    # CLEANUP -> IDLE return, routed down the left margin so it clears the FAIL_OPEN box
    b += "<path d='M60,313 L28,313 L28,93 L58,93' class='dsh' fill='none' marker-end='url(#a)'/>"
    b += "<text x='34' y='205' class='s'>→ IDLE</text>"
    b += "<text x='560' y='300' class='s'>Stale / unrelated / retransmitted packets take bypass paths</text>"
    b += "<text x='560' y='316' class='s'>(to_fwd) and do NOT change transaction state.</text>"
    return svg(820, 340, b)


# ---------- Diagram 6: deadline release (evidence chain) ----------
def d_evidence():
    b = title(20, 30, "Diagram 6 — Evidence chain (every number is traceable)")
    steps = ["raw PCAP", "transaction extraction (analyze_clrt.py)", "CLRT CSV / summary.json",
             "statistical analysis (fingerprint_eval.py, Miller-Madow + bootstrap)",
             "figures (make_pub_figures.py)", "reported claim"]
    x = 60
    y = 70
    for i, s in enumerate(steps):
        w = 340
        b += box(x, y, w, 40, s, cls=("hi" if i == len(steps) - 1 else "box"))
        if i < len(steps) - 1:
            b += arrow(x + w / 2, y + 40, x + w / 2, y + 54)
        y += 54
    b += "<text x='430' y='120' class='s'>Each stage names the script that produced it;</text>"
    b += "<text x='430' y='138' class='s'>re-running the script reproduces the next stage.</text>"
    return svg(820, y + 10, b)


# ---------- Diagram 7: G-selection guard ----------
def d_guard():
    b = title(20, 30, "Diagram 7 — G-selection guard")
    b += box(60, 70, 300, 50, "measure native_clrt = t_resp − t_ack", cls="acc")
    b += box(60, 160, 300, 50, "compare native_clrt vs policy G", cls="box")
    b += arrow(210, 120, 210, 158)
    b += box(430, 130, 200, 46, "native_clrt < G", cls="hi", sub="protection applied (held)")
    b += box(430, 220, 200, 46, "native_clrt ≥ G", cls="blk", sub="zero-hold — LOW-G WARNING")
    b += arrow(360, 175, 428, 153, green=True, label="sign bit set")
    b += arrow(360, 195, 428, 240, label="sign bit clear")
    b += "<text x='60' y='300' class='s'>Set G above the p99 native CLRT of the slowest device in the anonymity set.</text>"
    b += "<text x='60' y='318' class='s'>On the SEL-751 (native p99 ≈ 11.4 ms) we used G = 25 ms; G = 1 ms flags every txn zero-hold.</text>"
    return svg(680, 340, b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    diagrams = {
        "lab_topology.svg": d_topology(), "packet_path.svg": d_packet_path(),
        "queue_architecture.svg": d_queues(), "transaction_timeline.svg": d_timeline(),
        "state_machine.svg": d_state(), "deadline_release.svg": d_evidence(),
        "g_selection_guard.svg": d_guard(),
    }
    for name, s in diagrams.items():
        with open(os.path.join(a.out, name), "w") as f:
            f.write(s)
    print("wrote %d SVG diagrams to %s" % (len(diagrams), a.out))
    for n in diagrams:
        print("  ", n)


if __name__ == "__main__":
    main()
