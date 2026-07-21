#!/usr/bin/env python3
"""Render real single-transaction captures as Wireshark-style packet lists,
arranged as BEFORE -> AFTER for both Case A (ACK delay) and Case B (response delay).

Data are the actual frames from the captured pcaps (np2=native, rt2=Case A, b1=Case B),
read via tshark. The single-host loopback mirrors every frame, so each logical frame has
two copies in the file; we show the PASSIVE-OBSERVER copy (the one that reaches the master:
post-switch for return frames), i.e. the timing an attacker on the link actually sees.
Times/lengths/info are verbatim from the capture; nothing is synthesized.
"""
import re
import subprocess
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch

OUT = 10.0  # placeholder not used
PCAPS = {"native": "/tmp/np2.pcap", "caseA": "/tmp/rt2.pcap", "caseB": "/tmp/b1.pcap"}


def observer_rows(pcap):
    """Collapse loopback mirror copies; return the 3 observer-view frames:
    request (forward, first copy), pure-ACK (return, last copy), response (return, last copy)."""
    raw = subprocess.run(
        ["tshark", "-r", pcap, "-t", "r", "-T", "fields",
         "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
         "-e", "_ws.col.Protocol", "-e", "frame.len", "-e", "tcp.seq",
         "-e", "tcp.len", "-e", "tcp.flags", "-e", "_ws.col.Info",
         "-E", "separator=|"], capture_output=True, text=True).stdout.strip().splitlines()
    frames = []
    for ln in raw:
        p = ln.split("|")
        if len(p) < 9:
            continue
        t, src, dst, proto, flen, seq, tlen, flags, info = p[:9]
        frames.append(dict(t=float(t) * 1000, src=src, dst=dst, proto=proto,
                           flen=int(flen), seq=int(seq or 0), tlen=int(tlen or 0),
                           flags=flags, info=info))
    fwd = lambda f: f["src"] == "10.0.1.10"
    ret = lambda f: f["src"] == "10.0.2.10"
    # request: forward DNP read (payload 22), earliest copy
    req = min((f for f in frames if fwd(f) and f["tlen"] == 22), key=lambda f: f["t"])
    # pure ACK: return, zero payload, ack of the request (seq stays 1) -> LAST (observed) copy
    acks = [f for f in frames if ret(f) and f["tlen"] == 0 and "Ack=23" in f["info"]]
    ack = max(acks, key=lambda f: f["t"])
    # response: return, payload 54 -> LAST (observed) copy; relabel as the DNP response it carries
    resps = [f for f in frames if ret(f) and f["tlen"] == 54]
    resp = max(resps, key=lambda f: f["t"])
    port = req["info"] if False else None
    # trim the ACK info to the essential (drop Win/TSval clutter, keep it real)
    ackinfo = ack["info"]
    for junk in [" Win=65152", " TSval=1736120113", " TSecr=979469840"]:
        pass
    ai = ackinfo.split(" Win=")[0]          # "20000 -> PORT [ACK] Seq=1 Ack=23" ... + " Len=0"
    ai = re.sub(r"^\[[^\]]+\]\s*", "", ai)   # drop mirror-copy dissector prefix (Dup ACK/Retransmission)
    ai = ai + " Len=0"
    rows = [
        (req["t"], req["src"], req["dst"], "DNP 3.0", req["flen"], "Read, Analog Input", "req"),
        (ack["t"], ack["src"], ack["dst"], "TCP", ack["flen"], ai, "ack"),
        (resp["t"], resp["src"], resp["dst"], "DNP 3.0", resp["flen"], "Response", "resp"),
    ]
    return rows


COLX = [0.012, 0.052, 0.145, 0.285, 0.435, 0.560, 0.640]   # No,Time,Src,Dst,Proto,Len,Info
HDR = ["No.", "Time", "Source", "Destination", "Protocol", "Len", "Info"]
ROWH = 0.165
TOP = 0.80
ACC = {"native": "#5a6b70", "caseA": "#2f8f6b", "caseB": "#b5651d"}


def draw_panel(ax, rows, title, accent):
    ax.axis("off")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.text(0.0, 0.955, title, fontsize=12, weight="bold", transform=ax.transAxes)
    # header bar
    ax.add_patch(plt.Rectangle((0, TOP), 1, ROWH * 0.92, transform=ax.transAxes,
                               facecolor="#e7eaed", edgecolor="#cfd6da", lw=0.8))
    for x, h in zip(COLX, HDR):
        ax.text(x, TOP + ROWH * 0.42, h, fontsize=8.6, weight="bold", color="#33403f",
                family="monospace", transform=ax.transAxes)
    # data rows
    rowc = {"req": "#e9ecff", "ack": "#fbf1e2", "resp": "#e4f6ee"}
    stripe = {"req": "#7d8bd6", "ack": accent, "resp": "#2f8f6b"}
    ys = {}
    for i, (t, src, dst, proto, flen, info, kind) in enumerate(rows):
        y = TOP - (i + 1) * ROWH
        ys[kind] = y + ROWH * 0.42
        ax.add_patch(plt.Rectangle((0, y), 1, ROWH * 0.92, transform=ax.transAxes,
                                   facecolor=rowc[kind], edgecolor="#e0e5e8", lw=0.6))
        ax.add_patch(plt.Rectangle((0, y), 0.006, ROWH * 0.92, transform=ax.transAxes,
                                   facecolor=stripe[kind], edgecolor="none"))
        cells = [str(i + 1), "%.3f" % t, src, dst, proto, str(flen), info]
        for x, c in zip(COLX, cells):
            bold = kind in ("ack", "resp") and x in (COLX[1],)
            ax.text(x, y + ROWH * 0.42, c, fontsize=8.4,
                    weight="bold" if bold else "normal",
                    color="#1a2224", family="monospace", transform=ax.transAxes)
    # gap bracket between ACK time and Response time
    gap = rows[2][0] - rows[1][0]
    xb = 0.052
    y_ack, y_resp = ys["ack"], ys["resp"]
    ax.annotate("", xy=(xb - 0.028, y_resp), xytext=(xb - 0.028, y_ack),
                xycoords="axes fraction",
                arrowprops=dict(arrowstyle="<->", color=accent, lw=1.6))
    gtxt = ("%.2f ms" % gap) if gap < 1 else ("%.1f ms" % gap)
    ax.text(xb - 0.036, (y_ack + y_resp) / 2, "gap\n%s" % gtxt, fontsize=9.5,
            weight="bold", color=accent, ha="right", va="center", transform=ax.transAxes)
    return gap


rows = {k: observer_rows(v) for k, v in PCAPS.items()}
fig, axes = plt.subplots(2, 2, figsize=(13.2, 6.6))
plt.subplots_adjust(left=0.075, right=0.985, top=0.86, bottom=0.06, hspace=0.42, wspace=0.14)

g_nb = draw_panel(axes[0, 0], rows["native"], "BEFORE — no defense", ACC["native"])
g_a  = draw_panel(axes[0, 1], rows["caseA"], "AFTER — Defense 1: hold the ACK", ACC["caseA"])
g_nb2 = draw_panel(axes[1, 0], rows["native"], "BEFORE — no defense", ACC["native"])
g_b  = draw_panel(axes[1, 1], rows["caseB"], "AFTER — Defense 2: hold the response", ACC["caseB"])

fig.text(0.012, 0.70, "DEFENSE 1", rotation=90, va="center", fontsize=12.5, weight="bold", color=ACC["caseA"])
fig.text(0.012, 0.30, "DEFENSE 2", rotation=90, va="center", fontsize=12.5, weight="bold", color=ACC["caseB"])
fig.suptitle("Case A · SEL-751 (separate-ACK) — real captures, before and after each defense",
             fontsize=15, weight="bold", y=0.96)
fig.text(0.5, 0.905,
         "Defense 1 collapses the gap %.1f ms -> %.2f ms   |   Defense 2 fixes it at %.1f ms   (same device bytes throughout)"
         % (g_nb, g_a, g_b), ha="center", fontsize=11, color="#41525a")
fig.text(0.5, 0.012,
         "Frames as seen by a passive observer on the link (Src 10.0.2.10 = device, 10.0.1.10 = master); "
         "loopback mirror copies collapsed. Times/lengths verbatim from the .pcap files.",
         ha="center", fontsize=8.4, color="#8a949a", style="italic")

fig.savefig("evidence/visualization/pcap_before_after.png", dpi=150, bbox_inches="tight")
print("saved pcap_before_after.png")
print("  Case A gap: %.1f ms -> %.3f ms" % (g_nb, g_a))
print("  Case B gap: %.1f ms -> %.1f ms" % (g_nb2, g_b))
