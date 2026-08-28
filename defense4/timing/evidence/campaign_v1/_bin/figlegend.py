"""figlegend.py — place a figure's legend OUTSIDE the plot area.

A legend inside the axes can always end up on top of the data, and on a small IEEE figure
there is rarely a genuinely empty corner. Collecting the series into one legend above the
panels makes overlap structurally impossible and keeps the panels identical in size.
"""
from __future__ import annotations


def top_legend(fig, axes, ncol=None, top=0.86, y=0.995, fontsize=7.5, **kw):
    """Collect unique labelled artists from `axes` into one legend above the panels.

    Call AFTER the grid/tight_layout pass: it re-reserves the headroom that tight_layout
    just consumed, then anchors the legend into that reserved band.
    """
    axl = axes if isinstance(axes, (list, tuple)) else [axes]
    handles, labels = [], []
    for ax in axl:
        h, l = ax.get_legend_handles_labels()
        for hh, ll in zip(h, l):
            if ll not in labels:
                handles.append(hh); labels.append(ll)
        leg = ax.get_legend()
        if leg is not None:
            leg.remove()
    if not handles:
        return None
    if ncol is None:
        ncol = len(labels) if len(labels) <= 4 else 3
    fig.subplots_adjust(top=top)
    leg = fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, y),
                     ncol=ncol, frameon=True, framealpha=1.0, fontsize=fontsize,
                     handletextpad=0.4, borderpad=0.3, columnspacing=1.1,
                     borderaxespad=0.0, **kw)
    for h in leg.legend_handles:          # a translucent series must read solid in the key
        try:
            h.set_alpha(1.0)
        except Exception:
            pass
    return leg
