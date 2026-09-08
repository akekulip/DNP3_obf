#!/usr/bin/env python3
"""Verify that Dr. Lin's supplied Introduction paragraphs are installed word for word.

The reference below is his text as supplied in
`meeting/CLAUDE_Timing_Paper_Revision_and_GitHub_Handoff.md` section 4, with line wrapping
normalized and nothing else altered. The check strips LaTeX citation commands and collapses
whitespace, then compares token by token, so mapping `[9]` to a bibliography key passes while
changing, adding or removing any word of his prose fails.

    python3 check_lin_intro_verbatim.py          -> exit 0 if verbatim, 1 otherwise
"""
from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path

INTRO = Path(__file__).resolve().parents[1] / "sections" / "01_introduction.tex"

REFERENCE = [
    """Device fingerprinting has been an essential step in cyber reconnaissance, allowing
    adversaries to reveal unique features of target networks and to design effective, stealthy
    attack strategies. These techniques are becoming increasingly critical in industrial control
    systems (ICSs) such as power grids, where adversaries often use IP-based control networks
    and computing devices within as entry points to inflict physical damage. Consequently,
    fingerprinting shifts the focus from visited websites and user biometric behavior to device
    models and types of control operations that are critical to ICS attacks. In the 2015 attack
    that disrupted Ukrainian power grids and the Stuxnet attack that disrupted Iranian nuclear
    power facilities, it is widely believed that adversaries stay in their systems for at least
    6 months to perform cyber reconnaissance.""",

    """To disrupt device fingerprinting, many studies present network traffic obfuscation.
    Device fingerprinting targeting general computing environments generally relies on
    network-level features such as packet size and/or inter-packet latency observed from
    communication patterns. Consequently, existing traffic obfuscation often focuses on (i)
    padding and splitting network packets, which hide or change the distribution of network
    packet sizes, and (ii) delaying network packets and adding dummy ones, which disrupt the
    inter-packet timing pattern. Since manipulating communication networks can introduce runtime
    overhead, recent works have begun to offload traffic obfuscation onto programmable network
    switches, which change communication patterns at much higher line rates than CPUs.""",

    """Unfortunately, these methods cannot be directly applied to ICS environments for two main
    reasons. First, device fingerprinting methods on ICS devices rely on different features from
    the ones in general computing environments. Instead of using network layer knowledge, they
    attempt to use behavior on physical devices to reveal device model or types of operations.
    For example, work in uses the latency between the TCP acknowledge packets and the actual
    response from the same device to estimate execution time there. Since each vendors may
    choose different materials or algorithms to implement the same control functionality, this
    time can be accurate in fingerprinting those devices. Second, existing traffic obfuscation
    is performed over encrypted channels, which are necessary to mix the obfuscated and normal
    traffic. Unfortunately, ICS networks still rely on unencrypted traffic due to a wide range
    of legacy devices, despite ICS network protocols may provide security features. Directly
    padding or adding dummy packets can easily reveal obfuscated packets, exposing the the
    underlying traffic pattern to adversaries.""",
]


def normalize(text: str) -> list[str]:
    """Words only: citations removed, LaTeX escapes undone, whitespace collapsed."""
    text = re.sub(r"~?\\cite\{[^}]*\}", " ", text)
    text = re.sub(r"\\%", "%", text)
    text = text.replace("~", " ")
    # A citation removed from in front of a full stop would otherwise leave the stop as its own
    # token and register as a difference, so close the gap before punctuation.
    text = re.sub(r"\s+([,.;:)])", r"\1", text)
    return text.split()


def installed_paragraphs() -> list[str]:
    body = INTRO.read_text()
    body = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("%"))
    body = body.split("\\label{sec:intro}", 1)[1]
    body = body.split("In this paper, we present", 1)[0]
    return [p.strip() for p in body.split("\n\n") if p.strip()]


def main() -> int:
    paras = installed_paragraphs()
    problems = []
    if len(paras) != len(REFERENCE):
        problems.append("expected %d protected paragraphs, found %d"
                        % (len(REFERENCE), len(paras)))
    for i, (ref, got) in enumerate(zip(REFERENCE, paras), start=1):
        r, g = normalize(ref), normalize(got)
        if r == g:
            print("  paragraph %d: VERBATIM (%d words)" % (i, len(r)))
            continue
        problems.append("paragraph %d differs from Dr. Lin's supplied text" % i)
        for line in difflib.unified_diff(r, g, "supplied", "installed", lineterm="", n=2):
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                problems.append("    %s" % line)
    if problems:
        print("LIN INTRO VERBATIM CHECK: FAIL")
        for p in problems:
            print("  " + p if not p.startswith("    ") else p)
        return 1
    print("LIN INTRO VERBATIM CHECK: PASS  (%d paragraphs word-for-word)" % len(REFERENCE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
