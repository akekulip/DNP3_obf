#!/usr/bin/env python3
"""Mirror the NOMAD evaluation figures into the manuscript and render its tables from the evidence.

Source of every figure and table: the paper-evidence directory of campaign eval_m11_09_20261018_02,
built by seg61_02/analysis/paper_evidence.py. Each copied file is checked against that
directory's OUTPUTS.sha256, and every table cell is read from a CSV there, so no number in a table
is typed by hand.

    python3 sync_nomad_evidence.py           # copy figures, write tables/*.tex, write MIRROR.sha256
    python3 sync_nomad_evidence.py --check   # verify the mirror and tables are current
"""
from __future__ import annotations

import csv
import hashlib
import io
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
REPO = PAPER.parents[1]
EVIDENCE = (REPO / "defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/"
            "seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper")
FIG_OUT = PAPER / "figures" / "nomad_eval"
TAB_OUT = PAPER / "tables"
FIGURES = ("fig_motivation", "fig_clrt_four_arm", "fig_precision_tail", "fig_precision_bias", "fig_replacement",
           "fig_operate_hold", "fig_attackers", "fig_confusion", "fig_residual_sources", "fig_dj_curves",
           "fig_windows", "fig_envelope", "fig_latency")
ARM = {"No obfuscation": "No obfuscation", "Timing": "Timing", "Size": "Size", "Timing+Size": "Timing+Size"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recorded() -> dict[str, str]:
    out = {}
    for line in (EVIDENCE / "OUTPUTS.sha256").read_text().splitlines():
        digest, name = line.split()
        out[name] = digest
    return out


def rows(name: str) -> list[dict]:
    with open(EVIDENCE / "tables" / (name + ".csv"), newline="") as f:
        return list(csv.DictReader(f))


def tex_escape(s: str) -> str:
    return s.replace("\\", r"\textbackslash{}").replace("&", r"\&").replace("%", r"\%").replace("_", r"\_").replace("#", r"\#")


def table_point_map() -> str:
    r = rows("table_point_map")
    half = (len(r) + 1) // 2
    body = []
    for a, b in zip(r[:half], r[half:] + [None]):
        left = "%s & %s" % (a["index"], tex_escape(a["point_label"]))
        right = "%s & %s" % (b["index"], tex_escape(b["point_label"])) if b else "&"
        body.append(left + " & " + right + r" \\")
    return (r"\begin{tabular}{rl@{\hspace{1.4em}}rl}" "\n" r"\toprule" "\n"
            r"Index & Point & Index & Point \\" "\n" r"\midrule" "\n" + "\n".join(body) + "\n"
            r"\bottomrule" "\n" r"\end{tabular}" "\n")


def table_crawler() -> str:
    head = ["Vendor", "Devices", "Enc.+Auth.", "Auth.", "Unconf.", "None"]
    body = []
    for r in rows("table_crawler"):
        if r["grouping"] != "vendor":
            continue
        label = r"\textit{Total}" if r["group"] == "Total" else tex_escape(r["group"])
        if r["group"] == "Total":
            body.append(r"\midrule")
        body.append(" & ".join([label, r["devices"], r["Encryption+Auth"], r["Authentication"],
                                r["Opt-in (unconfirmed)"], r["None"]]) + r" \\")
    return (r"\begin{tabular}{lrrrrr}" "\n" r"\toprule" "\n" + " & ".join(head) + r" \\" "\n" r"\midrule" "\n"
            + "\n".join(body) + "\n" r"\bottomrule" "\n" r"\end{tabular}" "\n")


def table_resources() -> str:
    body = []
    for r in rows("table_resources"):
        if r["program"] in ("N", "E", "T"):
            body.append(" & ".join([r["program"], "%s %s" % (r["pipe"], r["gress"]), r["stages"], r["sram_blocks"],
                                    r["tcam_blocks"], r["stateful_alus"]]) + r" \\")
    util = {r["pipe"]: r for r in rows("table_resources") if r["gress"] == "all"}
    for pipe in ("p0", "p1"):
        u = util[pipe]
        body.append(" & ".join([r"\textit{%s avg.}" % pipe, "", "",
                                u["sram_utilization"].replace("%", r"\%"), u["tcam_utilization"].replace("%", r"\%"),
                                u["meter_alu_utilization"].replace("%", r"\%")]) + r" \\")
    return (r"\begin{tabular}{llrrrr}" "\n" r"\toprule" "\n"
            r"Program & Pipe & Stages & SRAM & TCAM & SALU \\" "\n" r"\midrule" "\n" + "\n".join(body[:3]) + "\n"
            r"\midrule" "\n" + "\n".join(body[3:]) + "\n" r"\bottomrule" "\n" r"\end{tabular}" "\n")


def table_delivery() -> str:
    conf = {r["arm"]: r for r in rows("table_conformance")}
    outc = {r["arm"]: r for r in rows("table_outcomes")}
    sizes = {}
    for r in rows("table_sizes"):
        sizes.setdefault(r["arm"], []).append("%s/%s" % (r["request_payload_bytes"], r["response_payload_bytes"]))
    body = []
    for arm in ARM:
        c, o = conf[arm], outc[arm]
        resp = "/".join(sorted({s.split("/")[1] for s in sizes[arm]}, key=int))
        body.append(" & ".join([arm, "{:,}".format(int(c["responses"])), "{:,}".format(int(c["verdicts_ok"])),
                                resp, "{:,}".format(int(o["OUT_ACK_COMMIT"])), "{:,}".format(int(o["OUT_ACK_FALLBACK"]) + int(o["OUT_RESP_FALLBACK"])),
                                o["retransmitted"]]) + r" \\")
    return (r"\begin{tabular}{lrrrrrr}" "\n" r"\toprule" "\n"
            r"Arm & Resp. & Conform. & Bytes & Commits & Fallb. & Retx. \\" "\n" r"\midrule" "\n"
            + "\n".join(body) + "\n" r"\bottomrule" "\n" r"\end{tabular}" "\n")


TABLES = {"tab_point_map": table_point_map, "tab_crawler": table_crawler,
          "tab_resources": table_resources, "tab_delivery": table_delivery}


def build() -> dict[str, bytes]:
    rec = recorded()
    out = {}
    for name in FIGURES:
        src = EVIDENCE / "figures" / (name + ".pdf")
        if sha(src) != rec["figures/%s.pdf" % name]:
            raise SystemExit("evidence figure changed since its build: " + name)
        out["figures/nomad_eval/%s.pdf" % name] = src.read_bytes()
    for name, fn in TABLES.items():
        out["tables/%s.tex" % name] = ("%% Generated by pipeline/sync_nomad_evidence.py from the campaign paper evidence; do not edit.\n"
                                       + fn()).encode()
    return out


def main() -> int:
    files = build()
    manifest = "".join("%s  %s\n" % (hashlib.sha256(v).hexdigest(), k) for k, v in sorted(files.items()))
    if "--check" in sys.argv:
        ok = all((PAPER / k).exists() and (PAPER / k).read_bytes() == v for k, v in files.items())
        ok = ok and (PAPER / "figures/nomad_eval/MIRROR.sha256").read_text() == manifest
        print("sync check: " + ("current" if ok else "STALE: run sync_nomad_evidence.py"))
        return 0 if ok else 1
    for k, v in files.items():
        (PAPER / k).parent.mkdir(parents=True, exist_ok=True)
        (PAPER / k).write_bytes(v)
    (FIG_OUT / "MIRROR.sha256").write_text(manifest)
    print("wrote %d files" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
