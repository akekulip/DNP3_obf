#!/usr/bin/env python3
"""Extract the agreed resource-report fields from a bf-p4c 9.13.1 output tree.

Usage:  python3 metrics.py <variant_dir>        # expects <dir>/out and <dir>/*.p4
Prints one markdown table row plus a labelled block.
"""
import hashlib
import json
import re
import sys
from pathlib import Path


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main(d: Path) -> None:
    out = d / "out"
    logs = out / "pipe" / "logs"
    src = sorted(d.glob("*.p4"))[0]
    log = d / "compile.log"

    res = {"name": d.name, "sha256": sha256(src)}

    txt = log.read_text() if log.exists() else ""
    m = re.search(r"(\d+) errors?, (\d+) warnings? generated", txt)
    res["errors"], res["warnings"] = (m.group(1), m.group(2)) if m else ("?", "?")
    res["error_lines"] = [l for l in txt.splitlines() if l.startswith("error")][:6]

    ts = (logs / "table_summary.log")
    if ts.exists():
        t = ts.read_text()
        for key, pat in (
            ("ingress_stages", r"Number of stages for ingress table allocation: (\d+)"),
            ("egress_stages", r"Number of stages for egress table allocation: (\d+)"),
            ("critical_path", r"Critical path length through the table dependency graph: (\d+)"),
            ("logical_tables", r"Number of tables allocated: (\d+)"),
        ):
            mm = re.search(pat, t)
            res[key] = mm.group(1) if mm else "?"

    mj = logs / "metrics.json"
    if mj.exists():
        j = json.loads(mj.read_text())
        mau = j["mau"]
        res["srams"] = mau["srams"]
        res["tcams"] = mau["tcams"]
        res["map_rams"] = mau["map_rams"]
        for lat in mau["latency"]:
            res[lat["gress"] + "_cycles"] = lat["cycles"]
        phv = j["phv"]["normal"]
        res["phv_norm"] = " ".join(
            f"{e['bit_width']}b:{e['containers_occupied']}c/{e['bits_occupied']}bits"
            for e in phv
        )
        tag = j["phv"]["tagalong"]
        res["phv_tagalong_containers"] = sum(e["containers_occupied"] for e in tag)

    mr = logs / "mau.resources.log"
    if mr.exists():
        rows = [l for l in mr.read_text().splitlines() if l.startswith("|    Totals")]
        if rows:
            cells = [c.strip() for c in rows[0].split("|")]
            # header order: Stage, ExactXbar, TernXbar, HashBit, HashDist, Gateway,
            # SRAM, MapRAM, TCAM, VLIW, MeterALU(=stateful), StatsALU, ...
            res["salu"] = cells[11]
            res["stats_alu"] = cells[12]
            res["gateways"] = cells[6]
            res["vliw"] = cells[10]

    pc = logs / "parser.characterize.log"
    if pc.exists():
        t = pc.read_text()
        for key, pat in (
            ("ig_parser_states", r"Number of states on ingress: (\d+)"),
            ("eg_parser_states", r"Number of states on egress: (\d+)"),
        ):
            mm = re.search(pat, t)
            res[key] = mm.group(1) if mm else "?"

    ps = logs / "phv_allocation_summary_0.log"
    if ps.exists():
        t = ps.read_text()
        mm = re.search(r"\|\s*Overall PHV Usage\s*\|\s*([^|]+)\|\s*([^|]+)\|", t)
        if mm:
            res["phv_overall"] = f"{mm.group(1).strip()} containers, {mm.group(2).strip()} bits"
        res["phv_unallocated"] = "yes" if "remain unallocated" in t else "no"

    for k, v in res.items():
        print(f"{k}: {v}")

    print()
    print("| variant | ig stages | eg stages | crit path | log tables | SRAM | mapRAM | TCAM "
          "| SALU | StatsALU | ig/eg parser states | ig cycles | err/warn |")
    print(f"| {res['name']} | {res.get('ingress_stages')} | {res.get('egress_stages')} | "
          f"{res.get('critical_path')} | {res.get('logical_tables')} | {res.get('srams')} | "
          f"{res.get('map_rams')} | {res.get('tcams')} | {res.get('salu')} | "
          f"{res.get('stats_alu')} | {res.get('ig_parser_states')}/{res.get('eg_parser_states')} | "
          f"{res.get('ingress_cycles')} | {res['errors']}/{res['warnings']} |")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
