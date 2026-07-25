#!/usr/bin/env python3
"""Extract a uniform Tofino-1 resource row from a bf-p4c output directory.

Usage: extract_resources.py <label> <p4_source> <out_dir> [compile_log]
Prints one JSON object.  All numbers come from real compiler artifacts:
  out/pipe/logs/table_summary.log        stages, critical path, logical tables
  out/pipe/logs/resources.json           SRAM / map RAM / TCAM / SALU / Stats ALU
  out/pipe/logs/parser.characterize.log  parser states per gress
  out/pipe/logs/phv_allocation_summary_0.log  PHV containers + bits
"""
import hashlib
import json
import re
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_table_summary(p: Path) -> dict:
    if not p.exists():
        return {}
    t = p.read_text()
    def grab(pat, cast=int):
        m = re.search(pat, t)
        return cast(m.group(1)) if m else None
    return {
        "stages_total": grab(r"Number of stages in table allocation:\s*(\d+)"),
        "ingress_stages": grab(r"Number of stages for ingress table allocation:\s*(\d+)"),
        "egress_stages": grab(r"Number of stages for egress table allocation:\s*(\d+)"),
        "critical_path": grab(r"Critical path length through the table dependency graph:\s*(\d+)"),
        "logical_tables": grab(r"Number of tables allocated:\s*(\d+)"),
    }


def parse_resources_json(p: Path) -> dict:
    """Count occupied MAU units across all stages (one list element = one unit)."""
    if not p.exists():
        return {}
    mau = json.loads(p.read_text())["resources"]["mau"]
    # (output key, top-level key, inner list key)
    spec = [("sram", "rams", "srams"),
            ("map_ram", "map_rams", "maprams"),
            ("tcam", "tcams", "tcams"),
            ("salu_meter_alu", "meter_alus", "meters"),
            ("stats_alu", "statistic_alus", "stats"),
            ("logical_tables_placed", "logical_tables", "ids"),
            ("gateways", "gateways", "gateways"),
            ("vliw_instr", "vliw", "instructions"),
            ("exm_search_buses", "exm_search_buses", "ids"),
            ("tind_result_buses", "tind_result_buses", "ids"),
            ("stashes", "stashes", "stashes")]
    tot = {k: 0 for k, _, _ in spec}
    tot["stages_occupied"] = 0
    tot["hash_bits"] = 0
    tot["xbar_bytes"] = 0
    for st in mau.get("mau_stages", []):
        busy = False
        for key, top, inner in spec:
            lst = st.get(top, {}).get(inner, [])
            if isinstance(lst, list):
                tot[key] += len(lst)
                busy = busy or bool(lst)
        hb = st.get("hash_bits", {}).get("bits", [])
        tot["hash_bits"] += len(hb) if isinstance(hb, list) else 0
        xb = st.get("xbar_bytes", {}).get("bytes", [])
        tot["xbar_bytes"] += len(xb) if isinstance(xb, list) else 0
        if busy:
            tot["stages_occupied"] += 1
    tot["mau_nStages"] = mau.get("nStages")
    return tot


def parse_parser(p: Path) -> dict:
    if not p.exists():
        return {}
    t = p.read_text()
    ing = re.search(r"Number of states on ingress:\s*(\d+)", t)
    igm = re.search(r"Number of matches on ingress:\s*(\d+)", t)
    egr = re.search(r"Number of states on egress:\s*(\d+)", t)
    egm = re.search(r"Number of matches on egress:\s*(\d+)", t)
    return {
        "ig_parser_states": int(ing.group(1)) if ing else None,
        "ig_parser_matches": int(igm.group(1)) if igm else None,
        "eg_parser_states": int(egr.group(1)) if egr else None,
        "eg_parser_matches": int(egm.group(1)) if egm else None,
    }


def parse_parser_tcam(p: Path) -> dict:
    """Count distinct parser TCAM rows actually used, per gress, from resources.json."""
    if not p.exists():
        return {}
    d = json.loads(p.read_text())["resources"]
    rows = {"ingress": set(), "egress": set()}
    for par in d.get("parser", {}).get("parsers", []):
        g = par.get("gress")
        if g not in rows:
            continue
        for st in par.get("states", []):
            tr = st.get("tcam_row")
            if tr is not None:
                rows[g].add(tr)
    return {"ig_parser_tcam_rows": len(rows["ingress"]),
            "eg_parser_tcam_rows": len(rows["egress"])}


def parse_phv(p: Path) -> dict:
    if not p.exists():
        return {}
    t = p.read_text()
    m = re.search(
        r"\|\s*Overall PHV Usage\s*\|\s*(\d+)\s*\(\s*([\d.]+)\s*%\)\s*\|\s*(\d+)\s*\(\s*([\d.]+)\s*%\)"
        r"\s*\|\s*(\d+)\s*\(\s*([\d.]+)\s*%\)\s*\|\s*(\d+)", t)
    out = {}
    if m:
        out.update({
            "phv_containers": int(m.group(1)), "phv_containers_pct": float(m.group(2)),
            "phv_bits_used": int(m.group(3)), "phv_bits_pct": float(m.group(4)),
            "phv_bits_ingress": int(m.group(5)), "phv_bits_egress": int(m.group(7)),
        })
    # Tagalong (T-PHV) Total row: 8b | 16b | 32b containers | Bits Used | Bits Allocated
    tail = t.split("Tagalong Collections:")[-1] if "Tagalong Collections:" in t else ""
    tg = re.search(
        r"\|\s*Total\s*\|\s*\|\s*(\d+)\s*\(\s*[\d.]+\s*%\)\s*\|\s*(\d+)\s*\(\s*[\d.]+\s*%\)"
        r"\s*\|\s*(\d+)\s*\(\s*[\d.]+\s*%\)\s*\|\s*(\d+)\s*\(\s*([\d.]+)\s*%\)"
        r"\s*\|\s*(\d+)\s*\(\s*([\d.]+)\s*%\)", tail)
    if tg:
        out["tagalong_bits_used"] = int(tg.group(4))
        out["tagalong_bits_alloc"] = int(tg.group(6))
        out["tagalong_alloc_pct"] = float(tg.group(7))
    return out


def parse_compile_log(p: Path) -> dict:
    if not p or not p.exists():
        return {}
    t = p.read_text()
    m = re.search(r"(\d+)\s+errors?,\s*(\d+)\s+warnings?", t)
    return {"errors": int(m.group(1)) if m else None,
            "warnings": int(m.group(2)) if m else None,
            "log_tail": "\n".join(t.strip().splitlines()[-6:])}


def main():
    label, src, outdir = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    clog = Path(sys.argv[4]) if len(sys.argv) > 4 else outdir.parent / "compile.log"
    logs = outdir / "pipe" / "logs"
    row = {"label": label, "source": str(src), "sha256": sha256(src) if src.exists() else None}
    row.update(parse_compile_log(clog))
    row.update(parse_table_summary(logs / "table_summary.log"))
    row.update(parse_resources_json(logs / "resources.json"))
    row.update(parse_parser(logs / "parser.characterize.log"))
    row.update(parse_parser_tcam(logs / "resources.json"))
    row.update(parse_phv(logs / "phv_allocation_summary_0.log"))
    print(json.dumps(row, indent=1))


if __name__ == "__main__":
    main()
