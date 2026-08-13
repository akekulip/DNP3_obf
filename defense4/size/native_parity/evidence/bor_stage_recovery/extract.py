#!/usr/bin/env python3
"""Extract a compact resource summary from a bf-p4c output dir + compile logs.

Usage: extract.py <variant_dir>
  expects <variant_dir>/out/pipe/... and <variant_dir>/compile.std{out,err}.log
Prints a human summary and writes <variant_dir>/SUMMARY.txt.
Robust to placement failure (no binary): still reports the requested-stage error.
"""
import sys, os, re, json, glob

def read(p):
    try:
        return open(p, errors='replace').read()
    except FileNotFoundError:
        return ''

def last_alloc_block(table_summary):
    """Return (ingress_stages, egress_stages, crit_path, ntables, state) from the LAST allocation block."""
    blocks = re.split(r'Table allocation done', table_summary)
    if len(blocks) < 2:
        return None
    b = blocks[-1]
    state = re.search(r'state\s*=\s*(\S+)', b)
    ig = re.search(r'ingress table allocation:\s*(\d+)', b)
    eg = re.search(r'egress table allocation:\s*(\d+)', b)
    cp = re.search(r'Critical path length[^:]*:\s*(\d+)', b)
    nt = re.search(r'Number of tables allocated:\s*(\d+)', b)
    return dict(
        state=state.group(1) if state else '?',
        ingress=int(ig.group(1)) if ig else None,
        egress=int(eg.group(1)) if eg else None,
        crit=int(cp.group(1)) if cp else None,
        ntables=int(nt.group(1)) if nt else None,
    )

def per_stage_ltid(mau_res):
    """Parse the first per-stage table (integer counts) -> {stage: ltid}. Last column = Logical TableID."""
    lines = mau_res.splitlines()
    out = {}
    for ln in lines:
        if not ln.startswith('|'):
            continue
        cols = [c.strip() for c in ln.strip('|').split('|')]
        if len(cols) < 5:
            continue
        # data rows: first col is an integer stage number
        if re.fullmatch(r'\d+', cols[0]):
            stage = int(cols[0])
            ltid = cols[-1]
            if re.fullmatch(r'\d+', ltid):
                # only take the first (integer) table, not the % table
                if stage not in out:
                    out[stage] = int(ltid)
    return out

def phv_groups(metrics):
    try:
        m = json.loads(metrics)
    except Exception:
        return None
    n = m.get('phv', {}).get('normal', [])
    t = m.get('phv', {}).get('tagalong', [])
    def fmt(lst):
        return {d['bit_width']: d['containers_occupied'] for d in lst}
    return dict(normal=fmt(n), tagalong=fmt(t),
               logical_tables=m.get('mau', {}).get('logical_tables'),
               ig_cycles=next((x['cycles'] for x in m.get('mau', {}).get('latency', []) if x['gress']=='ingress'), None))

def placement_failures(stderr, placement_logs):
    fails = []
    for m in re.finditer(r'tofino supports up to \d+ stages, using (\d+)', stderr):
        fails.append(('stage-overflow-using', m.group(1)))
    # "can't place X in stage N : reason"
    seen = set()
    for txt in placement_logs:
        for m in re.finditer(r"can't place (\S+) in stage (\d+)\s*:\s*([^\n]+)", txt):
            key = (m.group(1), m.group(2))
            if key not in seen:
                seen.add(key)
                fails.append(("cant-place", f"{m.group(1)} @stage{m.group(2)}: {m.group(3).strip()[:70]}"))
    return fails

def reg_count(context):
    """Number of stateful (register) ALUs from context.json (register_params / stateful)."""
    try:
        c = json.loads(context)
    except Exception:
        return None
    n = 0
    for t in c.get('tables', []):
        st = t.get('stateful') or (t.get('match_attributes', {}) or {}).get('stateful')
        if st:
            n += 1
    # fallback: count 'salu' rams
    return n if n else None

def main(vdir):
    pipe = os.path.join(vdir, 'out', 'pipe')
    logs = os.path.join(pipe, 'logs')
    stderr = read(os.path.join(vdir, 'compile.stderr.log'))
    stdout = read(os.path.join(vdir, 'compile.stdout.log'))
    ts = read(os.path.join(logs, 'table_summary.log'))
    mau = read(os.path.join(logs, 'mau.resources.log'))
    metrics = read(os.path.join(logs, 'metrics.json'))
    context = read(os.path.join(pipe, 'context.json'))
    placement_logs = [read(p) for p in glob.glob(os.path.join(logs, 'table_placement_*.log'))]
    # stage_adv / placement thrash also lives in table_placement logs and stderr

    alloc = last_alloc_block(ts)
    ltid = per_stage_ltid(mau)
    phv = phv_groups(metrics)
    fails = placement_failures(stderr + stdout, placement_logs)
    binary = bool(glob.glob(os.path.join(pipe, '*.bin'))) or os.path.exists(os.path.join(vdir,'out','pipe','tofino.bin'))
    errs = re.search(r'(\d+) errors', stderr + stdout)

    lines = []
    lines.append(f"VARIANT: {os.path.basename(vdir.rstrip('/'))}")
    lines.append(f"binary_generated: {binary}   frontend: {errs.group(0) if errs else '?'}")
    if alloc:
        lines.append(f"FINAL alloc (state={alloc['state']}): ingress_stages={alloc['ingress']} egress_stages={alloc['egress']} crit_path={alloc['crit']} tables={alloc['ntables']}")
    else:
        lines.append("FINAL alloc: <no allocation block> (placement failed before settle)")
    if fails:
        lines.append("PLACEMENT FAILURES:")
        for k, v in fails[:12]:
            lines.append(f"  [{k}] {v}")
    else:
        lines.append("PLACEMENT FAILURES: none")
    if ltid:
        tail = sorted(ltid.items())
        lines.append("per-stage Logical-TableID occupancy (stage:ltid, /16 max):")
        lines.append("  " + "  ".join(f"s{s}:{v}" for s, v in tail))
        full = [s for s, v in tail if v >= 16]
        lines.append(f"  stages at 16/16 (full LTID): {full}")
    if phv:
        lines.append(f"PHV normal (bitwidth:containers /16): {phv['normal']}   tagalong: {phv['tagalong']}")
        lines.append(f"logical_tables(metrics)={phv['logical_tables']}  ingress_cycles={phv['ig_cycles']}")
    out = "\n".join(lines)
    print(out)
    open(os.path.join(vdir, 'SUMMARY.txt'), 'w').write(out + "\n")

if __name__ == '__main__':
    main(sys.argv[1])
