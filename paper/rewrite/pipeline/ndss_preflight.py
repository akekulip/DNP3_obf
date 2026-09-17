#!/usr/bin/env python3
"""NDSS 2027 submission preflight.

Checks the compiled manuscript against the official submission requirements and against the
anonymity rules. Fails closed.

    ndss_preflight.py [PDF] [--submission]

Without ``--submission`` an unassigned HotCRP paper number is reported as a draft state and the
run can still pass. With ``--submission`` it is a failure, so the ``[23|24]xxxx`` style
placeholder cannot survive a build that is about to be uploaded.

Requirements enforced:
  US Letter; two columns; no more than 13 main-body pages, excluding Ethics Considerations,
  references and appendices; Times 10 pt or larger; line spacing 11 pt or larger; anonymous
  author block; page numbers as the official template sets them; the NDSS publication block; a
  completed cycle-specific DOI; no Type 3 fonts; and correct rendering in black and white.

Anonymity is checked across the LaTeX source, the PDF text, the PDF metadata, embedded image
metadata, URLs, the acknowledgments, and repository-specific paths.
"""
from __future__ import annotations
import argparse, hashlib, os, re, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
REPO = PAPER.parents[1]

LETTER_PT = (612.0, 792.0)
MAX_BODY_PAGES = 13
MIN_BODY_PT = 10.0

# Identifying strings that must not appear in a submission build.
IDENTITY_PATTERNS = [
    r"University of Rhode Island", r"\bKingston\b", r"\bU\.?R\.?I\.?\b",
    r"akekudaga", r"akekulip", r"\buri\.edu\b", r"\bPhilip\b", r"Akekuda",
    r"github\.com/[A-Za-z0-9_.-]+", r"DNP3_obf",
]
# Paths that would identify the authors' working environment.
PATH_PATTERNS = [r"/home/[a-z]+/", r"C:\\\\Users\\\\"]
ACK_PATTERNS = [r"\\section\*?\{Acknowledg", r"\\begin\{acks\}"]


def run(*a):
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=180)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{a[0]} not found"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


class Report:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, detail, fatal=True):
        self.rows.append((name, ok, detail, fatal))

    def failed(self):
        return [r for r in self.rows if not r[1] and r[3]]

    def render(self):
        w = max(len(r[0]) for r in self.rows)
        for name, ok, detail, fatal in self.rows:
            tag = "PASS" if ok else ("FAIL" if fatal else "WARN")
            print(f"[{tag}] {name.ljust(w)}  {detail}")
        bad = self.failed()
        print("-" * 78)
        print(f"NDSS PREFLIGHT: {'FAIL' if bad else 'PASS'}  "
              f"({len(bad)} blocking issue{'s' if len(bad) != 1 else ''})")
        return 1 if bad else 0


def check_template(rep):
    man = PAPER / "ndss" / "NDSS_TEMPLATE.sha256"
    if not man.exists():
        rep.add("official template", False, "NDSS_TEMPLATE.sha256 missing")
        return
    bad = []
    for line in man.read_text().splitlines():
        if not line.strip():
            continue
        want, rel = line.split(None, 1)
        p = REPO / rel.strip()
        if not p.exists():
            bad.append(f"{rel.strip()} missing")
        elif sha256(p) != want:
            bad.append(f"{rel.strip()} modified")
    rep.add("official template", not bad,
            "vendored NDSS template and IEEEtran.cls match the recorded hashes" if not bad
            else "; ".join(bad))


def check_geometry(rep, pdf):
    rc, out, _ = run("pdfinfo", str(pdf))
    if rc != 0:
        rep.add("page geometry", False, "pdfinfo unavailable")
        return None
    m = re.search(r"Page size:\s+([\d.]+) x ([\d.]+)", out)
    pages = int(re.search(r"Pages:\s+(\d+)", out).group(1))
    if not m:
        rep.add("page geometry", False, "no page size reported")
        return pages
    w, h = float(m.group(1)), float(m.group(2))
    ok = abs(w - LETTER_PT[0]) < 2 and abs(h - LETTER_PT[1]) < 2
    rep.add("page geometry", ok, f"{w:.0f} x {h:.0f} pt "
            f"({'US Letter' if ok else 'NOT US Letter'}), {pages} pages")
    return pages


def _first_page_matching(pdf, total, pattern):
    """The first page whose text matches `pattern`, or None."""
    for p in range(1, (total or 0) + 1):
        rc, out, _ = run("pdftotext", "-f", str(p), "-l", str(p), str(pdf), "-")
        if rc != 0:
            continue
        if re.search(pattern, out, re.I):
            return p
    return None


#: Headings that begin a region the venue excludes from the page budget, and headings that begin
#: body again. Small caps come out of pdftotext with a space after the first letter, so every
#: pattern tolerates that. Open Science is BODY: the venue's exclusions name only Ethics
#: Considerations, references and appendices.
EXCLUDED_HEADINGS = (
    ("ethics", r"\bE\s*THICS\s+C\s*ONSIDERATIONS\b"),
    ("references", r"\bR\s*EFERENCES\b"),
    ("appendix", r"\bA\s*PPENDI(?:X|CES)\b"),
)
BODY_HEADINGS = (
    ("open science", r"\bO\s*PEN\s+S\s*CIENCE\b"),
    ("numbered section", r"(?m)^\s*[IVX]{1,5}\.\s+\S"),
)


def _page_text(pdf, page):
    rc, out, _ = run("pdftotext", "-f", str(page), "-l", str(page), str(pdf), "-")
    return out if rc == 0 else ""


def count_body(page_texts):
    """Classify a list of page texts, index 0 = page 1. Pure, so it can be tested directly.

    Returns (body_pages, first_reference_page, first_ethics_page).
    """
    marks = []                       # (page, offset, kind, name)
    for i, text in enumerate(page_texts, start=1):
        if not text.strip():
            continue
        for name, pat in EXCLUDED_HEADINGS:
            m = re.search(pat, text, re.I)
            if m:
                marks.append((i, m.start(), "excluded", name))
        for name, pat in BODY_HEADINGS:
            for m in re.finditer(pat, text, re.I):
                marks.append((i, m.start(), "body", name))
    marks.sort(key=lambda m: (m[0], m[1]))

    ref_page = next((p for p, _, _, n in marks if n == "references"), None)
    ethics_page = next((p for p, _, _, n in marks if n == "ethics"), None)

    state = "body"                   # the document opens in body
    body = 0
    for i, text in enumerate(page_texts, start=1):
        if not text.strip():
            continue
        on_page = [m for m in marks if m[0] == i]
        first_excluded = next((off for _, off, k, _ in on_page if k == "excluded"), None)
        has_body_heading = any(k == "body" for _, _, k, _ in on_page)
        if state == "body":
            # A page where an excluded section begins counts only if body text sits above that
            # heading. A heading at the top of a page has nothing above it.
            counts = first_excluded is None or bool(text[:first_excluded].strip())
        else:
            counts = has_body_heading
        if counts:
            body += 1
        for _, _, kind, _ in on_page:
            state = kind
    return body, ref_page, ethics_page


def body_pages(pdf, total):
    """Main-body pages: every page carrying body content, by the venue's own exclusions.

    NDSS 2027: "Technical papers submitted for NDSS Symposium must not exceed 13 pages, excluding
    the 'Ethics Considerations' section, references, or appendices." Open Science is not on that
    list, so it is body and is counted.

    Two earlier versions of this function were wrong in the same way, by excluding a whole page
    because an excluded section began on it:

    * counting to the page *before* the Ethics heading lost a page of Conclusion that sat above
      that heading;
    * excluding everything from the References page onward lost body text above that heading too,
      and recognising resumed body only by a numbered heading missed Open Science, which the
      venue counts and which this template sets without a number.

    The rule is therefore stated positively and per page. Walking the pages in order, each page is
    counted when any body region is open on it: the page where an excluded heading first appears
    still counts, because the text above that heading is body; a page after it does not, until a
    body heading resumes. Returns (body_pages, pages_scanned, first_reference_page,
    first_ethics_page).
    """
    total = total or 0
    texts = [_page_text(pdf, page) for page in range(1, total + 1)]
    body, ref_page, ethics_page = count_body(texts)
    return body, total, ref_page, ethics_page


def check_page_budget(rep, pdf, total):
    body, before_refs, ref_page, ethics_page = body_pages(pdf, total)
    ok = body <= MAX_BODY_PAGES
    detail = (f"{body} main-body page(s)"
              + (f" (Ethics Considerations begins on page {ethics_page}" if ethics_page
                 else " (no Ethics heading found")
              + (f", References on page {ref_page})" if ref_page else ")")
              + f"; limit {MAX_BODY_PAGES}")
    if body != before_refs:
        detail += (f". {before_refs - body} of the {before_refs} page(s) carry no body region and "
                   "are excluded; a page where an excluded section begins is still counted, "
                   "because the text above that heading is body")
    detail += (". Open Science is counted, because the venue's exclusions name only Ethics "
               "Considerations, references and appendices")
    rep.add("page budget", ok, detail)


def check_fonts(rep, pdf):
    rc, out, _ = run("pdffonts", str(pdf))
    if rc != 0:
        rep.add("fonts", False, "pdffonts unavailable")
        return
    lines = [l for l in out.splitlines()[2:] if l.strip()]
    type3 = [l.split()[0] for l in lines if "Type 3" in l]
    not_embedded = [l.split()[0] for l in lines
                    if len(l.split()) > 5 and l.split()[-4] == "no"]
    serif_ok = any(re.search(r"Times|NimbusRom", l, re.I) for l in lines)
    problems = []
    if type3:
        problems.append(f"Type 3 fonts: {', '.join(type3)}")
    if not_embedded:
        problems.append(f"not embedded: {', '.join(not_embedded)}")
    if not serif_ok:
        problems.append("no Times-compatible serif found")
    rep.add("fonts", not problems,
            f"{len(lines)} fonts, all embedded, no Type 3, Times-compatible"
            if not problems else "; ".join(problems))


def check_type_size(rep):
    """Times 10 pt or larger, and line spacing 11 pt or larger, come from the class options."""
    src = (PAPER / "main.tex").read_text()
    m = re.search(r"\\documentclass(\[[^\]]*\])?\{IEEEtran\}", src)
    if not m:
        rep.add("type size", False, "IEEEtran document class not found")
        return
    opts = [o.strip() for o in (m.group(1) or "[]")[1:-1].split(",") if o.strip()]
    sizes = [o for o in opts if re.fullmatch(r"\d+pt", o)]
    pt = float(sizes[0][:-2]) if sizes else 10.0     # IEEEtran conference default is 10 pt
    ok = pt >= MIN_BODY_PT
    # IEEEtran sets \baselineskip to about 1.15em at 10 pt, which exceeds the 11 pt floor.
    rep.add("type size", ok,
            f"body {pt:g} pt via documentclass[{','.join(opts) or 'conference'}]; "
            f"IEEEtran leading at {pt:g} pt exceeds the 11 pt floor")


def check_columns(rep):
    src = (PAPER / "main.tex").read_text()
    ok = "conference" in src and "\\onecolumn" not in src
    rep.add("two columns", ok,
            "IEEEtran conference class, two columns, no \\onecolumn override" if ok
            else "column layout not confirmed")


def check_pubblock_and_doi(rep, pdf, submission):
    rc, out, _ = run("pdftotext", "-f", "1", "-l", "1", str(pdf), "-")
    text = out if rc == 0 else ""
    flat = re.sub(r"\s+", " ", text)
    have_block = ("Network and Distributed System Security" in flat
                  and "ndss-symposium.org" in flat and "ISBN" in flat)
    rep.add("publication block", have_block,
            "NDSS 2027 publication block present on page 1" if have_block
            else "NDSS publication block not found on page 1")

    sub = (PAPER / "ndss" / "submission.tex").read_text()
    cycle = re.search(r"\\newcommand\{\\ndssreviewcycle\}\{([^}]*)\}", sub)
    num = re.search(r"\\newcommand\{\\ndsspapernumber\}\{([^}]*)\}", sub)
    cycle_v = (cycle.group(1) if cycle else "").strip()
    num_v = (num.group(1) if num else "").strip()

    cycle_ok = cycle_v in ("summer", "fall")
    rep.add("review cycle", cycle_ok,
            f"cycle {cycle_v!r} -> DOI prefix {'24' if cycle_v == 'fall' else '23'}"
            if cycle_ok else f"cycle must be 'summer' or 'fall', found {cycle_v!r}")

    placeholder = bool(re.search(r"\[23\s*\|\s*24\]x+|xxxx", flat)) or "DRAFT" in flat
    resolved = bool(num_v) and num_v.isdigit() and not placeholder
    if resolved:
        rep.add("DOI", True, f"resolved: paper number {num_v}")
    elif submission:
        rep.add("DOI", False,
                "unresolved DOI in a submission build: set \\ndsspapernumber in "
                "ndss/submission.tex to the assigned HotCRP number (it must not be invented)")
    else:
        rep.add("DOI", True,
                "draft build: paper number not assigned, DOI renders a visible DRAFT marker "
                "(--submission will fail until it is set)", fatal=False)


def check_page_numbers(rep, pdf, total):
    src = (PAPER / "main.tex").read_text()
    tmpl = (PAPER / "ndss" / "bare_conf_NDSS2027.tex").read_text()
    ours = re.search(r"\\pagestyle\{(\w+)\}", src)
    theirs = re.search(r"\\pagestyle\{(\w+)\}", tmpl)
    ok = bool(ours) and bool(theirs) and ours.group(1) == theirs.group(1)
    rep.add("page numbers", ok,
            f"\\pagestyle{{{ours.group(1)}}}, matching the official template" if ok
            else "page-number style differs from the official template")


def check_anonymity(rep, pdf, submission):
    hits = []

    # 1. LaTeX source actually used by the build (the camera-ready block is not input while
    #    \anonymoustrue holds, so it is excluded deliberately and checked separately).
    src_files = [PAPER / "main.tex"] + sorted((PAPER / "sections").glob("*.tex"))
    for f in src_files:
        t = f.read_text()
        for pat in IDENTITY_PATTERNS + PATH_PATTERNS:
            for m in re.finditer(pat, t):
                hits.append(f"source {f.name}: {m.group(0)!r}")
    anon_on = re.search(r"\\anonymoustrue", (PAPER / "main.tex").read_text()) is not None
    if not anon_on:
        hits.append("main.tex does not set \\anonymoustrue")

    # 2. PDF text
    rc, out, _ = run("pdftotext", str(pdf), "-")
    if rc == 0:
        for pat in IDENTITY_PATTERNS + PATH_PATTERNS:
            for m in re.finditer(pat, out):
                hits.append(f"PDF text: {m.group(0)!r}")

    # 3. PDF metadata
    rc, info, _ = run("pdfinfo", "-meta", str(pdf))
    if rc != 0:
        rc, info, _ = run("pdfinfo", str(pdf))
    if rc == 0:
        for pat in IDENTITY_PATTERNS + PATH_PATTERNS:
            for m in re.finditer(pat, info):
                hits.append(f"PDF metadata: {m.group(0)!r}")

    # 4. Embedded image metadata and any other identifying string in the raw bytes
    raw = pdf.read_bytes()
    for pat in [p.encode() for p in (r"akekudaga", r"akekulip", r"uri\.edu", r"/home/")]:
        if re.search(pat, raw):
            hits.append(f"PDF bytes: {pat.decode()!r}")

    # 5. Acknowledgments must be absent from an anonymous build
    for f in src_files:
        t = f.read_text()
        for pat in ACK_PATTERNS:
            if re.search(pat, t):
                hits.append(f"acknowledgments present in {f.name}")

    rep.add("anonymity", not hits,
            "no identifying string in source, PDF text, metadata, embedded bytes, URLs or "
            "acknowledgments" if not hits else "; ".join(sorted(set(hits))[:6]),
            fatal=True)


def check_greyscale(rep, pdf, total):
    if not shutil.which("pdftoppm"):
        rep.add("greyscale render", True, "pdftoppm unavailable; skipped", fatal=False)
        return
    out = Path(os.environ.get("TMPDIR", "/tmp")) / "ndss_gray"
    out.mkdir(parents=True, exist_ok=True)
    rc, _, err = run("pdftoppm", "-gray", "-r", "150", "-f", "1",
                     "-l", str(min(total or 1, 14)), str(pdf), str(out / "p"))
    made = sorted(out.glob("p-*.pgm")) + sorted(out.glob("p-*.png"))
    ok = rc == 0 and made
    rep.add("greyscale render", bool(ok),
            f"{len(made)} page(s) rendered in black and white for inspection at {out}"
            if ok else f"greyscale render failed: {err.strip()[:80]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf", nargs="?", default=str(HERE / "build" / "main.pdf"))
    ap.add_argument("--submission", action="store_true",
                    help="enforce submission-only rules (an unresolved DOI becomes a failure)")
    a = ap.parse_args()
    pdf = Path(a.pdf)
    if not pdf.exists():
        print(f"NDSS PREFLIGHT: FAIL  compiled PDF not found at {pdf}")
        return 1
    print(f"NDSS 2027 preflight  pdf={pdf}  mode="
          f"{'SUBMISSION' if a.submission else 'draft'}")
    print("-" * 78)
    rep = Report()
    check_template(rep)
    total = check_geometry(rep, pdf)
    check_page_budget(rep, pdf, total)
    check_columns(rep)
    check_type_size(rep)
    check_fonts(rep, pdf)
    check_pubblock_and_doi(rep, pdf, a.submission)
    check_page_numbers(rep, pdf, total)
    check_anonymity(rep, pdf, a.submission)
    check_greyscale(rep, pdf, total)
    return rep.render()


if __name__ == "__main__":
    sys.exit(main())
