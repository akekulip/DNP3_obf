#!/usr/bin/env python3
"""lin_check.py - manuscript gate for the DNP3 timing-obfuscation paper.

Checks a draft (.tex / .md / .txt) for the problems the 2026-08-26 brief names:

  hard (FAIL = non-zero exit)
    forbidden_names     project codenames or an invented system name
    stale_labels        'native' / 'defended' / 'Timing ON' used as arm names
    firstness           an unsupported 'first' claim
    em_dashes           any em dash in the prose
    size_claims         a padding / splitting / segment-shape claim made as ours
    structure           required sections present, in the required order, with RO labels
                        defined in the threat model and reused in the Evaluation, and a
                        Limitations heading
    figures_after_refs  a figure environment after \\bibliography, or (with --pdf) a figure
                        caption on a page after the References heading
    citations           a \\cite key with no entry in the bibliography
    contribution_grammar  contribution headlines are verb-first
    sentence_health     no-main-clause fragments

  soft (WARN, never changes the exit code)
    acronyms            an acronym used before it is defined
    readability         the too-dense guard (Flesch / FK band)
    fact_hygiene        duplicate marquee examples, wrong year next to one
    connective_spine    informational only: fraction of sentences led by a connective
    voice_fingerprint   paper-voice metrics, if the skill is installed

The checker does not require stylistic filler and does not reward transitions.

Usage:
    python3 lin_check.py DRAFT.tex [--bib library.bib] [--pdf main.pdf] [--json]
    python3 lin_check.py --compare BEFORE AFTER      # non-regression gate (exit 3)

Deterministic: no network, no randomness.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("lin_check")

_VOICE_CHECK_PATH = os.path.expanduser(
    "~/.claude/skills/paper-voice/scripts/voice_check.py")


def _import_voice_check():
    if not os.path.isfile(_VOICE_CHECK_PATH):
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("voice_check", _VOICE_CHECK_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover
        logger.warning("failed to import voice_check.py: %s", exc)
        return None
    return module


VOICE = _import_voice_check()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CONNECTIVES: Tuple[str, ...] = (
    "for example", "for instance", "as a result", "consequently", "because", "since",
    "however", "unfortunately", "therefore", "thus", "instead", "hence",
)

FLESCH_FLOOR = 15.0
FK_CEILING = 18.0

SUBORDINATORS: Tuple[str, ...] = (
    "because", "since", "although", "while", "when", "if", "as", "whereas", "given", "though",
)

MARQUEE_TOKENS: Dict[str, str] = {"ukrain": "Ukraine", "stuxnet": "Stuxnet"}
MARQUEE_CANON_YEAR: Dict[str, str] = {"ukrain": "2015"}

# Names that must not appear in the manuscript (brief section 1 and CLAUDE.md).
FORBIDDEN_NAMES = ("ADTA", "GridCloak", "SysName", "\\sysname", "\\SysName")

# 'native' / 'defended' used as the name of an experimental arm, and the retired label.
STALE_LABEL_PATTERNS = (
    r"\b(?:native|defended)\s+(?:arm|baseline|traffic|captures?|condition|runs?|curves?|"
    r"mode|timing|CLRT|distribution|data|measurements?|case|setting|scenario)\b",
    r"\bnative\s*(?:versus|vs\.?|and|/|to)\s*defended\b",
    r"\bTiming ON\b",
)
# Allowed: 'unmodified' phrasing that negates the native-baseline claim, and file names.
STALE_LABEL_ALLOW = (
    r"not an? (?:unmodified )?native", r"unmodified (?:native )?(?:device )?baseline",
    r"no (?:pure )?(?:size-free )?native", r"never (?:an? )?native", r"e1_native", r"native_txn",
    r"defended_(?:read_)?txn", r"is not (?:a |an )?native", r"rather than (?:a |an )?native",
    r"not (?:a |an )?(?:pure )?native", r"native-versus-defended",
)

FIRSTNESS_PATTERNS = (
    r"to the best of our knowledge", r"\bwe are the first\b", r"\bthe first (?:in-network |"
    r"programmable |data-plane )?(?:work|system|study|paper|defense|defence|approach|framework|"
    r"implementation|design|effort|attempt)\b", r"\bfirst to (?:normalize|obfuscate|propose|"
    r"implement|evaluate|show|demonstrate)\b",
)

# Size-claim vocabulary. A sentence that uses one of these AND claims it as ours fails.
SIZE_TERMS = r"\b(?:padding|padded|pads?|packet splitting|split(?:s|ting)? (?:the |a |each |every )?(?:packets?|responses?|frames?)|segmentation|segment[- ]shape|" \
             r"segment sizes?|two segments|dummy packets?|cover (?:frames?|traffic)|decoys?|chaff|" \
             r"\[28,\s*21\]|49-byte|carve[sd]?)\b"
OURS_MARKERS = r"\b(?:we|our|the framework|the obfuscator|this paper|the proposed)\b"
SIZE_EXEMPT = r"\b(?:prior|previous|existing|related|earlier|general|not|neither|nor|without|" \
              r"outside|out of scope|no size|does not|do not|never|beyond|leave|future|" \
              r"is not|are not|instead of|rather than|active in both|held constant|" \
              r"both arms|shaping)\b"

ACRONYM_ALLOW = {
    "DNP3", "TCP", "IP", "ICS", "ICSs", "SCADA", "SEL", "IEEE", "ACM", "USENIX", "NDSS", "P4",
    "CRC", "CPU", "CPUs", "READ", "SELECT", "OPERATE", "SBO", "CLRT", "ACK", "RO1", "RO2",
    "RO3", "PDF", "ECDF", "CDF", "MI", "ID", "IEC", "LAN", "WAN", "IoT", "ML", "AI", "SDN",
    "OT", "II", "III", "IV", "VI", "VII", "VIII", "IX", "XI", "FIN", "SYN", "TODO", "PRE",
    "MAU", "SDE", "NIC", "BA", "CI", "JS", "GHz", "MHz", "Gbps", "Mbps", "kB", "MB", "GB",
    "NSDI", "CCS", "TDSC", "TSG", "ATC", "SIGCOMM", "PoPETs", "UTC", "AICT", "IFIP",
    "AINA", "CSIIRW", "LASER", "ASIACCS", "ESORICS", "INFOCOM", "SmartGridComm", "MSP",
    "E-ISAC", "SANS", "US", "USA", "CROB", "FIRST", "LATER", "GTID", "PIFO", "SP-PIFO",
    "WTF-PAD", "RAINCOAT", "ALU", "OFF", "P4X", "AUTHOR", "BLOCK", "PENDING", "FIGURE",
    "PLACEHOLDER", "SEL-751A", "SEL-751", "ETRI",
}

AUX_VERBS = {
    "is", "are", "was", "were", "be", "been", "being", "am", "has", "have", "had", "do",
    "does", "did", "can", "could", "will", "would", "shall", "should", "may", "might", "must",
    "cannot",
}

VERB_BASES = {
    "make", "use", "show", "reach", "focus", "rely", "work", "know", "hold", "release", "run",
    "add", "change", "offload", "introduce", "leak", "identify", "inject", "pad", "stay",
    "shift", "apply", "need", "become", "give", "place", "send", "return", "arrive", "answer",
    "record", "repeat", "mark", "fix", "keep", "bring", "create", "install", "write", "forward",
    "drop", "seed", "fill", "generate", "touch", "edit", "recompute", "update", "compile",
    "evaluate", "exist", "differ", "suppress", "resist", "shape", "operate", "obfuscate",
    "complement", "frame", "define", "distinguish", "assume", "state", "treat", "let", "enter",
    "reflect", "produce", "lay", "consider", "realize", "reduce", "present", "provide",
    "measure", "implement", "actuate", "echo", "arm", "confirm", "narrow", "raise", "expose",
    "reveal", "starve", "drift", "seek", "recover", "tell", "decode", "carry", "signal",
    "target", "violate", "check", "break", "cost", "force", "transform", "move", "ship", "read",
    "learn", "watch", "begin", "address", "separate", "test", "replace", "establish", "verify",
    "regenerate", "quantify", "permit", "bound", "fit", "hide", "morph", "adapt", "protect",
    "normalize", "split", "carve", "replicate", "pin", "anchor", "schedule", "block", "trigger",
    "load", "capture", "compare", "map", "match", "reassemble", "deliver", "process", "detect",
    "attack", "name", "predict", "observe", "vary", "help", "cause", "get", "take", "come",
    "go", "see", "find", "want", "call", "try", "ask", "turn", "start", "mean", "seem",
    "leave", "put", "build", "design", "act", "depend", "consist", "involve", "require",
    "support", "enable", "prevent", "achieve", "defend", "demonstrate", "characterize",
    "eliminate", "mitigate", "disrupt", "report", "count", "exclude", "include", "collapse",
    "settle", "remain", "sit", "fall", "rise", "span", "lie", "cancel", "subtract", "learn",
    "admit", "prepare", "allocate", "reject", "refuse", "restrict", "limit", "cover", "list",
    "describe", "explain", "argue", "note", "discuss", "extend", "follow", "train", "classify",
    "estimate", "compute", "derive", "plot", "draw", "assert", "disclose", "hash", "verify",
    "poll", "wait", "expire", "retire", "clear", "guard", "bypass", "recirculate", "queue",
    "drain", "prime", "stamp", "spend", "own", "share", "serve", "isolate", "attribute",
    "matter", "suffice", "hurt", "reveal", "grant", "pass", "gate", "form", "belong",
}

CONTRIB_VERB_LEXICON = {
    "disrupts", "mitigates", "normalizes", "holds", "shows", "measures", "implements",
    "evaluates", "reduces", "presents", "provides", "designs", "builds", "demonstrates",
    "characterizes", "suppresses", "has", "achieves", "enables", "defends", "prevents",
    "obfuscates", "proposes", "introduces", "quantifies", "pins", "removes", "replaces",
    "supports", "handles", "isolates", "separates", "establishes", "reports", "bounds",
}
# A contribution headline is normally written in the bare imperative ("Design a framework",
# "Implement it on a Tofino", "Evaluate it against a relay") rather than in the third person.
# Both forms are verb-first; the lexicon above only carried the third-person form, so the bare
# stems are added here and the two sets are checked together.
CONTRIB_VERB_LEXICON |= {
    "disrupt", "mitigate", "normalize", "hold", "show", "measure", "implement",
    "evaluate", "reduce", "present", "provide", "design", "build", "demonstrate",
    "characterize", "suppress", "have", "achieve", "enable", "defend", "prevent",
    "obfuscate", "propose", "introduce", "quantify", "pin", "remove", "replace",
    "support", "handle", "isolate", "separate", "establish", "report", "bound",
}


# --------------------------------------------------------------------------- #
# Result model and document parsing
# --------------------------------------------------------------------------- #

class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "NA"


@dataclass
class CheckResult:
    name: str
    status: Status
    summary: str
    numbers: Dict[str, object] = field(default_factory=dict)
    detail: List[str] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Section:
    title: str
    order: int
    raw: str
    prose: str
    level: int  # 1 = \section, 2 = \subsection


@dataclass
class Document:
    path: str
    kind: str
    raw: str
    prose: str
    paragraphs: List[str]
    sentences: List[str]
    sections: List[Section]
    is_fragment: bool
    bib_keys: Optional[set]
    pdf_pages: Optional[List[str]]


def _strip(text: str) -> str:
    if VOICE is not None:
        try:
            return VOICE.strip_markup(text)
        except (Exception, SystemExit):
            pass
    text = re.sub(r"(?:^|(?<=\s))%.*", "", text, flags=re.M)
    text = re.sub(r"\\[a-zA-Z]+\*?(?:\[[^\]]*\])?(?:\{([^{}]*)\})?", r"\1", text)
    text = re.sub(r"^#{1,6}\s+.*$", "", text, flags=re.M)
    text = re.sub(r"\*\*?|__?", "", text)
    return text


def _split_sentences(text: str) -> List[str]:
    if VOICE is not None:
        try:
            return VOICE.split_sentences(text)
        except (Exception, SystemExit):
            pass
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if len(p.split()) >= 4]


def _strip_comments(raw: str) -> str:
    return re.sub(r"(?<!\\)%.*", "", raw)


def _parse_sections(raw: str, kind: str) -> List[Section]:
    heads: List[Tuple[int, str, int]] = []
    if kind == "tex":
        for m in re.finditer(r"\\(section|subsection)\*?\{([^}]*)\}", raw):
            heads.append((m.start(), m.group(2).strip(), 1 if m.group(1) == "section" else 2))
    elif kind == "md":
        for m in re.finditer(r"^(#{1,3})\s+(.*)$", raw, flags=re.M):
            heads.append((m.start(), m.group(2).strip(), len(m.group(1))))
    if not heads:
        return []
    out = []
    for i, (pos, title, lvl) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(raw)
        body = raw[pos:end]
        out.append(Section(title=title, order=i, raw=body, prose=_strip(body), level=lvl))
    return out


def _load_bib_keys(draft_path: str, raw: str, bib_arg: Optional[str]) -> Optional[set]:
    paths = []
    if bib_arg:
        paths = [bib_arg]
    else:
        m = re.search(r"\\bibliography\{([^}]*)\}", raw)
        if m:
            for name in m.group(1).split(","):
                name = name.strip()
                cand = name if name.endswith(".bib") else name + ".bib"
                for base in (os.path.dirname(draft_path),
                             os.path.dirname(os.path.dirname(draft_path))):
                    p = os.path.join(base, cand)
                    if os.path.isfile(p):
                        paths.append(p)
                        break
    if not paths:
        return None
    keys = set()
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            keys.update(re.findall(r"^@\w+\s*\{\s*([^,\s]+)\s*,", fh.read(), flags=re.M))
    return keys


def _pdf_pages(pdf: Optional[str]) -> Optional[List[str]]:
    if not pdf or not os.path.isfile(pdf):
        return None
    try:
        out = subprocess.run(["pdftotext", "-layout", pdf, "-"], check=True,
                             capture_output=True, text=True).stdout
    except Exception as exc:  # pragma: no cover
        logger.warning("pdftotext failed: %s", exc)
        return None
    return out.split("\f")


def load_document(path: str, bib: Optional[str] = None, pdf: Optional[str] = None) -> Document:
    ext = os.path.splitext(path)[1].lower()
    kind = "tex" if ext == ".tex" else "md" if ext in (".md", ".markdown") else "txt"
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    if kind == "tex":
        raw = _strip_comments(raw)
    prose = _strip(raw)
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", prose) if p.strip()]
    paragraphs = [p for p in paragraphs if _split_sentences(p)]
    sentences = _split_sentences(prose)
    sections = _parse_sections(raw, kind)
    n_words = len(re.findall(r"[A-Za-z][A-Za-z'-]*", prose))
    is_fragment = (not sections) and n_words < 400
    return Document(path=path, kind=kind, raw=raw, prose=prose, paragraphs=paragraphs,
                    sentences=sentences, sections=sections, is_fragment=is_fragment,
                    bib_keys=_load_bib_keys(path, raw, bib), pdf_pages=_pdf_pages(pdf))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _leading_connective(sentence: str) -> Optional[str]:
    s = sentence.lstrip().lower()
    for conn in CONNECTIVES:
        if s.startswith(conn) and re.match(re.escape(conn) + r"\b", s):
            return conn
    return None


def _first_word(sentence: str) -> str:
    m = re.match(r"\s*([A-Za-z][A-Za-z'-]*)", sentence)
    return m.group(1).lower() if m else ""


def _lemma_candidates(word: str) -> set:
    w = word.lower()
    c = {w}
    if w.endswith("ies") and len(w) > 4:
        c.add(w[:-3] + "y")
    if w.endswith("es") and len(w) > 3:
        c.add(w[:-2]); c.add(w[:-1])
    elif w.endswith("s") and len(w) > 2:
        c.add(w[:-1])
    if w.endswith("ed") and len(w) > 3:
        c.add(w[:-2]); c.add(w[:-1])
    if w.endswith("ing") and len(w) > 4:
        c.add(w[:-3]); c.add(w[:-3] + "e")
    return c


def _has_finite_verb(clause: str) -> bool:
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z'-]*", clause)]
    for w in words:
        if w in AUX_VERBS or (VERB_BASES & _lemma_candidates(w)):
            return True
        if (w.endswith("ed") or w.endswith("ing")) and len(w) > 4:
            return True
    return False


def _find(patterns, text, flags=re.I):
    hits = []
    for pat in patterns:
        for m in re.finditer(pat, text, flags=flags):
            hits.append((m.start(), m.group(0)))
    return hits


def _context(text: str, pos: int, width: int = 70) -> str:
    return re.sub(r"\s+", " ", text[max(0, pos - width): pos + width]).strip()


# --------------------------------------------------------------------------- #
# Hard checks
# --------------------------------------------------------------------------- #

def check_forbidden_names(doc: Document) -> CheckResult:
    hits = []
    for name in FORBIDDEN_NAMES:
        for m in re.finditer(re.escape(name), doc.raw):
            hits.append("%s: %s" % (name, _context(doc.raw, m.start())))
    status = Status.FAIL if hits else Status.PASS
    return CheckResult("forbidden_names", status,
                       "%d forbidden name(s)" % len(hits) if hits else "no forbidden project or system name",
                       numbers={"hits": len(hits)}, detail=hits)


def check_stale_labels(doc: Document) -> CheckResult:
    hits = []
    for pos, text in _find(STALE_LABEL_PATTERNS, doc.prose):
        ctx = _context(doc.prose, pos)
        if any(re.search(a, ctx, flags=re.I) for a in STALE_LABEL_ALLOW):
            continue
        hits.append("%s: %s" % (text, ctx))
    status = Status.FAIL if hits else Status.PASS
    return CheckResult("stale_labels", status,
                       "%d stale arm label(s); use Timing OFF / Obfuscated" % len(hits) if hits
                       else "arms named Timing OFF / Obfuscated",
                       numbers={"hits": len(hits)}, detail=hits)


def check_firstness(doc: Document) -> CheckResult:
    hits = ["%s: %s" % (t, _context(doc.prose, p)) for p, t in _find(FIRSTNESS_PATTERNS, doc.prose)]
    # WARN, not FAIL: the author kept a firstness claim in the verbatim Introduction (2026-08-26).
    status = Status.WARN if hits else Status.PASS
    return CheckResult("firstness", status,
                       "%d firstness claim(s) present (author's choice; verify against the literature)" % len(hits) if hits
                       else "no firstness claim",
                       numbers={"hits": len(hits)}, detail=hits)


def check_em_dashes(doc: Document) -> CheckResult:
    hits = []
    for m in re.finditer(r"\u2014|(?<!-)---(?!-)", doc.prose):
        hits.append(_context(doc.prose, m.start(), 50))
    status = Status.FAIL if hits else Status.PASS
    return CheckResult("em_dashes", status,
                       "%d em dash(es)" % len(hits) if hits else "no em dashes",
                       numbers={"em_dashes": len(hits)}, detail=hits)


def check_size_claims(doc: Document) -> CheckResult:
    fails, infos = [], []
    for s in doc.sentences:
        if not re.search(SIZE_TERMS, s, flags=re.I):
            continue
        if re.search(OURS_MARKERS, s, flags=re.I) and not re.search(SIZE_EXEMPT, s, flags=re.I):
            fails.append(s.strip())
        else:
            infos.append(s.strip())
    status = Status.FAIL if fails else Status.PASS
    return CheckResult("size_claims", status,
                       "%d sentence(s) claim size obfuscation as ours" % len(fails) if fails
                       else "no size claim made as ours (%d context mention(s))" % len(infos),
                       numbers={"claimed": len(fails), "context_mentions": len(infos)},
                       detail=["CLAIM: " + f for f in fails])


REQUIRED_ORDER = [
    ("introduction", lambda t: "introduction" in t),
    ("background", lambda t: "background" in t),
    ("threat model", lambda t: "threat" in t),
    ("design", lambda t: "design" in t and "background" not in t),
    ("implementation", lambda t: "implementation" in t),
    ("evaluation", lambda t: "evaluation" in t),
    ("related work", lambda t: "related" in t),
    ("conclusion", lambda t: "conclusion" in t),
]


def check_structure(doc: Document) -> CheckResult:
    if doc.is_fragment or not doc.sections:
        return CheckResult("structure", Status.NA, "fragment: no section structure to check")
    top = [(s.order, s.title.lower()) for s in doc.sections if s.level == 1]
    problems = []
    found = {}
    for name, pred in REQUIRED_ORDER:
        o = next((o for o, t in top if pred(t)), None)
        found[name] = o
        if o is None:
            problems.append("missing section: %s" % name)
    present = [(found[n], n) for n, _ in REQUIRED_ORDER if found[n] is not None]
    for (o1, n1), (o2, n2) in zip(present, present[1:]):
        if o2 < o1:
            problems.append("section order: '%s' before '%s'" % (n2, n1))
    if found.get("related work") is not None and found.get("conclusion") is not None:
        later = [t for o, t in top if o > found["related work"] and o != found["conclusion"]]
        if later:
            problems.append("related work is not second-last (followed by %s)" % later)
    # labels
    labels = sorted(set(re.findall(r"\bRO\d+\b", doc.prose)))
    tm = next((s for s in doc.sections if s.level == 1 and "threat" in s.title.lower()), None)
    ev = next((s for s in doc.sections if s.level == 1 and "evaluation" in s.title.lower()), None)
    defined_in_tm = sorted(set(re.findall(r"\bRO\d+\b", tm.prose))) if tm else []
    # the evaluation's prose = its own section body until the next \section
    reused = []
    if ev:
        ev_end = next((s.order for s in doc.sections if s.level == 1 and s.order > ev.order), None)
        ev_prose = " ".join(s.prose for s in doc.sections
                            if s.order >= ev.order and (ev_end is None or s.order < ev_end))
        reused = sorted(set(l for l in labels if re.search(r"\b%s\b" % l, ev_prose)))
    if not labels:
        problems.append("no research-objective labels (RO1..) defined")
    elif not defined_in_tm:
        problems.append("RO labels are not defined in the threat-model section")
    elif not reused:
        problems.append("RO labels %s not reused in the Evaluation" % ",".join(labels))
    # limitations heading
    if not any("limitation" in s.title.lower() for s in doc.sections):
        problems.append("no Limitations section or subsection")
    status = Status.PASS if not problems else Status.FAIL
    return CheckResult("structure", status,
                       "; ".join(problems) if problems else
                       "required sections present and ordered; RO labels defined and reused; Limitations present",
                       numbers={"sections": found, "labels_defined": defined_in_tm,
                                "labels_reused_in_eval": reused},
                       detail=["section %d: %s" % (o, t) for o, t in top])


def check_figures_after_refs(doc: Document) -> CheckResult:
    problems = []
    if doc.kind == "tex":
        m = re.search(r"\\bibliography\{|\\begin\{thebibliography\}|\\printbibliography", doc.raw)
        if m and re.search(r"\\begin\{figure\*?\}|\\begin\{table\*?\}", doc.raw[m.end():]):
            problems.append("a figure/table environment appears after the bibliography command")
    if doc.pdf_pages:
        ref_page = next((i for i, p in enumerate(doc.pdf_pages)
                         if re.search(r"R\s?EFERENCES|\bReferences\b", p)), None)
        if ref_page is not None:
            for i, p in enumerate(doc.pdf_pages):
                if i > ref_page and re.search(r"\bFig\.\s*\d+[.:]", p):
                    problems.append("PDF page %d (after the References page %d) carries a figure caption"
                                    % (i + 1, ref_page + 1))
            # layout mode merges the two columns, so a caption on the References page itself
            # cannot be ordered against the heading from the text; it is reported for the
            # visual inspection, not failed.
            if re.search(r"\bFig\.\s*\d+[.:]", doc.pdf_pages[ref_page]):
                logger.warning("a figure caption shares page %d with the References heading; "
                               "confirm by visual inspection", ref_page + 1)
        else:
            problems.append("PDF given but no References heading found (check the render)")
    status = Status.FAIL if problems else Status.PASS
    return CheckResult("figures_after_refs", status,
                       "; ".join(problems) if problems else
                       ("no figure after References" + (" (PDF checked)" if doc.pdf_pages else "")),
                       numbers={"pdf_checked": bool(doc.pdf_pages)}, detail=problems)


def check_citations(doc: Document) -> CheckResult:
    if doc.kind != "tex":
        return CheckResult("citations", Status.NA, "not a .tex draft")
    cited = set()
    for m in re.finditer(r"\\cite[tp]?\*?(?:\[[^\]]*\])?\{([^}]*)\}", doc.raw):
        cited.update(k.strip() for k in m.group(1).split(",") if k.strip())
    if doc.bib_keys is None:
        return CheckResult("citations", Status.WARN, "no bibliography found to check %d keys against" % len(cited),
                           numbers={"cited": len(cited)})
    missing = sorted(k for k in cited if k not in doc.bib_keys)
    status = Status.FAIL if missing else Status.PASS
    return CheckResult("citations", status,
                       "%d undefined citation key(s)" % len(missing) if missing
                       else "all %d cited keys resolve" % len(cited),
                       numbers={"cited": len(cited), "missing": missing}, detail=missing)


def _headline_is_verb_first(headline: str) -> bool:
    first = _first_word(headline)
    if not first or first in ("a", "an", "the", "our", "this", "we"):
        return False
    if first in CONTRIB_VERB_LEXICON:
        return True
    return bool(re.match(r"[a-z]+(?:s|es)$", first) and first not in
                {"process", "access", "address", "analysis", "class"})


def _find_contribution_headlines(doc: Document) -> List[str]:
    heads = []
    if doc.kind == "tex":
        for m in re.finditer(r"\\begin\{itemize\}(.*?)\\end\{itemize\}", doc.raw, flags=re.S):
            block = m.group(1)
            pre = doc.raw[max(0, m.start() - 400):m.start()].lower()
            if "contribution" not in pre and "contribution" not in block.lower():
                continue
            for hm in re.finditer(r"\\item\s*\\textbf\{([^}]*)\}", block):
                heads.append(hm.group(1).strip())
    else:
        cue = re.search(r"contribution", doc.raw, flags=re.I)
        region = doc.raw[cue.start():] if cue else doc.raw
        for hm in re.finditer(r"^\s*[-*]\s*\*\*([^*]+)\*\*", region, flags=re.M):
            heads.append(hm.group(1).strip())
    return heads


def check_contribution_grammar(doc: Document) -> CheckResult:
    if doc.is_fragment:
        return CheckResult("contribution_grammar", Status.NA, "fragment: no contributions list expected")
    heads = _find_contribution_headlines(doc)
    if not heads:
        return CheckResult("contribution_grammar", Status.WARN, "no bold contribution headlines found (plain bullets accepted)",
                           numbers={"headlines": 0})
    non_verb = [h for h in heads if not _headline_is_verb_first(h)]
    status = Status.PASS if not non_verb else Status.WARN   # the author's contribution list is kept verbatim
    return CheckResult("contribution_grammar", status,
                       "%d/%d headlines are not verb-first" % (len(non_verb), len(heads)) if non_verb
                       else "all %d contribution headlines verb-first" % len(heads),
                       numbers={"headlines": len(heads), "not_verb_first": len(non_verb)},
                       detail=["not verb-first: " + h for h in non_verb])


def _is_dangling_subordinate(sentence: str) -> bool:
    s = sentence.strip()
    low = s.lower()
    first = _first_word(s)
    if re.match(r"by\s+\w+ing\b", low) and re.search(r"\b(?:because|since|so that|as)\b", low):
        return True
    if first in SUBORDINATORS:
        for c in [c.strip() for c in re.split(r",|;", s) if c.strip()]:
            cw = _first_word(c)
            if cw in SUBORDINATORS or cw in ("such", "which", "who", "that"):
                continue
            if _has_finite_verb(c):
                return False
        return True
    return False


def check_sentence_health(doc: Document) -> CheckResult:
    if not doc.sentences:
        return CheckResult("sentence_health", Status.NA, "no sentences")
    fragments, verbless = [], []
    intro = next((sec for sec in doc.sections if sec.level == 1 and "introduction" in sec.title.lower()), None)
    intro_norm = re.sub(r"\s+", " ", intro.prose) if intro else ""
    for s in doc.sentences:
        if intro_norm and re.sub(r"\s+", " ", s.strip())[:80] in intro_norm:
            continue   # the Introduction is the authors' verbatim text; not scored
        if _is_dangling_subordinate(s):
            fragments.append(s)
        elif not _has_finite_verb(s):
            verbless.append(s)
    if fragments:
        status, summary = Status.FAIL, "%d dangling / no-main-clause fragment(s)" % len(fragments)
    elif verbless:
        status, summary = Status.WARN, "%d sentence(s) with no obvious finite verb" % len(verbless)
    else:
        status, summary = Status.PASS, "no fragments detected"
    return CheckResult("sentence_health", status, summary,
                       numbers={"fragments": len(fragments), "verbless_warnings": len(verbless),
                                "sentences": len(doc.sentences)},
                       detail=["FRAGMENT: " + f for f in fragments] + ["no-verb?: " + v for v in verbless])


# --------------------------------------------------------------------------- #
# Soft checks
# --------------------------------------------------------------------------- #

def check_acronyms(doc: Document) -> CheckResult:
    prose = doc.prose
    defined = set(re.findall(r"\(([A-Z][A-Za-z0-9-]{1,8})s?\)", prose))
    # also: "ACRONYM (expansion)" form is rare; accept "term (ACR)" only.
    seen_pos: Dict[str, int] = {}
    for m in re.finditer(r"\b([A-Z][A-Z0-9-]{1,7})s?\b", prose):
        a = m.group(1)
        if (a in ACRONYM_ALLOW or a in defined or re.fullmatch(r"[A-Z]", a)
                or re.fullmatch(r"[0-9-]+", a) or a.endswith("-")):
            continue
        seen_pos.setdefault(a, m.start())
    undefined = {}
    for a, pos in seen_pos.items():
        dm = re.search(r"\(%s\)" % re.escape(a), prose)
        if dm is None or dm.start() > pos:
            undefined[a] = _context(prose, pos, 40)
    status = Status.WARN if undefined else Status.PASS
    return CheckResult("acronyms", status,
                       "%d acronym(s) used before definition" % len(undefined) if undefined
                       else "every acronym defined before use (allow-list applied)",
                       numbers={"undefined": sorted(undefined)},
                       detail=["%s: %s" % (a, c) for a, c in sorted(undefined.items())])


def _readability(text: str):
    if VOICE is None:
        return None
    try:
        m = VOICE.measure(text)
        return m["flesch_reading_ease"], m["fk_grade"]
    except (Exception, SystemExit):
        return None


def check_readability(doc: Document) -> CheckResult:
    r = _readability(doc.prose)
    if r is None:
        return CheckResult("readability", Status.NA, "voice_check unavailable")
    fre, fk = r
    dense = []
    per = []
    for sec in doc.sections:
        if sec.level != 1:
            continue
        rr = _readability(sec.prose)
        if rr is None:
            continue
        per.append("%s: flesch %.1f fk %.1f" % (sec.title, rr[0], rr[1]))
        if rr[0] < FLESCH_FLOOR or rr[1] > FK_CEILING:
            dense.append(sec.title)
    too_dense = fre < FLESCH_FLOOR or fk > FK_CEILING
    status = Status.WARN if (too_dense or dense) else Status.PASS
    return CheckResult("readability", status,
                       "too dense: overall flesch %.1f / fk %.1f; dense sections %s" % (fre, fk, dense)
                       if status is Status.WARN else "readability within band (flesch %.1f, fk %.1f)" % (fre, fk),
                       numbers={"overall_flesch": fre, "overall_fk_grade": fk,
                                "flesch_floor": FLESCH_FLOOR, "fk_ceiling": FK_CEILING},
                       detail=per)


def check_fact_hygiene(doc: Document) -> CheckResult:
    warnings = []
    para_tokens = {t: [] for t in MARQUEE_TOKENS}
    for i, para in enumerate(doc.paragraphs):
        low = para.lower()
        for stem in MARQUEE_TOKENS:
            if re.search(r"\b%s" % stem, low):
                para_tokens[stem].append(i)
    for stem, ps in para_tokens.items():
        if len(ps) > 1:
            warnings.append("'%s' appears in %d paragraphs (use each marquee example once)"
                            % (MARQUEE_TOKENS[stem], len(ps)))
    for stem, canon in MARQUEE_CANON_YEAR.items():
        for m in re.finditer(r"\b%s" % stem, doc.prose, flags=re.I):
            window = doc.prose[max(0, m.start() - 120):m.end() + 120]
            for y in re.findall(r"\b(?:19|20)\d{2}\b", window):
                if y != canon:
                    warnings.append("'%s' near year %s (expected %s)" % (MARQUEE_TOKENS[stem], y, canon))
    warnings = sorted(set(warnings))
    return CheckResult("fact_hygiene", Status.WARN if warnings else Status.PASS,
                       "; ".join(warnings) if warnings else "no duplicate marquee examples or year slips",
                       detail=warnings)


def check_connective_spine(doc: Document) -> CheckResult:
    sents = doc.sentences
    if not sents:
        return CheckResult("connective_spine", Status.NA, "no sentences")
    led = [s for s in sents if _leading_connective(s)]
    counts: Dict[str, int] = {}
    for s in led:
        c = _leading_connective(s)
        counts[c] = counts.get(c, 0) + 1
    frac = len(led) / len(sents)
    return CheckResult("connective_spine", Status.PASS,
                       "informational: %.1f%% of sentences lead with a connective (not scored)" % (100 * frac),
                       numbers={"overall_fraction": round(frac, 3), "by_connective": counts})


def check_voice(doc: Document) -> CheckResult:
    if VOICE is None:
        return CheckResult("voice_fingerprint", Status.NA, "voice_check.py unavailable")
    try:
        m = VOICE.measure(doc.raw)
    except SystemExit as exc:
        return CheckResult("voice_fingerprint", Status.NA, str(exc))
    except Exception as exc:  # pragma: no cover
        return CheckResult("voice_fingerprint", Status.WARN, "voice_check failed: %s" % exc)
    flags = m.get("ai_flags", {})
    numbers = {
        "words_per_sentence_mean": m.get("words_per_sentence_mean"),
        "we_per_100_sentences": m.get("we_per_100_sentences"),
        "hedges_per_1000_words": m.get("hedges_per_1000_words"),
        "flesch_reading_ease": m.get("flesch_reading_ease"),
        "fk_grade": m.get("fk_grade"),
        "ai_flags": flags,
    }
    total = int(sum(flags.values())) if flags else 0
    return CheckResult("voice_fingerprint", Status.WARN if total else Status.PASS,
                       "voice measured; %d AI-pattern flag(s)" % total if total else "voice measured; no AI-pattern flags",
                       numbers=numbers, detail=["%s: %s" % kv for kv in flags.items()])


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

HARD_CHECKS = {
    "forbidden_names", "stale_labels", "em_dashes", "size_claims", "structure",
    "figures_after_refs", "citations", "sentence_health",
}


def run_all(doc: Document) -> List[CheckResult]:
    return [
        check_forbidden_names(doc), check_stale_labels(doc), check_firstness(doc),
        check_em_dashes(doc), check_size_claims(doc), check_structure(doc),
        check_figures_after_refs(doc), check_citations(doc), check_contribution_grammar(doc),
        check_sentence_health(doc), check_acronyms(doc), check_readability(doc),
        check_fact_hygiene(doc), check_connective_spine(doc), check_voice(doc),
    ]


def _exit_code(results: List[CheckResult]) -> int:
    return 1 if any(r.status is Status.FAIL and r.name in HARD_CHECKS for r in results) else 0


def build_payload(doc: Document, results: List[CheckResult], code: int) -> Dict[str, object]:
    return {"draft": doc.path, "kind": doc.kind, "is_fragment": doc.is_fragment,
            "n_sentences": len(doc.sentences), "n_sections": len(doc.sections),
            "exit_code": code, "checks": [r.to_dict() for r in results]}


def score_document(path: str, bib=None, pdf=None) -> Dict[str, object]:
    doc = load_document(path, bib, pdf)
    results = run_all(doc)
    return build_payload(doc, results, _exit_code(results))


def _looks_like_scorecard(path: str) -> bool:
    if path.lower().endswith(".json"):
        return True
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096).lstrip()
        if not head.startswith("{"):
            return False
        with open(path, encoding="utf-8", errors="replace") as fh:
            obj = json.load(fh)
        return isinstance(obj, dict) and "checks" in obj
    except (ValueError, OSError):
        return False


def load_or_score(path: str, bib=None, pdf=None) -> Dict[str, object]:
    if _looks_like_scorecard(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            payload = json.load(fh)
        if "checks" not in payload:
            raise ValueError("%s is JSON but not a lin_check scorecard" % path)
        payload.setdefault("draft", path)
        payload["source"] = "scorecard"
        return payload
    payload = score_document(path, bib, pdf)
    payload["source"] = "scored"
    return payload


def print_report(doc: Document, results: List[CheckResult]) -> None:
    n_words = len(re.findall(r"[A-Za-z][A-Za-z'-]*", doc.prose))
    print("=" * 78)
    print("lin_check  -  manuscript gate (Dr. Lin writing guide, 2026-08-26 brief)")
    print("draft: %s  (%s, %d sentences, %d words, %d sections%s)"
          % (doc.path, doc.kind, len(doc.sentences), n_words, len(doc.sections),
             ", FRAGMENT" if doc.is_fragment else ""))
    print("=" * 78)
    for r in results:
        hard = " [hard]" if r.name in HARD_CHECKS else ""
        print("[%-4s] %-22s%s  %s" % (r.status.value, r.name, hard, r.summary))
        for key, val in r.numbers.items():
            print("         %-26s = %s" % (key, val))
        for line in r.detail[:40]:
            print("           - %s" % line)
        if len(r.detail) > 40:
            print("           - ... %d more" % (len(r.detail) - 40))
    print("-" * 78)
    hard_fails = [r.name for r in results if r.status is Status.FAIL and r.name in HARD_CHECKS]
    warns = [r.name for r in results if r.status is Status.WARN]
    print("RESULT: %s" % ("FAIL  (hard checks failing: %s)" % ", ".join(hard_fails) if hard_fails
                          else "PASS  (no hard-check failures)"))
    if warns:
        print("        warnings: %s" % ", ".join(warns))
    print("=" * 78)


# --------------------------------------------------------------------------- #
# Non-regression compare
# --------------------------------------------------------------------------- #

REGRESSION_EXIT = 3


def _by_name(payload):
    return {c["name"]: c for c in payload.get("checks", [])}


def _num(check, key, default=None):
    return check.get("numbers", {}).get(key, default) if check else default


def _voice_dev(check):
    flags = check.get("numbers", {}).get("ai_flags") if check else None
    return None if flags is None else int(sum(flags.values()))


def _outside(check):
    if not check:
        return None
    n = check.get("numbers", {})
    fre, fk = n.get("overall_flesch"), n.get("overall_fk_grade")
    if fre is None or fk is None:
        return None
    return round(max(0.0, n.get("flesch_floor", FLESCH_FLOOR) - fre)
                 + max(0.0, fk - n.get("fk_ceiling", FK_CEILING)), 2)


def compare_payloads(before, after):
    b, a = _by_name(before), _by_name(after)
    regressions, improvements, rows = [], [], []
    for hc in sorted(HARD_CHECKS):
        bs, as_ = b.get(hc, {}).get("status"), a.get(hc, {}).get("status")
        if as_ == "FAIL" and bs in ("PASS", "WARN", "NA"):
            regressions.append("%s: status %s -> FAIL" % (hc, bs))
        elif bs == "FAIL" and as_ in ("PASS", "WARN"):
            improvements.append("%s: status FAIL -> %s" % (hc, as_))

    def rec(name, bv, av, lower_is_better, fmt):
        verdict = "same"
        if bv is not None and av is not None:
            worse = (av > bv + 1e-9) if lower_is_better else (av < bv - 1e-9)
            better = (av < bv - 1e-9) if lower_is_better else (av > bv + 1e-9)
            if worse:
                verdict = "WORSE"; regressions.append("%s: %s -> %s" % (name, fmt % bv, fmt % av))
            elif better:
                verdict = "better"; improvements.append("%s: %s -> %s" % (name, fmt % bv, fmt % av))
        rows.append({"dimension": name, "before": bv, "after": av, "verdict": verdict})

    rec("sentence_health.fragments", _num(b.get("sentence_health"), "fragments"),
        _num(a.get("sentence_health"), "fragments"), True, "%d")
    rec("voice_fingerprint.ai_flags", _voice_dev(b.get("voice_fingerprint")),
        _voice_dev(a.get("voice_fingerprint")), True, "%d")
    rec("readability.outside_band", _outside(b.get("readability")), _outside(a.get("readability")), True, "%.2f")
    rec("em_dashes", _num(b.get("em_dashes"), "em_dashes"), _num(a.get("em_dashes"), "em_dashes"), True, "%d")
    rec("stale_labels.hits", _num(b.get("stale_labels"), "hits"), _num(a.get("stale_labels"), "hits"), True, "%d")
    status_rows = [{"check": n, "before_status": b.get(n, {}).get("status", "-"),
                    "after_status": a.get(n, {}).get("status", "-"), "hard": n in HARD_CHECKS}
                   for n in [c["name"] for c in after.get("checks", [])]]
    code = REGRESSION_EXIT if regressions else 0
    return {"before": before.get("draft"), "after": after.get("draft"),
            "before_source": before.get("source", "scored"), "after_source": after.get("source", "scored"),
            "verdict": "REGRESSION" if regressions else "NO REGRESSION", "exit_code": code,
            "regressions": regressions, "improvements": improvements,
            "numeric_dimensions": rows, "status_rows": status_rows}, code


def print_compare(comp):
    print("=" * 78)
    print("lin_check --compare  (non-regression gate)")
    print("BEFORE: %s  [%s]" % (comp["before"], comp["before_source"]))
    print("AFTER : %s  [%s]" % (comp["after"], comp["after_source"]))
    print("=" * 78)
    for row in comp["numeric_dimensions"]:
        print("%-30s %10s %10s   %s" % (row["dimension"], row["before"], row["after"], row["verdict"]))
    print("-" * 78)
    for sr in comp["status_rows"]:
        print("  %-22s %5s -> %-5s%s" % (sr["check"], sr["before_status"], sr["after_status"],
                                          " [hard]" if sr["hard"] else ""))
    for i in comp["improvements"]:
        print("  + " + i)
    if comp["verdict"] == "REGRESSION":
        print("VERDICT: REGRESSION")
        for r in comp["regressions"]:
            print("  ! " + r)
    else:
        print("VERDICT: NO REGRESSION (equal or better on every hard dimension)")
    print("=" * 78)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", nargs="?")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--bib", help="bibliography file(s) to resolve \\cite keys against")
    ap.add_argument("--pdf", help="compiled PDF; checks that no figure follows References")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(name)s: %(levelname)s: %(message)s")
    if args.compare:
        for p in args.compare:
            if not os.path.isfile(p):
                logger.error("compare input not found: %s", p)
                return 2
        try:
            before = load_or_score(args.compare[0], args.bib, args.pdf)
            after = load_or_score(args.compare[1], args.bib, args.pdf)
        except ValueError as exc:
            logger.error("%s", exc)
            return 2
        comp, code = compare_payloads(before, after)
        print(json.dumps(comp, indent=2) if args.json else "", end="")
        if not args.json:
            print_compare(comp)
        return code
    if not args.draft:
        ap.error("provide a draft to score, or use --compare BEFORE AFTER")
    if not os.path.isfile(args.draft):
        logger.error("draft not found: %s", args.draft)
        return 2
    doc = load_document(args.draft, args.bib, args.pdf)
    results = run_all(doc)
    code = _exit_code(results)
    if args.json:
        print(json.dumps(build_payload(doc, results, code), indent=2))
    else:
        print_report(doc, results)
    return code


if __name__ == "__main__":
    sys.exit(main())
