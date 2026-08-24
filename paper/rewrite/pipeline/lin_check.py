#!/usr/bin/env python3
"""lin_check.py - reproducible ENFORCEMENT scorer for the Dr. Lin writing contract.

Layer B of the writing-pipeline rebuild. Grades a draft (.tex / .md / .txt)
against the checkable signals in ``paper/LIN_STYLE_CONTRACT.md`` (see the table
in section 9). It WRAPS the existing voice fingerprint from
``~/.claude/skills/paper-voice/scripts/voice_check.py`` (sentence / lexicon /
stance metrics are reused, not reimplemented) and ADDS the structural,
connective, contribution-grammar, readability, sentence-health and fact-hygiene
checks the contract requires.

Usage:
    python3 lin_check.py DRAFT.tex
    python3 lin_check.py DRAFT.txt --json
    python3 lin_check.py DRAFT.md  --connective-target 0.12

Fail-closed: exits non-zero if any hard check reports FAIL. WARN and NA do not
change the exit code. Deterministic - no network, no randomness.

Reuses $RESEARCH_PYTHON (numpy present, textstat optional). Readability degrades
gracefully to the Flesch / Flesch-Kincaid formulas from voice_check when the
textstat package is absent.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("lin_check")

# --------------------------------------------------------------------------- #
# Reuse the paper-voice fingerprint. We import its module and call its
# strip_markup / split_sentences / measure / count_syllables so the sentence,
# lexicon and stance metrics stay single-sourced.
# --------------------------------------------------------------------------- #

_VOICE_CHECK_PATH = os.path.expanduser(
    "~/.claude/skills/paper-voice/scripts/voice_check.py"
)


def _import_voice_check():
    """Import voice_check.py by absolute path; return the module or None."""
    if not os.path.isfile(_VOICE_CHECK_PATH):
        logger.warning("voice_check.py not found at %s", _VOICE_CHECK_PATH)
        return None
    import importlib.util

    spec = importlib.util.spec_from_file_location("voice_check", _VOICE_CHECK_PATH)
    if spec is None or spec.loader is None:
        logger.warning("could not build import spec for voice_check.py")
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("failed to import voice_check.py: %s", exc)
        return None
    return module


VOICE = _import_voice_check()


# --------------------------------------------------------------------------- #
# Contract constants (LIN_STYLE_CONTRACT.md sections 4, 5, 9).
# --------------------------------------------------------------------------- #

# The scored connective spine (contract section 5 / task spec). Multi-word
# phrases first so they match before their single-word prefixes.
CONNECTIVES: Tuple[str, ...] = (
    "for example",
    "for instance",
    "as a result",
    "consequently",
    "because",
    "since",
    "however",
    "unfortunately",
    "therefore",
    "thus",
    "instead",
    "hence",
)

DEFAULT_CONNECTIVE_TARGET = 0.12  # overall fraction of sentences led by a connective

# Readability band (the "too dense" guard, contract section 5 / 9).
FLESCH_FLOOR = 15.0   # below -> too dense
FK_CEILING = 18.0     # above -> too dense

# Subordinators used for the dangling-clause fragment class (contract section 5).
SUBORDINATORS: Tuple[str, ...] = (
    "because", "since", "although", "while", "when", "if", "as", "whereas",
    "given", "though",
)

# Marquee example stems for fact hygiene (contract section 5). Stems match
# inflected forms, e.g. "ukrain" catches both "Ukraine" and "Ukrainian".
MARQUEE_TOKENS: Dict[str, str] = {
    "ukrain": "Ukraine", "stuxnet": "Stuxnet", "mirai": "Mirai",
    "colonial": "Colonial",
}
# Known-correct years for a marquee example -> any other year near it warns.
MARQUEE_CANON_YEAR: Dict[str, str] = {"ukrain": "2015"}

# Auxiliaries, modals and copulas: surface forms are matched directly.
AUX_VERBS = {
    "is", "are", "was", "were", "be", "been", "being", "am",
    "has", "have", "had", "do", "does", "did",
    "can", "could", "will", "would", "shall", "should", "may", "might",
    "must", "cannot", "wo", "ca",  # wo/ca from won't / can't tokenization
}

# Base forms of common English + draft-domain verbs. A crude lemmatizer maps a
# surface word (sends, confirmed, repeats, relies) back to its base before this
# lookup, so we need bases only. Kept broad on purpose: the safe failure
# direction for the sentence-health check is to over-detect a verb (never
# false-FAIL a well-formed clause).
VERB_BASES = {
    "make", "use", "show", "reach", "focus", "rely", "work", "know", "hold",
    "release", "run", "add", "change", "offload", "introduce", "leak",
    "identify", "inject", "pad", "stay", "shift", "apply", "need", "become",
    "give", "place", "send", "return", "arrive", "answer", "record", "repeat",
    "mark", "fix", "keep", "bring", "create", "install", "write", "initialize",
    "forward", "drop", "seed", "fill", "generate", "touch", "edit", "recompute",
    "update", "compile", "evaluate", "exist", "differ", "suppress", "resist",
    "shape", "operate", "obfuscate", "complement", "frame", "define",
    "distinguish", "assume", "state", "treat", "let", "enter", "reflect",
    "produce", "lay", "consider", "realize", "reduce", "present", "provide",
    "measure", "implement", "actuate", "echo", "arm", "confirm", "arbitrate",
    "narrow", "raise", "shat", "expose", "reveal", "co-place", "starve",
    "drift", "seek", "recover", "tell", "decode", "carry", "signal", "target",
    "violate", "check", "break", "cost", "force", "transform", "move", "ship",
    "read", "learn", "watch", "begin", "address", "separate", "test", "replace",
    "establish", "verify", "regenerate", "quantify", "permit", "brings",
    "install", "bound", "fit", "hide", "morph", "adapt", "collide", "cooperate",
    "protect", "normalize", "split", "carve", "replicate", "pin", "anchor",
    "schedule", "block", "trigger", "load", "capture", "compare", "differ",
    "map", "match", "reassemble", "deliver", "process", "detect", "attack",
    "watch", "learn", "name", "predict", "observe", "assume", "hold", "vary",
    "help", "cause", "get", "take", "come", "go", "see", "find", "want",
    "call", "try", "ask", "turn", "start", "mean", "keep", "let", "begin",
    "seem", "leave", "put", "build", "design", "act", "depend", "consist",
    "involve", "require", "support", "enable", "prevent", "achieve", "defend",
    "demonstrate", "characterize", "eliminate", "mitigate", "disrupt",
}


# --------------------------------------------------------------------------- #
# Result model.
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

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# --------------------------------------------------------------------------- #
# Document parsing.
# --------------------------------------------------------------------------- #

@dataclass
class Section:
    title: str
    order: int
    raw: str          # raw markup of the section body
    prose: str        # markup stripped


@dataclass
class Document:
    path: str
    kind: str                       # "tex" | "md" | "txt"
    raw: str
    prose: str                      # whole-document markup stripped
    paragraphs: List[str]
    sentences: List[str]
    sections: List[Section]
    is_fragment: bool               # no sections + short => structural checks NA


def _strip(text: str) -> str:
    if VOICE is not None:
        return VOICE.strip_markup(text)
    # Minimal fallback if voice_check is unavailable.
    text = re.sub(r"(?:^|(?<=\s))%.*", "", text, flags=re.M)
    text = re.sub(r"\\[a-zA-Z]+\*?(?:\[[^\]]*\])?(?:\{([^{}]*)\})?", r"\1", text)
    text = re.sub(r"^#{1,6}\s+.*$", "", text, flags=re.M)
    text = re.sub(r"\*\*?|__?", "", text)
    return text


def _split_sentences(text: str) -> List[str]:
    if VOICE is not None:
        return VOICE.split_sentences(text)
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if len(p.split()) >= 4]


def _parse_sections(raw: str, kind: str) -> List[Section]:
    """Split into sections by \\section{...} (tex) or leading # headers (md)."""
    heads: List[Tuple[int, str]] = []
    if kind == "tex":
        for m in re.finditer(r"\\section\*?\{([^}]*)\}", raw):
            heads.append((m.start(), m.group(1).strip()))
    elif kind == "md":
        for m in re.finditer(r"^(#{1,3})\s+(.*)$", raw, flags=re.M):
            heads.append((m.start(), m.group(2).strip()))
    if not heads:
        return []
    sections: List[Section] = []
    for i, (pos, title) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(raw)
        body = raw[pos:end]
        sections.append(
            Section(title=title, order=i, raw=body, prose=_strip(body))
        )
    return sections


def load_document(path: str) -> Document:
    ext = os.path.splitext(path)[1].lower()
    kind = "tex" if ext == ".tex" else "md" if ext in (".md", ".markdown") else "txt"
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    prose = _strip(raw)
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", prose) if p.strip()]
    paragraphs = [p for p in paragraphs if _split_sentences(p)]
    sentences = _split_sentences(prose)
    sections = _parse_sections(raw, kind)
    n_words = len(re.findall(r"[A-Za-z][A-Za-z'-]*", prose))
    is_fragment = (not sections) and n_words < 400
    return Document(
        path=path, kind=kind, raw=raw, prose=prose, paragraphs=paragraphs,
        sentences=sentences, sections=sections, is_fragment=is_fragment,
    )


# --------------------------------------------------------------------------- #
# Shared helpers.
# --------------------------------------------------------------------------- #

def _leading_connective(sentence: str) -> Optional[str]:
    """Return the connective a sentence leads with, else None."""
    s = sentence.lstrip().lower()
    for conn in CONNECTIVES:
        # must be at the very start and be a whole-word / phrase boundary
        if s.startswith(conn) and re.match(re.escape(conn) + r"\b", s):
            return conn
    return None


def _first_word(sentence: str) -> str:
    m = re.match(r"\s*([A-Za-z][A-Za-z'-]*)", sentence)
    return m.group(1).lower() if m else ""


def _lemma_candidates(word: str) -> set:
    """Crude base-form candidates: uses->{us,use}, relies->rely, sending->send.

    English inflection is ambiguous from spelling alone (violates->violate vs
    focuses->focus), so we return several candidates and let any match count.
    """
    w = word.lower()
    cands = {w}
    if w.endswith("ies") and len(w) > 4:
        cands.add(w[:-3] + "y")
    if w.endswith("es") and len(w) > 3:
        cands.add(w[:-2])          # focuses->focus, reaches->reach
        cands.add(w[:-1])          # violates->violate, uses->use
    elif w.endswith("s") and len(w) > 2:
        cands.add(w[:-1])          # sends->send
    if w.endswith("ed") and len(w) > 3:
        cands.add(w[:-2])          # worked->work
        cands.add(w[:-1])          # placed->place
    if w.endswith("ing") and len(w) > 4:
        cands.add(w[:-3])          # sending->send
        cands.add(w[:-3] + "e")    # placing->place
    return cands


def _has_finite_verb(clause: str) -> bool:
    """Best-effort: does the clause contain a finite/main verb?

    Matches auxiliaries/modals by surface form, and content verbs by generating
    base-form candidates and looking them up in a broad base-verb set, plus a
    -ed / -ing morphology fallback. Over-detection is the safe direction for the
    sentence-health FAIL check (never false-FAIL a well-formed clause).
    """
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z'-]*", clause)]
    for w in words:
        if w in AUX_VERBS:
            return True
        if VERB_BASES & _lemma_candidates(w):
            return True
        # verb-specific morphology (past / gerund) not covered by the lexicon
        if (w.endswith("ed") or w.endswith("ing")) and len(w) > 4:
            return True
    return False


# --------------------------------------------------------------------------- #
# Check 1: connective-spine density (contract section 5, table row 1).
# --------------------------------------------------------------------------- #

def check_connective_spine(doc: Document, target: float) -> CheckResult:
    sents = doc.sentences
    if not sents:
        return CheckResult("connective_spine", Status.NA,
                           "no measurable sentences")
    led = [s for s in sents if _leading_connective(s)]
    overall = len(led) / len(sents)

    per_para: List[Dict[str, object]] = []
    for i, para in enumerate(doc.paragraphs):
        psents = _split_sentences(para)
        if not psents:
            continue
        pled = sum(1 for s in psents if _leading_connective(s))
        per_para.append({
            "paragraph": i,
            "sentences": len(psents),
            "led": pled,
            "fraction": round(pled / len(psents), 3),
            "leads_with_connective": bool(_leading_connective(psents[0])),
        })

    counts: Dict[str, int] = {}
    for s in led:
        c = _leading_connective(s)
        counts[c] = counts.get(c, 0) + 1

    status = Status.PASS if overall >= target else Status.FAIL
    summary = ("%.1f%% of sentences lead with a logical connective "
               "(target >= %.1f%%)" % (100 * overall, 100 * target))
    return CheckResult(
        "connective_spine", status, summary,
        numbers={
            "overall_fraction": round(overall, 3),
            "target": target,
            "sentences_led": len(led),
            "sentences_total": len(sents),
            "by_connective": counts,
        },
        detail=[
            "para %d: %d/%d led (%.0f%%)%s" % (
                p["paragraph"], p["led"], p["sentences"],
                100 * float(p["fraction"]),
                "" if p["leads_with_connective"] else "")
            for p in per_para
        ],
    )


# --------------------------------------------------------------------------- #
# Check 2: contribution grammar (contract section 4, table row 2).
# --------------------------------------------------------------------------- #

# A verb-first headline starts with an imperative / present-tense verb. We
# accept a small lexicon of the verbs Lin's contribution headlines use, plus a
# morphological fallback (word ends in a verb inflection and is not a determiner).
CONTRIB_VERB_LEXICON = {
    "disrupts", "disrupt", "mitigates", "mitigate", "normalizes", "normalize",
    "holds", "hold", "splits", "split", "shows", "show", "measures", "measure",
    "implements", "implement", "evaluates", "evaluate", "reduces", "reduce",
    "presents", "present", "provides", "provide", "designs", "design",
    "builds", "build", "demonstrates", "demonstrate", "characterizes",
    "characterize", "eliminates", "eliminate", "suppresses", "suppress",
    "has", "have", "achieves", "achieve", "enables", "enable", "defends",
    "defend", "prevents", "prevent", "obfuscates", "obfuscate",
}


def _headline_is_verb_first(headline: str) -> bool:
    first = _first_word(headline)
    if not first:
        return False
    if first in ("a", "an", "the", "our", "this", "we", "an"):
        return False
    if first in CONTRIB_VERB_LEXICON:
        return True
    # morphological fallback: present-tense 3rd person / imperative verb
    return bool(re.match(r"[a-z]+(?:s|es)$", first) and first not in
                {"process", "access", "address", "analysis", "class"})


def _find_contribution_headlines(doc: Document) -> List[str]:
    """Locate the contributions list and return each bold headline."""
    raw = doc.raw
    # Find the contributions region: a cue word near an itemize / bullet list.
    heads: List[str] = []
    if doc.kind == "tex":
        for m in re.finditer(r"\\begin\{itemize\}(.*?)\\end\{itemize\}",
                             raw, flags=re.S):
            block = m.group(1)
            # only treat as contributions if the surrounding text cues it
            pre = raw[max(0, m.start() - 400):m.start()].lower()
            if "contribution" not in pre and "contribution" not in block.lower():
                continue
            for hm in re.finditer(r"\\item\s*\\textbf\{([^}]*)\}", block):
                heads.append(hm.group(1).strip())
    else:  # md / txt
        # bold markdown bullets: - **Headline.** ...
        cue = re.search(r"contribution", raw, flags=re.I)
        region = raw[cue.start():] if cue else raw
        for hm in re.finditer(r"^\s*[-*]\s*\*\*([^*]+)\*\*", region, flags=re.M):
            heads.append(hm.group(1).strip())
    return heads


def check_contribution_grammar(doc: Document) -> CheckResult:
    if doc.is_fragment:
        return CheckResult("contribution_grammar", Status.NA,
                           "fragment: no contributions list expected")
    headlines = _find_contribution_headlines(doc)
    firstness = bool(re.search(
        r"to the best of our knowledge|we are the first|first to (?:the best|our)|"
        r"the first (?:work|system|study|paper|defense|approach) to",
        doc.prose, flags=re.I))

    if not headlines:
        # No contributions list found in a full document is itself a divergence.
        status = Status.FAIL
        summary = "no contributions list with bold headlines found"
        return CheckResult("contribution_grammar", status, summary,
                           numbers={"headlines": 0,
                                    "firstness_claim": firstness})

    verb_first = [h for h in headlines if _headline_is_verb_first(h)]
    non_verb = [h for h in headlines if not _headline_is_verb_first(h)]
    ok_verb = len(non_verb) == 0
    status = Status.PASS if (ok_verb and firstness) else Status.FAIL
    reasons = []
    if not ok_verb:
        reasons.append("%d/%d headlines are not verb-first"
                       % (len(non_verb), len(headlines)))
    if not firstness:
        reasons.append("missing 'to the best of our knowledge' first-ness claim")
    summary = ("; ".join(reasons) if reasons
               else "all headlines verb-first and first-ness claim present")
    return CheckResult(
        "contribution_grammar", status, summary,
        numbers={
            "headlines": len(headlines),
            "verb_first": len(verb_first),
            "not_verb_first": len(non_verb),
            "firstness_claim": firstness,
        },
        detail=["not verb-first: " + h for h in non_verb],
    )


# --------------------------------------------------------------------------- #
# Check 3: structure (contract section 2, table row 3).
# --------------------------------------------------------------------------- #

def check_structure(doc: Document) -> CheckResult:
    if doc.is_fragment or not doc.sections:
        return CheckResult("structure", Status.NA,
                           "fragment: no section structure to check")
    titles = [(s.order, s.title) for s in doc.sections]
    lower = [(o, t.lower()) for o, t in titles]

    def _order_of(pred: Callable[[str], bool]) -> Optional[int]:
        for o, t in lower:
            if pred(t):
                return o
        return None

    bg_order = _order_of(lambda t: "background" in t)
    tm_order = _order_of(lambda t: "threat model" in t or "threat" in t)
    # distinct Design/Approach section = a section whose title names design or
    # approach and is NOT merged with Background.
    design_order = _order_of(
        lambda t: (("design" in t or "approach" in t) and "background" not in t))
    eval_order = _order_of(lambda t: "evaluation" in t or "evaluat" in t)

    problems: List[str] = []

    # (a) threat model appears in/before Background
    if tm_order is None:
        problems.append("no threat-model section found")
    elif bg_order is not None and tm_order > bg_order:
        problems.append("threat model (sec %d) appears AFTER Background (sec %d)"
                        % (tm_order, bg_order))

    # (b) a distinct Design/Approach section exists
    if design_order is None:
        merged = _order_of(lambda t: "design" in t or "approach" in t)
        if merged is not None:
            problems.append("Design content is merged into '%s', not a distinct "
                            "Design section" % dict(lower)[merged])
        else:
            problems.append("no distinct Design/Approach section")

    # (c) goal/objective labels defined and reused in Evaluation
    labels = sorted(set(re.findall(r"\b(?:RO|G|RG|SG)\d+\b", doc.prose)))
    reused = []
    if eval_order is not None:
        eval_prose = next(s.prose for s in doc.sections if s.order == eval_order)
        reused = sorted(set(l for l in labels
                            if re.search(r"\b%s\b" % re.escape(l), eval_prose)))
    if not labels:
        problems.append("no goal/objective labels (G1../RO1..) defined")
    elif eval_order is None:
        problems.append("no Evaluation section to reuse labels in")
    elif not reused:
        problems.append("goal labels %s are defined but not reused in Evaluation"
                        % ",".join(labels))

    status = Status.PASS if not problems else Status.FAIL
    summary = ("; ".join(problems) if problems
               else "threat model early, distinct Design section, labels reused")
    return CheckResult(
        "structure", status, summary,
        numbers={
            "background_section": bg_order,
            "threat_model_section": tm_order,
            "design_section": design_order,
            "evaluation_section": eval_order,
            "labels_defined": labels,
            "labels_reused_in_eval": reused,
        },
        detail=["section %d: %s" % (o, t) for o, t in titles],
    )


# --------------------------------------------------------------------------- #
# Check 4: readability band (contract section 5, table row 4).
# --------------------------------------------------------------------------- #

def _readability(text: str) -> Optional[Tuple[float, float]]:
    """Return (flesch_reading_ease, fk_grade) or None. textstat -> formula."""
    try:
        import textstat  # type: ignore
        fre = float(textstat.flesch_reading_ease(text))
        fk = float(textstat.flesch_kincaid_grade(text))
        return round(fre, 1), round(fk, 1)
    except Exception:
        pass
    # Fallback: reuse voice_check's own Flesch / FK computation.
    if VOICE is None:
        return None
    try:
        m = VOICE.measure(text)
        return m["flesch_reading_ease"], m["fk_grade"]
    except SystemExit:
        return None
    except Exception:  # pragma: no cover - defensive
        return None


def check_readability(doc: Document) -> CheckResult:
    overall = _readability(doc.prose)
    if overall is None:
        return CheckResult("readability", Status.NA,
                           "could not compute readability (no textstat, no "
                           "voice_check)")
    fre, fk = overall
    per_section: List[Dict[str, object]] = []
    dense: List[str] = []
    for sec in doc.sections:
        r = _readability(sec.prose)
        if r is None:
            continue
        s_fre, s_fk = r
        entry = {"section": sec.title, "flesch": s_fre, "fk_grade": s_fk}
        per_section.append(entry)
        if s_fre < FLESCH_FLOOR or s_fk > FK_CEILING:
            dense.append("%s (flesch %.1f, fk %.1f)" % (sec.title, s_fre, s_fk))

    too_dense_overall = fre < FLESCH_FLOOR or fk > FK_CEILING
    if too_dense_overall or dense:
        status = Status.WARN
        summary = "too dense: overall flesch %.1f / fk %.1f" % (fre, fk)
    else:
        status = Status.PASS
        summary = "readability within band (flesch %.1f, fk %.1f)" % (fre, fk)
    return CheckResult(
        "readability", status, summary,
        numbers={
            "overall_flesch": fre,
            "overall_fk_grade": fk,
            "flesch_floor": FLESCH_FLOOR,
            "fk_ceiling": FK_CEILING,
            "textstat": _have_textstat(),
        },
        detail=["dense: " + d for d in dense]
        + ["%s: flesch %.1f fk %.1f" % (e["section"], e["flesch"], e["fk_grade"])
           for e in per_section],
    )


def _have_textstat() -> bool:
    try:
        import textstat  # noqa: F401
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Check 5: sentence health (contract section 5, table row 5).
# --------------------------------------------------------------------------- #

def _is_dangling_subordinate(sentence: str) -> bool:
    """Flag the 'By learning X..., because Y...' no-main-clause class.

    Two triggers:
      (a) opens with 'By <gerund>' and later contains a subordinator such as
          'because' -> adjunct opener with no independent clause; or
      (b) opens with a bare subordinator and the sentence contains no
          comma-delimited clause that both lacks a leading subordinator and
          carries a finite verb (i.e. no main clause resolves).
    """
    s = sentence.strip()
    low = s.lower()
    first = _first_word(s)

    # (a) By-gerund adjunct that derails into a subordinator.
    if re.match(r"by\s+\w+ing\b", low):
        if re.search(r"\b(?:because|since|so that|as)\b", low):
            return True

    # (b) bare subordinator opener with no resolving main clause.
    if first in SUBORDINATORS:
        clauses = [c.strip() for c in re.split(r",|;", s) if c.strip()]
        for c in clauses:
            cw = _first_word(c)
            if cw in SUBORDINATORS or cw in ("such", "which", "who", "that"):
                continue
            if _has_finite_verb(c):
                return False  # a main clause resolves it
        return True
    return False


def check_sentence_health(doc: Document) -> CheckResult:
    sents = doc.sentences
    if not sents:
        return CheckResult("sentence_health", Status.NA, "no sentences")
    fragments: List[str] = []
    verbless: List[str] = []
    for s in sents:
        if _is_dangling_subordinate(s):
            fragments.append(s)
        elif not _has_finite_verb(s):
            verbless.append(s)

    if fragments:
        status = Status.FAIL
        summary = "%d dangling / no-main-clause fragment(s)" % len(fragments)
    elif verbless:
        status = Status.WARN
        summary = "%d sentence(s) with no obvious finite verb" % len(verbless)
    else:
        status = Status.PASS
        summary = "no fragments detected"
    return CheckResult(
        "sentence_health", status, summary,
        numbers={"fragments": len(fragments),
                 "verbless_warnings": len(verbless),
                 "sentences": len(sents)},
        detail=["FRAGMENT: " + f for f in fragments]
        + ["no-verb?: " + v for v in verbless],
    )


# --------------------------------------------------------------------------- #
# Check 6: fact hygiene (contract section 5, table row 6) - WARN only.
# --------------------------------------------------------------------------- #

def check_fact_hygiene(doc: Document) -> CheckResult:
    warnings: List[str] = []
    numbers: Dict[str, object] = {}

    # duplicate marquee examples across paragraphs
    para_tokens: Dict[str, List[int]] = {t: [] for t in MARQUEE_TOKENS}
    for i, para in enumerate(doc.paragraphs):
        low = para.lower()
        for stem in MARQUEE_TOKENS:
            if re.search(r"\b%s" % re.escape(stem), low):
                para_tokens[stem].append(i)
    dupes = {t: ps for t, ps in para_tokens.items() if len(ps) > 1}
    for stem, ps in dupes.items():
        warnings.append("'%s' appears in %d paragraphs %s (use each marquee "
                        "example once)" % (MARQUEE_TOKENS[stem], len(ps), ps))
    numbers["marquee_paragraph_counts"] = {
        MARQUEE_TOKENS[t]: len(ps) for t, ps in para_tokens.items() if ps}

    # year inconsistency near a canonical marquee example
    year_issues: List[str] = []
    for stem, canon in MARQUEE_CANON_YEAR.items():
        for m in re.finditer(r"\b%s" % re.escape(stem), doc.prose, flags=re.I):
            window = doc.prose[max(0, m.start() - 120):m.end() + 120]
            full_years = re.findall(r"\b(?:19|20)\d{2}\b", window)
            for y in full_years:
                if y != canon:
                    year_issues.append("'%s' near year %s (expected %s)"
                                       % (MARQUEE_TOKENS[stem], y, canon))
    year_issues = sorted(set(year_issues))
    warnings.extend(year_issues)
    numbers["year_issues"] = year_issues

    status = Status.WARN if warnings else Status.PASS
    summary = ("; ".join(warnings) if warnings
               else "no duplicate marquee examples or year slips")
    return CheckResult("fact_hygiene", status, summary,
                       numbers=numbers, detail=warnings)


# --------------------------------------------------------------------------- #
# Check 7: voice fingerprint (contract table row 7) - wraps voice_check.measure.
# --------------------------------------------------------------------------- #

def check_voice(doc: Document) -> CheckResult:
    if VOICE is None:
        return CheckResult("voice_fingerprint", Status.WARN,
                           "voice_check.py unavailable")
    try:
        m = VOICE.measure(doc.raw)
    except SystemExit as exc:
        return CheckResult("voice_fingerprint", Status.NA, str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        return CheckResult("voice_fingerprint", Status.WARN,
                           "voice_check failed: %s" % exc)
    em_dashes = m.get("ai_flags", {}).get("em dash", 0)
    numbers = {
        "words_per_sentence_mean": m.get("words_per_sentence_mean"),
        "we_per_100_sentences": m.get("we_per_100_sentences"),
        "hedges_per_1000_words": m.get("hedges_per_1000_words"),
        "flesch_reading_ease": m.get("flesch_reading_ease"),
        "fk_grade": m.get("fk_grade"),
        "em_dashes": em_dashes,
        "ai_flags": m.get("ai_flags", {}),
    }
    # Informational, but surface em-dashes (contract expects 0) as a WARN.
    status = Status.WARN if em_dashes else Status.PASS
    summary = ("voice measured; %d em-dash(es) (contract expects 0)" % em_dashes
               if em_dashes else "voice measured; 0 em-dashes")
    return CheckResult("voice_fingerprint", status, summary, numbers=numbers)


# --------------------------------------------------------------------------- #
# Driver.
# --------------------------------------------------------------------------- #

# Checks whose FAIL makes the run fail-closed (non-zero exit).
HARD_CHECKS = {
    "connective_spine", "contribution_grammar", "structure", "sentence_health",
}


def run_all(doc: Document, connective_target: float) -> List[CheckResult]:
    return [
        check_connective_spine(doc, connective_target),
        check_contribution_grammar(doc),
        check_structure(doc),
        check_readability(doc),
        check_sentence_health(doc),
        check_fact_hygiene(doc),
        check_voice(doc),
    ]


def _exit_code(results: List[CheckResult]) -> int:
    for r in results:
        if r.status is Status.FAIL and r.name in HARD_CHECKS:
            return 1
    return 0


def build_payload(doc: Document, results: List[CheckResult],
                  connective_target: float, code: int) -> Dict[str, object]:
    """The single-draft scorecard dict; also the shape emitted by --json."""
    return {
        "draft": doc.path,
        "kind": doc.kind,
        "is_fragment": doc.is_fragment,
        "n_sentences": len(doc.sentences),
        "n_sections": len(doc.sections),
        "connective_target": connective_target,
        "exit_code": code,
        "checks": [r.to_dict() for r in results],
    }


def score_document(path: str, connective_target: float) -> Dict[str, object]:
    """Score a draft file and return its scorecard payload."""
    doc = load_document(path)
    results = run_all(doc, connective_target)
    return build_payload(doc, results, connective_target,
                         _exit_code(results))


def _looks_like_scorecard(path: str) -> bool:
    """Detect a prior --json scorecard by extension or by content."""
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


def load_or_score(path: str, connective_target: float) -> Dict[str, object]:
    """Return a scorecard payload: load a prior --json file, else score a draft."""
    if _looks_like_scorecard(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            payload = json.load(fh)
        if "checks" not in payload:
            raise ValueError("%s is JSON but not a lin_check scorecard "
                             "(no 'checks')" % path)
        payload.setdefault("draft", path)
        payload["source"] = "scorecard"
        return payload
    payload = score_document(path, connective_target)
    payload["source"] = "scored"
    return payload


def print_report(doc: Document, results: List[CheckResult]) -> None:
    n_words = len(re.findall(r"[A-Za-z][A-Za-z'-]*", doc.prose))
    print("=" * 78)
    print("lin_check  -  Dr. Lin style contract enforcement")
    print("draft: %s  (%s, %d sentences, %d words, %d sections%s)"
          % (doc.path, doc.kind, len(doc.sentences), n_words,
             len(doc.sections), ", FRAGMENT" if doc.is_fragment else ""))
    print("=" * 78)
    for r in results:
        hard = " [hard]" if r.name in HARD_CHECKS else ""
        print("[%-4s] %-22s%s  %s" % (r.status.value, r.name, hard, r.summary))
        for key, val in r.numbers.items():
            print("         %-26s = %s" % (key, val))
        for line in r.detail:
            print("           - %s" % line)
    print("-" * 78)
    hard_fails = [r.name for r in results
                  if r.status is Status.FAIL and r.name in HARD_CHECKS]
    warns = [r.name for r in results if r.status is Status.WARN]
    if hard_fails:
        print("RESULT: FAIL  (hard checks failing: %s)" % ", ".join(hard_fails))
    else:
        print("RESULT: PASS  (no hard-check failures)")
    if warns:
        print("        warnings: %s" % ", ".join(warns))
    print("=" * 78)


# --------------------------------------------------------------------------- #
# Non-regression compare mode (BEFORE -> AFTER).
# --------------------------------------------------------------------------- #

REGRESSION_EXIT = 3
_EPS = 1e-9


def _checks_by_name(payload: Dict[str, object]) -> Dict[str, dict]:
    return {c["name"]: c for c in payload.get("checks", [])}


def _num(check: Optional[dict], key: str, default=None):
    if not check:
        return default
    return check.get("numbers", {}).get(key, default)


def _voice_deviation(check: Optional[dict]) -> Optional[int]:
    """Total voice deviations = sum of AI-pattern flags (em-dashes included)."""
    if not check:
        return None
    flags = check.get("numbers", {}).get("ai_flags")
    if flags is None:
        return None
    return int(sum(flags.values()))


def _readability_outside(check: Optional[dict]) -> Optional[float]:
    """Distance outside the readability band; 0.0 means within band."""
    if not check:
        return None
    nums = check.get("numbers", {})
    fre = nums.get("overall_flesch")
    fk = nums.get("overall_fk_grade")
    if fre is None or fk is None:
        return None
    floor = nums.get("flesch_floor", FLESCH_FLOOR)
    ceil = nums.get("fk_ceiling", FK_CEILING)
    return round(max(0.0, floor - fre) + max(0.0, fk - ceil), 2)


def compare_payloads(before: Dict[str, object], after: Dict[str, object]
                     ) -> Tuple[Dict[str, object], int]:
    """Diff two scorecards; flag any regression on a hard dimension.

    A regression (exit REGRESSION_EXIT) is any of, on the AFTER scorecard:
      - a hard check that went PASS/WARN -> FAIL,
      - connective_spine overall fraction dropped,
      - sentence_health fragment count increased,
      - voice deviation count increased,
      - readability moved further outside the band.
    NO REGRESSION (exit 0) requires every hard dimension equal-or-better.
    """
    b = _checks_by_name(before)
    a = _checks_by_name(after)
    regressions: List[str] = []
    improvements: List[str] = []
    rows: List[Dict[str, object]] = []

    # ---- hard-check status transitions -----------------------------------
    for hc in ("connective_spine", "contribution_grammar", "structure",
               "sentence_health"):
        bs = b.get(hc, {}).get("status")
        as_ = a.get(hc, {}).get("status")
        if as_ == "FAIL" and bs in ("PASS", "WARN"):
            regressions.append("%s: status %s -> FAIL" % (hc, bs))
        elif bs == "FAIL" and as_ in ("PASS", "WARN"):
            improvements.append("%s: status FAIL -> %s" % (hc, as_))

    # ---- numeric hard dimensions -----------------------------------------
    def _record(name: str, bv, av, better_is_lower: bool, fmt: str):
        verdict = "same"
        if bv is not None and av is not None:
            if better_is_lower:
                if av > bv + _EPS:
                    verdict = "WORSE"
                    regressions.append("%s: %s -> %s (increased)"
                                       % (name, fmt % bv, fmt % av))
                elif av < bv - _EPS:
                    verdict = "better"
                    improvements.append("%s: %s -> %s (decreased)"
                                        % (name, fmt % bv, fmt % av))
            else:
                if av < bv - _EPS:
                    verdict = "WORSE"
                    regressions.append("%s: %s -> %s (dropped)"
                                       % (name, fmt % bv, fmt % av))
                elif av > bv + _EPS:
                    verdict = "better"
                    improvements.append("%s: %s -> %s (rose)"
                                        % (name, fmt % bv, fmt % av))
        rows.append({
            "dimension": name,
            "before": None if bv is None else round(bv, 3)
            if isinstance(bv, float) else bv,
            "after": None if av is None else round(av, 3)
            if isinstance(av, float) else av,
            "verdict": verdict,
        })

    _record("connective_spine.fraction",
            _num(b.get("connective_spine"), "overall_fraction"),
            _num(a.get("connective_spine"), "overall_fraction"),
            better_is_lower=False, fmt="%.3f")
    _record("sentence_health.fragments",
            _num(b.get("sentence_health"), "fragments"),
            _num(a.get("sentence_health"), "fragments"),
            better_is_lower=True, fmt="%d")
    _record("voice_fingerprint.deviations",
            _voice_deviation(b.get("voice_fingerprint")),
            _voice_deviation(a.get("voice_fingerprint")),
            better_is_lower=True, fmt="%d")
    _record("readability.outside_band",
            _readability_outside(b.get("readability")),
            _readability_outside(a.get("readability")),
            better_is_lower=True, fmt="%.2f")

    # ---- status rows for every check (informational) ---------------------
    status_rows = []
    for name in [c["name"] for c in after.get("checks", [])] or list(a):
        status_rows.append({
            "check": name,
            "before_status": b.get(name, {}).get("status", "-"),
            "after_status": a.get(name, {}).get("status", "-"),
            "hard": name in HARD_CHECKS,
        })

    regressed = bool(regressions)
    code = REGRESSION_EXIT if regressed else 0
    comparison = {
        "before": before.get("draft"),
        "after": after.get("draft"),
        "before_source": before.get("source", "scored"),
        "after_source": after.get("source", "scored"),
        "verdict": "REGRESSION" if regressed else "NO REGRESSION",
        "exit_code": code,
        "regressions": regressions,
        "improvements": improvements,
        "numeric_dimensions": rows,
        "status_rows": status_rows,
    }
    return comparison, code


def print_compare(comp: Dict[str, object]) -> None:
    print("=" * 78)
    print("lin_check --compare  (non-regression gate)")
    print("BEFORE: %s  [%s]" % (comp["before"], comp["before_source"]))
    print("AFTER : %s  [%s]" % (comp["after"], comp["after_source"]))
    print("=" * 78)
    print("%-30s %10s %10s   %s"
          % ("hard dimension", "before", "after", "verdict"))
    print("-" * 78)
    for row in comp["numeric_dimensions"]:
        print("%-30s %10s %10s   %s"
              % (row["dimension"], row["before"], row["after"], row["verdict"]))
    print("-" * 78)
    print("per-check status (before -> after):")
    for sr in comp["status_rows"]:
        hard = " [hard]" if sr["hard"] else ""
        print("  %-22s %5s -> %-5s%s"
              % (sr["check"], sr["before_status"], sr["after_status"], hard))
    print("-" * 78)
    if comp["improvements"]:
        print("improvements:")
        for i in comp["improvements"]:
            print("  + " + i)
    if comp["verdict"] == "REGRESSION":
        print("VERDICT: REGRESSION  (AFTER lowered the Lin-voice score)")
        print("offending dimensions:")
        for r in comp["regressions"]:
            print("  ! " + r)
    else:
        print("VERDICT: NO REGRESSION (equal or better on every hard dimension)")
    print("=" * 78)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", nargs="?",
                    help="path to a .tex / .md / .txt draft to score")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"),
                    help="non-regression gate: each of BEFORE/AFTER is a draft "
                         "file OR a prior --json scorecard; exit %d if AFTER "
                         "regressed on any hard dimension" % REGRESSION_EXIT)
    ap.add_argument("--json", action="store_true",
                    help="emit the structured report as JSON")
    ap.add_argument("--connective-target", type=float,
                    default=DEFAULT_CONNECTIVE_TARGET,
                    help="overall connective-lead fraction target "
                         "(default %(default)s)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(name)s: %(levelname)s: %(message)s")

    # ---- non-regression compare mode -------------------------------------
    if args.compare:
        before_path, after_path = args.compare
        for p in (before_path, after_path):
            if not os.path.isfile(p):
                logger.error("compare input not found: %s", p)
                return 2
        try:
            before = load_or_score(before_path, args.connective_target)
            after = load_or_score(after_path, args.connective_target)
        except ValueError as exc:
            logger.error("%s", exc)
            return 2
        comparison, code = compare_payloads(before, after)
        if args.json:
            print(json.dumps(comparison, indent=2))
        else:
            print_compare(comparison)
        return code

    # ---- single-draft scoring mode ---------------------------------------
    if not args.draft:
        ap.error("provide a draft to score, or use --compare BEFORE AFTER")
    if not os.path.isfile(args.draft):
        logger.error("draft not found: %s", args.draft)
        return 2

    doc = load_document(args.draft)
    results = run_all(doc, args.connective_target)
    code = _exit_code(results)

    if args.json:
        print(json.dumps(build_payload(doc, results, args.connective_target,
                                       code), indent=2))
    else:
        print_report(doc, results)
    return code


if __name__ == "__main__":
    sys.exit(main())
