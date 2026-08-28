# `paper/rewrite/pipeline/` — build and gate

| file | purpose |
|---|---|
| `build.sh` | `tectonic` compile (offline) of `../main.tex` into `build/`, then `lin_check.py` on the flattened manuscript with `--bib ../library.bib --pdf build/main.pdf`; scorecard to `reports/main_<stamp>.{txt,json}`. Fails closed on a compile error or a hard-check failure. |
| `lin_check.py` | the manuscript gate (below) |
| `make_final_figures.py` | regenerates `../FINAL_FIGURES.md` from the figure sidecars and the LaTeX |
| `DR_LIN_WRITING_GUIDE.md` | the active writing guide |
| `samples/lin_intro.txt` | Dr. Lin's introduction paragraphs, verbatim (protected text) |
| `reports/` | the named reports (tracked) and the timestamped scorecards (untracked) |

## What `lin_check.py` checks

Hard (FAIL, non-zero exit): forbidden project or system names; `native` / `defended` / `Timing ON`
used as arm names; an unsupported firstness claim; em dashes; a padding / splitting /
segment-shape claim made as ours; the required sections present and in order (Introduction,
Background, Threat Model, Design, Implementation, Evaluation, Related Work second-last,
Conclusion last) with RO labels defined in the threat model and reused in the Evaluation and a
Limitations heading; a figure or table environment after the bibliography command, or, with
`--pdf`, a figure caption on a page after the References heading; a `\cite` key missing from the
bibliography; contribution headlines that are not verb-first; no-main-clause fragments.

Soft (WARN): acronyms used before definition; readability outside the band (Flesch < 15 or
FK grade > 18); duplicate marquee examples or a wrong year next to one; the paper-voice
fingerprint flags. Connective density is reported for information only and is not scored: the
gate does not require stylistic filler or reward transitions.

```sh
python3 lin_check.py ../main.tex --bib ../library.bib            # single file (no \input following)
./build.sh                                                        # the real gate, on the flattened manuscript
python3 lin_check.py --compare before.json build/main_flat.tex --bib ../library.bib   # exit 3 on regression
```

`--compare` fails when a hard check goes to FAIL or when fragments, voice flags, em dashes, stale
labels or the readability distance outside the band increase. Deterministic: no network, no
randomness. The paper-voice `voice_check.py` is imported by absolute path if present; without it
the readability and voice rows report NA.
