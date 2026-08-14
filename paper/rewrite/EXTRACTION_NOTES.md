# Extraction notes — faithful re-extraction of the five target PDFs

Scope: re-extract the five reference PDFs in `paper/target/` more faithfully than the first
`pdftotext -layout` pass (in `paper/rewrite/target_extract/`), and flag anything that could
affect the paper. Per-paper output: `paper/rewrite/target_extract_v2/<name>.md`.

## Tool used

- **PyMuPDF 1.28.2** (`import pymupdf` / legacy `fitz`), the primary requested tool.
- `fitz` was **not** importable in `$RESEARCH_PYTHON` (`~/.venvs/research`), so — per the fallback
  instruction — PyMuPDF was installed into a **fresh throwaway venv via `uv`**
  (`uv venv` + `uv pip install pymupdf`, Python 3.13). MinerU was not used (unavailable).
- Method: `page.get_text("dict")` → per-line spans with font size/flags/coordinates →
  **column-aware reading-order reconstruction** (two-column IEEE/NDSS layout split at x≈300 pt,
  lines ordered page → left column top-to-bottom → right column). Headings detected by the
  roman-numeral / lettered-subsection pattern; figure/table captions by label pattern **gated on
  caption font size (< body) or a following colon** to reject inline "Figure N …" body references;
  references sliced from the `References` heading and re-split on `[n]`.
- Post-processing on the `.md` files: Unicode ligatures (ﬁ ﬂ ﬀ ﬃ ﬄ) normalized to ASCII, en-dash →
  hyphen, curly quotes → straight. 114 ligature glyphs were present before normalization.

This is materially more faithful than `pdftotext -layout` for the two-column reference lists and
the captions (see below). Both tools were cross-checked at the trouble spots.

## Where the earlier `pdftotext -layout` extraction was garbled or mis-ordered

1. **Two-column reference lists interleave line-by-line (all five papers).** `pdftotext -layout`
   places left- and right-column text that share a y-coordinate on the *same output line*. Example
   from `target_extract/RAINCOAT (2).txt` line 854:
   `REFERENCES   ...   Attacks," in IEEE Transactions on Control of Network Systems, vol. 4,`
   — the "REFERENCES" heading is glued to an unrelated right-column reference fragment. The
   column-aware PyMuPDF pass reconstructs each reference as one clean entry (40 for RAINCOAT, 79
   DefRec, 59 Testbed, 101 ditto, 26 Formby).

2. **The Testbed (LASER) venue footer is font-obfuscated — BOTH tools render it garbled.** On
   page 1 of `10336809.pdf` the venue line is drawn with a shifted (+1 Caesar) font cmap. Raw
   output (identical in `pdftotext` line 57 and PyMuPDF) is:
   `-FBSOJOH GSPN "VUIPSJUBUJWF 4FDVSJUZ &YQFSJNFOU 3FTVMUT -"4&3  2020`
   Decoding each letter back by one gives **"Learning from Authoritative Security Experiment
   Results (LASER) 2020"**. The venue is only recoverable by decoding this line *or* from the
   adjacent DOI line `https://dx.doi.org/10.14722/laser.2020.`. The neighbouring ISBN line also
   comes out truncated/garbled (`ISBN1-891562-6-`). Anyone reading the raw footer literally would
   NOT see "LASER". Flagged, but note it does not change the venue conclusion.

3. **Formby captions are split labels.** Formby draws the label ("Fig. 1.") and the caption text as
   two separate positioned runs on the same visual row. A naive reader (and the first pass) tends to
   capture only "Fig. 1." The v2 pass rejoins them, recovering all 30 figure captions + Table I.

4. **Ligatures.** PyMuPDF preserves the original ﬁ/ﬂ ligature codepoints (e.g. "conﬁguration",
   "identiﬁes"); `pdftotext` silently maps them to "fi"/"fl". The v2 `.md` files were normalized to
   ASCII so they are safe to paste into `refs.bib`/prose without stray U+FB0x characters.

5. **Residual layout oddities carried from the source PDFs (not tool-fixable, minor):** a few
   references that wrap awkwardly in the original get split across the entry boundary — e.g. Testbed
   `[20]/[21]` (Glover, *Power System Analysis and Design*) and DefRec [4]'s "and others". Side-by-side
   sub-figures that share a caption band (DefRec Fig 11/12, ditto Fig 11/12 and 14/15) yield one
   caption of the pair; the dropped twin is noted per file where it occurs. Section auto-detection
   missed three Testbed top-level headings (I, V, and the fact that VII is absent) — corrected by
   hand in `testbed.md` from the raw text.

## Contradiction check — venue / year vs. `refs.bib`

Values relied on in `paper/rewrite/refs.bib` were checked against the **printed front-matter of each
PDF** (title-page banner, copyright line, DOI). **No contradictions were found — every venue and year
is confirmed by the printed PDF.** Details:

| Paper | refs.bib claim | Printed on the PDF (verbatim) | Verdict |
|---|---|---|---|
| DefRec (`10139606`) | NDSS 2020 | p1 footer: "Network and Distributed Systems Security (NDSS) Symposium 2020, 23-26 February 2020, San Diego, CA, USA. ISBN 1-891562-61-4. dx.doi.org/10.14722/ndss.2020.24365" | **CONFIRMED.** (The `10139606` filename is an IEEE Xplore doc id, but the paper itself is NDSS 2020.) |
| Testbed (`10336809`) | LASER 2020 | p1 footer (font-decoded): "Learning from Authoritative Security Experiment Results (LASER) 2020, 23 February 2020, San Diego". DOI `10.14722/laser.2020.` | **CONFIRMED** (venue text obfuscated in raw output — see garble #2). |
| RAINCOAT | IEEE TSG 2018/2019 | Header: "DOI 10.1109/TSG.2018.2870362, IEEE Transactions on Smart Grid". Footer: "1949-3053 (c) 2018 IEEE … accepted for publication in a future issue of this journal, but has not been fully edited." | **CONSISTENT.** This is the IEEE **early-access** reprint (DOI year 2018); the archival version is TSG vol. 10 (2019). The "2018/2019" hedge in refs.bib is correct. |
| Formby | NDSS 2016 | p1 footer: "NDSS '16, 21-24 February 2016, San Diego, CA, USA. Copyright 2016 Internet Society, ISBN 1-891562-41-X. dx.doi.org/10.14722/ndss.2016.23142" | **CONFIRMED** (independently corroborated by DefRec's own ref [18] and Testbed ref [19]). |
| ditto | NDSS 2022 | p1 footer: "Network and Distributed Systems Security (NDSS) Symposium 2022, 24-28 April 2022, San Diego, CA, USA. ISBN 1-891562-74-6. dx.doi.org/10.14722/ndss.2022.24056" | **CONFIRMED.** |

### Secondary metadata — cross-checked against `refs.bib`, only cosmetic differences

All five `refs.bib` entries (`formby2016`, `defrec2020`, `raincoat2019`, `lintestbed2020`,
`ditto2022`) were compared to the printed metadata. Author lists, venues, years, and RAINCOAT's
volume/pages (TSG vol. 10, no. 5, pp. 4893–4906, 2019) and DOI all match. The only differences are
cosmetic title-casing, which do not affect the citation:

- **RAINCOAT**: the printed title capitalizes internal letters to spell the acronym
  ("RAndomization … cyber INfrastructure … Attackers"); `refs.bib` uses normal case
  ("Randomization … Infrastructure … Attackers"). Both read *Attackers* (not *Attacks*) — consistent.
  Printed authors Hui Lin / Zbigniew Kalbarczyk / Ravishankar K. Iyer match `raincoat2019`.
- **ditto**: the paper styles the name lowercase ("ditto"); `refs.bib` capitalizes it ("Ditto").
  Cosmetic only.
- **DefRec** authors: Hui Lin, Jianing Zhuang, Yih-Chun Hu, Huayu Zhou. **Testbed** authors: Hui
  Lin, Bibek Shrestha, Yih-Chun Hu.
- Internal quirk (Testbed only, does not affect citation): the printed paper **skips section VII** —
  it runs VI. Related Work → VIII. Conclusion. Recorded in `testbed.md`.

## Files written

- `paper/rewrite/target_extract_v2/defrec.md` (NDSS 2020)
- `paper/rewrite/target_extract_v2/testbed.md` (LASER 2020)
- `paper/rewrite/target_extract_v2/raincoat.md` (IEEE TSG 2018/2019)
- `paper/rewrite/target_extract_v2/ditto.md` (NDSS 2022)
- `paper/rewrite/target_extract_v2/formby.md` (NDSS 2016)

`refs.bib` was **not** modified (no contradiction required it).
