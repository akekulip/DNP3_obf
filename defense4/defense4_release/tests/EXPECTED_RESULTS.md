# Expected results — `run_all.sh`

Run from the release root:

```bash
./tests/run_all.sh
```

| Step | Check | Expected |
|---|---|---|
| 1 | Python syntax | all `code/**/*.py` compile — **PASS** |
| 2 | Offline unified lifecycle | **19/19 invariants**, **11/11 mutants killed** — PASS (exit 0) |
| 3 | Decision-table vs oracle | **2,580,480 / 2,580,480 tuples** match, no MISMATCH — PASS |
| 4 | Guarded-control safety test | forbidden index sets (incl. index 6 breaker-close) **refused** — PASS |
| 5 | E_FINAL manifest | every listed file's SHA-256 matches — PASS |
| 6 | Size reconstruction (needs `scapy`) | native → `[49]`, defended → `[28,21]`; **0** unsplit-49-byte escapes — PASS, else SKIP |
| 7 | Document render (needs `pdfinfo`) | `DEFENSE4_EXPLAINER.pdf` ~25 pp, `DEFENSE4_SIMPLE.pdf` ~6 pp, `MEETING_REFERENCE.pdf` ~3 pp — PASS, else SKIP |

**Overall:** `PASS=… FAIL=0 SKIP=…`, exit 0. SKIP only occurs for the two optional dependencies
(`scapy`, `poppler-utils`/`pdfinfo`); install them to run steps 6–7:

```bash
pip install scapy           # step 6
# poppler-utils via your package manager   # step 7 (pdfinfo)
```

## Headline numbers these checks correspond to (from `evidence/E_FINAL/`)

- CLRT: native READ 1.272 / SELECT 2.107 ms → defended **4.001 ms, std ≈0.02**.
- Segmentation: native 100×[49] → defended **1280×[28,21]**, all CRC/checksum-valid, **0 escapes**.
- BOR: **echo − ACK = 4.00 ms, std ≈0.026**, invariant across J = 2/6/12 ms.
- Formby: MI 0.424 → **0.0018 bits**; classifier BA 0.592 → **0.500** (chance).
- Safety: **all 32 relay outputs OPEN**; index-6 refused.

## What these checks do NOT prove

They are **offline** checks of the model, the decision logic, the guard, and the recorded evidence.
They do not re-run the silicon campaign. Relay-facing `T0 + J` and exactly-once release were never
captured (dp68 is internal) and are outside these tests — see `../CLAIMS_AND_LIMITATIONS.md`.
