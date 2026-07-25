#!/usr/bin/env bash
# build_meeting_package.sh — assemble the shareable meeting package (direcr2 §28).
# Reproducible + re-runnable: wipes and rebuilds meeting_package/, then makes the tar.gz + SHA256SUMS.
set -euo pipefail

DELIV="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DELIV/.." && pwd)"
TUT="$DELIV/timing_tutorial"
TF="$REPO/research/timing_final"
PKG="$DELIV/meeting_package"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u '+%Y%m%d')"

echo "[1/6] refresh the tutorial HTML/PDF"
bash "$TUT/source/build_tutorial.sh" >/dev/null

echo "[2/6] lay out meeting_package/"
rm -rf "$PKG"
mkdir -p "$PKG"/{demo,source,figures,example_pcaps,evidence_summary}

# top-level docs
cp "$TUT/DNP3_TIMING_NORMALIZER_TUTORIAL.pdf" "$PKG/"
cp "$TUT/QUICKSTART.md" "$PKG/"
cp "$TUT/index.html" "$PKG/TUTORIAL.html"
# operational guides (Wireshark guide is required by §28 START_HERE links)
cp "$TUT/WIRESHARK_GUIDE.md" "$TUT/CODE_WALKTHROUGH.md" "$TUT/LAB_RUNBOOK.md" \
   "$TUT/TROUBLESHOOTING.md" "$TUT/README_FIRST.md" "$TUT/TECHNICAL_TALK_5_MINUTES.md" "$PKG/"

# runnable demo (the Makefile interface; runs from a switch-connected host)
cp "$TF/Makefile" "$PKG/demo/"
cp -r "$TF/scripts" "$PKG/demo/scripts"
[ -d "$TF/config" ] && cp -r "$TF/config" "$PKG/demo/config"
[ -d "$TF/lib" ] && cp -r "$TF/lib" "$PKG/demo/lib" 2>/dev/null || true
find "$PKG/demo" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# complete code
cp "$TF/p4/dnp3_timing_normalizer.p4" "$PKG/source/"
cp "$REPO/research/ibspg_dnp3_replay/harness/p13_guard.py" "$PKG/source/" 2>/dev/null || true
cp "$TF/scripts/analyze_clrt.py" "$TF/scripts/fingerprint_eval.py" "$TF/scripts/make_pub_figures.py" "$PKG/source/"

# figures (all 10)
cp "$TF/evidence/figures/"fig*.png "$PKG/figures/"

# example pcaps
cp "$TUT/example_pcaps/"* "$PKG/example_pcaps/"

# evidence summary
cp "$TF/evidence/MANIFEST.md" "$PKG/evidence_summary/"
cp "$TF/TIMING_FINAL_RESULT.md" "$TF/TIMING_FINGERPRINTING_ANALYSIS.md" "$TF/TIMING_MECHANISM_EXPLAINED.md" "$PKG/evidence_summary/"
cp "$TF/evidence/fingerprinting/fingerprint_eval.json" "$PKG/evidence_summary/" 2>/dev/null || true

echo "[3/6] write START_HERE.html"
cat > "$PKG/START_HERE.html" <<HTML
<!DOCTYPE html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>DNP3 Timing Normalizer — Meeting Package</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--acc:#1f6feb;--card:#f5f6f8;--line:#dcdfe3}
@media(prefers-color-scheme:dark){:root{--bg:#0f1418;--fg:#e6e8ea;--muted:#9aa4ad;--acc:#589bff;--card:#161c22;--line:#2a323a}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:840px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:1.8em;margin:.2em 0 .1em}.sub{color:var(--muted);margin:0 0 1.4em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin:1.4em 0}
a.card{display:block;text-decoration:none;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
a.card:hover{border-color:var(--acc)}a.card b{color:var(--acc)}a.card span{display:block;color:var(--muted);font-size:.88em;margin-top:4px}
.note{background:var(--card);border-left:3px solid var(--acc);border-radius:0 8px 8px 0;padding:.6em 1em;font-size:.92em}
img{max-width:100%;border:1px solid var(--line);border-radius:8px;margin:1em 0;background:#fff}
code{background:var(--card);padding:.1em .35em;border-radius:4px;font-size:.9em}
</style></head><body><main>
<h1>DNP3 In-Network Timing Normalizer</h1>
<p class=sub>Meeting package · commit <code>$COMMIT</code> · concealing the Cross-Layer Response Time (CLRT) fingerprint on Intel Tofino-1</p>
<div class=note><b>What this shows:</b> the switch normalizes the ACK&rarr;RESPONSE interval of a real
SEL-751 relay to a policy constant G, byte-for-byte, reducing the CLRT-magnitude fingerprint from
2.73 bits to 0.00 bits at millisecond resolution. It does <b>not</b> hide ACK mode, TCP-stack
signature, or response size, and is not size obfuscation or full device anonymity.</div>
<div class=grid>
<a class=card href="TUTORIAL.html"><b>&#128214; Full tutorial (HTML)</b><span>Two-layer walkthrough, diagrams, results — start here</span></a>
<a class=card href="DNP3_TIMING_NORMALIZER_TUTORIAL.pdf"><b>&#128196; Tutorial (PDF)</b><span>Printable, for sharing</span></a>
<a class=card href="figures/fig01_architecture.png"><b>&#127959; Architecture diagram</b><span>Lab topology & data path</span></a>
<a class=card href="evidence_summary/DEMO_2_MIN.md" onclick="this.href='TUTORIAL.html#13-how-to-run-it'"><b>&#9654; Two-minute demo</b><span>See "How to run it" in the tutorial</span></a>
<a class=card href="source/dnp3_timing_normalizer.p4"><b>&#128187; Complete code</b><span>P4 program + control plane + analysis</span></a>
<a class=card href="example_pcaps/"><b>&#128230; Example PCAPs</b><span>native_demo.pcap, protected_demo.pcap</span></a>
<a class=card href="WIRESHARK_GUIDE.md"><b>&#128269; Wireshark guide</b><span>Inspect the captures; version-correct DNP3 filters</span></a>
<a class=card href="TUTORIAL.html#12-results"><b>&#128202; Final results</b><span>Native vs protected, entropy, resource use</span></a>
<a class=card href="TUTORIAL.html#14-limitations-and-security-scope"><b>&#9888; Limitations & scope</b><span>What is and is not claimed</span></a>
<a class=card href="QUICKSTART.md"><b>&#128295; Quick start / restoration</b><span>10-minute path; restore = <code>make restore</code></span></a>
<a class=card href="evidence_summary/MANIFEST.md"><b>&#128203; Evidence manifest</b><span>Every number &rarr; its source file</span></a>
</div>
<h2>Result at a glance</h2>
<img src="figures/fig03_native_vs_protected_hist.png" alt="native vs protected CLRT">
<p class=sub>Native CLRT (grey) spreads from ~2 ms past 11 ms; protected (green, G = 25 ms) collapses to a single spike. Byte-identical, 100/100 responses.</p>
<div class=note><b>Restoration:</b> the switch is returned to <code>queue_microbench</code> with
<code>make restore</code>. The demo default is safe replay of the relay's real frames — no relay
modification, no DNP3 control/write. See QUICKSTART.md and demo/ for details.</div>
</main></body></html>
HTML

echo "[4/6] copy the 2-min demo script into evidence_summary for the START_HERE link"
cp "$TUT/DEMO_SCRIPT_2_MINUTES.md" "$PKG/evidence_summary/DEMO_2_MIN.md"

echo "[5/6] SHA256SUMS"
( cd "$PKG" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "    $(wc -l < "$PKG/SHA256SUMS") files hashed"

echo "[6/6] tar.gz + verify"
TAR="$DELIV/timing_meeting_package_${DATE}_${COMMIT}.tar.gz"
rm -f "$TAR"
( cd "$DELIV" && tar czf "$TAR" meeting_package )
echo "    wrote $TAR ($(du -h "$TAR" | cut -f1))"
( cd "$PKG" && sha256sum -c SHA256SUMS >/dev/null && echo "    SHA256SUMS verify: PASS" )
echo "done."
