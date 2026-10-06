"""Turn a draw.io Desktop SVG export into a manuscript schematic: exact printed width,
no dark-mode background, and the accessible title/desc every schematic in this repo carries."""
import re, sys
src, dst, slug, title, desc = sys.argv[1:6]
s = open(src).read()
s = re.sub(r"<\?xml[^>]*\?>\s*|<!DOCTYPE[^>]*>\s*", "", s)
m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', s)
w, h = float(m.group(1)), float(m.group(2))
root = (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'viewBox="0 0 {w:g} {h:g}" width="{w/72:.3f}in" height="{h/72:.3f}in" role="img" '
        f'aria-labelledby="{slug}-title {slug}-desc">'
        f'<title id="{slug}-title">{title}</title><desc id="{slug}-desc">{desc}</desc>'
        f'<rect width="{w:g}" height="{h:g}" fill="#ffffff"/>')
s = re.sub(r"<svg\b[^>]*>", root, s, count=1)
# draw.io writes every colour twice: as a plain fill/stroke attribute, and again as CSS
# light-dark() for dark-mode viewers. A print figure has one mode, and a converter that
# honours the CSS could pick the dark variant, so the CSS copies are removed.
s = re.sub(r'\s+style="[^"]*light-dark\([^"]*"', "", s)
s = re.sub(r'<rect fill="#ffffff" width="100%" height="100%" x="0" y="0"\s*/>', "", s)
assert "light-dark" not in s, "dark-mode colour survived"
open(dst, "w").write(s)
print(f"{dst}: {w:g} x {h:g} units = {w/72:.2f} x {h/72:.2f} in")
