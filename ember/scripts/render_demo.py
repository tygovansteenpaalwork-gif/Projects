"""Render `ember scan examples/infected_tree.rbxmx` as a terminal-style SVG for the README.

Usage: python scripts/render_demo.py > docs/demo.svg
"""

import html
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SGR = re.compile(r"\x1b\[([0-9;]*)m")
PALETTE_256 = {45: "#00d7ff", 160: "#d70000", 196: "#ff3b30", 202: "#ff5f00", 214: "#ffaf00", 245: "#8a8a8a", 252: "#d0d0d0"}
BG, FG = "#0d0d0d", "#c0c0c0"
CHAR_W, LINE_H, PAD = 8.4, 19, 20


def parse(line):
    spans, style = [], {}
    pos = 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            spans.append((line[pos:m.start()], dict(style)))
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                style = {}
            elif c == 1:
                style["bold"] = True
            elif c == 2:
                style["dim"] = True
            elif c == 32:
                style["fg"] = "#30d158"
            elif c == 97:
                style["fg"] = "#ffffff"
            elif c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:
                style["fg" if c == 38 else "bg"] = PALETTE_256.get(codes[i + 2], FG)
                i += 2
            i += 1
        pos = m.end()
    if pos < len(line):
        spans.append((line[pos:], dict(style)))
    return spans


def main():
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    out = subprocess.run(
        [sys.executable, "-m", "ember", "scan", "examples/infected_tree.rbxmx", "--color", "always", "--fail-on", "none"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    ).stdout
    lines = ["$ ember scan examples/infected_tree.rbxmx"] + out.rstrip("\n").split("\n")
    width = int(max(len(SGR.sub("", l)) for l in lines) * CHAR_W + PAD * 2)
    height = int(len(lines) * LINE_H + PAD * 2 + 30)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" rx="8" fill="{BG}"/>',
        '<circle cx="20" cy="18" r="6" fill="#ff5f57"/><circle cx="40" cy="18" r="6" fill="#febc2e"/>'
        '<circle cx="60" cy="18" r="6" fill="#28c840"/>',
        f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14" fill="{FG}" xml:space="preserve">',
    ]
    for n, line in enumerate(lines):
        y = PAD + 30 + n * LINE_H
        x = PAD
        for text, st in parse(line):
            w = len(text) * CHAR_W
            if st.get("bg"):
                parts.append(f'<rect x="{x:.1f}" y="{y - 14}" width="{w:.1f}" height="{LINE_H - 1}" fill="{st["bg"]}"/>')
            attrs = []
            if st.get("fg"):
                attrs.append(f'fill="{st["fg"]}"')
            if st.get("bold"):
                attrs.append('font-weight="700"')
            if st.get("dim"):
                attrs.append('opacity="0.55"')
            if n == 0:
                attrs.append('fill="#ff7b00"')
            if text.strip():
                parts.append(f'<text x="{x:.1f}" y="{y}" {" ".join(attrs)}>{html.escape(text).replace(" ", "&#160;")}</text>')
            x += w
    parts.append("</g></svg>")
    print("\n".join(parts))


if __name__ == "__main__":
    main()
