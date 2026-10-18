"""Turn the evaluation JSON saved from the web app into TikZ confusion matrices (figures/cm_*.tex).

    python make_figs.py <paper_dir>
"""
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
SHORT = {"benign": "Benign", "botnet_c2": "C2", "port_scan_fast": "Port scan", "ssh_bruteforce": "SSH b.f.",
         "syn_flood": "SYN flood", "udp_flood": "UDP flood", "unknown_anomaly": "Unknown", "unmatched": "Unclass."}


def matrix(rows, cols, mat, path, cell=5.4):
    """Row-normalised heat map; numbers are window counts, outlined cells are correct."""
    L = [r"\begin{tikzpicture}[x=%.1fmm,y=%.1fmm,font=\tiny]" % (cell, cell)]
    n, m = len(rows), len(cols)
    for i, (r, row) in enumerate(zip(rows, mat)):
        tot = sum(row) or 1
        y = n - 1 - i
        L.append(r"\node[anchor=east] at (-0.1,%g) {%s};" % (y + 0.5, SHORT.get(r, r)))
        for j, v in enumerate(row):
            s = v / tot
            fill = r"cmblue!%d!white" % round(8 + 92 * s) if v else "white"
            L.append(r"\fill[%s] (%d,%d) rectangle ++(1,1);" % (fill, j, y))
            if v:
                L.append(r"\node[text=%s] at (%g,%g) {%d};" % ("white" if s > 0.45 else "black", j + 0.5, y + 0.5, v))
    L.append(r"\draw[black!25, step=1] (0,0) grid (%d,%d);" % (m, n))
    for i, r in enumerate(rows):
        if r in cols:
            L.append(r"\draw[black, thick] (%d,%d) rectangle ++(1,1);" % (cols.index(r), n - 1 - i))
    for j, c in enumerate(cols):
        L.append(r"\node[anchor=west, rotate=60] at (%g,%g) {%s};" % (j + 0.35, n + 0.1, SHORT.get(c, c)))
    L.append(r"\node[rotate=90, font=\scriptsize] at (-3.4,%g) {True behaviour};" % (n / 2))
    L.append(r"\node[font=\scriptsize] at (%g,-0.6) {Detected category};" % (m / 2))
    L.append(r"\end{tikzpicture}")
    (out / "figures" / path).write_text("\n".join(L) + "\n", encoding="utf-8")


def binary(b, path, cell=7):
    cells = [["tp", "fn"], ["fp", "tn"]]
    names = ["Attack", "Benign"]
    L = [r"\begin{tikzpicture}[x=%dmm,y=%dmm,font=\scriptsize]" % (round(cell * 1.6), cell)]
    for i in range(2):
        tot = sum(b[k] for k in cells[i]) or 1
        for j in range(2):
            v = b[cells[i][j]]; s = v / tot; y = 1 - i
            L.append(r"\fill[%s] (%d,%d) rectangle ++(1,1);" % (r"cmblue!%d!white" % round(8 + 92 * s) if v else "white", j, y))
            L.append(r"\node[text=%s, align=center] at (%g,%g) {%s~%d};" % ("white" if s > 0.45 else "black", j + .5, y + .5,
                                                                            cells[i][j].upper(), v))
        L.append(r"\node[anchor=east] at (-0.05,%g) {%s};" % (1 - i + .5, names[i]))
        L.append(r"\node[anchor=south] at (%g,2.05) {%s};" % (i + .5, names[i]))
    L.append(r"\draw[black!25] (0,0) grid (2,2);")
    L.append(r"\node[font=\tiny] at (1,2.75) {Predicted};")
    L.append(r"\node[rotate=90, font=\tiny] at (-0.62,1) {True};")
    L.append(r"\end{tikzpicture}")
    (out / "figures" / path).write_text("\n".join(L) + "\n", encoding="utf-8")


for run in ("mixed", "demo"):
    m = json.load(open(out / f"results/web_{run}_eval.json"))
    for mode in ("online", "final"):
        c = m[mode]["confusion"]
        matrix(c["rows"], c["cols"], c["matrix"], f"cm_{run}_{mode}.tex")
    binary(m["binary"], f"cm_{run}_binary.tex")
print("ok")
