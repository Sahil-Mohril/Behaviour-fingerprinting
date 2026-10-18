"""Order thebibliography entries by first citation (IEEE style)."""
import re
import sys

p = sys.argv[1]
s = open(p, encoding="utf-8").read()
BEGIN = "\\begin{thebibliography}{99}"
a = s.index(BEGIN)
b = s.index("\\end{thebibliography}")
body = s[a + len(BEGIN):b]
items = re.findall(r"(\\bibitem\{([^}]+)\}.*?)(?=\\bibitem\{|\Z)", body, re.S)
order = []
for m in re.finditer(r"\\cite\{([^}]+)\}", s[:a]):
    for k in m.group(1).split(","):
        k = k.strip()
        if k not in order:
            order.append(k)
d = {k: t.strip() for t, k in items}
print("missing", [k for k in order if k not in d], "unused", [k for k in d if k not in order], "n", len(order))
s = s[:a] + BEGIN + "\n" + "\n".join(d[k] for k in order if k in d) + "\n" + s[b:]
open(p, "w", encoding="utf-8").write(s)
