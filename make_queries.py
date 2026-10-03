#!/usr/bin/env python3
"""Build a query file from CWE IDs you choose.

    python3 make_queries.py CWE-22 CWE-79 CWE-89 > queries/mine.json
    python3 make_queries.py --list            # the CWE IDs the catalog knows

Descriptions come from queries/cwe-catalog.json, which holds the 145 CWE classes of Cisco's
vulnerability-localization benchmark (Apache-2.0) in the wording the model was evaluated with.
For a CWE outside the catalog, add an entry to the output by hand in the same form:
"CWE-N: Name \u2014 description from the MITRE definition".
"""
import json
import re
import sys
from pathlib import Path

catalog = json.loads((Path(__file__).resolve().parent / "queries" / "cwe-catalog.json").read_text(encoding="utf-8"))
args = sys.argv[1:]
if not args or args[0] in ("-h", "--help"):
    sys.exit(__doc__)
if args[0] == "--list":
    for k, v in catalog.items():
        print(v.split(" \u2014 ")[0])
    sys.exit(0)
out, missing = [], []
for a in args:
    m = re.fullmatch(r"(?:CWE-)?(\d+)", a.strip(), re.I)
    if not m:
        sys.exit(f"not a CWE ID: {a}")
    cwe = f"CWE-{m.group(1)}"
    if cwe in catalog:
        out.append({"id": cwe.lower(), "cwe": cwe, "cwe_description": catalog[cwe]})
    else:
        missing.append(cwe)
if missing:
    sys.exit("not in the catalog: " + ", ".join(missing) + ". Add these by hand; see the note at the top of this script.")
json.dump(out, sys.stdout, indent=1, ensure_ascii=False)
print()
