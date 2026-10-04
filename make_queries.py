#!/usr/bin/env python3
# Scorpius Sweep
# Copyright 2026 Nate Carroll (Nate-Carroll-Cyber)
# SPDX-License-Identifier: Apache-2.0
"""Build a query file, from the official Antares CLI's plan or from CWE IDs you choose.

    antares plan targets/NAME --format json | python3 make_queries.py --plan - > queries/NAME.json
    python3 make_queries.py --plan plan.json > queries/NAME.json
    python3 make_queries.py CWE-22 CWE-79 CWE-89 > queries/mine.json
    python3 make_queries.py --list            # the CWE IDs the catalog knows

--plan reads the JSON that `antares plan PATH --format json` prints and keeps its selected CWEs in
the plan's order. The plan picks classes from evidence in the repository, with no model call.

Descriptions come from queries/cwe-catalog.json, which holds the 145 CWE classes of Cisco's
vulnerability-localization benchmark (Apache-2.0) in the wording the model was evaluated with.
A planned CWE outside the catalog gets the same form, "CWE-N: Name — description", built from the
name and MITRE description the plan carries. For a hand-picked CWE outside the catalog, add an
entry to the output by hand in that form.
"""
import json
import re
import sys
from pathlib import Path

CATALOG = Path(__file__).resolve().parent / "queries" / "cwe-catalog.json"


def from_plan(plan: dict, catalog: dict) -> list:
    out, seen = [], set()
    for check in plan.get("selected_checks", []):
        for raw in check.get("cwe_ids", []):
            m = re.fullmatch(r"(?:CWE-)?0*(\d+)", str(raw).strip(), re.I)
            if not m:
                continue
            cwe = f"CWE-{m.group(1)}"
            if cwe in seen:
                continue
            seen.add(cwe)
            text = catalog.get(cwe)
            if text is None:
                title = " ".join(str(check.get("title", "")).split())
                summary = " ".join(str(check.get("plain_language_summary", "")).split())
                if not title:
                    continue
                text = f"{cwe}: {title}" + (f" — {summary}" if summary else "")
            out.append({"id": cwe.lower(), "cwe": cwe, "cwe_description": text})
    return out


def main(args: list) -> int:
    if not args or args[0] in ("-h", "--help"):
        sys.exit(__doc__)
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if args[0] == "--list":
        for v in catalog.values():
            print(v.split(" — ")[0])
        return 0
    if args[0] == "--plan":
        if len(args) != 2:
            sys.exit("usage: make_queries.py --plan FILE   (use - for standard input)")
        raw = sys.stdin.read() if args[1] == "-" else Path(args[1]).read_text(encoding="utf-8")
        try:
            plan = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.exit(f"the plan is not JSON ({e}). Run: antares plan PATH --format json")
        out = from_plan(plan, catalog)
        if not out:
            sys.exit("the plan has no selected CWEs")
        outside = [q["cwe"] for q in out if q["cwe"] not in catalog]
        print(f"{len(out)} classes from the plan, {len(outside)} outside the benchmark catalog"
              + (": " + ", ".join(outside) if outside else ""), file=sys.stderr)
    else:
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
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
