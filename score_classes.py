#!/usr/bin/env python3
# Scorpius Sweep
# Copyright 2026 Nate Carroll (Nate-Carroll-Cyber)
# SPDX-License-Identifier: Apache-2.0
"""Score each CWE class by how Antares searched for it, from the sweep transcripts.

    python3 score_classes.py --out results/<name> --queries queries/all.json \\
        [--controls results/<name>-controls --control-queries queries/controls.json]

A sweep on one repository cannot say which classes the model was trained on: a class with no hit
may be absent from the repository or unknown to the model. What the transcripts do show is whether
the model has a search strategy for a class. This script measures that, per class:

  learned_terms   search terms that are not words from the CWE description, are not generic (used
                  for more than a quarter of all classes), and were not used for any control. A
                  model that only echoes the description, or reuses the same terms everywhere,
                  scores near zero.
  echo_share      share of its search terms that are just words from the description.
  agreed_files    source files named by at least two runs.
  invented_share  share of submitted paths that do not exist.
  repeat_share    share of commands that repeat an earlier command in the same run.

With --controls, the same scores are computed for invented classes that do not exist. A real class
is listed as "has a strategy" only when its learned_terms beat every control.

Writes class-scores.json and class-scores.md into --out. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

STOP = set("""rg grep egrep fgrep find cat head tail sed awk ls tree wc sort uniq cut xargs file stat echo pwd cd nl du diff
name iname type print maxdepth mindepth path not include exclude glob files with matches line number only and the for
workspace repo src lib test tests node modules json yaml yml txt true false null var let const function return import from
""".split())
TOOL_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)
NOISE = re.compile(r"(\.d\.ts$|\.(spec|test|eval)\.[a-z]+$|(^|/)(tests?|__tests__|fixtures?|node_modules|dist|build|vendor)/"
                   r"|(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|tsconfig[^/]*\.json|wrangler\.(jsonc?|toml)|CHANGELOG\.md|README\.md|LICENSE)$"
                   r"|(^|/)\.[^/]+$|\.config\.[a-z]+$|\.(md|lock|map|snap)$)", re.I)


def words(text: str) -> set[str]:
    out = set()
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", text):
        out.add(w.lower())
        for part in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", w):  # camelCase pieces
            if len(part) >= 3:
                out.add(part.lower())
    return out


def stem(w: str) -> str:
    for suf in ("ization", "isation", "ations", "ation", "ments", "ment", "ings", "ing", "ized", "ised", "ies", "ed", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


def search_terms(command: str) -> set[str]:
    """Words the model searched for: everything in the command except tool names, options and paths."""
    terms = set()
    for tok in re.findall(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+", command):
        bare = tok.strip("\"'")
        if tok.startswith("-") or bare in (".", "/workspace/repo", "{}", ";", "\\;", "|", "&&"):
            continue
        if tok[0] not in "\"'" and ("/" in bare or bare.startswith(".")):
            continue  # an unquoted path
        terms |= {w for w in words(bare) if w not in STOP}
    return terms


def read_class(out: Path, qid: str, description: str) -> dict | None:
    desc_stems = {stem(w) for w in words(description)}
    terms: set[str] = set()
    commands = repeats = runs = 0
    for n in range(1, 50):
        t = out / "transcripts" / f"{qid}.run{n}.jsonl"
        r = out / "transcripts" / f"{qid}.run{n}.result.json"
        if not t.is_file() or not r.is_file():
            break
        runs += 1
        seen = set()
        for line in t.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("role") != "assistant":
                continue
            m = TOOL_CALL.search(rec.get("content", ""))
            if not m:
                continue
            try:
                call = json.loads(m.group(1))
            except json.JSONDecodeError:
                continue
            if call.get("name") != "terminal":
                continue
            cmd = str((call.get("arguments") or {}).get("command", ""))
            commands += 1
            repeats += cmd in seen
            seen.add(cmd)
            terms |= search_terms(cmd)
    if not runs:
        return None
    votes: dict[str, int] = {}
    real = fake = submitted = 0
    for n in range(1, runs + 1):
        res = json.loads((out / "transcripts" / f"{qid}.run{n}.result.json").read_text(encoding="utf-8"))
        submitted += res["status"] == "submitted"
        real += len(res["files"])
        fake += len(res["files_not_in_repo"])
        for f in res["files"]:
            votes[f] = votes.get(f, 0) + 1
    desc_prefixes = {w[:5] for w in words(description) if len(w) >= 5}
    echo = {t for t in terms if stem(t) in desc_stems or (len(t) >= 5 and t[:5] in desc_prefixes)}
    return {"id": qid, "runs": runs, "submitted": submitted, "commands": commands, "terms": sorted(terms), "echo": sorted(echo),
            "agreed_files": sorted(f for f, c in votes.items() if c >= min(2, runs) and not NOISE.search(f)),
            "invented_share": round(fake / (real + fake), 2) if real + fake else None,
            "repeat_share": round(repeats / commands, 2) if commands else None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="sweep output folder")
    ap.add_argument("--queries", required=True, help="the query file the sweep used")
    ap.add_argument("--controls", help="output folder of a sweep over invented classes")
    ap.add_argument("--control-queries", default="queries/controls.json")
    ap.add_argument("--common", type=float, default=0.25, help="a term counts as generic when more than this share of classes use it (default 0.25)")
    args = ap.parse_args()

    out = Path(args.out)
    classes = [c for q in json.loads(Path(args.queries).read_text(encoding="utf-8"))
               if (c := read_class(out, q["id"], q["cwe_description"]))]
    if not classes:
        raise SystemExit(f"no finished runs found under {out / 'transcripts'}")
    names = {q["id"]: q["cwe_description"].split(" — ")[0] for q in json.loads(Path(args.queries).read_text(encoding="utf-8"))}
    df: dict[str, int] = {}
    for c in classes:
        for t in c["terms"]:
            df[t] = df.get(t, 0) + 1
    limit = max(2, math.floor(args.common * len(classes)))
    control_raw = []
    if args.controls:
        for q in json.loads(Path(args.control_queries).read_text(encoding="utf-8")):
            c = read_class(Path(args.controls), q["id"], q["cwe_description"])
            if c:
                control_raw.append(c)
    control_terms = {t for c in control_raw for t in c["terms"] if t not in c["echo"]}

    def finish(c: dict, is_control: bool = False) -> dict:
        learned = [t for t in c["terms"] if t not in c["echo"] and df.get(t, 0) <= limit and (is_control or t not in control_terms)]
        c["learned_terms"] = len(learned)
        c["learned_examples"] = learned[:12]
        c["echo_share"] = round(len(c["echo"]) / len(c["terms"]), 2) if c["terms"] else None
        c.pop("terms"), c.pop("echo")
        return c

    controls = [finish(c, True) for c in control_raw]
    classes = [finish(c) for c in classes]
    bar = max((c["learned_terms"] for c in controls), default=None)
    for c in classes:
        c["name"] = names.get(c["id"], c["id"])
        c["has_strategy"] = None if bar is None else c["learned_terms"] > bar
    classes.sort(key=lambda c: (-c["learned_terms"], c["id"]))
    report = {"classes_scored": len(classes), "generic_term_limit": limit, "control_bar_learned_terms": bar,
              "classes_with_a_strategy": None if bar is None else sum(1 for c in classes if c["has_strategy"]),
              "controls": controls, "classes": classes}
    (out / "class-scores.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    lines = ["# Class scores", "",
             f"{len(classes)} classes scored. A term is generic when more than {limit} classes use it.",
             "No control run was supplied, so no threshold is applied." if bar is None else
             f"Control bar: {bar} learned terms. {report['classes_with_a_strategy']} classes beat it.", "",
             "| Class | Learned terms | Examples | Echo share | Agreed files | Invented share | Repeat share |", "|---|---|---|---|---|---|---|"]
    for c in controls + classes:
        lines.append(f"| {c.get('name', c['id'])} | {c['learned_terms']} | {', '.join(c['learned_examples'][:6])} | {c['echo_share']} | "
                     f"{len(c['agreed_files'])} | {c['invented_share']} | {c['repeat_share']} |")
    (out / "class-scores.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out / 'class-scores.json'} and {out / 'class-scores.md'}")
    if bar is not None:
        print(f"{report['classes_with_a_strategy']} of {len(classes)} classes beat the control bar of {bar} learned terms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
