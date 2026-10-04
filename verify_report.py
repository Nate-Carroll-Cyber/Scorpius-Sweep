#!/usr/bin/env python3
# Scorpius Sweep
# Copyright 2026 Nate Carroll (Nate-Carroll-Cyber)
# SPDX-License-Identifier: Apache-2.0
"""Check the driver's report against the target's source. No model is involved.

    python3 verify_report.py                         # report and target from .antares-target
    python3 verify_report.py --report results/<name>/security-review.md --repo targets/<name>

A driver model can quote code that is not in the repository, cite a file that does not exist, or
give a line number past the end of a file. This script reads every citation and every quoted
piece of code in the report and looks each one up in the source.

  citation   a `path`, `path:line` or `path:line-line` in the report, or "path L12". A path may be
             given in full or by its last part, such as a bare file name.
  quote      a fenced code block, a "> quoted line" under a citation, or code in backticks
             straight after a citation. A quote is
             checked against the file its citation names. Indentation and line breaks are ignored,
             and a line shortened with an ellipsis is matched piece by piece.

Verdict for each quote:

  verified     every quoted line is in the cited file, at or near the cited line
  wrong-line   every quoted line is in the cited file, somewhere else
  partial      some quoted lines are in the cited file and some are nowhere in it
  elsewhere    the quoted lines are in another file of the repository, not the cited one
  not-found    the quoted lines are not in the repository
  no-file      the cited file is not in the repository

verified and wrong-line count as real. The script answers one question: did the report quote
code that exists where it says. It does not judge whether a finding is right, and it says
nothing about code the report never mentions.

Writes report-check.md and report-check.json beside the report. Exit status is 1 when any quote or
citation fails, so it can gate a pipeline. Standard library only.
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from pathlib import Path

EXT = (r"(?:tsx?|jsx?|mjs|cjs|py|go|rs|java|kt|kts|c|h|cc|cpp|hpp|cs|rb|php|swift|scala|sh|bash|zsh|sql|jsonc?|ya?ml|toml|xml|html?|css|scss|"
       r"md|tf|ini|cfg|conf|env|lock|gradle|proto|vue|svelte|txt|ps1|pl|lua|dart|ex|exs|erl|hs|m|mm|plist|properties)")
NAME = r"(?:\.?[\w@][\w@.+-]*\." + EXT + r"|Dockerfile(?:\.[\w-]+)?|Makefile|Jenkinsfile|Gemfile|Procfile)"
PATH = r"(?:[\w@.+-]+/)*" + NAME
CITE = re.compile(r"(?<![\w/.@+*-])(" + PATH + r")(?![\w/])"
                  r"(?:`?\s*(?::|,?\s*\(?\s*(?:L|[Ll]ines?\s+))\s*L?(\d+)(?:\s*[-–]\s*L?(\d+))?)?")
FULL_PATH = re.compile(r"^" + PATH + r"$")
TICK = re.compile(r"`([^`\n]+)`")
FENCE = re.compile(r"^\s*(```|~~~)")
ELLIPSIS = re.compile(r"\.{3,}|\u2026")
# what may sit between a citation and its inline quote: punctuation and at most two short words ("sets", "uses")
ADJACENT = re.compile(r"[`*:\s(\u2013\u2014-]{0,10}(?:[A-Za-z]{1,12}\s){0,2}[`*:\s(]{0,4}")
QUOTE_LINE = re.compile(r"^\s*>\s?(.*)$")
COMMENT = re.compile(r"^\s*(//|#|/\*|\*|--|<!--|;)")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".turbo", ".next"}
NEAR = 3            # a quote counts as at the cited line when it is within this many lines of it
MAX_BYTES = 2_000_000
REAL = ("verified", "wrong-line")
PATHLIKE = re.compile(r"^[\w@./*+-]*/[\w@./*+-]*$")        # a path or glob in backticks is a mention, not a quote
KIT_FILES = {"leads.json", "results.json", "reference-score.json", "class-scores.json", "class-scores.md", "report-check.json",
             "report-check.md", "security-review.md", "id-map.json", "probe.json", "chosen.json", "controls.json", "all.json"}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def squash(s: str) -> str:
    """Text with all whitespace removed, so indentation and line breaks do not matter."""
    return re.sub(r"\s+", "", s)


def alnum(s: str) -> int:
    return len(re.findall(r"[A-Za-z0-9]", s))


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.lines: dict[str, int] = {}                 # relative path -> number of lines
        self.text: dict[str, str] = {}                  # relative path -> the file with all whitespace removed
        self.starts: dict[str, list[int]] = {}          # relative path -> offset in that text where each line begins
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink() or p.stat().st_size > MAX_BYTES:
                        continue
                    raw = p.read_bytes()
                except OSError:
                    continue
                if b"\0" in raw[:4096]:
                    continue
                rel = p.relative_to(root).as_posix()
                parts, starts, at = [], [], 0
                for line in raw.decode("utf-8", "replace").splitlines():
                    q = squash(line)
                    starts.append(at)
                    parts.append(q)
                    at += len(q)
                self.lines[rel], self.text[rel], self.starts[rel] = len(parts), "".join(parts), starts

    def resolve(self, cited: str) -> list[str]:
        """Repository files a cited path can mean: the path itself, or files whose path ends with it."""
        c = cited.strip()
        while c.startswith("./"):
            c = c[2:]
        c = c.lstrip("/")
        if c.startswith("workspace/repo/"):
            c = c[len("workspace/repo/"):]
        if c in self.lines:
            return [c]
        hits = [f for f in self.lines if f.endswith("/" + c)]
        if not hits and "/" in c:  # a longer prefix than the repository has, e.g. targets/<name>/src/a.ts
            parts = c.split("/")
            for i in range(1, len(parts)):
                tail = "/".join(parts[i:])
                if tail in self.lines:
                    return [tail]
        return sorted(hits)

    def where(self, fragments: list[str], path: str) -> list[int]:
        """1-based line numbers in `path` where the fragments occur, in order and close together."""
        text, out, at = self.text[path], [], 0
        while True:
            i = text.find(fragments[0], at)
            if i < 0:
                return out
            j, ok = i + len(fragments[0]), True
            for f in fragments[1:]:
                k = text.find(f, j, j + 600)
                if k < 0:
                    ok = False
                    break
                j = k + len(f)
            if ok:
                out.append(bisect.bisect_right(self.starts[path], i))
            at = i + 1

    def elsewhere(self, fragments: list[str], skip: set[str]) -> str | None:
        for f in self.text:
            if f not in skip and self.where(fragments, f):
                return f
        return None


def countable(line: str) -> list[str] | None:
    """The parts of a quoted line worth looking up, or None for blanks, brackets, comments and ellipses.

    A model often shortens a line with an ellipsis or adds a trailing comment. The line is split at
    each ellipsis and the pieces must appear in the source in order.
    """
    s = re.sub(r"^\s*\d+\s*[:|]\s?", "", line).strip()        # a leading line number
    if not s or COMMENT.match(s):
        return None
    s = re.sub(r"\s+(//|#)\s.*$", "", s)                       # a trailing comment
    frags = [squash(x) for x in ELLIPSIS.split(s)]
    frags = [f for f in frags if alnum(f) >= 6]
    return frags or None


def check_quote(repo: Repo, cite: dict | None, lines: list[str]) -> dict:
    shown = [norm(x) for x in lines if countable(x)]
    wanted = [c for c in (countable(x) for x in lines) if c]
    res = {"lines": len(wanted)}
    if not wanted:
        return {**res, "verdict": "no-evidence", "detail": "nothing to check in the quote"}
    if cite is None:
        other = repo.elsewhere(wanted[0], set())
        return {**res, "verdict": "uncited", "detail": f"no citation; first line is in {other}" if other else "no citation; first line is not in the repository"}
    if not cite["files"]:
        return {**res, "verdict": "no-file", "detail": f"{cite['path']} is not in the repository"}
    best = None
    for path in cite["files"]:
        found, near, first = 0, 0, None
        lo = (cite["start"] or 0) - NEAR
        hi = max(cite["end"] or 0, (cite["start"] or 0) + len(lines)) + NEAR
        missing = []
        for w, text in zip(wanted, shown):
            at = repo.where(w, path)
            if at:
                found += 1
                near += any(lo <= n <= hi for n in at)
                first = first or at[0]
            else:
                missing.append(text)
        cand = (found, near, path, missing, first)
        if best is None or cand[:2] > best[:2]:
            best = cand
    found, near, path, missing, first = best
    res.update({"file": path, "found": found})
    if found == len(wanted):
        if cite["start"] is None or near * 2 >= found:
            return {**res, "verdict": "verified", "detail": f"{found} of {found} quoted lines in {path}" + ("" if cite["start"] else ", no line cited")}
        return {**res, "verdict": "wrong-line", "detail": f"in {path} at line {first}, cited {cite['start']}"}
    if found:
        return {**res, "verdict": "partial", "detail": f"{found} of {len(wanted)} quoted lines in {path}; not there: {missing[0][:70]}"}
    other = repo.elsewhere(wanted[0], set(cite["files"]))
    if other:
        return {**res, "verdict": "elsewhere", "detail": f"not in {path}; first line is in {other}"}
    return {**res, "verdict": "not-found", "detail": f"not in the repository: {shown[0][:70]}"}


def first_line(lines: list[str]) -> str:
    return next(norm(x) for x in lines if countable(x))[:90]


def parse(report: str, repo: Repo) -> tuple[list[dict], list[dict]]:
    """Citations and quotes, in report order."""
    cites: list[dict] = []
    quotes: list[dict] = []
    section = "(top)"
    current, current_age = None, 99          # the last citation in prose, and how many text lines ago it was
    in_fence, block, block_start = False, [], 0

    def make_cite(m, lineno) -> dict:
        start = int(m.group(2)) if m.group(2) else None
        end = int(m.group(3)) if m.group(3) else start
        files = repo.resolve(m.group(1))
        if not files and "/" not in m.group(1) and not m.group(2) and (m.group(1).startswith(".") or m.group(1) in KIT_FILES):
            return None                      # ".spec.ts" in prose is a kind of file, and leads.json is the kit's own
        c = {"report_line": lineno, "section": section, "path": m.group(1), "start": start, "end": end, "files": files}
        if not files:
            c["status"] = "no-file"
        elif start is not None and all(start > repo.lines[f] for f in files):
            c["status"] = "line-past-end"
            c["detail"] = f"line {start} cited, {files[0]} has {repo.lines[files[0]]} lines"
        else:
            c["status"] = "ok"
        cites.append(c)
        return c

    def flush_block(lineno):
        segs: list[tuple[dict | None, list[str]]] = [(current if current_age <= 6 else None, [])]
        for bl in block:
            m = CITE.search(bl) if COMMENT.match(bl) else None
            c = make_cite(m, block_start) if m else None
            if c:
                segs.append((c, []))
            else:
                segs[-1][1].append(bl)
        for cite, lines in segs:
            if not any(countable(x) for x in lines):
                continue
            q = check_quote(repo, cite, lines)
            quotes.append({"report_line": block_start, "section": section, "kind": "block",
                           "cited": None if cite is None else cite["path"] + (f":{cite['start']}" if cite["start"] else ""),
                           "quote": first_line(lines), **q})

    for lineno, line in enumerate(report.splitlines(), 1):
        if FENCE.match(line):
            if in_fence:
                flush_block(lineno)
            else:
                block, block_start = [], lineno
            in_fence = not in_fence
            continue
        if in_fence:
            block.append(line)
            continue
        if line.lstrip().startswith("#"):
            section = line.strip("# ").strip()[:90]
            current, current_age = None, 99
        if line.strip():
            current_age += 1
        found = [(m.start(), m.end(), make_cite(m, lineno)) for m in CITE.finditer(line)]
        found = [x for x in found if x[2] is not None]
        bq = QUOTE_LINE.match(line)
        if bq and not found and current is not None and current_age <= 2:   # a "> quoted line" under its citation
            spans = [t.group(1) for t in TICK.finditer(bq.group(1))] or [bq.group(1)]
            for text in spans:
                q = check_quote(repo, current, [text])
                if q["verdict"] != "no-evidence":
                    quotes.append({"report_line": lineno, "section": section, "kind": "blockquote",
                                   "cited": current["path"] + (f":{current['start']}" if current["start"] else ""), "quote": norm(text)[:90], **q})
            continue
        if found:
            current, current_age = found[-1][2], 0
        for t in TICK.finditer(line):           # code in backticks straight after a citation is an inline quote
            text = t.group(1).strip()
            owner = [c for st, e, c in found if e <= t.start() + 1 and ADJACENT.fullmatch(line[e:t.start()])]
            if not owner or FULL_PATH.match(text) or PATHLIKE.match(text) or alnum(text) < 6 or re.fullmatch(r"CWE-\d+", text):
                continue
            c = owner[-1]
            q = check_quote(repo, c, [text])
            if q["verdict"] != "no-evidence":
                quotes.append({"report_line": lineno, "section": section, "kind": "inline",
                               "cited": c["path"] + (f":{c['start']}" if c["start"] else ""), "quote": text[:90], **q})
    return cites, quotes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--report", help="the driver's report (default: OUT_DIR/security-review.md from .antares-target)")
    ap.add_argument("--repo", help="the target's source (default: TARGET_DIR from .antares-target)")
    args = ap.parse_args()
    kit = Path(__file__).resolve().parent
    target: dict[str, str] = {}
    if (kit / ".antares-target").is_file():
        for ln in (kit / ".antares-target").read_text(encoding="utf-8").splitlines():
            k, _, v = ln.partition("=")
            target[k.strip()] = v.strip().strip("'\"")
    if not args.repo and "TARGET_DIR" not in target or not args.report and "OUT_DIR" not in target:
        raise SystemExit("no .antares-target here: pass --report and --repo")
    repo_dir = Path(args.repo) if args.repo else (kit / target["TARGET_DIR"])
    report_path = Path(args.report) if args.report else (kit / target["OUT_DIR"] / "security-review.md")
    if not repo_dir.is_dir():
        raise SystemExit(f"target not found: {repo_dir}")
    if not report_path.is_file():
        raise SystemExit(f"report not found: {report_path}")

    repo = Repo(repo_dir.resolve())
    cites, quotes = parse(report_path.read_text(encoding="utf-8", errors="replace"), repo)
    checked = [q for q in quotes if q["verdict"] != "uncited"]
    real = [q for q in checked if q["verdict"] in REAL]
    bad_cites = [c for c in cites if c["status"] != "ok"]
    tally: dict[str, int] = {}
    for q in quotes:
        tally[q["verdict"]] = tally.get(q["verdict"], 0) + 1
    sections: dict[str, dict] = {}
    for q in checked:
        s = sections.setdefault(q["section"], {"quotes": 0, "real": 0})
        s["quotes"] += 1
        s["real"] += q["verdict"] in REAL
    summary = {"report": str(report_path), "repo": str(repo_dir), "quotes_checked": len(checked), "quotes_real": len(real),
               "verdicts": tally, "citations": len(cites), "citations_with_a_missing_file": sum(c["status"] == "no-file" for c in cites),
               "citations_past_the_end_of_the_file": sum(c["status"] == "line-past-end" for c in cites)}
    out = {"summary": summary, "sections": sections, "quotes": quotes,
           "bad_citations": [{k: c[k] for k in ("report_line", "section", "path", "start", "status") if k in c} | ({"detail": c["detail"]} if "detail" in c else {})
                             for c in bad_cites]}
    report_path.with_name("report-check.json").write_text(json.dumps(out, indent=1), encoding="utf-8")

    def esc(s):
        return str(s).replace("|", "\\|")
    md = ["# Report check", "",
          f"Report `{report_path.name}` against `{repo_dir.name}`. No model was used.", "",
          f"{len(real)} of {len(checked)} quotes are in the source where the report says "
          f"({tally.get('verified', 0)} at the cited line, {tally.get('wrong-line', 0)} in the cited file at another line).",
          f"{len(cites)} citations, {summary['citations_with_a_missing_file']} name a file that is not in the repository and "
          f"{summary['citations_past_the_end_of_the_file']} give a line past the end of the file.", "",
          "This checks that quoted code exists. It does not check that a finding is right.", "",
          "## By section", "", "| Section | Quotes in the source | Quotes checked |", "|---|---|---|"]
    md += [f"| {esc(name)} | {s['real']} | {s['quotes']} |" for name, s in sections.items()]
    md += ["", "## Quotes", "", "| Report line | Cited | Verdict | Detail | Quote |", "|---|---|---|---|---|"]
    md += [f"| {q['report_line']} | `{esc(q['cited'])}` | {q['verdict']} | {esc(q['detail'])} | `{esc(q['quote'])}` |" for q in quotes]
    if bad_cites:
        md += ["", "## Citations that do not resolve", "", "| Report line | Cited | Problem |", "|---|---|---|"]
        md += [f"| {c['report_line']} | `{esc(c['path'])}{':' + str(c['start']) if c['start'] else ''}` | "
               f"{c.get('detail', 'file is not in the repository')} |" for c in bad_cites]
    report_path.with_name("report-check.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"{len(real)} of {len(checked)} quotes are in the source where the report says; "
          f"{summary['citations_with_a_missing_file']} citations name a missing file, {summary['citations_past_the_end_of_the_file']} give a line past the end of the file")
    print("verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items())))
    print(f"wrote {report_path.with_name('report-check.md')}")
    return 1 if len(real) < len(checked) or bad_cites else 0


if __name__ == "__main__":
    sys.exit(main())
