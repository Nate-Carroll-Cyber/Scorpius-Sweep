#!/usr/bin/env python3
# Scorpius Sweep
# Copyright 2026 Nate Carroll (Nate-Carroll-Cyber)
# SPDX-License-Identifier: Apache-2.0
"""Score each CWE class of a finished sweep against the control runs.

    python3 score_classes.py --out results/<name>
    python3 score_classes.py --out results/<name> --controls-dir results/<other> --queries queries/<subset>.json --write-leads

The control queries (queries/controls.json) ask the model about no class and about invented classes.
The rate at which those runs name a file is what the model does on this repository whatever it is
asked. A file counts for a real class only when the class named it in most of its runs and at a
higher rate than the controls did (one-sided Fisher exact test, p at most --alpha).

  lift            the class has such a file. The class label changed the answer.
  baseline-only   the class agreed on files, and the controls name each of them about as often.
  no-agreed-lead  no source file was named by enough runs.

Per class it also reports invented_share (submitted paths that do not exist) and repeat_share
(commands that repeat an earlier command in the same run). Per file it reports how many classes
agreed on it and how many control runs named it.

Reads the per-run result files under <out>/transcripts and <controls-dir>/transcripts, so it works
on an interrupted sweep and on one made before controls were part of the run. Writes
class-scores.json and class-scores.md into --out. With --write-leads it also rewrites leads.json.
Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from antares_locate import DEFAULT_ALPHA, baseline_files, build_leads, is_noise_file, majority, rate_p  # noqa: E402

TOOL_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)
RESULT_NAME = re.compile(r"^(?P<id>.+)\.run(?P<n>\d+)\.result\.json$")


def repeat_counts(transcript: Path) -> tuple[int, int]:
    """Commands in one run, and how many of them repeat an earlier command of that run."""
    commands = repeats = 0
    seen = set()
    for line in transcript.read_text(encoding="utf-8").splitlines():
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
    return commands, repeats


def read_entries(folder: Path, names: dict[str, str], only: set[str] | None = None) -> list[dict]:
    """Result entries in the shape antares_locate.py writes to results.json, rebuilt from the per-run files."""
    by_id: dict[str, list[tuple[int, Path]]] = {}
    for p in (folder / "transcripts").glob("*.result.json"):
        m = RESULT_NAME.match(p.name)
        if m and (only is None or m.group("id") in only):
            by_id.setdefault(m.group("id"), []).append((int(m.group("n")), p))
    order = {qid: i for i, qid in enumerate(names)}
    entries = []
    for qid in sorted(by_id, key=lambda q: (order.get(q, len(order)), q)):
        runs, votes = [], {}
        commands = repeats = 0
        have_transcripts = True
        for _, p in sorted(by_id[qid]):
            res = json.loads(p.read_text(encoding="utf-8"))
            runs.append(res)
            for f in res["files"]:
                votes[f] = votes.get(f, 0) + 1
            t = p.with_name(p.name.replace(".result.json", ".jsonl"))
            if t.is_file():
                c, r = repeat_counts(t)
                commands, repeats = commands + c, repeats + r
            else:
                have_transcripts = False
        ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
        real = sum(len(r["files"]) for r in runs)
        fake = sum(len(r.get("files_not_in_repo", [])) for r in runs)
        entries.append({"id": qid, "query": names.get(qid, qid), "ranked_files": [{"file": f, "runs": c} for f, c in ranked], "runs": runs,
                        "invented_share": round(fake / (real + fake), 2) if real + fake else None,
                        "repeat_share": round(repeats / commands, 2) if have_transcripts and commands else None})
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="sweep output folder")
    ap.add_argument("--controls-dir", help="folder holding the control runs (default: <out>/controls)")
    ap.add_argument("--queries", help="score only the classes in this query file; default is every class with finished runs in --out")
    ap.add_argument("--min-agree", type=int, help="runs that must name a file for it to count; default is more than half of the runs")
    ap.add_argument("--alpha", type=float, default=DEFAULT_ALPHA, help=f"significance level for the rate comparison (default {DEFAULT_ALPHA})")
    ap.add_argument("--write-leads", action="store_true", help="rewrite <out>/leads.json from the runs on disk")
    args = ap.parse_args()

    out = Path(args.out)
    names: dict[str, str] = {}
    only = None
    if args.queries:
        qs = json.loads(Path(args.queries).read_text(encoding="utf-8"))
        names = {q["id"]: q.get("cwe_description") or q.get("query") or q["id"] for q in qs}
        only = set(names)
    elif (out / "results.json").is_file():
        names = {e["id"]: e["query"] for e in json.loads((out / "results.json").read_text(encoding="utf-8")).get("results", [])}
    entries = read_entries(out, names, only)
    if not entries:
        raise SystemExit(f"no finished runs found under {out / 'transcripts'}")
    cdir = Path(args.controls_dir) if args.controls_dir else out / "controls"
    controls = read_entries(cdir, {}) if (cdir / "transcripts").is_dir() else []
    if not controls:
        raise SystemExit(f"no control runs found under {cdir / 'transcripts'}. Run the sweep with --controls queries/controls.json "
                         f"(run_review.sh does), or point --controls-dir at a folder that has them.")
    runs = max(len(e["runs"]) for e in entries)
    need = min(args.min_agree or majority(runs), runs)
    baseline = baseline_files(controls)
    m = sum(len(e["runs"]) for e in controls)
    lead_file = build_leads(entries, runs, need, controls, args.alpha)
    lift = {x["id"]: {f["file"] for f in x["files"]} for x in lead_file["leads"]}
    base_only = set(lead_file["baseline_only"])

    classes = []
    spread: dict[str, int] = {}
    for e in entries:
        n = len(e["runs"])
        agreed = [f for f in e["ranked_files"] if f["runs"] >= need and not is_noise_file(f["file"])]
        rows = []
        for f in agreed:
            spread[f["file"]] = spread.get(f["file"], 0) + 1
            c = baseline.get(f["file"], 0)
            rows.append({"file": f["file"], "runs": f["runs"], "control_runs": c, "p": round(rate_p(f["runs"], n, c, m), 4)})
        verdict = "lift" if e["id"] in lift else "baseline-only" if e["id"] in base_only else "no-agreed-lead"
        classes.append({"id": e["id"], "name": e["query"].split(" \u2014 ")[0], "verdict": verdict, "runs": n,
                        "submitted": sum(r["status"] == "submitted" for r in e["runs"]),
                        "lift_files": [r for r in rows if r["p"] <= args.alpha],
                        "baseline_files": [r for r in rows if r["p"] > args.alpha],
                        "invented_share": e["invented_share"], "repeat_share": e["repeat_share"]})
    rank = {"lift": 0, "baseline-only": 1, "no-agreed-lead": 2}
    classes.sort(key=lambda c: (rank[c["verdict"]], -len(c["lift_files"]), c["id"]))
    hot = {h["file"] for h in lead_file["hotspots"]}
    files = sorted(({"file": f, "classes": n, "hotspot": f in hot, "control_runs": baseline.get(f, 0)} for f, n in spread.items()),
                   key=lambda x: (-x["classes"], x["file"]))
    counts = {v: sum(1 for c in classes if c["verdict"] == v) for v in rank}
    control_rows = [{"id": e["id"], "submitted": sum(r["status"] == "submitted" for r in e["runs"]), "runs": len(e["runs"]),
                     "agreed_files": [f["file"] for f in e["ranked_files"] if f["runs"] >= majority(len(e["runs"])) and not is_noise_file(f["file"])],
                     "invented_share": e["invented_share"], "repeat_share": e["repeat_share"]} for e in controls]
    report = {"classes_scored": len(classes), "runs_per_class": runs, "min_runs_agreeing": need, "verdicts": counts,
              "baseline": {**lead_file["baseline"], "source_files": {f: c for f, c in sorted(baseline.items()) if not is_noise_file(f)}},
              "controls": control_rows, "files": files, "classes": classes}
    (out / "class-scores.json").write_text(json.dumps(report, indent=1), encoding="utf-8")

    b = lead_file["baseline"]

    def cell(rows):
        return ", ".join(f"`{r['file']}` {r['runs']}/{runs} vs {r['control_runs']}/{m}, p {r['p']}" for r in rows) or "none"

    lines = ["# Class scores", "",
             f"{len(classes)} classes at up to {runs} runs each, compared with {b['control_runs']} control runs "
             f"(agreement {need} runs, alpha {args.alpha}).",
             f"{counts['lift']} show lift, {counts['baseline-only']} agreed only on files the controls name as often, "
             f"{counts['no-agreed-lead']} had no agreed file."]
    if not b["enough_runs"]:
        lines.append("There are too few runs for any file to clear the rate comparison at this alpha.")
    lines += ["", "## Files", "", "| File | Classes that agreed on it | Hotspot | Control runs |", "|---|---|---|---|"]
    lines += [f"| `{x['file']}` | {x['classes']} | {'yes' if x['hotspot'] else 'no'} | {x['control_runs']} of {m} |" for x in files]
    lines += ["", "## Controls", "", "| Control | Submitted | Agreed files | Invented share | Repeat share |", "|---|---|---|---|---|"]
    lines += [f"| {c['id']} | {c['submitted']} of {c['runs']} | {', '.join('`' + f + '`' for f in c['agreed_files']) or 'none'} | "
              f"{c['invented_share']} | {c['repeat_share']} |" for c in control_rows]
    lines += ["", "## Classes", "", "| Class | Verdict | Files above the control rate | Files at the control rate | Invented share | Repeat share |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {c['name']} | {c['verdict']} | {cell(c['lift_files'])} | {cell(c['baseline_files'])} | "
              f"{c['invented_share']} | {c['repeat_share']} |" for c in classes]
    (out / "class-scores.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out / 'class-scores.json'} and {out / 'class-scores.md'}")
    if args.write_leads:
        (out / "leads.json").write_text(json.dumps(lead_file, indent=1), encoding="utf-8")
        print(f"rewrote {out / 'leads.json'}")
    print(f"{len(classes)} classes, {b['control_runs']} control runs: {counts['lift']} lift, {counts['baseline-only']} baseline-only, "
          f"{counts['no-agreed-lead']} no agreed lead")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
