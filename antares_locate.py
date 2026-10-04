#!/usr/bin/env python3
# Scorpius Sweep
# Copyright 2026 Nate Carroll (Nate-Carroll-Cyber)
# SPDX-License-Identifier: Apache-2.0
#
# This file includes material adapted from cisco-foundation-ai/vulnerability-localization-benchmark
# (commit fa50b67), Copyright 2026 Cisco Systems, Inc. and its affiliates, Apache License 2.0:
#   - OFFICIAL_SYSTEM_PROMPT and OFFICIAL_TOOLS, copied from model_runners/base.py
#   - official_system_content, official_user_prompt and official_prompt, which reproduce the prompt
#     built by model_runners/vllm_antares.py and agent.py
#   - the loop rules in run_official, which follow agent.py
# The token list, the tool-response pattern and the escaping approach in neutralize are adapted from
# the Antares CLI (antares-cli 1.0.0, Cisco Foundation AI, Apache License 2.0), inference/granite.py.
# Changes from the original: the code is rewritten for the Ollama /api/generate route with raw=true,
# role tokens and tool-response tags in command output are escaped before they enter the prompt,
# commands run against a read-only mount of a local checkout, an aborted prediction is retried once,
# submitted paths that do not exist are dropped and counted, results are ranked across runs, and
# each class is compared with control runs.
# See the NOTICE file.
"""Scorpius Sweep: run Antares (served by Ollama) as a vulnerability-localization agent over a local repository.

The model is not a chat model. It emits one tool call per turn:

    <think> ... </think>
    <tool_call> {"name": "terminal", "arguments": {"command": "..."}} </tool_call>

and ends with `submit_vulnerable_files` or `submit_no_vulnerability_found`. This script is the loop
around it: send the prompt, parse the tool call, run the command read-only against the repository,
return the output, repeat. Limits follow the published harness: 15 terminal commands, 10 s per
command, output cut at 2,000 characters, 4,096 tokens per turn, temperature 0.3, frequency penalty 0.3.
Commands run only inside a Docker container with no network and a read-only mount of the repository.

Usage:
    python3 antares_locate.py --repo targets/NAME --queries queries/all.json --controls queries/controls.json
    python3 antares_locate.py --repo PATH --query "CWE-78: OS command injection ..." --runs 5

Standard library only. Python 3.9+ (the Python that ships with macOS command line tools works).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_MODEL = "antares-1b"   # an Ollama model name; see RUNBOOK.md section 6 for creating it from the official weights
VIRTUAL_ROOT = "/workspace/repo"
MAX_COMMANDS = 15
CMD_TIMEOUT = 10
OUT_LIMIT = 2000
MAX_TOKENS = 4096


# --------------------------------------------------------------------------------------------
# Docker executor: a real shell in a container with no network and a read-only mount.
# --------------------------------------------------------------------------------------------

class DockerExecutor:
    name = "docker"

    def __init__(self, root: Path, image: str = "antares-sandbox"):
        self.shell = "bash"
        self.root = root.resolve()
        r = subprocess.run(
            ["docker", "run", "-d", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "4g", "--cpus", "2",
             "--tmpfs", "/tmp:rw,size=64m", "-v", f"{self.root}:{VIRTUAL_ROOT}:ro", "-w", VIRTUAL_ROOT,
             image, "sleep", "infinity"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise SystemExit(f"could not start the sandbox container: {r.stderr.strip()}")
        self.cid = r.stdout.strip()

    def run(self, command: str) -> str:
        try:
            r = subprocess.run(
                ["docker", "exec", "-w", VIRTUAL_ROOT, self.cid, "timeout", str(CMD_TIMEOUT), self.shell, "-c", command],
                capture_output=True, text=True, errors="replace", timeout=CMD_TIMEOUT + 5,
            )
        except subprocess.TimeoutExpired:
            return f"[command timed out after {CMD_TIMEOUT} seconds]"
        if r.returncode == 124:
            return f"[command timed out after {CMD_TIMEOUT} seconds]"
        out = (r.stdout or "") + (r.stderr or "")
        return out if out.strip() else f"[no output, exit status {r.returncode}]"

    def close(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.cid], capture_output=True)


# --------------------------------------------------------------------------------------------
# Model I/O
# --------------------------------------------------------------------------------------------

TOOL_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)
TOOL_CALL_OPEN = re.compile(r"<tool_call>\s*(\{.*)", re.S)

# Extra Ollama options applied to every request. {"num_gpu": 0} keeps the model on CPU.
EXTRA_OPTIONS: dict = {}


def parse_tool_call(text: str) -> tuple[str, dict] | None:
    """First tool call in the turn, or None. Tolerates a missing closing tag and trailing text."""
    m = TOOL_CALL.search(text)
    raw = m.group(1) if m else None
    obj = None
    if raw:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            obj = None
    if obj is None:
        # the opening tag is sometimes dropped, leaving a bare JSON object after </think>
        m = TOOL_CALL_OPEN.search(text) or re.search(r'(\{\s*"name"\s*:.*)', text, re.S)
        if not m:
            return None
        try:
            obj, _ = json.JSONDecoder().raw_decode(m.group(1))
        except json.JSONDecodeError:
            return None
    if not isinstance(obj, dict) or not isinstance(obj.get("name"), str):
        return None
    args = obj.get("arguments", obj.get("parameters", {}))
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"value": args}
    return obj["name"], args if isinstance(args, dict) else {"value": args}


def submitted_files(args: dict) -> list[str]:
    """Paths from a submission. The tool's argument is ranked_files; a list or a delimited string is accepted."""
    vals: list[str] = []
    for v in args.values():
        if isinstance(v, list):
            vals += [str(x) for x in v]
        elif isinstance(v, str):
            vals += [x for x in re.split(r"[\n,]+", v) if x.strip()]
    out = []
    for v in vals:
        v = v.strip().strip("'\"")
        if v.startswith(VIRTUAL_ROOT):
            v = v[len(VIRTUAL_ROOT):]
        v = v.lstrip("/")
        if v.startswith("./"):
            v = v[2:]
        if v and v not in out:
            out.append(v)
    return out


# --------------------------------------------------------------------------------------------
# Official protocol. The prompt, tool definitions, prompt rendering and loop rules below follow
# Cisco's benchmark harness (cisco-foundation-ai/vulnerability-localization-benchmark, Apache-2.0,
# commit fa50b67: model_runners/base.py, model_runners/vllm_antares.py, agent.py, sandbox.py).
# The model is sent a raw prompt, not chat messages, because a server-side chat template changes it.
# --------------------------------------------------------------------------------------------

OFFICIAL_SYSTEM_PROMPT = """You are a security vulnerability localization agent. You have read-only terminal access to a codebase.

Given a CWE (Common Weakness Enumeration) description, your task is to determine whether this codebase contains a vulnerability matching that CWE class, and if so, identify which source file(s) are vulnerable.

You can explore the codebase using the `terminal` tool \u2014 it runs read-only commands (ls, find, cat, head, tail, grep, rg, tree, etc.) inside the repository. You have up to 15 terminal calls.

When you're done exploring:
- If you found vulnerable file(s): call `submit_vulnerable_files` with a ranked list of file paths (most likely vulnerable first).
- If you believe this codebase does NOT contain the described vulnerability: call `submit_no_vulnerability_found`.

You may be looking at code that has already been patched \u2014 in that case, the correct answer is to submit nothing. Do not guess or hallucinate files. Only submit files you have evidence for.

NOTE: Submitted paths must be exact file paths (e.g. src/utils.js), never globs or wildcards. Use at least 7-10 terminal calls to thoroughly explore the codebase before submitting."""

OFFICIAL_TOOLS = [
    {"type": "function", "function": {
        "name": "terminal",
        "description": "Execute a read-only terminal command in the repository. Allowed: ls, tree, find, cat, head, tail, sed, grep, rg, wc, sort, uniq, cut, awk, file, stat, du, pwd, nl, basename, dirname, realpath, diff, echo. Pipes OK. No python/bash/node, no writes, no redirects.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "The shell command to run"},
            "max_chars": {"type": "integer", "description": "Max output chars (default 2000)", "default": 2000}},
            "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "submit_vulnerable_files",
        "description": "Submit your answer: a ranked list of file paths you believe contain the vulnerability. Most likely vulnerable file first. Paths relative to repository root.",
        "parameters": {"type": "object", "properties": {
            "ranked_files": {"type": "array", "items": {"type": "string"}, "description": "Ordered list of file paths, most vulnerable first"}},
            "required": ["ranked_files"]}}},
    {"type": "function", "function": {
        "name": "submit_no_vulnerability_found",
        "description": "Declare that no vulnerability matching the CWE description was found in this codebase.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
]
OFFICIAL_STOP = ["<|end_of_text|>", "<|start_of_role|>"]
OFFICIAL_MAX_TURNS = 20
NUDGE = "Please call one of: terminal, submit_vulnerable_files, or submit_no_vulnerability_found."


def official_system_content() -> str:
    tools_block = "<tools>\n" + "\n".join(json.dumps(t) for t in OFFICIAL_TOOLS) + "\n</tools>"
    return (f"{OFFICIAL_SYSTEM_PROMPT}\n\n"
            "You are a helpful assistant with access to the following tools. "
            "You may call one or more tools to assist with the user query.\n\n"
            "You are provided with function signatures within <tools></tools> XML tags:\n"
            f"{tools_block}\n\n"
            "For each tool call, return a json object with function name and arguments "
            "within <tool_call></tool_call> XML tags:\n"
            "<tool_call>\n"
            '{"name": <function-name>, "arguments": <args-json-object>}\n'
            "</tool_call>. If a tool does not exist in the provided list of tools, "
            "notify the user that you do not have the ability to fulfill the request.")


def official_user_prompt(cwe_description: str) -> str:
    return (f"Analyze this codebase for the following vulnerability class:\n\n{cwe_description}\n\n"
            "The repository is at /workspace/repo/. Use the terminal tool to explore "
            "and determine if this vulnerability exists. Then either submit the "
            "vulnerable file(s) or declare no vulnerability found.")


CONTROL_TOKENS = ("<|start_of_role|>", "<|end_of_role|>", "<|end_of_text|>", "<|endoftext|>", "<|eot_id|>")
TOOL_RESPONSE_TAG = re.compile(r"</?tool_response(?:\s+[^>]*)?>", re.I)


def neutralize(text: str, tool_output: bool = False) -> str:
    """Stop text from the target repository forging turns in the raw prompt.

    Command output is untrusted: a file can contain Granite role tokens or a closing tool_response tag.
    Adapted from the Antares CLI's inference/granite.py, which escapes the same sequences.
    """
    for tok in CONTROL_TOKENS:
        text = text.replace(tok, f"[escaped control token: {tok[2:-2]}]")
    if tool_output:
        text = TOOL_RESPONSE_TAG.sub("[escaped tool-response delimiter]", text)
    return text


def official_prompt(conv: list[dict]) -> str:
    parts = []
    for m in conv:
        if m["role"] == "tool_response":
            parts.append(f"<|start_of_role|>user<|end_of_role|>\n<tool_response>\n{neutralize(m['content'], True)}\n</tool_response><|end_of_text|>")
        else:
            parts.append(f"<|start_of_role|>{m['role']}<|end_of_role|>{neutralize(m['content'])}<|end_of_text|>")
    parts.append("<|start_of_role|>assistant<|end_of_role|><think>\n")
    return "\n".join(parts)


def ollama_generate(host: str, model: str, prompt: str, seed: int | None, attempt: int = 0) -> dict:
    """One raw completion from Ollama (/api/generate with raw=true, so no template is applied).

    Returns {"text": str} or {"error": str, "partial": str}.
    """
    options = {"temperature": 0.3, "frequency_penalty": 0.3 + 0.3 * attempt, "num_ctx": 32768, "num_predict": MAX_TOKENS,
               "stop": OFFICIAL_STOP}
    if seed is not None:
        options["seed"] = seed + attempt
    options.update(EXTRA_OPTIONS)
    payload = {"model": model, "prompt": prompt, "raw": True, "stream": True, "options": options}
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    out = []
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            for line in r:
                line = line.strip()
                if not line:
                    continue
                chunk = json.loads(line.decode("utf-8", "replace"))
                if chunk.get("error"):
                    return {"error": str(chunk["error"]), "partial": "".join(out)}
                if chunk.get("response"):
                    out.append(chunk["response"])
                if chunk.get("done"):
                    break
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            body = json.loads(body).get("error", body)
        except json.JSONDecodeError:
            pass
        return {"error": f"HTTP {e.code}: {body[:300]}", "partial": "".join(out)}
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach Ollama at {host}: {e.reason}. Is the Ollama app running?")
    return {"text": "".join(out)}


def official_truncate(output: str, max_chars) -> str:
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or not 0 < max_chars <= OUT_LIMIT:
        max_chars = OUT_LIMIT
    if output.startswith("[no output, exit status"):
        output = "(no output)"
    if len(output) > max_chars:
        return output[:max_chars] + f"\n\n[TRUNCATED \u2014 {len(output)} total chars, showing first {max_chars}]"
    return output


def probe_official(host: str, model: str, cwe_description: str, seed: int | None, devices: tuple = ("gpu", "cpu")):
    """First turn on each device in order; keep the first device that yields a tool call. Returns (device|None, attempts)."""
    conv = [{"role": "system", "content": official_system_content()}, {"role": "user", "content": official_user_prompt(cwe_description)}]
    attempts = []
    for device in devices:
        EXTRA_OPTIONS.pop("num_gpu", None)
        if device == "cpu":
            EXTRA_OPTIONS["num_gpu"] = 0
        for attempt in range(2):
            reply = ollama_generate(host, model, official_prompt(conv), seed, attempt)
            text = reply.get("partial", "") if "error" in reply else reply["text"]
            call = None if "error" in reply else parse_tool_call(text)
            attempts.append({"mode": "official", "device": device, "attempt": attempt + 1, "error": reply.get("error"),
                             "tool_call": call[0] if call else None, "output_head": text[:500]})
            if call:
                return device, attempts
    EXTRA_OPTIONS.pop("num_gpu", None)
    return None, attempts


def run_official(executor, repo: Path, cwe_description: str, host: str, model: str, seed: int | None, log) -> dict:
    """One episode under the benchmark's rules: 20 turns, 15 terminal calls, first valid tool call per turn."""
    conv = [{"role": "system", "content": official_system_content()}, {"role": "user", "content": official_user_prompt(cwe_description)}]
    log({"role": "user", "content": conv[1]["content"]})
    commands = errors = no_calls = 0
    status, files = "turn_limit", []
    for turn in range(OFFICIAL_MAX_TURNS):
        prompt = official_prompt(conv)
        reply = ollama_generate(host, model, prompt, None if seed is None else seed + turn)
        if "error" in reply:  # not in the official loop: one retry with a stronger frequency penalty
            log({"role": "error", "content": reply["error"], "partial_output": reply.get("partial", "")[:600]})
            errors += 1
            reply = ollama_generate(host, model, prompt, None if seed is None else seed + turn, attempt=1)
            if "error" in reply:
                log({"role": "error", "content": reply["error"], "partial_output": reply.get("partial", "")[:600]})
                status = "model_error"
                break
        raw = reply["text"]
        m = TOOL_CALL.search(raw)
        text = "<think>\n" + (raw[:m.end()] if m else raw)
        conv.append({"role": "assistant", "content": text})
        log({"role": "assistant", "content": text})
        call = parse_tool_call(raw)
        if call is None:
            no_calls += 1
            if no_calls >= 3:
                status = "no_tool_call"
                break
            conv.append({"role": "tool_response", "content": NUDGE})
            log({"role": "tool", "content": NUDGE})
            continue
        no_calls = 0
        name, args = call
        if name == "submit_vulnerable_files":
            files = submitted_files({"ranked_files": args.get("ranked_files", [])} if "ranked_files" in args else args)
            status = "submitted"
            break
        if name == "submit_no_vulnerability_found":
            status = "none_found"
            break
        if name != "terminal":
            output = f"ERROR: Unknown tool '{name}'."
        elif commands >= MAX_COMMANDS:
            output = f"ERROR: Terminal call budget exhausted ({MAX_COMMANDS}/{MAX_COMMANDS}). Please submit your answer now."
        else:
            commands += 1
            output = official_truncate(executor.run(str(args.get("command", ""))), args.get("max_chars", OUT_LIMIT))
            output += f"\n[{MAX_COMMANDS - commands} tool-calls remaining]"
        conv.append({"role": "tool_response", "content": output})
        log({"role": "tool", "content": output})
    existing = [f for f in files if (repo / f).is_file()]
    return {"status": status, "commands": commands, "model_errors": errors,
            "files": existing, "files_not_in_repo": [f for f in files if f not in existing]}


# --------------------------------------------------------------------------------------------
# Ranking: agreement between runs, compared with the rate at which control runs name the same file
# --------------------------------------------------------------------------------------------

NOISE_FILE = re.compile(
    r"(\.d\.ts$|\.(spec|test|eval)\.[a-z]+$|(^|/)(tests?|__tests__|fixtures?|node_modules|dist|build|vendor)/"
    r"|(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|tsconfig[^/]*\.json|wrangler\.(jsonc?|toml)|CHANGELOG\.md|README\.md|LICENSE)$"
    r"|(^|/)\.[^/]+$|\.config\.[a-z]+$|\.(md|lock|map|snap)$)", re.I)
DEFAULT_ALPHA = 0.05


def is_noise_file(path: str) -> bool:
    """Generated, test, manifest and config files. They are never put forward as a lead."""
    return bool(NOISE_FILE.search(path))


def majority(runs: int) -> int:
    """Runs that must name a file for it to count: more than half."""
    return runs // 2 + 1


def baseline_files(control_entries: list[dict]) -> dict[str, int]:
    """How many control runs named each file.

    control_entries are result entries for control queries: ones with no class and ones with
    invented classes. They show what the model names when the class carries no information.
    """
    counts: dict[str, int] = {}
    for e in control_entries:
        for run in e["runs"]:
            for f in set(run["files"]):
                counts[f] = counts.get(f, 0) + 1
    return counts


def rate_p(k: int, n: int, c: int, m: int) -> float:
    """One-sided Fisher exact test. A class named the file in k of its n runs and the controls in c
    of their m runs. Returns the probability of k or more class runs if both name it at the same rate."""
    total = math.comb(n + m, n)
    hits = k + c
    return sum(math.comb(hits, x) * math.comb(n + m - hits, n - x) for x in range(k, min(n, hits) + 1)) / total


def build_leads(entries: list[dict], runs: int, need: int, control_entries: list[dict] | None = None,
                alpha: float = DEFAULT_ALPHA) -> dict:
    """The reviewer's file.

    A file is agreed when at least `need` of a class's runs named it and it is not a noise file.
    Without controls every class with an agreed file is a lead. With controls an agreed file is a
    lead for the class only when the class named it at a higher rate than the control runs did
    (rate_p at most alpha). Agreed files that do not clear that test are listed once as hotspots,
    without a class.
    """
    run_status: dict[str, int] = {}
    for e in entries:
        for x in e["runs"]:
            run_status[x["status"]] = run_status.get(x["status"], 0) + 1
    out = {"queries": len(entries), "to_review": 0, "runs_per_query": runs, "min_runs_agreeing": need, "run_status": run_status}
    leads, baseline_only, no_lead = [], [], []
    if control_entries is None:
        for e in entries:
            agreed = [f for f in e["ranked_files"] if f["runs"] >= need and not is_noise_file(f["file"])]
            (leads.append({"id": e["id"], "cwe": e["query"], "files": agreed[:6]}) if agreed else no_lead.append(e["id"]))
        out.update({"to_review": len(leads), "leads": leads, "no_agreed_lead": no_lead})
        return out
    counts = baseline_files(control_entries)
    m = sum(len(e["runs"]) for e in control_entries)
    spread: dict[str, int] = {}
    for e in entries:
        n = len(e["runs"])
        agreed = [f for f in e["ranked_files"] if f["runs"] >= need and not is_noise_file(f["file"])]
        above = []
        for f in agreed:
            c = counts.get(f["file"], 0)
            p = rate_p(f["runs"], n, c, m)
            if p <= alpha:
                above.append({"file": f["file"], "runs": f["runs"], "control_runs": c, "p": round(p, 4)})
            else:
                spread[f["file"]] = spread.get(f["file"], 0) + 1
        if above:
            leads.append({"id": e["id"], "cwe": e["query"], "files": above[:6]})
        elif agreed:
            baseline_only.append(e["id"])
        else:
            no_lead.append(e["id"])
    for e in control_entries:  # a file most runs of one control named is a hotspot even when no class agreed on it
        for f in e["ranked_files"]:
            if f["runs"] >= majority(len(e["runs"])) and not is_noise_file(f["file"]):
                spread.setdefault(f["file"], 0)
    hotspots = sorted(({"file": f, "classes": k, "control_runs": counts.get(f, 0)} for f, k in spread.items()),
                      key=lambda h: (-h["classes"], -h["control_runs"], h["file"]))
    n_class = max((len(e["runs"]) for e in entries), default=runs)
    out.update({"to_review": len(leads), "hotspots_to_review": len(hotspots),
                "baseline": {"control_queries": len(control_entries), "control_runs": m, "files": len(counts), "alpha": alpha,
                             # False when even a file every class run named and no control run named could not pass
                             "enough_runs": rate_p(n_class, n_class, 0, m) <= alpha if m else False},
                "leads": leads, "hotspots": hotspots, "baseline_only": baseline_only, "no_agreed_lead": no_lead})
    return out


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------

def make_executor(repo: Path, image: str):
    """The Docker sandbox, or exit. There is no weaker fallback: commands the model writes never run on the host."""
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise SystemExit("Docker is not answering. Start Docker Desktop (or the Docker daemon) and run again. "
                         "The model's commands only run inside the sandbox container.")
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
        # Never substitute a bare image: without rg and tree a quarter of Antares-1B's commands fail.
        kit = Path(__file__).resolve().parent
        if image == "antares-sandbox" and (kit / "Dockerfile").is_file():
            print(f"docker image '{image}' is not built; building it from {kit / 'Dockerfile'}", flush=True)
            b = subprocess.run(["docker", "build", "-q", "-t", image, str(kit)], capture_output=True, text=True)
            if b.returncode != 0:
                raise SystemExit(f"could not build the sandbox image: {b.stderr.strip()[-600:]}")
        else:
            raise SystemExit(f"docker image '{image}' does not exist. Build it, or pass --image with an image that has rg and tree.")
    return DockerExecutor(repo, image)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True, help="path to the repository to search")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--query", help="one vulnerability description, in the form 'CWE-N: Name — description'")
    g.add_argument("--queries", help="JSON file: list of {id, cwe_description, [reference_files]}. reference_files are used only for scoring, "
                                         "written to reference-score.json; the model never sees them")
    ap.add_argument("--only", help="comma-separated query ids to run from --queries")
    ap.add_argument("--runs", type=int, default=5, help="runs per query (default 5); files are ranked by how many runs name them")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST_URL", "http://localhost:11434"))
    ap.add_argument("--device", choices=["auto", "gpu", "cpu"], default="auto",
                    help="cpu: send num_gpu 0 so Ollama keeps the model off the GPU. gpu: Ollama's default. "
                         "auto: probe gpu first, then cpu, and keep the one that works.")
    ap.add_argument("--image", default="antares-sandbox", help="docker image for the sandbox; it needs rg and tree")
    ap.add_argument("--min-agree", type=int, help="runs that must name a file for it to count; default is more than half of --runs")
    ap.add_argument("--resume", action="store_true", help="reuse finished runs already in the output folder; for an interrupted sweep, "
                                                          "or to add runs after raising --runs")
    ap.add_argument("--controls", help="JSON file of control queries (no class, invented classes), e.g. queries/controls.json. They run after "
                                       "the sweep into <out>/controls. leads.json then lists per class only the files the class named at a "
                                       "higher rate than the control runs did. Finished control runs are reused")
    ap.add_argument("--rerun-controls", action="store_true", help="run the control queries again instead of reusing finished control runs")
    ap.add_argument("--alpha", type=float, default=DEFAULT_ALPHA,
                    help=f"significance level for the class-against-controls rate comparison (default {DEFAULT_ALPHA})")
    ap.add_argument("--probe", action="store_true", help="only probe the model on the first query and print what it returned")
    ap.add_argument("--seed", type=int, help="base seed; run N uses seed+N")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        raise SystemExit(f"not a directory: {repo}")
    if args.query:
        queries = [{"id": "adhoc", "cwe_description": args.query}]
    else:
        queries = json.loads(Path(args.queries).read_text(encoding="utf-8"))
        if args.only:
            wanted = set(args.only.split(","))
            queries = [q for q in queries if q["id"] in wanted]
    if not queries:
        raise SystemExit("no queries selected")

    def qtext(q):
        return q.get("cwe_description") or q["query"]

    out_dir = Path(args.out)
    (out_dir / "transcripts").mkdir(parents=True, exist_ok=True)

    device = args.device
    EXTRA_OPTIONS.pop("num_gpu", None)
    if device == "cpu":
        EXTRA_OPTIONS["num_gpu"] = 0
    if device == "auto" or args.probe:
        device, attempts = probe_official(args.host, args.model, qtext(queries[0]), args.seed,
                                          devices=("gpu", "cpu") if args.device == "auto" else (args.device,))
        (out_dir / "probe.json").write_text(json.dumps(attempts, indent=1), encoding="utf-8")
        for a in attempts:
            head = a["output_head"].replace("\n", "\\n")[:220]
            print(f"[probe {a['device']} #{a['attempt']}] tool_call={a['tool_call']} error={a['error']}\n    output: {head}", flush=True)
        if device is None:
            print(f"\nNo device produced a tool call. Details are in {out_dir / 'probe.json'}.")
            return 2
        (out_dir / "chosen.json").write_text(json.dumps({"device": device}), encoding="utf-8")
        print(f"device: {device}\n", flush=True)
        if args.probe:
            return 0

    executor = make_executor(repo, args.image)
    report = {"repo": str(repo), "model": args.model, "sandbox": executor.name, "device": device, "runs_per_query": args.runs, "results": []}
    score: list[dict] = []

    def sweep(qs: list[dict], folder: Path, reuse: bool, keep_score: bool) -> list[dict]:
        (folder / "transcripts").mkdir(parents=True, exist_ok=True)
        entries = []
        for q in qs:
            votes: dict[str, int] = {}
            runs = []
            for n in range(args.runs):
                tpath = folder / "transcripts" / f"{q['id']}.run{n + 1}.jsonl"
                rpath = folder / "transcripts" / f"{q['id']}.run{n + 1}.result.json"
                res = None
                if reuse and rpath.is_file():  # a finished run from an earlier or interrupted sweep
                    try:
                        res = json.loads(rpath.read_text(encoding="utf-8"))
                    except json.JSONDecodeError:
                        res = None
                if res is None:
                    with tpath.open("w", encoding="utf-8") as tf:
                        rseed = None if args.seed is None else args.seed + 100 * n
                        res = run_official(executor, repo, qtext(q), args.host, args.model, rseed, lambda rec: tf.write(json.dumps(rec) + "\n"))
                    rpath.write_text(json.dumps(res), encoding="utf-8")
                runs.append(res)
                for f in res["files"]:
                    votes[f] = votes.get(f, 0) + 1
                print(f"[{q['id']} run {n + 1}/{args.runs}] {res['status']}, {res['commands']} commands, {len(res['files'])} files", flush=True)
            ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
            entries.append({"id": q["id"], "query": qtext(q), "ranked_files": [{"file": f, "runs": c} for f, c in ranked], "runs": runs})
            ref = q.get("reference_files")
            if ref and keep_score:  # kept out of results.json so a reviewer reading the results is not handed the answers
                got = {f for f, _ in ranked}
                score.append({"id": q["id"], "reference_files": ref, "reference_hits": sorted(got & set(ref))})
        return entries

    control_entries = None
    try:
        report["results"] = sweep(queries, out_dir, args.resume, True)
        if args.controls:
            controls = json.loads(Path(args.controls).read_text(encoding="utf-8"))
            print(f"\ncontrol queries from {args.controls}", flush=True)
            control_entries = sweep(controls, out_dir / "controls", not args.rerun_controls, False)
    finally:
        executor.close()
    (out_dir / "results.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    need = min(args.min_agree or majority(args.runs), args.runs)
    if control_entries is not None:
        (out_dir / "controls" / "results.json").write_text(json.dumps(
            {"model": args.model, "runs_per_query": args.runs, "results": control_entries}, indent=1), encoding="utf-8")
    # A short file for the reviewer. Agreement between runs is the localizer's most reliable signal, and the
    # comparison with the control runs removes the files it names whatever class it is asked about.
    lead_file = build_leads(report["results"], args.runs, need, control_entries, args.alpha)
    leads = lead_file["leads"]
    (out_dir / "leads.json").write_text(json.dumps(lead_file, indent=1), encoding="utf-8")
    refs = {x["id"]: x["reference_files"] for x in score}
    if score:
        (out_dir / "reference-score.json").write_text(json.dumps(
            {"queries_with_a_hit": sum(1 for x in score if x["reference_hits"]), "queries_scored": len(score), "results": score},
            indent=1), encoding="utf-8")

    print(f"\nwrote {out_dir / 'results.json'} and {out_dir / 'leads.json'}")
    total = len(report["results"])
    if control_entries is None:
        print(f"{len(leads)} of {total} queries have a source file named by at least {need} of {args.runs} runs:")
    else:
        b = lead_file["baseline"]
        print(f"controls: {b['control_runs']} runs named {b['files']} files")
        if not b["enough_runs"]:
            print("too few runs for the rate comparison: no file can clear it at this --alpha. Raise --runs or add control queries.")
        print(f"{len(leads)} of {total} queries have a source file named by at least {need} of {args.runs} runs and at a higher rate than "
              f"the controls, {len(lead_file['baseline_only'])} agreed only on files the controls name as often, "
              f"{len(lead_file['no_agreed_lead'])} had no agreed file:")
    for e in leads:
        print(f"\n{e['id']}")
        for r in e["files"]:
            mark = "  ref" if r["file"] in refs.get(e["id"], []) else ""
            ctl = f"  (controls {r['control_runs']}/{lead_file['baseline']['control_runs']})" if control_entries is not None else ""
            print(f"  {r['runs']}/{args.runs}  {r['file']}{ctl}{mark}")
    if control_entries is not None and lead_file["hotspots"]:
        print("\nhotspots (named whatever the class):")
        for h in lead_file["hotspots"]:
            print(f"  {h['classes']:>3} classes, {h['control_runs']} control runs  {h['file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
