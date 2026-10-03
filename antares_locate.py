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
# Changes from the original: the code is rewritten for the Ollama /api/generate route with raw=true,
# commands run against a read-only mount of a local checkout, an aborted prediction is retried once,
# submitted paths that do not exist are dropped and counted, and results are ranked across runs.
# See the NOTICE file.
"""Scorpius Sweep: run Antares (served by Ollama) as a vulnerability-localization agent over a local repository.

The model is not a chat model. It emits one tool call per turn:

    <think> ... </think>
    <tool_call> {"name": "terminal", "arguments": {"command": "..."}} </tool_call>

and ends with `submit_vulnerable_files` or `submit_no_vulnerability_found`. This script is the loop
around it: send the prompt, parse the tool call, run the command read-only against the repository,
return the output, repeat. Limits follow the published harness: 15 terminal commands, 10 s per
command, output cut at 2,000 characters, 4,096 tokens per turn, temperature 0.3, top_p 1.0.

Usage:
    python3 antares_locate.py --repo targets/NAME --queries queries/all.json
    python3 antares_locate.py --repo PATH --query "CWE-78: OS command injection ..." --runs 5

Standard library only. Python 3.9+ (the Python that ships with macOS command line tools works).
"""
from __future__ import annotations

import argparse
import glob as globmod
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_MODEL = "antares-1b"   # an Ollama model name; see RUNBOOK.md section 6 for creating it from the official weights
VIRTUAL_ROOT = "/workspace/repo"
SYSTEM_PROMPT = (
    "You are a security vulnerability localization agent.\n"
    "You have access to a terminal with the repository mounted at /workspace/repo/.\n"
    "Use shell commands (grep, find, cat, etc.) to explore the codebase and identify\n"
    "files that contain the reported vulnerability. When confident, submit your findings."
)
MAX_COMMANDS = 15
CMD_TIMEOUT = 10
OUT_LIMIT = 2000
MAX_TOKENS = 4096


class Rejected(Exception):
    """A command the sandbox refuses to run. The message is returned to the model."""


# --------------------------------------------------------------------------------------------
# Allowlist executor: no shell, read-only tools only, every path confined to the repository.
# --------------------------------------------------------------------------------------------

READ_ONLY = {
    "grep", "egrep", "fgrep", "rg", "find", "cat", "head", "tail", "ls", "wc", "sort", "uniq", "cut",
    "tr", "nl", "file", "stat", "tree", "basename", "dirname", "echo", "sed", "true",
}
GREPS = {"grep", "egrep", "fgrep", "rg"}
NO_PATH_ARGS = {"echo", "tr", "basename", "dirname"}
# options whose following argument is a value, not a path
VALUE_OPTS = {
    "grep": {"-e", "-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir", "--max-count"},
    "egrep": {"-e", "-m", "-A", "-B", "-C"},
    "fgrep": {"-e", "-m", "-A", "-B", "-C"},
    "rg": {"-e", "-g", "--glob", "-t", "--type", "-T", "-m", "-A", "-B", "-C", "--max-count", "--max-depth"},
    "find": {"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-maxdepth", "-mindepth",
             "-size", "-mtime", "-perm"},
    "head": {"-n", "-c"},
    "tail": {"-n", "-c"},
    "cut": {"-d", "-f", "-c"},
    "sort": {"-k", "-t"},
    "tree": {"-L", "-I", "-P"},
    "stat": {"-c", "-f"},
    "sed": {"-e"},
}
FORBIDDEN_ARGS = {
    "find": {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls",
             "-L", "-H", "-follow", "-newer", "-samefile"},
    "grep": {"--dereference-recursive", "--file"},
    "egrep": set(), "fgrep": set(),
    "rg": {"--follow", "--hostname-bin", "--file", "--search-zip"},
    "sort": {"-o", "--output", "--compress-program", "-T", "--files0-from"},
    "tree": {"-o", "-l"},
    "file": {"-C", "-m", "-f", "--compile", "--magic-file", "--files-from"},
    "wc": {"--files0-from"},
    "ls": {"-L", "--dereference"},
    "stat": {"-L", "--dereference"},
}
# single letters that must not appear in a combined short-option cluster such as -rnR
FORBIDDEN_LETTERS = {"grep": "RfSO", "egrep": "RfSO", "fgrep": "RfSO", "rg": "Lfz", "sort": "oT", "ls": "L"}
SED_SCRIPT = re.compile(r"^\d+(,\d+)?p$|^\d+q$|^\$p$")
OPERATORS = {"|", "&&", "||", ";"}
XARGS_MAX_ITEMS = 300


class AllowlistExecutor:
    name = "allowlist"

    def __init__(self, root: Path, seatbelt: bool = False):
        self.root = root.resolve()
        self.seatbelt = seatbelt and sys.platform == "darwin" and shutil.which("sandbox-exec") is not None
        self.env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "LC_ALL": "C", "HOME": str(self.root)}

    # -- parsing -------------------------------------------------------------------------
    def _tokens(self, command: str) -> list[str]:
        if "`" in command or "$(" in command or "<(" in command or ">(" in command:
            raise Rejected("command substitution is not available; run one command at a time")
        command = re.sub(r"\s*2>\s*/dev/null", "", command)
        command = re.sub(r"\s*2>&1", "", command)
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        try:
            toks = list(lex)
        except ValueError as e:
            raise Rejected(f"could not parse command: {e}")
        for t in toks:
            if t and set(t) <= set("();<>|&") and t not in OPERATORS:
                raise Rejected(f"operator '{t}' is not available (no redirection, subshells, or background jobs)")
        return toks

    def _inside(self, p: Path) -> bool:
        try:
            p.resolve().relative_to(self.root)
            return True
        except (ValueError, OSError):
            return False

    def _map_path(self, arg: str, cwd: Path) -> str:
        """Rewrite /workspace/repo to the real root and refuse anything that leaves it, symlinks included."""
        if arg == VIRTUAL_ROOT or arg.startswith(VIRTUAL_ROOT + "/"):
            arg = str(self.root) + arg[len(VIRTUAL_ROOT):]
        if arg.startswith("~"):
            raise Rejected("paths outside /workspace/repo are not available")
        target = Path(arg) if arg.startswith("/") else cwd / arg
        if arg.startswith("/") or ".." in Path(arg).parts or target.exists() or target.is_symlink():
            if not self._inside(target):
                raise Rejected("paths outside /workspace/repo are not available")
        return arg

    def _validate(self, argv: list[str], cwd: Path) -> list[str]:
        if not argv:
            raise Rejected("empty command")
        cmd = argv[0]
        if "/" in cmd or cmd not in READ_ONLY:
            raise Rejected(
                f"'{cmd}' is not available. Available: {', '.join(sorted(READ_ONLY - {'true'}))}, xargs after a pipe. "
                "This terminal is read-only."
            )
        forbidden = FORBIDDEN_ARGS.get(cmd, set())
        letters = FORBIDDEN_LETTERS.get(cmd, "")
        value_opts = VALUE_OPTS.get(cmd, set())
        sed_msg = "sed is limited to printing line ranges: sed -n 'START,ENDp' FILE"
        out = [cmd]
        positional = 0
        pattern_given = False
        i = 1
        while i < len(argv):
            a = argv[i]
            if a.startswith("-") and len(a) > 1:
                base = a.split("=", 1)[0]
                if base in forbidden:
                    raise Rejected(f"option '{base}' is not available for {cmd}")
                if letters and not a.startswith("--") and cmd != "find" and any(ch in letters for ch in a[1:]) \
                        and not a[1:].lstrip("+-").isdigit():
                    raise Rejected(f"option '{a}' is not available for {cmd}")
                if cmd == "rg" and base.startswith("--pre"):
                    raise Rejected("option '--pre' is not available for rg")
                if cmd == "sed" and base != "-n" and base != "-e":
                    raise Rejected(sed_msg)
                out.append(a)
                if base in value_opts and "=" not in a and i + 1 < len(argv):
                    if a == "-e":
                        pattern_given = True
                    if cmd == "sed" and not SED_SCRIPT.match(argv[i + 1]):
                        raise Rejected(sed_msg)
                    out.append(argv[i + 1])
                    i += 2
                    continue
                i += 1
                continue
            positional += 1
            if cmd in GREPS and not pattern_given:
                pattern_given = True
                out.append(a)
            elif cmd == "sed" and positional == 1 and "-e" not in argv:
                if not SED_SCRIPT.match(a):
                    raise Rejected(sed_msg)
                out.append(a)
            elif cmd in NO_PATH_ARGS:
                out.append(a)
            elif cmd == "uniq" and positional > 1:
                raise Rejected("uniq with an output file is not available")
            elif cmd == "find" and a in ("!", "-o", "-a"):
                out.append(a)
            else:
                mapped = self._map_path(a, cwd)
                if any(ch in mapped for ch in "*?["):
                    if mapped.startswith("/"):
                        hits = sorted(globmod.glob(mapped))
                    else:  # glob.glob(root_dir=) needs Python 3.10, so join and strip instead
                        prefix = str(cwd) + os.sep
                        hits = sorted(h[len(prefix):] for h in globmod.glob(prefix + mapped))
                    hits = [h for h in hits if self._inside(Path(h) if h.startswith("/") else cwd / h)]
                    out += hits if hits else [mapped]
                else:
                    out.append(mapped)
            i += 1
        if cmd == "sed" and "-n" not in out:
            raise Rejected(sed_msg)
        return out

    # -- execution -----------------------------------------------------------------------
    def _wrap(self, argv: list[str]) -> list[str]:
        if self.seatbelt:
            return ["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", *argv]
        return argv

    def _run_pipeline(self, stages: list[list[str]], cwd: Path, deadline: float, stdin_text: str | None = None) -> tuple[str, int]:
        procs: list[subprocess.Popen] = []
        prev = None
        try:
            for n, argv in enumerate(stages):
                first_in = subprocess.PIPE if (n == 0 and stdin_text is not None) else subprocess.DEVNULL
                p = subprocess.Popen(
                    self._wrap(argv), cwd=str(cwd), env=self.env, stdin=prev if prev else first_in,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
                )
                if prev:
                    prev.close()
                prev = p.stdout
                procs.append(p)
            remaining = max(0.1, deadline - time.monotonic())
            if stdin_text is not None and len(procs) == 1:
                out, _ = procs[0].communicate(input=stdin_text.encode("utf-8"), timeout=remaining)
            else:
                if stdin_text is not None:
                    data = stdin_text.encode("utf-8")

                    def feed(proc=procs[0]):
                        try:
                            proc.stdin.write(data)
                            proc.stdin.close()
                        except (BrokenPipeError, OSError):
                            pass

                    threading.Thread(target=feed, daemon=True).start()
                out, _ = procs[-1].communicate(timeout=remaining)
            for p in procs[:-1]:
                p.wait(timeout=max(0.1, deadline - time.monotonic()))
            return out.decode("utf-8", "replace"), procs[-1].returncode
        except subprocess.TimeoutExpired:
            for p in procs:
                p.kill()
            return f"[command timed out after {CMD_TIMEOUT} seconds]", 124
        except FileNotFoundError as e:
            for p in procs:
                p.kill()
            return f"{e.filename}: command not found on this machine\n", 127

    def _run_stages(self, raw_stages: list[list[str]], cwd: Path, deadline: float) -> tuple[str, int]:
        """Run one pipeline. xargs is emulated so every item it passes on is checked against the repo."""
        xi = next((n for n, s in enumerate(raw_stages) if s and s[0] == "xargs"), None)
        if xi is None:
            return self._run_pipeline([self._validate(s, cwd) for s in raw_stages], cwd, deadline)
        if xi == 0:
            raise Rejected("xargs needs input from a pipe")
        if any(s and s[0] == "xargs" for s in raw_stages[xi + 1:]):
            raise Rejected("only one xargs per pipeline is available")
        feed_text, _ = self._run_pipeline([self._validate(s, cwd) for s in raw_stages[:xi]], cwd, deadline)
        x = raw_stages[xi][1:]
        null_sep, placeholder = False, None
        while x and x[0].startswith("-"):
            opt = x.pop(0)
            if opt == "-0":
                null_sep = True
            elif opt == "-I":
                placeholder = x.pop(0) if x else None
            elif opt in ("-n", "-L", "-P"):
                if x:
                    x.pop(0)
            elif opt in ("-r", "-t") or re.fullmatch(r"-[nLP]\d+", opt):
                pass
            elif opt.startswith("-I") and len(opt) > 2:
                placeholder = opt[2:]
            else:
                raise Rejected(f"option '{opt}' is not available for xargs")
        if not x:
            x = ["echo"]
        items = []
        for it in (feed_text.split("\0") if null_sep else feed_text.split()):
            it = it.strip()
            if not it:
                continue
            try:
                mapped = self._map_path(it, cwd)
            except Rejected:
                continue
            tgt = Path(mapped) if mapped.startswith("/") else cwd / mapped
            if tgt.exists() and self._inside(tgt):
                items.append(mapped)
        items = items[:XARGS_MAX_ITEMS]
        if not items:
            produced, rc = "", 0
        elif placeholder:
            chunks = []
            rc = 0
            for it in items[:40]:
                argv = self._validate([a.replace(placeholder, it) for a in x], cwd)
                text, rc = self._run_pipeline([argv], cwd, deadline)
                chunks.append(text)
            produced = "".join(chunks)
        else:
            argv = self._validate(x, cwd) + items
            produced, rc = self._run_pipeline([argv], cwd, deadline)
        rest = raw_stages[xi + 1:]
        if rest:
            return self._run_pipeline([self._validate(s, cwd) for s in rest], cwd, deadline, stdin_text=produced)
        return produced, rc

    def run(self, command: str) -> str:
        toks = self._tokens(command)
        sequences: list[tuple[list[list[str]], str]] = []
        stage: list[str] = []
        pipeline: list[list[str]] = []
        for t in toks + [";"]:
            if t == "|":
                pipeline.append(stage)
                stage = []
            elif t in ("&&", "||", ";"):
                pipeline.append(stage)
                if any(pipeline) or t != ";":
                    sequences.append((pipeline, t))
                stage, pipeline = [], []
            else:
                stage.append(t)
        cwd = self.root
        outputs: list[str] = []
        rc = 0
        skip_next = False
        deadline = time.monotonic() + CMD_TIMEOUT
        for pipeline, op in sequences:
            if not skip_next:
                if any(not s for s in pipeline):
                    raise Rejected("empty command in pipeline")
                if len(pipeline) == 1 and pipeline[0][0] == "cd":
                    arg = pipeline[0][1] if len(pipeline[0]) > 1 else VIRTUAL_ROOT
                    target = self._map_path(arg, cwd)
                    new = (Path(target) if target.startswith("/") else cwd / target).resolve()
                    if not self._inside(new) or not new.is_dir():
                        outputs.append(f"cd: {arg}: no such directory in {VIRTUAL_ROOT}\n")
                        rc = 1
                    else:
                        cwd, rc = new, 0
                else:
                    text, rc = self._run_stages(pipeline, cwd, deadline)
                    outputs.append(text)
            skip_next = (op == "&&" and rc != 0) or (op == "||" and rc == 0)
        out = "".join(outputs).replace(str(self.root), VIRTUAL_ROOT)
        return out if out.strip() else f"[no output, exit status {rc}]"

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------------------------
# Docker executor: a real shell in a container with no network and a read-only mount.
# --------------------------------------------------------------------------------------------

class DockerExecutor:
    name = "docker"

    def __init__(self, root: Path, image: str = "ubuntu:24.04"):
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

# Sent in native mode. Ollama's Granite template renders these into the system turn inside <tools> tags.
# The published card names the three tools; parameter names are not published, so these are a best guess.
TOOLS = [
    {"type": "function", "function": {
        "name": "terminal",
        "description": "Run a read-only shell command in the repository at /workspace/repo and return its output.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string", "description": "The shell command to run."}},
                       "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "submit_vulnerable_files",
        "description": "Submit the final answer: file paths believed to contain the vulnerability, most likely first.",
        "parameters": {"type": "object", "properties": {"files": {"type": "array", "items": {"type": "string"},
                                                                  "description": "Repository-relative file paths."}},
                       "required": ["files"]}}},
    {"type": "function", "function": {
        "name": "submit_no_vulnerability_found",
        "description": "Submit the final answer: the repository does not contain the vulnerability.",
        "parameters": {"type": "object", "properties": {}}}},
]


# Extra Ollama options applied to every request. {"num_gpu": 0} keeps the model on CPU.
EXTRA_OPTIONS: dict = {}


def ollama_chat(host: str, model: str, messages: list[dict], seed: int | None, native: bool, attempt: int = 0) -> dict:
    """One model turn, streamed so that partial output survives an aborted prediction.

    Returns {"message": {...}} on success, or {"error": str, "partial": str} when Ollama aborts the turn.
    """
    options = {"temperature": 0.3, "top_p": 1.0, "num_ctx": 32768, "num_predict": MAX_TOKENS}
    if seed is not None:
        options["seed"] = seed + attempt
    if attempt:
        options["repeat_penalty"] = 1.2
    options.update(EXTRA_OPTIONS)
    payload = {"model": model, "messages": messages, "stream": True, "options": options}
    if native:
        payload["tools"] = TOOLS
    req = urllib.request.Request(host.rstrip("/") + "/api/chat", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    content, thinking, calls = [], [], []
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            for line in r:
                line = line.strip()
                if not line:
                    continue
                chunk = json.loads(line.decode("utf-8", "replace"))
                if chunk.get("error"):
                    return {"error": str(chunk["error"]), "partial": "".join(thinking + content)}
                m = chunk.get("message") or {}
                if m.get("content"):
                    content.append(m["content"])
                if m.get("thinking"):
                    thinking.append(m["thinking"])
                if m.get("tool_calls"):
                    calls += m["tool_calls"]
                if chunk.get("done"):
                    break
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            body = json.loads(body).get("error", body)
        except json.JSONDecodeError:
            pass
        return {"error": f"HTTP {e.code}: {body[:300]}", "partial": "".join(thinking + content)}
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach Ollama at {host}: {e.reason}. Is the Ollama app running?")
    msg = {"role": "assistant", "content": "".join(content)}
    if thinking:
        msg["thinking"] = "".join(thinking)
    if calls:
        msg["tool_calls"] = calls
    return {"message": msg}


def assistant_text(message: dict) -> str:
    """The assistant turn as one string, whichever fields Ollama split it into."""
    parts = []
    if message.get("thinking"):
        parts.append(f"<think>{message['thinking']}</think>")
    if message.get("content"):
        parts.append(message["content"])
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function", {})
        parts.append("<tool_call>\n" + json.dumps({"name": fn.get("name"), "arguments": fn.get("arguments", {})}) + "\n</tool_call>")
    return "\n".join(parts)


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
    """The submission's argument name is not published, so accept any list or delimited string."""
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


def truncate(text: str) -> str:
    if len(text) <= OUT_LIMIT:
        return text
    return text[:OUT_LIMIT] + f"\n[output truncated at {OUT_LIMIT} characters; narrow the command]"


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


def official_prompt(conv: list[dict]) -> str:
    parts = []
    for m in conv:
        if m["role"] == "tool_response":
            parts.append(f"<|start_of_role|>user<|end_of_role|>\n<tool_response>\n{m['content']}\n</tool_response><|end_of_text|>")
        else:
            parts.append(f"<|start_of_role|>{m['role']}<|end_of_role|>{m['content']}<|end_of_text|>")
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
    commands = rejected = errors = no_calls = 0
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
            try:
                output = official_truncate(executor.run(str(args.get("command", ""))), args.get("max_chars", OUT_LIMIT))
            except Rejected as e:
                rejected += 1
                output = f"ERROR: Command rejected \u2014 {e}"
            output += f"\n[{MAX_COMMANDS - commands} tool-calls remaining]"
        conv.append({"role": "tool_response", "content": output})
        log({"role": "tool", "content": output})
    existing = [f for f in files if (repo / f).is_file()]
    return {"status": status, "commands": commands, "rejected_commands": rejected, "model_errors": errors,
            "files": existing, "files_not_in_repo": [f for f in files if f not in existing]}


# --------------------------------------------------------------------------------------------
# Agent loop (chat protocol, kept for comparison)
# --------------------------------------------------------------------------------------------

NOISE_FILE = re.compile(
    r"(\.d\.ts$|\.(spec|test|eval)\.[a-z]+$|(^|/)(tests?|__tests__|fixtures?|node_modules|dist|build|vendor)/"
    r"|(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|tsconfig[^/]*\.json|wrangler\.(jsonc?|toml)|CHANGELOG\.md|README\.md|LICENSE)$"
    r"|(^|/)\.[^/]+$|\.config\.[a-z]+$|\.(md|lock|map|snap)$)", re.I)


def is_noise_file(path: str) -> bool:
    """Generated, test, manifest and config files. They are never put forward as a lead."""
    return bool(NOISE_FILE.search(path))


def first_messages(query: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Vulnerability to locate:\n{query}"},
    ]


SEED_COMMAND = "find . -type f -not -path './.git/*' | sort"
SEED_LIMIT = 16000
SEED_SKIP_DIRS = {".git", ".vscode", ".changeset", ".husky", "node_modules", "dist", "build", "vendor", ".venv", "__pycache__", ".turbo", ".next", "coverage"}
SEED_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf", ".woff", ".woff2", ".ttf", ".map", ".lock",
                 ".snap", ".zip", ".gz", ".bin", ".md", ".txt"}
SEED_SKIP_NAMES = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "LICENSE", ".gitignore", ".npmrc", ".prettierrc",
                   ".prettierignore", ".editorconfig", "tsconfig.json", ".eslintrc.cjs", "CODEOWNERS"}
SEED_TEST = re.compile(r"(^|/)(tests?|__tests__|evals?|fixtures?)/|\.(test|spec|eval)\.[a-z]+$|\.d\.ts$")


def seed_listing(repo: Path) -> str:
    """A listing of the repository's source files, used as the output of a first command the harness runs itself.

    Assets, lock files, and documentation are left out. Tests go next if the list is still too long, then it is cut.
    """
    files = []
    for base, dirs, names in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SEED_SKIP_DIRS)
        for n in names:
            if n in SEED_SKIP_NAMES or Path(n).suffix.lower() in SEED_SKIP_EXT:
                continue
            full = Path(base) / n
            if full.is_symlink() or not full.is_file():
                continue
            files.append("./" + full.relative_to(repo).as_posix())
    files.sort()
    note = ""
    if sum(len(f) + 1 for f in files) > SEED_LIMIT:
        files = [f for f in files if not SEED_TEST.search(f)]
        note = "\n[tests, assets, lock files and docs omitted]"
    text = "\n".join(files)
    if len(text) > SEED_LIMIT:
        text = text[:SEED_LIMIT].rsplit("\n", 1)[0]
        note = "\n[listing cut; tests, assets, lock files and docs omitted; use find or ls on a directory for the rest]"
    return text + note


def seed_turns(listing: str, native: bool) -> list[dict]:
    """The listing as a first assistant command and its output, in the same shape as a real turn."""
    thought = "I'll list the repository files first so I search real paths."
    if native:
        assistant = {"role": "assistant", "content": f"<think>\n{thought}\n</think>\n",
                     "tool_calls": [{"function": {"name": "terminal", "arguments": {"command": SEED_COMMAND}}}]}
    else:
        call = json.dumps({"name": "terminal", "arguments": {"command": SEED_COMMAND}})
        assistant = {"role": "assistant", "content": f"<think>\n{thought}\n</think>\n\n<tool_call>\n{call}\n</tool_call>"}
    return [assistant, tool_message(listing, native)]


def history_entry(message: dict, text: str, native: bool) -> dict:
    """What goes back into the conversation for the assistant's own turn."""
    if native and message.get("tool_calls"):
        # keep the structured call so the template renders it in the model's own format
        return {"role": "assistant", "content": message.get("content", ""), "tool_calls": message["tool_calls"][:1]}
    return {"role": "assistant", "content": text}


def tool_message(output: str, native: bool) -> dict:
    if native:  # the Granite template wraps a tool-role message in <tool_response> tags itself
        return {"role": "tool", "content": output}
    return {"role": "user", "content": f"<tool_response>\n{output}\n</tool_response>"}


def probe_mode(host: str, model: str, query: str, seed: int | None,
               devices: tuple = ("gpu", "cpu"), modes: tuple = (True, False)) -> tuple[tuple[bool, str] | None, list[dict]]:
    """Find a request style and device that give a usable first turn.

    Tries each device for native mode before falling back to plain. Returns ((native?, device), attempts),
    or (None, attempts) when nothing worked. Leaves EXTRA_OPTIONS set for the chosen device.
    """
    attempts = []
    for native in modes:
        for device in devices:
            EXTRA_OPTIONS.pop("num_gpu", None)
            if device == "cpu":
                EXTRA_OPTIONS["num_gpu"] = 0
            for attempt in range(2):
                reply = ollama_chat(host, model, first_messages(query), seed, native, attempt)
                text = reply.get("partial", "") if "error" in reply else assistant_text(reply["message"])
                call = None if "error" in reply else parse_tool_call(text)
                attempts.append({"mode": "native" if native else "plain", "device": device, "attempt": attempt + 1,
                                 "error": reply.get("error"), "tool_call": call[0] if call else None, "output_head": text[:500]})
                if call and call[0] == "terminal":
                    return (native, device), attempts
    EXTRA_OPTIONS.pop("num_gpu", None)
    return None, attempts


def run_once(executor, repo: Path, query: str, host: str, model: str, native: bool, seed: int | None, log,
             listing: str | None = None) -> dict:
    messages = first_messages(query)
    if listing:
        messages += seed_turns(listing, native)
        log({"role": "seed", "content": f"{SEED_COMMAND}\n{listing}"})
    commands = 0
    bad_turns = 0
    errors = 0
    status = "turn_limit"
    files: list[str] = []
    rejected = 0
    for _ in range(MAX_COMMANDS + 4):
        reply = ollama_chat(host, model, messages, seed, native)
        if "error" in reply:  # one retry with a different seed and a stronger repeat penalty
            log({"role": "error", "content": reply["error"], "partial_output": reply.get("partial", "")[:600]})
            errors += 1
            reply = ollama_chat(host, model, messages, seed, native, attempt=1)
            if "error" in reply:
                log({"role": "error", "content": reply["error"], "partial_output": reply.get("partial", "")[:600]})
                status = "model_error"
                break
        message = reply["message"]
        text = assistant_text(message)
        messages.append(history_entry(message, text, native))
        log({"role": "assistant", "content": text})
        call = parse_tool_call(text)
        if call is None:
            bad_turns += 1
            if bad_turns >= 2:
                status = "no_tool_call"
                break
            nudge = "No tool call was found. Reply with one <tool_call> for terminal, submit_vulnerable_files, or submit_no_vulnerability_found."
            messages.append({"role": "user", "content": nudge})
            log({"role": "user", "content": nudge})
            continue
        name, args = call
        if name == "submit_vulnerable_files":
            files = submitted_files(args)
            status = "submitted"
            break
        if name == "submit_no_vulnerability_found":
            status = "none_found"
            break
        if name != "terminal":
            output = f"unknown tool '{name}'. Tools: terminal, submit_vulnerable_files, submit_no_vulnerability_found."
        elif commands >= MAX_COMMANDS:
            output = "Command budget exhausted. Submit your findings now with submit_vulnerable_files or submit_no_vulnerability_found."
        else:
            commands += 1
            command = str(args.get("command", args.get("cmd", args.get("value", ""))))
            try:
                output = truncate(executor.run(command))
            except Rejected as e:
                rejected += 1
                output = f"[not run: {e}]"
        messages.append(tool_message(output, native))
        log({"role": "tool", "content": output})
    existing = [f for f in files if (repo / f).is_file()]
    return {
        "status": status, "commands": commands, "rejected_commands": rejected, "model_errors": errors,
        "files": existing, "files_not_in_repo": [f for f in files if f not in existing],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True, help="path to the repository to search")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--query", help="one vulnerability description")
    g.add_argument("--queries", help="JSON file: list of {id, cwe_description, [reference_files]}. reference_files are used only for scoring, "
                                         "written to reference-score.json; the model never sees them")
    ap.add_argument("--only", help="comma-separated query ids to run from --queries")
    ap.add_argument("--runs", type=int, default=3, help="runs per query; files are ranked by how many runs name them")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST_URL", "http://localhost:11434"))
    ap.add_argument("--sandbox", choices=["auto", "docker", "allowlist"], default="auto",
                    help="auto: docker if a daemon answers, else allowlist (default). "
                         "docker: real shell in a container with no network and a read-only mount. "
                         "allowlist: no shell, read-only tools, paths confined to the repo.")
    ap.add_argument("--seatbelt", action="store_true", help="macOS: also wrap allowlist commands in sandbox-exec with network denied")
    ap.add_argument("--mode", choices=["auto", "native", "plain"], default="auto",
                    help="native: send the tool definitions and use tool-role replies (what Ollama's Granite template expects). "
                         "plain: no tool definitions, parse <tool_call> from text. auto: probe both on the first query and keep the one that works.")
    ap.add_argument("--device", choices=["auto", "gpu", "cpu"], default="auto",
                    help="cpu: send num_gpu 0 so Ollama keeps the model off the GPU. gpu: Ollama's default. "
                         "auto: probe gpu first, then cpu, and keep the one that works.")
    ap.add_argument("--protocol", choices=["official", "chat"], default="official",
                    help="official: raw prompt, tool definitions and loop rules from Cisco's benchmark harness (default). "
                         "chat: Ollama's chat route with this kit's earlier prompt; kept for comparison.")
    ap.add_argument("--image", default="antares-sandbox", help="docker image for the sandbox; falls back to ubuntu:24.04 if it is not built")
    ap.add_argument("--seed-listing", action="store_true",
                    help="chat protocol only: start each run with a harness-supplied listing of the repository's source files")
    ap.add_argument("--min-agree", type=int, default=2,
                    help="a query goes to the reviewer only when a source file was named by at least this many runs (default 2)")
    ap.add_argument("--resume", action="store_true", help="reuse finished runs already in the output folder; for an interrupted sweep")
    ap.add_argument("--probe", action="store_true", help="only run the mode probe on the first query and print what the model returned")
    ap.add_argument("--seed", type=int, help="base seed; run N uses seed+N")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        raise SystemExit(f"not a directory: {repo}")
    if args.query:
        queries = [{"id": "adhoc", "query": args.query}]
    else:
        queries = json.loads(Path(args.queries).read_text(encoding="utf-8"))
        if args.only:
            wanted = set(args.only.split(","))
            queries = [q for q in queries if q["id"] in wanted]
    if not queries:
        raise SystemExit("no queries selected")

    out_dir = Path(args.out)
    (out_dir / "transcripts").mkdir(parents=True, exist_ok=True)

    official = args.protocol == "official"
    def qtext(q):
        return (q.get("cwe_description") or q["query"]) if official else (q.get("query") or q["cwe_description"])
    native = args.mode == "native"
    device = args.device
    if device == "cpu":
        EXTRA_OPTIONS["num_gpu"] = 0
    attempts = None
    if official and (device == "auto" or args.probe):
        dev, attempts = probe_official(args.host, args.model, qtext(queries[0]), args.seed,
                                       devices=("gpu", "cpu") if device == "auto" else (device,))
        chosen = None if dev is None else (True, dev)
    elif not official and (args.mode == "auto" or device == "auto" or args.probe):
        chosen, attempts = probe_mode(args.host, args.model, qtext(queries[0]), args.seed,
                                      devices=("gpu", "cpu") if device == "auto" else (device,),
                                      modes=(True, False) if args.mode == "auto" else (native,))
    mode_name = "official" if official else None
    if attempts is not None:
        (out_dir / "probe.json").write_text(json.dumps(attempts, indent=1), encoding="utf-8")
        for a in attempts:
            head = a["output_head"].replace("\n", "\\n")[:220]
            print(f"[probe {a['mode']} {a['device']} #{a['attempt']}] tool_call={a['tool_call']} error={a['error']}\n    output: {head}", flush=True)
        if chosen is None:
            print(f"\nNo request style and device produced a tool call. Details are in {out_dir / 'probe.json'}.")
            return 2
        native, device = chosen
        mode_name = mode_name or ("native" if native else "plain")
        (out_dir / "chosen.json").write_text(json.dumps({"mode": mode_name, "device": device}), encoding="utf-8")
        print(f"mode: {mode_name}, device: {device}\n", flush=True)
        if args.probe:
            return 0
    mode_name = mode_name or ("native" if native else "plain")

    sandbox = args.sandbox
    if sandbox == "auto":
        ok = shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0
        sandbox = "docker" if ok else "allowlist"
    if sandbox == "docker":
        image = args.image
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
            # Never fall back to a bare image silently: without rg and tree a quarter of Antares-1B's commands fail.
            kit = Path(__file__).resolve().parent
            if image == "antares-sandbox" and (kit / "Dockerfile").is_file():
                print(f"docker image '{image}' is not built; building it from {kit / 'Dockerfile'}", flush=True)
                b = subprocess.run(["docker", "build", "-q", "-t", image, str(kit)], capture_output=True, text=True)
                if b.returncode != 0:
                    raise SystemExit(f"could not build the sandbox image: {b.stderr.strip()[-600:]}")
            else:
                raise SystemExit(f"docker image '{image}' does not exist. Build it, or pass --image with an image that has rg and tree.")
        executor = DockerExecutor(repo, image)
    else:
        executor = AllowlistExecutor(repo, seatbelt=args.seatbelt)

    listing = seed_listing(repo) if args.seed_listing and not official else None
    report = {"repo": str(repo), "model": args.model, "sandbox": executor.name, "mode": mode_name, "device": device, "seeded_listing": listing is not None,
              "runs_per_query": args.runs, "results": []}
    score: list[dict] = []
    try:
        for q in queries:
            votes: dict[str, int] = {}
            runs = []
            for n in range(args.runs):
                tpath = out_dir / "transcripts" / f"{q['id']}.run{n + 1}.jsonl"
                rpath = out_dir / "transcripts" / f"{q['id']}.run{n + 1}.result.json"
                res = None
                if args.resume and rpath.is_file():  # a finished run from an interrupted sweep
                    try:
                        res = json.loads(rpath.read_text(encoding="utf-8"))
                    except json.JSONDecodeError:
                        res = None
                if res is None:
                    with tpath.open("w", encoding="utf-8") as tf:
                        rseed = None if args.seed is None else args.seed + 100 * n
                        logf = lambda rec: tf.write(json.dumps(rec) + "\n")
                        if official:
                            res = run_official(executor, repo, qtext(q), args.host, args.model, rseed, logf)
                        else:
                            res = run_once(executor, repo, qtext(q), args.host, args.model, native, rseed, logf, listing)
                    rpath.write_text(json.dumps(res), encoding="utf-8")
                runs.append(res)
                for f in res["files"]:
                    votes[f] = votes.get(f, 0) + 1
                print(f"[{q['id']} run {n + 1}/{args.runs}] {res['status']}, {res['commands']} commands, {len(res['files'])} files", flush=True)
            ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
            entry = {"id": q["id"], "query": qtext(q), "ranked_files": [{"file": f, "runs": c} for f, c in ranked], "runs": runs}
            ref = q.get("reference_files")
            if ref:  # kept out of results.json so a reviewer reading the results is not handed the answers
                got = {f for f, _ in ranked}
                score.append({"id": q["id"], "reference_files": ref, "reference_hits": sorted(got & set(ref))})
            report["results"].append(entry)
    finally:
        executor.close()
    (out_dir / "results.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    # A short file for the reviewer. A query is put forward for review only when a real source file was
    # named by enough of its runs; agreement between runs is the localizer's most reliable signal.
    need = min(args.min_agree, args.runs)
    leads, no_lead = [], []
    for e in report["results"]:
        agreed = [f for f in e["ranked_files"] if f["runs"] >= need and not is_noise_file(f["file"])]
        if agreed:
            leads.append({"id": e["id"], "cwe": e["query"], "files": agreed[:6]})
        else:
            no_lead.append(e["id"])
    run_status: dict[str, int] = {}
    for e in report["results"]:
        for x in e["runs"]:
            run_status[x["status"]] = run_status.get(x["status"], 0) + 1
    (out_dir / "leads.json").write_text(json.dumps(
        {"queries": len(report["results"]), "to_review": len(leads), "runs_per_query": args.runs, "min_runs_agreeing": need,
         "run_status": run_status, "leads": leads, "no_agreed_lead": no_lead}, indent=1), encoding="utf-8")
    refs = {x["id"]: x["reference_files"] for x in score}
    if score:
        (out_dir / "reference-score.json").write_text(json.dumps(
            {"queries_with_a_hit": sum(1 for x in score if x["reference_hits"]), "queries_scored": len(score), "results": score},
            indent=1), encoding="utf-8")

    print(f"\nwrote {out_dir / 'results.json'} and {out_dir / 'leads.json'}")
    print(f"{len(leads)} of {len(report['results'])} queries have a source file named by at least {need} of {args.runs} runs:")
    for e in leads:
        print(f"\n{e['id']}")
        for r in e["files"]:
            mark = "  ref" if r["file"] in refs.get(e["id"], []) else ""
            print(f"  {r['runs']}/{args.runs}  {r['file']}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
