#!/usr/bin/env python3
"""Tests for antares_locate.py. No model needed: a local HTTP server plays Ollama with scripted replies.

    python3 tests/test_harness.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import antares_locate as al  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL  {name}  {detail}")


def make_repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "src" / "auth").mkdir(parents=True)
    (repo / "src" / "auth" / "token.ts").write_text("export const ttl = 60 * 60 * 24 * 30\nconst SECRET_MARK = 'in-repo'\n")
    (repo / "src" / "exec.ts").write_text("import { exec } from 'child_process'\nexec(userInput)\n")
    (repo / "README.md").write_text("# demo\n")
    outside = tmp / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE-SECRET\n")
    os.symlink(outside / "secret.txt", repo / "link.txt")
    os.symlink(outside, repo / "linkdir")
    return repo


def sandbox_tests(repo: Path, tmp: Path) -> None:
    ex = al.AllowlistExecutor(repo)

    def run(cmd):
        try:
            return ex.run(cmd)
        except al.Rejected as e:
            return f"REJECTED: {e}"

    # things that must work
    check("grep -rn", "src/exec.ts:2" in run("grep -rn 'exec(' ."), run("grep -rn 'exec(' ."))
    check("grep include", "token.ts" in run('grep -rl --include="*.ts" ttl /workspace/repo/src'))
    check("virtual root in output", "/workspace/repo/src" in run("find /workspace/repo/src -name '*.ts'") and str(repo) not in run("find /workspace/repo/src -name '*.ts'"))
    check("pipe", run("find . -name '*.ts' | wc -l").strip() == "2", run("find . -name '*.ts' | wc -l"))
    check("cd &&", "token.ts" in run("cd src/auth && ls"))
    check("sed range", "exec(userInput)" in run("sed -n '2,2p' src/exec.ts"))
    check("head", "import" in run("head -1 src/exec.ts"))
    check("glob", "exec(userInput)" in run("cat src/*.ts"))
    check("xargs grep", "src/exec.ts" in run("find . -name '*.ts' | xargs grep -l child_process"), run("find . -name '*.ts' | xargs grep -l child_process"))
    check("xargs -I", "import" in run("find src -name 'exec.ts' | xargs -I {} head -1 {}"))
    check("xargs then pipe", run("find . -name '*.ts' | xargs cat | wc -l").strip() == "4", run("find . -name '*.ts' | xargs cat | wc -l"))
    check("2>/dev/null", "exec.ts" in run("grep -rl exec . 2>/dev/null"))
    check("|| fallback", "README" in run("ls nonexistent 2>/dev/null || ls"))
    check("no output note", "no output" in run("grep -r zzzzzz src"))

    # things that must not leak or change anything
    leak = "OUTSIDE-SECRET"
    hostile = [
        "cat /etc/passwd", "cat ../outside/secret.txt", "cat link.txt", "head -1 link.txt", "ls linkdir", "cat linkdir/secret.txt",
        "grep -r SECRET linkdir", "find linkdir -type f", "find -L . -name secret.txt", "grep -R OUTSIDE .", "rg -L OUTSIDE .",
        f"cat {tmp}/outside/secret.txt", "cat ~/.ssh/id_rsa", "ls /", "ls ..", "cd .. && ls", "cd /tmp && ls",
        "echo ../outside/secret.txt | xargs cat", f"echo {tmp}/outside/secret.txt | xargs cat", "echo link.txt | xargs cat",
        "find . -name '*.ts' -exec cat /etc/passwd ;", "find . -o -exec id ;", "find . -delete", "find . -fprint /tmp/x",
        "cat src/exec.ts > /tmp/pwn", "cat src/exec.ts >> out.txt", "cat < /etc/passwd", "ls; id", "ls && whoami", "ls | sh",
        "bash -c id", "python3 -c 'print(1)'", "awk 'BEGIN{system(\"id\")}'", "curl http://example.com", "rm -rf src", "touch x",
        "sed -i s/a/b/ src/exec.ts", "sed -n '1w /tmp/x' src/exec.ts", "sed 's/a/b/e' src/exec.ts", "sort -o src/exec.ts src/exec.ts",
        "$(id)", "ls `id`", "ls $(cat /etc/passwd)", "grep -f /etc/passwd -r .", "grep -rnf /etc/passwd .", "rg --pre cat x .",
        "/bin/cat /etc/passwd", "./evil", "env", "xargs cat", "find . | xargs rm", "find . | xargs -I {} sh -c 'id'",
        "tree -o /tmp/t", "file -f /etc/passwd", "stat -L link.txt", "ls -L linkdir", "uniq src/exec.ts /tmp/out",
        "cat src/exec.ts &", "(ls)", "ls | tee x", "sort --compress-program=sh src/exec.ts", "wc --files0-from=/etc/passwd",
    ]
    before = sorted(str(p) for p in repo.rglob("*"))
    for cmd in hostile:
        out = run(cmd)
        bad = leak in out or "root:" in out or "uid=" in out
        check(f"hostile: {cmd}", not bad, out[:120])
    check("repo unchanged", before == sorted(str(p) for p in repo.rglob("*")))
    check("no /tmp/pwn", not Path("/tmp/pwn").exists() and not Path("/tmp/x").exists() and not Path("/tmp/t").exists())
    check("exec.ts intact", (repo / "src" / "exec.ts").read_text().startswith("import"))
    # specific rejections (not just silent failure)
    for cmd, word in [("cat /etc/passwd", "outside"), ("ls | sh", "not available"), ("cat a > b", "operator"), ("$(id)", "substitution"),
                      ("find . -exec id ;", "not available"), ("sed -i s/a/b/ f", "sed is limited"), ("grep -R x .", "not available")]:
        out = run(cmd)
        check(f"rejects: {cmd}", out.startswith("REJECTED") and word in out, out[:120])
    check("truncate", len(al.truncate("x" * 5000)) < 2100 and "truncated" in al.truncate("x" * 5000))


def parser_tests() -> None:
    p = al.parse_tool_call
    check("parse basic", p('<think>x</think>\n<tool_call> {"name": "terminal", "arguments": {"command": "ls"}} </tool_call>') == ("terminal", {"command": "ls"}))
    check("parse no close tag", p('<tool_call>{"name": "terminal", "arguments": {"command": "ls -la"}}') == ("terminal", {"command": "ls -la"}))
    check("parse nested braces", p('<tool_call>{"name":"terminal","arguments":{"command":"grep -r \\"{a}\\" ."}}</tool_call>')[1]["command"] == 'grep -r "{a}" .')
    check("parse string args", p('<tool_call>{"name":"terminal","arguments":"{\\"command\\": \\"ls\\"}"}</tool_call>') == ("terminal", {"command": "ls"}))
    check("parse none", p("I think the file is src/a.ts") is None)
    check("parse garbage", p("<tool_call>{not json}</tool_call>") is None)
    check("parse first of two", p('<tool_call>{"name":"terminal","arguments":{"command":"a"}}</tool_call><tool_call>{"name":"terminal","arguments":{"command":"b"}}</tool_call>')[1]["command"] == "a")
    s = al.submitted_files
    check("files list", s({"files": ["/workspace/repo/src/a.ts", "./src/b.ts", "src/a.ts"]}) == ["src/a.ts", "src/b.ts"])
    check("files other key", s({"file_paths": ["src/a.ts"]}) == ["src/a.ts"])
    check("files string", s({"vulnerable_files": "src/a.ts, src/b.ts\nsrc/c.ts"}) == ["src/a.ts", "src/b.ts", "src/c.ts"])
    m = al.assistant_text({"thinking": "t", "content": "", "tool_calls": [{"function": {"name": "terminal", "arguments": {"command": "ls"}}}]})
    check("structured tool_calls rebuilt", p(m) == ("terminal", {"command": "ls"}) and "<think>t</think>" in m)


class Mock(BaseHTTPRequestHandler):
    """Plays Ollama's /api/chat with streamed NDJSON. Script items: a message dict, {"error": "..."} for an
    abort after partial output, or {"http500": "..."} for an immediate HTTP 500."""
    script: list = []
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Mock.seen.append(body)
        reply = Mock.script.pop(0) if Mock.script else {"content": "nothing"}
        if "http500" in reply:
            data = json.dumps({"error": reply["http500"]}).encode()
            self.send_response(500)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        lines = []
        if self.path == "/api/generate":
            if "error" in reply:
                lines = [{"response": reply.get("partial", "aaaa"), "done": False}, {"error": reply["error"]}]
            else:
                c = reply.get("content", "")
                lines = [{"response": c[:len(c) // 2], "done": False}, {"response": c[len(c) // 2:], "done": False}, {"response": "", "done": True}]
        elif "error" in reply:
            lines.append({"message": {"role": "assistant", "content": reply.get("partial", "aaaa")}, "done": False})
            lines.append({"error": reply["error"]})
        else:
            content = reply.get("content", "")
            half = len(content) // 2
            lines.append({"message": {"role": "assistant", "content": content[:half]}, "done": False})
            last = {"role": "assistant", "content": content[half:]}
            if reply.get("tool_calls"):
                last["tool_calls"] = reply["tool_calls"]
            lines.append({"message": last, "done": False})
            lines.append({"message": {"role": "assistant", "content": ""}, "done": True})
        data = "".join(json.dumps(x) + "\n" for x in lines).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def tc(name, args):
    return {"content": "<think>looking</think>\n<tool_call> " + json.dumps({"name": name, "arguments": args}) + " </tool_call>"}


def stc(name, args):
    """A structured tool call, the way Ollama returns one when tool definitions were sent."""
    return {"content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


REPEAT = {"error": "prediction aborted, token repeat limit reached", "partial": "the the the the"}


def loop_tests(repo: Path, tmp: Path) -> None:
    srv = HTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = f"http://127.0.0.1:{srv.server_port}"
    ex = al.AllowlistExecutor(repo)
    logs: list = []

    def go(script, native=False):
        Mock.script, Mock.seen = list(script), []
        logs.clear()
        return al.run_once(ex, repo, "CWE-78 OS command injection", host, "m", native, 7, logs.append)

    def otc(name, args, tail=""):
        """Raw completion text as the model writes it after the pre-filled <think> tag."""
        return {"content": "looking\n</think>\n<tool_call>\n" + json.dumps({"name": name, "arguments": args}) + "\n</tool_call>" + tail}

    def ogo(script):
        Mock.script, Mock.seen = list(script), []
        logs.clear()
        return al.run_official(ex, repo, "CWE-78: X \u2014 Y", host, "m", 7, logs.append)

    # official protocol: raw prompt to /api/generate, rendered byte-for-byte as the benchmark harness does
    r = ogo([otc("terminal", {"command": "grep -rln child_process ."}, tail="\n<tool_call>junk"),
             otc("submit_vulnerable_files", {"ranked_files": ["src/exec.ts", "./src/missing.ts"]})])
    first, second = Mock.seen[0], Mock.seen[1]
    sysc = al.official_system_content()
    check("official submit", r["status"] == "submitted" and r["files"] == ["src/exec.ts"] and r["files_not_in_repo"] == ["src/missing.ts"] and r["commands"] == 1, str(r))
    check("official request shape", first["raw"] is True and first["stream"] is True and "messages" not in first and "tools" not in first
          and first["options"] == {"temperature": 0.3, "frequency_penalty": 0.3, "num_ctx": 32768, "num_predict": 4096,
                                   "stop": ["<|end_of_text|>", "<|start_of_role|>"], "seed": 7}, str(first["options"]))
    check("official first prompt", first["prompt"] == "<|start_of_role|>system<|end_of_role|>" + sysc + "<|end_of_text|>\n<|start_of_role|>user<|end_of_role|>"
          + al.official_user_prompt("CWE-78: X \u2014 Y") + "<|end_of_text|>\n<|start_of_role|>assistant<|end_of_role|><think>\n", first["prompt"][-300:])
    check("official system content", sysc.startswith("You are a security vulnerability localization agent. You have read-only terminal access")
          and '"ranked_files"' in sysc and '"max_chars"' in sysc and sysc.count("<tools>") == 2 and "\u2014" in sysc, sysc[:200])
    tail = second["prompt"].split("<|start_of_role|>assistant<|end_of_role|>")[1]
    check("official history", tail.startswith("<think>\nlooking\n</think>\n<tool_call>\n{") and "junk" not in tail
          and "</tool_call><|end_of_text|>\n<|start_of_role|>user<|end_of_role|>\n<tool_response>\n" in tail
          and "src/exec.ts" in tail and "\n[14 tool-calls remaining]\n</tool_response><|end_of_text|>\n" in tail, tail[:400])
    r = ogo([{"content": "hm"}, {"content": "hm"}, otc("submit_no_vulnerability_found", {})])
    check("official nudge", r["status"] == "none_found" and al.NUDGE + "\n</tool_response>" in Mock.seen[1]["prompt"], str(r))
    r = ogo([{"content": "hm"}] * 3)
    check("official three silent turns", r["status"] == "no_tool_call" and len(Mock.seen) == 3, str(r))
    r = ogo([otc("terminal", {"command": "ls"})] * 25)
    check("official budgets", r["commands"] == 15 and r["status"] == "turn_limit" and len(Mock.seen) == 20
          and "budget exhausted (15/15)" in Mock.seen[-1]["prompt"], str(r))
    r = ogo([otc("terminal", {"command": "cat /etc/passwd"}), otc("terminal", {"command": "cat src/exec.ts", "max_chars": 10}), otc("submit_vulnerable_files", {"ranked_files": "src/exec.ts"})])
    check("official reject and max_chars", r["rejected_commands"] == 1 and "ERROR: Command rejected" in Mock.seen[1]["prompt"] and "root:" not in Mock.seen[2]["prompt"]
          and "total chars, showing first 10]" in Mock.seen[2]["prompt"] and r["files"] == ["src/exec.ts"], str(r))
    r = ogo([REPEAT, otc("submit_no_vulnerability_found", {})])
    check("official abort retry", r["status"] == "none_found" and r["model_errors"] == 1 and Mock.seen[1]["options"]["frequency_penalty"] == 0.6, str(r))
    Mock.script, Mock.seen = [REPEAT, REPEAT, otc("terminal", {"command": "ls"})], []
    dev, attempts = al.probe_official(host, "m", "CWE-78: X", 1)
    check("official probe falls back to cpu", dev == "cpu" and len(attempts) == 3 and Mock.seen[2]["options"].get("num_gpu") == 0
          and "num_gpu" not in Mock.seen[0]["options"], str(attempts))
    al.EXTRA_OPTIONS.clear()

    # plain mode: no tool definitions, tags parsed from text, output returned in a tagged user turn
    r = go([tc("terminal", {"command": "grep -rln child_process ."}), tc("submit_vulnerable_files", {"files": ["/workspace/repo/src/exec.ts", "src/missing.ts"]})])
    check("plain submit", r["status"] == "submitted" and r["files"] == ["src/exec.ts"] and r["files_not_in_repo"] == ["src/missing.ts"] and r["commands"] == 1, str(r))
    first = Mock.seen[0]
    check("plain request shape", first["messages"][0]["role"] == "system" and first["messages"][1]["content"].startswith("Vulnerability to locate:\n")
          and first["options"] == {"temperature": 0.3, "top_p": 1.0, "num_ctx": 32768, "num_predict": 4096, "seed": 7}
          and first["stream"] is True and "tools" not in first, str(first)[:300])
    second = Mock.seen[1]["messages"]
    check("plain tool response", second[-1]["role"] == "user" and second[-1]["content"].startswith("<tool_response>\n") and "src/exec.ts" in second[-1]["content"], str(second[-1]))
    check("plain assistant turn kept", "<tool_call>" in second[-2]["content"] and second[-2]["role"] == "assistant")
    check("stream chunks joined", "<think>looking</think>" in second[-2]["content"])

    # native mode: tool definitions sent, structured calls kept, output returned with the tool role
    r = go([stc("terminal", {"command": "ls"}), stc("submit_vulnerable_files", {"files": ["README.md"]})], native=True)
    names = [t["function"]["name"] for t in Mock.seen[0].get("tools", [])]
    hist = Mock.seen[1]["messages"]
    check("native submit", r["status"] == "submitted" and r["files"] == ["README.md"] and r["commands"] == 1, str(r))
    check("native sends tools", names == ["terminal", "submit_vulnerable_files", "submit_no_vulnerability_found"], str(names))
    check("native history", hist[-2]["role"] == "assistant" and hist[-2]["tool_calls"][0]["function"]["name"] == "terminal"
          and hist[-1] == {"role": "tool", "content": hist[-1]["content"]} and "README.md" in hist[-1]["content"], str(hist[-2:])[:300])
    r = go([tc("terminal", {"command": "ls"}), tc("submit_no_vulnerability_found", {})], native=True)
    check("native with text tags", r["status"] == "none_found" and Mock.seen[1]["messages"][-1]["role"] == "tool", str(r))

    r = go([{"content": "the file is exec.ts"}, {"content": "still chatting"}])
    check("loop no_tool_call", r["status"] == "no_tool_call" and len(Mock.seen) == 2, str(r))

    r = go([tc("terminal", {"command": "cat /etc/passwd"}), tc("terminal", {"command": "rm -rf ."}), tc("submit_vulnerable_files", {"files": []})])
    fed = Mock.seen[1]["messages"][-1]["content"]
    check("loop rejects hostile", r["rejected_commands"] == 2 and "[not run:" in fed and "root:" not in json.dumps(Mock.seen), str(r))

    r = go([tc("terminal", {"command": "ls"})] * 25)
    check("loop budget", r["commands"] == al.MAX_COMMANDS and r["status"] == "turn_limit" and "budget exhausted" in json.dumps(Mock.seen[-1]["messages"][-1]), str(r))

    r = go([tc("browse", {"url": "x"}), tc("submit_vulnerable_files", {"paths": "src/exec.ts"})])
    check("loop unknown tool", r["status"] == "submitted" and r["files"] == ["src/exec.ts"] and "unknown tool" in Mock.seen[1]["messages"][-1]["content"], str(r))

    # aborted predictions: one retry with a different seed and repeat penalty, then give up on that run only
    r = go([REPEAT, tc("terminal", {"command": "ls"}), tc("submit_vulnerable_files", {"files": ["README.md"]})])
    check("abort then retry", r["status"] == "submitted" and r["model_errors"] == 1 and Mock.seen[1]["options"].get("repeat_penalty") == 1.2
          and Mock.seen[1]["options"]["seed"] == 8, str(r) + str(Mock.seen[1]["options"]))
    check("abort logged with partial", any(x.get("role") == "error" and "the the" in x.get("partial_output", "") for x in logs), str(logs)[:200])
    r = go([REPEAT, REPEAT])
    check("abort twice", r["status"] == "model_error" and len(Mock.seen) == 2, str(r))
    r = go([{"http500": "prediction aborted, token repeat limit reached"}, {"http500": "x"}])
    check("http 500 handled", r["status"] == "model_error", str(r))

    # probe: picks the first request style that yields a terminal call
    Mock.script, Mock.seen = [stc("terminal", {"command": "ls"})], []
    chosen, attempts = al.probe_mode(host, "m", "CWE-78", 1)
    check("probe native gpu", chosen == (True, "gpu") and len(attempts) == 1 and "tools" in Mock.seen[0]
          and "num_gpu" not in Mock.seen[0]["options"], str(attempts))
    # GPU output is garbage twice, CPU works: stays native, and later turns keep num_gpu 0
    Mock.script, Mock.seen = [REPEAT, REPEAT, stc("terminal", {"command": "ls"})], []
    chosen, attempts = al.probe_mode(host, "m", "CWE-78", 1)
    check("probe falls back to cpu", chosen == (True, "cpu") and len(attempts) == 3 and Mock.seen[2]["options"].get("num_gpu") == 0
          and "tools" in Mock.seen[2] and "num_gpu" not in Mock.seen[1]["options"], str(attempts))
    r = go([tc("submit_no_vulnerability_found", {})], native=True)
    check("cpu choice persists", Mock.seen[0]["options"].get("num_gpu") == 0, str(Mock.seen[0]["options"]))
    al.EXTRA_OPTIONS.clear()
    Mock.script, Mock.seen = [REPEAT, {"content": "hello"}, REPEAT, {"content": "hello"}, tc("terminal", {"command": "ls"})], []
    chosen, attempts = al.probe_mode(host, "m", "CWE-78", 1)
    check("probe falls back to plain", chosen == (False, "gpu") and len(attempts) == 5 and "tools" not in Mock.seen[4] and attempts[0]["error"], str(attempts))
    Mock.script, Mock.seen = [REPEAT] * 8, []
    chosen, attempts = al.probe_mode(host, "m", "CWE-78", 1)
    check("probe nothing works", chosen is None and len(attempts) == 8 and not al.EXTRA_OPTIONS, str(attempts))
    Mock.script, Mock.seen = [REPEAT] * 2, []
    chosen, attempts = al.probe_mode(host, "m", "CWE-78", 1, devices=("cpu",), modes=(True,))
    check("probe pinned", chosen is None and len(attempts) == 2 and all(x["options"].get("num_gpu") == 0 for x in Mock.seen), str(attempts))
    al.EXTRA_OPTIONS.clear()

    # end to end through the CLI, official protocol (the default)
    qf0 = tmp / "q0.json"
    qf0.write_text(json.dumps([{"id": "q1", "query": "long custom text", "cwe_description": "CWE-78: X", "reference_files": ["src/exec.ts"]}]))
    Mock.script = [REPEAT, REPEAT, otc("terminal", {"command": "ls"}),
                   otc("terminal", {"command": "grep -rl exec src"}), otc("submit_vulnerable_files", {"ranked_files": ["src/exec.ts"]}),
                   otc("submit_vulnerable_files", {"ranked_files": ["src/exec.ts", "src/auth/token.ts"]})]
    Mock.seen = []
    out0 = tmp / "out0"
    cp = subprocess.run([sys.executable, str(HERE.parent / "antares_locate.py"), "--repo", str(repo), "--queries", str(qf0), "--runs", "2",
                         "--sandbox", "allowlist", "--host", host, "--out", str(out0)], capture_output=True, text=True)
    res = json.loads((out0 / "results.json").read_text()) if (out0 / "results.json").exists() else {}
    check("cli official end to end", cp.returncode == 0 and res.get("mode") == "official" and res.get("device") == "cpu"
          and res["results"][0]["ranked_files"] == [{"file": "src/exec.ts", "runs": 2}, {"file": "src/auth/token.ts", "runs": 1}]
          and res["results"][0]["query"] == "CWE-78: X" and "CWE-78: X" in Mock.seen[0]["prompt"] and "long custom text" not in Mock.seen[0]["prompt"]
          and all(x["options"].get("num_gpu") == 0 for x in Mock.seen[2:]), cp.stdout[-400:] + cp.stderr[-300:])

    # end to end through the CLI, chat protocol with --mode auto
    qf = tmp / "q.json"
    qf.write_text(json.dumps([{"id": "q1", "query": "CWE-78", "reference_files": ["src/exec.ts"]}]))
    Mock.script = [REPEAT, REPEAT, stc("terminal", {"command": "ls"}),                  # probe: gpu fails, native on cpu works
                   stc("terminal", {"command": "grep -rl exec src"}), stc("submit_vulnerable_files", {"files": ["src/exec.ts"]}),
                   stc("submit_vulnerable_files", {"files": ["src/exec.ts", "src/auth/token.ts"]})]
    Mock.seen = []
    out = tmp / "out"
    cp = subprocess.run([sys.executable, str(HERE.parent / "antares_locate.py"), "--repo", str(repo), "--queries", str(qf), "--runs", "2",
                         "--sandbox", "allowlist", "--protocol", "chat", "--host", host, "--out", str(out)], capture_output=True, text=True)
    res = json.loads((out / "results.json").read_text()) if (out / "results.json").exists() else {}
    ranked = res.get("results", [{}])[0].get("ranked_files")
    check("cli end to end", cp.returncode == 0 and ranked == [{"file": "src/exec.ts", "runs": 2}, {"file": "src/auth/token.ts", "runs": 1}]
          and "reference_files" not in res["results"][0] and "reference_hits" not in res["results"][0]
          and json.loads((out / "reference-score.json").read_text())["results"][0]["reference_hits"] == ["src/exec.ts"]
          and json.loads((out / "leads.json").read_text()) == {"queries": 1, "to_review": 1, "runs_per_query": 2, "min_runs_agreeing": 2, "run_status": {"submitted": 2},
                 "leads": [{"id": "q1", "cwe": "CWE-78", "files": [{"file": "src/exec.ts", "runs": 2}]}], "no_agreed_lead": []}
          and (out / "transcripts" / "q1.run2.result.json").exists()
          and res["mode"] == "native" and res["device"] == "cpu"
          and all(x["options"].get("num_gpu") == 0 for x in Mock.seen[2:])
          and (out / "transcripts" / "q1.run1.jsonl").exists() and (out / "probe.json").exists(), cp.stdout[-400:] + cp.stderr[-300:])
    # resume: finished runs are reused, so the model is not called again
    Mock.script, Mock.seen = [], []
    cp = subprocess.run([sys.executable, str(HERE.parent / "antares_locate.py"), "--repo", str(repo), "--queries", str(qf), "--runs", "2",
                         "--sandbox", "allowlist", "--protocol", "chat", "--mode", "native", "--device", "cpu", "--resume",
                         "--host", host, "--out", str(out)], capture_output=True, text=True)
    check("cli resume reuses runs", cp.returncode == 0 and Mock.seen == [] and "1 of 1 queries" in cp.stdout, cp.stdout[-300:] + cp.stderr[-300:])
    for path, noise in (("packages/a/worker-configuration.d.ts", True), ("src/a.spec.ts", True), ("package.json", True), ("apps/x/wrangler.jsonc", True),
                        (".eslintrc.cjs", True), ("vitest.config.ts", True), ("docs/CHANGELOG.md", True), ("src/tests/helper.ts", True),
                        ("src/exec.ts", False), ("apps/x/src/tools/d1.tools.ts", False), ("apps/c/Dockerfile", False), (".github/workflows/main.yml", False)):
        check(f"noise filter {path}", al.is_noise_file(path) is noise)
    Mock.script, Mock.seen = [REPEAT] * 8, []
    cp = subprocess.run([sys.executable, str(HERE.parent / "antares_locate.py"), "--repo", str(repo), "--queries", str(qf), "--probe", "--protocol", "chat",
                         "--host", host, "--out", str(tmp / "out2")], capture_output=True, text=True)
    check("cli probe failure exits 2", cp.returncode == 2 and "No request style and device" in cp.stdout and "the the the" in cp.stdout, cp.stdout[-300:])
    srv.shutdown()


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d).resolve()
        repo = make_repo(tmp)
        sandbox_tests(repo, tmp)
        parser_tests()
        loop_tests(repo, tmp)
    print(f"{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
