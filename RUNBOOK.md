# Scorpius Sweep runbook

Scorpius Sweep is a local, two-model verification harness for Cisco's Antares-1B using Ollama and
Cline. Antares-1B sweeps a repository for CWE classes and names candidate files. A second, general
model in Cline reads those files and confirms or dismisses each lead. This runbook is the working
configuration as of 3 Oct 2026 on a Mac Studio (M3 Ultra). The worked example is a public MCP
server monorepo written in TypeScript.

## 1. What the stack is

| Part | Role | What is used |
|---|---|---|
| Antares | Names candidate files for a CWE class. Knows three tool calls and nothing else. | Antares-1B. Official weights from `fdtn-ai/antares-1b` on Hugging Face, converted to GGUF (section 6) and registered in Ollama as `antares-1b`. Antares-350M was also run and was less effective (section 7). |
| Harness | Builds the prompt, runs the model's shell commands, ranks submitted files. | `antares_locate.py` in this folder |
| Sandbox | Contains the model-written commands. | Docker, no network, read-only mount, image `antares-sandbox` |
| Driver model | Runs Cline and verifies each candidate by reading the code. | `qwen3.8:27b-mlx` through Ollama |
| Cline | Agent that follows `.clinerules/scorpius-sweep.md`. | VS Code extension, Ollama provider |
| Target | Code under review. | Any git URL or local checkout, chosen at setup |
| CWE list | What to look for. One query per CWE class. | You supply it (section 3). Antares does not choose. |

Antares cannot drive Cline and Cline cannot chat with Antares. Antares stays behind the harness.

### What Antares is, next to a rules-driven approach

Antares behaves as a learned search policy. Given a CWE, it decides what to `rg` and `find` for
and which files to name. In the worked example 347 of its 579 commands were `rg` calls, it output
file paths and nothing else, and every confirmed finding came from the driver model reading the
code. It is closer to a grep strategy tuned on vulnerability data than to a reviewer.

Project CodeGuard, which Cisco donated to the Coalition for Secure AI in February 2026, takes the
opposite route. It is a model-agnostic ruleset and skills framework that a general coding agent
loads.

| | Antares | Project CodeGuard |
|---|---|---|
| Where the security knowledge lives | In the weights of a small specialized model | In rules and skills given to a general model |
| What it does | Names candidate files for a CWE class | Guides design, code generation and AI-assisted review |
| What it needs | A harness, a sandbox with `rg`, and a second model or a person to verify | A capable coding agent that follows the rules |
| Output | Ranked file paths | Guidance and findings from the host agent |
| Runs on | A laptop CPU, no data leaves the machine | Whatever the host agent runs on |

The two sit at different stages. Antares narrows where to look. A rules-driven agent does the
looking. They can be combined, with Antares feeding ranked files to an agent that carries the rules.

## 2. Prerequisites

| Item | Version used | Note |
|---|---|---|
| Python | 3.14.8 | 3.9 or newer. |
| Ollama | 0.34.4 | Answering on `localhost:11434`. |
| Docker Desktop | current | Running, with `/Users` in the file sharing list. |
| Working folder | `$WORKDIR` | Any folder you choose. The kit sits at `$WORKDIR/scorpius-sweep`. Keep it outside `~/Documents`, `~/Desktop` and `~/Downloads`. macOS blocks Docker from mounting those. |

## 3. Setup

Set the working folder once per shell. Every command below uses it.

```
export WORKDIR=/path/to/your/working/folder
```

The target repository is a parameter. Nothing in the kit names one. Run setup once per machine
with the first target.

```
cd "$WORKDIR/scorpius-sweep"
chmod +x setup.sh run_review.sh

./setup.sh <git-url> [commit-or-ref]      # clones into targets/<name>
./setup.sh <path-to-local-checkout>       # uses an existing directory
```

After that, `run_review.sh` takes the same target arguments, so a new repository is one command.

```
./run_review.sh <git-url> [commit-or-ref] --device cpu
./run_review.sh <path-to-local-checkout> --device cpu
./run_review.sh --device cpu              # the target from the last run
```

`<name>` is the last part of the URL or path, reduced to letters, digits, dot, underscore and
hyphen. The choice is recorded in `.antares-target`, which the Cline rule reads.

| Value in `.antares-target` | Meaning |
|---|---|
| `TARGET_NAME` | Name used for folders. |
| `TARGET_DIR` | The code under review. |
| `QUERIES` | Query file in use. |
| `OUT_DIR` | `results/<name>`. Each target keeps its own results. |
| `MODEL` | The Ollama model name `run_review.sh` uses. |

`setup.sh` does the following in order.

1. Checks Python and Ollama.
2. Checks that the Antares model is registered in Ollama. The default name is `antares-1b`. Set `ANTARES_MODEL` to another Ollama model name before `./setup.sh` to use a different one. Section 6 shows how to create the model from the official weights.
3. Clones the target, pinned to the commit or ref if one was given. Skipped for a local path.
4. Runs the harness tests (148 checks).
5. Builds the `antares-sandbox` Docker image (Ubuntu 24.04 with `rg` and `tree`). The harness also builds it on first use if it is missing, and stops with an error if it cannot. It does not fall back to a bare image.
6. Probes the model and picks the device that returns a tool call.
7. Runs one smoke query, the first in the query file.

A local checkout must sit in a folder Docker can mount. `~/Documents`, `~/Desktop`, and
`~/Downloads` are blocked by macOS.

### Queries: which CWEs are searched

Antares checks only the CWE classes it is given. It does not decide which weaknesses matter for a
repository. By default the kit gives it every class it was benchmarked on, so no class is picked by
hand. Bring your own list only when you want a narrower or wider search.

| File | Use |
|---|---|
| `queries/all.json` | The default. All 145 CWE classes of Cisco's benchmark, with the description text the model was evaluated on. |
| `queries/<name>.json` | Your own list for a target. Picked up automatically when `<name>` matches the target name. |
| `ANTARES_QUERIES=path ./setup.sh ...` | A query file at any other path. |
| `queries/cwe-catalog.json` | The same 145 classes as a lookup table, used by `make_queries.py`. |

What the 145 are. Cisco's benchmark covers 147 unique CWE IDs across 500 tasks. Its manifest gives
description text for 145 of them, and those are the 145 here. CWE-117 and CWE-459 have no
description in the manifest and are left out. This is the set the model was evaluated on. It is
not a published training list. Cisco describes the training data as proprietary and says the
benchmark repositories were held out from it, so which CWE classes the model was trained on is
not known. The model takes any CWE description as input.
Some classes cannot apply to a given language, such as memory-safety classes on a TypeScript
target. They are left in so that nothing is filtered by judgment. The agreement threshold in
section 5 keeps them from reaching the driver.

To search a subset or add a class, build your own file.

```
python3 make_queries.py --list                               # CWE IDs in the catalog
python3 make_queries.py CWE-22 CWE-79 CWE-89 > queries/<name>.json
```

A query has three fields.

```
[
 {"id": "cwe-89", "cwe": "CWE-89",
  "cwe_description": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') — The product constructs ..."}
]
```

| Field | Rule |
|---|---|
| `id` | Neutral, such as `cwe-89`. The driver reads ids in `leads.json`, so a descriptive id such as `raw-sql-tool` tells it what to look for. |
| `cwe_description` | The CWE ID, its name, and its generic MITRE description. Nothing about the target. This is the only text the model sees. |
| `reference_files` | Optional, for scoring a run against known answers. The model and the driver never see it. Results go to `results/<name>/reference-score.json`. A new target needs none. |

A CWE outside the catalog can be added by hand with text from its MITRE definition. The model was
not evaluated on it, and the model card says it does poorly on classes without grep-able patterns.

The official Antares CLI has a `plan` command that selects CWEs for a repository. This kit does
not select. It runs them all.

## 4. How the harness talks to the model

The harness reproduces Cisco's benchmark harness
(`cisco-foundation-ai/vulnerability-localization-benchmark`, commit `fa50b67`). A test checks that
its prompt is byte-identical to Cisco's runner.

| Element | Value |
|---|---|
| System prompt and tool definitions | Copied from `model_runners/base.py`. Tools are `terminal`, `submit_vulnerable_files` (argument `ranked_files`), and `submit_no_vulnerability_found`. |
| Prompt format | Built by hand with Granite role tokens. Generation is pre-filled with `<think>`. |
| Request | Ollama `/api/generate` with `raw: true`, so no server-side template is applied. |
| Sampling | Temperature 0.3, frequency penalty 0.3. |
| Loop | 20 turns, 15 terminal calls, first valid tool call per turn, `[N tool-calls remaining]` after each output. |
| Output limit | 2,000 characters per command. |
| Query | A CWE ID and its generic description. Nothing about the target. |
| Device | CPU (`num_gpu: 0`). The harness probes GPU first and falls back to CPU. On this Mac (Ollama 0.34.4, Metal) both Antares-350M and Antares-1B returned only `@` on the GPU path and valid tool calls on CPU. |

The query text comes from the `cwe_description` field of your query file (section 3).

## 5. Run the localizer

```
./run_review.sh --device cpu                              # recorded target
./run_review.sh <git-url-or-path> [ref] --device cpu     # a different target
```

This runs every query in the query file three times against the recorded target. With all 145
classes that is 435 runs. Antares-1B on CPU took about 23 seconds per run, so allow about 2 hours
45 minutes. If the sweep is interrupted, rerun the same command with `--resume` and finished runs
are reused.

Output goes to `results/<name>/`.

| File | Content |
|---|---|
| `leads.json` | What the driver reads. The classes that have a lead, with their files, and the list of classes that have none. |
| `results.json` | Per-run detail for every class: status, command counts, submitted paths. |
| `reference-score.json` | Hits against `reference_files`, when the query file has any. |
| `transcripts/` | One file per run with every command and its output. |

A class has a lead when a source file was named by at least 2 of its 3 runs. Agreement between
runs is the localizer's most reliable signal, and in the worked example the hits that held up
were the ones named by 2 or 3 runs. Generated files, tests, manifests and config files never
count as a lead. Classes without a lead are listed in `leads.json` under `no_agreed_lead` and the
driver does not investigate them.

| Flag | Effect |
|---|---|
| `--device cpu` | Stay on CPU and skip the GPU probe. |
| `--only ID1,ID2` | Run a subset of the CWEs in the query file. |
| `--runs N` | Change runs per query. |
| `--min-agree N` | Runs that must name a file for it to count as a lead. Default 2. |
| `--resume` | Reuse finished runs in the output folder after an interruption. |
| `--model NAME` | Use another model, for example an Antares-1B build. |

## 6. Converting weights from safetensors to GGUF

Ollama runs GGUF files. The official Antares repositories (`fdtn-ai/antares-350m` and
`fdtn-ai/antares-1b`, both gated on Hugging Face) ship `model.safetensors`, so the weights have to
be converted first. Request access, download the repository files into a folder, and convert. The conversion uses the
upstream llama.cpp script and needs no GPU.

### Converter validation

Before converting Antares-1B, the procedure was checked on the official Antares-350M safetensors,
for which an independently published Q8_0 GGUF exists to compare against.

| Item | Value |
|---|---|
| Input | Official `model.safetensors` (704,786,224 bytes), `config.json`, `tokenizer.json`, `tokenizer_config.json`, `generation_config.json`, `chat_template.jinja` |
| Converter | `convert_hf_to_gguf.py` from `ggml-org/llama.cpp` at commit `eec18f5` (3 Oct 2026) |
| Python packages | torch 2.14.1, transformers 5.18.0, gguf 0.19.0, sentencepiece 0.2.2, numpy 2.5.3 |
| Output | Q8_0 GGUF, 254 tensors, 374.6 MB, architecture `granite`, tokenizer pre-type `granite-docling` |
| Time | About 100 seconds on CPU |
| Check | Same official prompt (872 tokens) and seeds 1, 2 and 3 through llama-cpp-python 0.3.36 on CPU, temperature 0.3, frequency penalty 0.3 |
| Result | Output identical to the independently published GGUF on all three seeds, including the tool call |
| Weights | All 254 tensors byte-identical to the independently published GGUF (same names, types, shapes and data). Tokenizer metadata identical. Only descriptive metadata differs (name, license, tags). |

Upstream llama.cpp therefore converts this architecture correctly, and results from either file
are results from the official weights.

### Antares-1B conversion

Run on the Mac with the same steps, from the official `fdtn-ai/antares-1b` safetensors.

| Item | Value |
|---|---|
| Input | `model.safetensors` (3,674,580,408 bytes, bf16), architecture `GraniteMoeHybridForCausalLM`, 40 attention layers, hidden size 2048 |
| Environment | Python 3.14, torch 2.14.1, transformers 5.18.0, gguf 0.19.0, sentencepiece 0.2.2, numpy 2.5.3 |
| Output | `antares-1b-q8_0.gguf`, Q8_0, 363 tensors, 1.95 GB, architecture `granite`, context length 131,072 |
| Write time | 31 seconds |
| Ollama import | `ollama create antares-1b -f Modelfile.antares-1b` ended with `success` (layer `sha256:98adb0d9...`) |

The converter prints three warnings. All three also appear on the 350M conversion, whose output
matched the independently published GGUF, so they are expected for this architecture.

| Warning | Meaning |
|---|---|
| `Duplicated key name 'general.architecture', overwriting it with new value 'granite'` | The hybrid class is written as the plain `granite` architecture, which is correct for attention-only models. |
| `Unknown RoPE type: default` | The config's `rope_type` is `default`. The file is written with no RoPE scaling and theta 10,000,000. |
| `Duplicated key name 'granite.attention.head_count_kv'` | The per-layer value list replaces the single value. |

The converted 1B model passed the probe check below. With seed 1 on CPU its first turn was
`cd /workspace/repo && ls` as a `terminal` tool call.

### Steps

Work outside the kit folder so the weight files never sit in the Cline workspace.

```
cd "$WORKDIR"
python3 -m venv gguf-venv && source gguf-venv/bin/activate
pip install torch transformers gguf sentencepiece numpy
git clone --depth 1 https://github.com/ggml-org/llama.cpp

python llama.cpp/convert_hf_to_gguf.py <folder-with-safetensors> \
  --outfile <name>-q8_0.gguf --outtype q8_0      # <name> is antares-1b

printf 'FROM ./<name>-q8_0.gguf\n' > Modelfile.<name>
ollama create <name> -f Modelfile.<name>
deactivate
```

| Detail | Note |
|---|---|
| Input folder | Must hold `model.safetensors`, `config.json`, `tokenizer.json` and `tokenizer_config.json` from the official repository. |
| `--outtype q8_0` | 8-bit weights, about half the size of the bf16 original. Use `f16` or `bf16` to keep full precision. |
| Chat template | The script embeds the repository's template in the GGUF. The harness sends a raw prompt, so the template is not used. |
| Python version | If pip finds no torch wheel for your Python, build the venv with an older one, for example `python3.12 -m venv gguf-venv`. |
| Modelfile | `FROM` alone is enough. No template or parameters are needed for raw requests. |

### Check the converted model

Run the harness probe with a fixed seed on CPU. It prints the first turn.

```
cd "$WORKDIR/scorpius-sweep"
python3 antares_locate.py --repo "$(. ./.antares-target; echo $TARGET_DIR)" \
  --queries queries/all.json --probe --seed 1 --device cpu --model <name> --out /tmp/probe-<name>
```

A good conversion returns a `terminal` tool call. Garbage, an empty reply, or a load error means
the conversion or the import failed.

### Run the review with the converted model

```
./run_review.sh --model <name> --out results/<target>-<name>
```

A separate `--out` keeps results from different models side by side.

## 7. Worked example

Target is a public MCP server monorepo in TypeScript (478 tracked files), pinned to one commit.
The results below come from a first round with a hand-picked query file of 14 CWE classes. The query file also lists reference files
taken from a prior threat model of the same target, used only for scoring.

```
./setup.sh https://github.com/<org>/<repo> <commit>
./run_review.sh --device cpu
```

| Measure | Antares-1B |
|---|---|
| Runs ending in a submission | 42 of 42 |
| Terminal commands per run, average | 13.8 |
| Commands using `rg` | 347 of 579 |
| Paths submitted | 143 |
| Submitted paths that exist | 125 |
| Submitted paths that do not exist | 18 of 143 (13%) |
| Runs that named a reference file | 11 of 42 |
| Queries with a reference-file hit | 5 of 14 |
| Reference entries hit | 9 of 25 |

| Query | Reference files hit | Runs |
|---|---|---|
| OS command injection (CWE-78) | The sandbox container app and both server-side container modules | 3 of 3 |
| Session expiration (CWE-613) | The OAuth approval utility module and the OAuth handler | 3 of 3 |
| Insufficiently protected credentials (CWE-522) | The OAuth handler and the OAuth router | 2 of 3 |
| Privilege management (CWE-269) | The OAuth handler | 2 of 3 |
| Insufficient logging (CWE-778) | The metrics module | 1 of 3 |

Nine queries had no hit (CWE-20, 89, 250, 489, 829, 862, 918, 1188, 1427). On several of them a
generated type-definition file ranked first, which is noise.

Reference files here were taken from a prior threat model of the same target. They are a
yardstick for scoring, not ground truth, and the model searches the cloned repository without
them. The model card reports a File F1 of 0.209 for Antares-1B. Treat the ranking as leads that a
second model or a person must verify.

Antares-1B depends on `rg`, which it used in 347 of 579 commands. The sandbox image must include
it. The harness builds the `antares-sandbox` image and refuses to run without it.

### Antares-350M on the same queries

Antares-350M was run on the same 14 queries, protocol, target commit and CPU, and was less
effective.

| Measure | Antares-350M | Antares-1B |
|---|---|---|
| Queries with a reference-file hit | 3 of 14 | 5 of 14 |
| Runs that named a reference file | 5 of 42 | 11 of 42 |
| Reference entries hit | 3 of 25 | 9 of 25 |
| Submitted paths that do not exist | 70 of 226 (31%) | 18 of 143 (13%) |
| Terminal commands per run, average | 7.6 | 13.8 |

The 350M model never used `rg`. It guessed a filename, ran `find -name` on the guess, and repeated
it. Its only hit that 1B missed was the database tool file for SQL injection, on one run of three.

### Verification pass by the driver model

The driver (`qwen3.8:27b-mlx`, 128,000-token context, in Cline) was run twice. Each report was
then checked by hand against the source at the pinned commit.

| | Pass A | Pass B |
|---|---|---|
| Localizer results | Antares-350M | Antares-1B |
| Reference files visible to the driver | Yes | No |
| Query ids | Descriptive | Neutral (`cwe-78`) |
| Queries covered | 14 of 14 | 9 of 14 |
| Findings marked Confirmed | 8 | 1 |
| Findings marked Unverified | 1 | 0 |
| Cited `path:line` holds the quoted code | 9 of 9 findings | 10 of 10 citations |

Pass A reconfirmed known answers. Seven of its nine findings rest on the reference list it was
shown, so it measures the driver's ability to confirm a finding it has been pointed at.

Pass B is the unassisted result. With only Antares's ranked files and its own search, the driver
confirmed one finding, the shell `exec` on request input in the sandbox container, which Antares
ranked in all three runs. The hand check found that Pass B missed weaknesses that Pass A had
confirmed in the same code.

| Query | Pass B verdict | What the code shows |
|---|---|---|
| Session expiration (CWE-613) | Dismissed, citing two cookies with a 600-second lifetime | The same file sets the approved-clients cookie with a one-year lifetime, 75 lines above the lines it quoted |
| Active debug code (CWE-489) | Dismissed, "no active debug code" | A development switch replaces per-user credentials with one fixed token. The driver quoted a line from inside that branch under a different query |
| Privilege management (CWE-269) | Dismissed | The authorization handler replaces the requested scope with the server's full fixed set |
| Unnecessary privileges (CWE-250) | Dismissed, ranked files were generated | The sandbox image has no `USER` line and the container starts with internet access |
| Five queries (CWE-778, 862, 918, 1188, 1427) | Not covered. The driver reported "all 9 queries" | The results held 14 |

Three conclusions.

- The driver quotes accurately in both passes and misjudges in both. A dismissal from it is not
  evidence of absence.
- Shown where to look, it confirmed eight findings. Left to Antares's ranking and its own
  search, it confirmed one. On this target the reference list did most of the work in Pass A.
- It stopped after 9 of 14 queries without saying so. The harness now writes a short
  `leads.json` with a query count, and the task text makes the driver state the count and check
  it at the end.

## 8. Driver model and context window

Pull the driver and build a variant with a larger context.

```
ollama pull qwen3.8:27b-mlx
cd "$WORKDIR/scorpius-sweep"
cat > Modelfile <<'EOF'
FROM qwen3.8:27b-mlx
PARAMETER num_ctx 128000
EOF
ollama create qwen3.8-128k -f Modelfile
```

In Cline, set the provider to Ollama, select `qwen3.8-128k`, set Model Context Window to 128000,
and turn on Use Compact Prompt. The two context values are set separately and must match. If
Cline's value is larger than Ollama's, Ollama drops the oldest part of the prompt silently.

Confirm after the first request.

```
ollama ps
```

The CONTEXT column should read 128000.

Sizing observed with this driver. Cline's first prompt is about 42,000 tokens before it reads any
target file. Prompt processing runs at roughly 250 tokens a second. Memory peaked at 35 GB with
57,000 tokens of context.

## 9. Cline task

### Step 1. Start Cline in the kit folder

Cline must run with `$WORKDIR/scorpius-sweep` as its workspace. Otherwise it works in its own scratch
area under `~/.cline/data/workspaces`, cannot see the rule file or the results, and substitutes
whatever files it finds.

| Cline form | How |
|---|---|
| CLI | `cd "$WORKDIR/scorpius-sweep"` and then `cline` |
| VS Code extension | File, Open Folder, `$WORKDIR/scorpius-sweep`. Open that folder itself and not a parent. |

The rule file `.clinerules/scorpius-sweep.md` loads on its own only when the kit is the workspace.

### Step 2. Check the workspace before any work

Send this as the first message of a new task.

```
The workspace for this task is /absolute/path/to/scorpius-sweep. Work only inside that folder.

Read /absolute/path/to/scorpius-sweep/.antares-target and
/absolute/path/to/scorpius-sweep/.clinerules/scorpius-sweep.md.
Reply with the value of TARGET_DIR and OUT_DIR and nothing else. Do not do anything else yet.
```

Replace `/absolute/path/to/scorpius-sweep` with the real path (`echo "$WORKDIR/scorpius-sweep"`). The reply must match `.antares-target`, for
example `TARGET_DIR=targets/<name>` and `OUT_DIR=results/<name>`. If Cline
says a file is missing, or names tools that do not exist, stop the task. It is in the wrong folder
or the driver model is not following Cline's tool protocol.

### Step 3. Send the review task

Send this once the check passes. The rule file carries the full procedure, so the task is short.

When the localizer has already run.

```
Follow .clinerules/scorpius-sweep.md. Skip steps 1 and 2, the localizer already ran.
Start at step 3 with OUT_DIR/leads.json.
```

To have Cline run the localizer as well.

```
Follow .clinerules/scorpius-sweep.md from step 1.
```

What the rule file enforces.

| Rule | Reason |
|---|---|
| Read `leads.json`, state how many classes were searched and how many have a lead, and check the count at the end | A driver that read the long results file in pieces stopped after 9 of 14 queries and reported it as complete. |
| Review only classes with a lead | With 145 classes the driver's work has to be bounded. Classes with no agreed lead are reported as not investigated. |
| Read every candidate source file in full | A driver limited to excerpts dismissed a file after quoting two safe cookies and missed a third, unsafe one 75 lines away. |
| Run its own search for every class it reviews | The listed files are a starting point, and the weakness is often in a neighbouring file. |
| Check every instance before dismissing, and list what was read and searched | Dismissals were the driver's weakest output. |
| Open nothing under `results/` except `leads.json`, and nothing under `queries/` | Those folders hold scoring answers. |
| Write each query to the report before starting the next | A stalled session keeps its finished work. |

Cline settings. Allow file reads in the workspace. Keep command execution on manual approval.
Deny anything that builds, installs, or runs code from the target.

## 10. Safety boundaries

- The model writes shell commands. The container is the boundary. It has no network, a read-only
  root, a read-only mount of the target, and no added capabilities.
- A command allowlist is not a boundary. The benchmark's own allowlist lets `find -exec` and `awk`
  through.
- The target is untrusted input to the driver model. The Cline rule treats text in the target as
  data and forbids building or running it.
- The local driver keeps everything on the Mac. A hosted driver would receive file contents from
  the target.

## 11. License and attribution

Scorpius Sweep is licensed under Apache 2.0 (`LICENSE`). The `NOTICE` file and the comment block at
the top of `antares_locate.py` record what is adapted from Cisco's benchmark harness, which is
also Apache 2.0, and what was changed.

| Material | Origin |
|---|---|
| System prompt, tool definitions, prompt format, loop rules | `cisco-foundation-ai/vulnerability-localization-benchmark`, commit `fa50b67` |
| Sandbox image tool set | The same repository's `Dockerfile` |
| CWE IDs, names and descriptions in `queries/` | The same repository's `data/manifest.csv`. CWE content is (c) The MITRE Corporation. |
| Model weights | Not included. Obtained from `fdtn-ai/antares-1b` under its own license. |

The project is not affiliated with or endorsed by Cisco.

## 12. Sources

- Antares-350M weights and model card https://huggingface.co/fdtn-ai/antares-350m
- Antares-1B weights and model card https://huggingface.co/fdtn-ai/antares-1b
- Antares model collection https://huggingface.co/collections/fdtn-ai/antares
- llama.cpp converter https://github.com/ggml-org/llama.cpp
- Official benchmark harness https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark
- Official quickstart https://github.com/cisco-foundation-ai/cookbook/blob/main/1_quickstarts/Quickstart_Antares.md
- Independent Mac reproduction of Antares-1B https://github.com/juliogomez/antares
- Project CodeGuard donation announcement https://www.oasis-open.org/2026/02/09/cisco-donates-project-codeguard-to-coalition-for-secure-ai
