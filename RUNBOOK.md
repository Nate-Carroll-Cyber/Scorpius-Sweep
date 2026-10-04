# Scorpius Sweep runbook

Scorpius Sweep is a local, two-model verification harness for Cisco's Antares-1B using Ollama and
Cline. Its purpose is to help test Antares. Antares-1B sweeps a repository for CWE classes and
names candidate files, a second, general model in Cline reads those files and confirms or
dismisses each lead, and the kit records what was found, what was missed, and how the model
searched. This runbook is the working configuration as of 4 Oct 2026 on a Mac Studio (M3 Ultra).
The worked example is a public MCP server monorepo written in TypeScript.

Limits to read before using any result.

| Limit | Detail |
|---|---|
| Not a vulnerability scanner | A clean result does not mean the code is clean. Run without hints, the pipeline confirmed one finding in the worked example and dismissed four weaknesses in files it had read (section 7). |
| Low precision | Cisco reports a File F1 of 0.209 for Antares-1B on its own benchmark. Generated files often rank first. |
| Training classes unknown | The 145 CWE classes in the catalog are the ones the benchmark evaluates. Cisco does not publish the training list (section 3). |
| It always answers | Asked about no class or an invented one, Antares-1B submitted files in 30 of 30 control runs and never answered "no vulnerability found". Those answers were scattered, with no file in more than 4 of the 30. Each class is compared with the control runs (sections 5 and 7). |
| One target | Every number here comes from one TypeScript repository on one machine. Classes that belong to other languages score poorly for that reason alone. |
| Driver reliability | The driver model misjudges real code, and in one run it invented the code it quoted. `verify_report.py` checks every quote against the source (section 9). Its dismissals are not evidence of absence. |
| Human review | Every lead needs a person to verify it. |

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
| Docker Desktop | current | Required and running, with `/Users` in the file sharing list. The model's commands run only in the container, and the harness stops if Docker is not answering. |
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
3. Clones the target, pinned to the commit or ref if one was given. Skipped for a local path. Then chooses the query file (see below).
4. Runs the harness tests (81 checks, and 5 more against the real sandbox when Docker is answering).
5. Builds the `antares-sandbox` Docker image (Ubuntu 24.04 with `rg` and `tree`) and stops if Docker is not answering. The harness also builds the image on first use if it is missing. It does not fall back to a bare image or to running commands on the host.
6. Probes the model and picks the device that returns a tool call.
7. Runs one smoke query, the first in the query file.

A local checkout must sit in a folder Docker can mount. `~/Documents`, `~/Desktop`, and
`~/Downloads` are blocked by macOS.

### Queries: which CWEs are searched

Antares checks only the CWE classes it is given. It does not decide which weaknesses matter for a
repository. The official Antares CLI does, with its `plan` command, and the kit uses that
selection when the CLI is installed. The CLI is optional. Without it the kit sweeps all 145
benchmark classes and needs nothing beyond Python, Ollama and Docker.

`setup.sh` takes the first of these that applies.

| Order | Source | Use |
|---|---|---|
| 1 | `ANTARES_QUERIES=path ./setup.sh ...` | A query file at any path. |
| 2 | `queries/<name>.json` | The file for this target, when `<name>` matches the target name. A plan from an earlier setup, or your own list. |
| 3 | `antares plan` | When `antares` is on the `PATH`. The selection is written to `queries/<name>.json` and the full plan, with its reasons and evidence, to `queries/<name>.plan.json`. |
| 4 | `queries/all.json` | All 145 CWE classes of Cisco's benchmark. Used when the CLI is not installed or `ANTARES_PLAN=0` is set. |

Planning with the official CLI. `antares plan` profiles the repository on disk and ranks the MITRE
CWE catalog (version 4.20, 969 entries) by evidence it finds there, such as languages, request
handling, file access and credential handling. It selects up to 50 classes. It makes no model
call and needs no endpoint. The CLI ships in the `assets` folder of the Antares-1B model repository
(https://huggingface.co/fdtn-ai/antares-1b). Install it once from a source checkout (Python 3.11
or newer).

```
cd <antares-cli checkout> && uv tool install .
antares plan targets/<name>                                   # the selection with its reasons
```

`setup.sh` and `run_review.sh` then plan a new target without further steps. To plan by hand, or
to change the limits, write the file yourself and delete or replace it to plan again.

```
antares plan targets/<name> --format json | python3 make_queries.py --plan - > queries/<name>.json
antares plan targets/<name> --max-cwes 30 --scope top25 --format json | python3 make_queries.py --plan - > queries/<name>.json
```

`make_queries.py --plan` keeps the plan's classes in the plan's order. A class in the benchmark
catalog keeps the description text the model was evaluated on. A class outside it gets the same
form from the name and MITRE description the plan carries. Only the selection is taken from the
CLI. The sweep still runs through this kit's harness and Ollama, because the CLI's own scan needs
a streaming `/v1/completions` endpoint and uses a different prompt and tool set.

The plan selects on evidence in the repository. It does not know which classes the model handles
well, and in the worked example it did not raise the share of classes that showed lift (section
7). Its effect is a shorter sweep on classes that can apply to the target.

Running without the plan. Nothing in the sweep, the controls, the scoring or the driver step
depends on the CLI. Any of these runs every benchmark class with nothing picked by hand or by plan.

```
./run_review.sh --all --device cpu                            # this run only, whatever is recorded
ANTARES_PLAN=0 ./setup.sh <git-url-or-path>                   # a new target, CLI installed but not used
ANTARES_QUERIES=queries/all.json ./setup.sh <git-url-or-path> # the same, stated as a query file
```

Give a full sweep its own output folder with `--out results/<name>-all` if a planned sweep of the
same target already exists. Some classes cannot apply to a given language, such as memory-safety
classes on a TypeScript target. The agreement threshold and the control comparison in section 5
keep them from reaching the driver.

What the 145 are. Cisco's benchmark covers 147 unique CWE IDs across 500 tasks. Its manifest gives
description text for 145 of them, and those are the 145 in `queries/all.json` and
`queries/cwe-catalog.json`. CWE-117 and CWE-459 have no description in the manifest and are left
out. This is the set the model was evaluated on. It is not a published training list. Cisco
describes the training data as proprietary and says the benchmark repositories were held out from
it, so which CWE classes the model was trained on is not known. The model takes any CWE
description as input.

To search classes you choose, build the file from CWE IDs.

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

## 4. How the harness talks to the model

The harness reproduces Cisco's benchmark harness
(`cisco-foundation-ai/vulnerability-localization-benchmark`, commit `fa50b67`). A test checks that
its prompt is byte-identical to Cisco's runner.

| Element | Value |
|---|---|
| System prompt and tool definitions | Copied from `model_runners/base.py`. Tools are `terminal`, `submit_vulnerable_files` (argument `ranked_files`), and `submit_no_vulnerability_found`. |
| Prompt format | Built by hand with Granite role tokens. Generation is pre-filled with `<think>`. |
| Request | Ollama `/api/generate` with `raw: true`, so no server-side template is applied. |
| Sampling | Temperature 0.3 and frequency penalty 0.3. These are Cisco's values, the defaults in the benchmark's Antares runner (`model_runners/vllm_antares.py`) and in the Antares CLI. The harness sends them with every request, so Ollama's own default temperature of 0.8 is never used. At 0.3 the model still samples, which is why the same class can name different files on different runs. |
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

This runs every query in the query file five times against the recorded target, then the six
control queries five times each, 30 control runs. Antares-1B on CPU took about 23 seconds per run.
A planned sweep of 50 classes is 280 runs, about 1 hour 50 minutes. All 145 classes is 755 runs,
just under five hours. If the sweep is interrupted, rerun the same command with `--resume` and
finished runs are reused. `--resume` also tops up a sweep made with fewer runs per class. Only
the missing runs are made.

Output goes to `results/<name>/`.

| File | Content |
|---|---|
| `leads.json` | What the driver reads. The classes that have a lead with their files, the hotspot files, and the classes that have neither. |
| `results.json` | Per-run detail for every class with status, command counts and submitted paths. |
| `controls/` | The control runs, in the same layout, with their own `results.json` and `transcripts/`. |
| `reference-score.json` | Hits against `reference_files`, when the query file has any. |
| `transcripts/` | One file per run with every command and its output. |

### The control runs

Antares almost never answers "no vulnerability found", and it names some files whatever it is
asked. `queries/controls.json` measures that on each target. It holds two queries with no class
(the benchmark's own fallback text "Unknown vulnerability class", and an unspecified weakness)
and four invented classes that do not exist. The share of control runs that name a file is the
rate at which the model names it when the class carries no information.

A file is agreed for a class when more than half of the class's runs named it, 3 of 5 by default.
An agreed file becomes a lead for the class only when the class named it at a higher rate than
the control runs did. The comparison is a one-sided Fisher exact test at `--alpha` 0.05.

| Class runs naming the file | Control runs naming it, of 30, at which it is still a lead |
|---|---|
| 3 of 5 | up to 4 |
| 4 of 5 | up to 8 |
| 5 of 5 | up to 15 |

`leads.json` sorts each class by that comparison.

| Group in `leads.json` | Meaning | Driver |
|---|---|---|
| `leads` | The class has an agreed source file that it named at a higher rate than the controls. The class label changed the answer. Each file carries `runs`, `control_runs` and the test's `p`. | Reviews each for its class. |
| `hotspots` | Agreed source files that did not clear the comparison for some class, and files most runs of one control named. Each carries the number of classes and control runs that named it. Listed once, without a class. | Reviews each once, for any weakness. |
| `baseline_only` | Classes whose agreed files are all named about as often by the controls. The answer would have been much the same without the class. | Not investigated by class. Their files are in `hotspots`. |
| `no_agreed_lead` | No source file was named by enough runs. | Not investigated. |

Agreement between runs is the localizer's most reliable signal. Generated files, tests, manifests
and config files never count as a lead or a hotspot. A lead shows that the class steered the
search. It does not show that the file is vulnerable. A hotspot is not noise either, since the
files the model names for any question on a target are often its security-relevant ones, so the
driver reviews hotspots as well as leads. One file can be a lead for the classes that named it in
every run and a hotspot for the rest.

Three limits on the comparison. It tests each agreed file on its own, so with 50 classes a few
leads at `p` near 0.05 are expected by chance. The invented classes carry words of their own, so
the control rate can sit below the model's true default rate for a file. And `baseline.enough_runs`
in `leads.json` is false when there are too few runs for any file to clear the test.

Finished control runs in `controls/` are reused on later runs for the same output folder.

| Flag | Effect |
|---|---|
| `--device cpu` | Stay on CPU and skip the GPU probe. |
| `--only ID1,ID2` | Run a subset of the CWEs in the query file. |
| `--runs N` | Change runs per query. Default 5. |
| `--min-agree N` | Runs that must name a file for it to count. Default is more than half of the runs. |
| `--alpha X` | Significance level for the comparison with the control runs. Default 0.05. |
| `--resume` | Reuse finished runs in the output folder, after an interruption or to add runs. |
| `--model NAME` | Use another model, for example an Antares-350M build. |
| `--all` | Sweep all 145 benchmark classes instead of the recorded query file. |
| `--controls FILE` | Use another control set. |
| `--rerun-controls` | Run the controls again instead of reusing finished control runs. |
| `--no-controls` | Skip the controls. `leads.json` then lists every class with an agreed file and has no hotspots. |
| `--image NAME` | Use another sandbox image. It needs `rg` and `tree`. |

### Score the classes

`score_classes.py` reports the same comparison per class and per file, for testing the model
rather than for the driver.

```
python3 score_classes.py --out results/<name>
```

| Output | Meaning |
|---|---|
| Verdict | `lift`, `baseline-only` or `no-agreed-lead`, as in the table above. |
| Files above the control rate | Agreed files that cleared the comparison, each with its class runs, control runs and `p`. |
| Files at the control rate | Agreed files that did not. |
| Invented share | Share of submitted paths that do not exist. |
| Repeat share | Share of commands that repeat an earlier command in the same run. |
| Files table | For each agreed file, how many classes agreed on it, how many control runs named it, and whether it is a hotspot. |

The output is `class-scores.md` and `class-scores.json` in the sweep folder. It is built from the
per-run files, so it works on an interrupted sweep.

| Flag | Effect |
|---|---|
| `--controls-dir DIR` | Take the control runs from another folder. For a sweep made without controls. |
| `--queries FILE` | Score only the classes in that query file. |
| `--min-agree N`, `--alpha X` | As for the sweep. |
| `--write-leads` | Rewrite `leads.json` from the runs on disk. |

The scores describe one model on one target. They are not a training list. A class with no lift on
a TypeScript repository may show lift on a C or Java one.

## 6. Converting weights from safetensors to GGUF

The official Antares repositories (`fdtn-ai/antares-350m` and `fdtn-ai/antares-1b`, both gated on
Hugging Face) ship `model.safetensors`. Request access, download the repository files into a
folder, and convert them to GGUF with the upstream llama.cpp script. The conversion needs no GPU.

Ollama can also import a safetensors folder directly, with a Modelfile whose `FROM` line points at
the folder. That route was not tested here. The llama.cpp route was used because its output can be
checked. The converted 350M file matched an independently published GGUF tensor for tensor, and
the quantization is stated on the command line. If you try the direct import, run the probe in
"Check the converted model" below before trusting it, since Ollama's own converter has to
recognise the Granite architecture and a model that loads can still answer with garbage.

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
  evidence of absence. A later run did not quote accurately (see the third pass below).
- Shown where to look, it confirmed eight findings. Left to Antares's ranking and its own
  search, it confirmed one. On this target the reference list did most of the work in Pass A.
- It stopped after 9 of 14 queries without saying so. The harness now writes a short
  `leads.json` with a query count, and the task text makes the driver state the count and check
  it at the end.

A third pass. The same driver was later run on the leads of the planned sweep, and its report
quoted code that is not in the repository. `verify_report.py` was written in response and run on
all three reports.

| Report | Quotes found in the source | Citations naming a missing file | Citations past the end of a file |
|---|---|---|---|
| Pass A | 12 of 12 | 0 | 0 |
| Pass B | 3 of 3 | 0 | 0 |
| Third pass | 0 of 18 | 8 | 9 |

The third report listed 14 confirmed findings. Its quotes included a session identifier built
with `Math.random()`, a refresh-token field and a path-normalising function, none of which exist
in the source, and it cited line 383 of a 71-line file. It also listed hotspot files and control
counts that were not in `leads.json`. Context size was checked and was not the cause. A driver
that quotes accurately on one run and invents on the next cannot be trusted on its own word in
either, so the report is now checked by script before a person reads it.

### The 145-class sweep and the control runs

After the passes above, Antares-1B was run on all 145 benchmark classes, then on four control
queries. This sweep was made at 3 runs per class and 12 control runs, before the defaults were
raised to 5 and 30. The figures below are from those runs, scored with the comparison in section
5. Agreement is 2 of 3. They are provisional until the sweep is topped up to the new defaults.

| Measure | Result |
|---|---|
| Runs | 435, of which 434 ended with a submission |
| Commands per run | 13.8 of the 15 allowed |
| Submitted paths | 1,444, of which 272 (19%) do not exist |
| Classes with an agreed source file | 62 of 145 |
| Distinct agreed files across those 62 classes | 23 |
| Control runs | 12, all ended with a submission. None answered "no vulnerability found" |
| Files named by a control run | 25 |

The control with no class at all ("Unknown vulnerability class") named the OAuth handler, the
OAuth router and the server entry file in 2 of 3 runs each. One invented class agreed on a file
as well. The model has a default answer for this repository.

| Verdict | Classes |
|---|---|
| Lift, an agreed file named at a higher rate than the controls | 44 |
| Baseline only | 18 |
| No agreed file | 83 |

| File | Classes that agreed on it | Classes for which it is a lead | Control runs that named it, of 12 |
|---|---|---|---|
| OAuth handler | 22 | 12 | 2 |
| Sandbox container app | 14 | 6 | 1 |
| OAuth helper utilities | 14 | 14 | 0 |
| OAuth router | 8 | 2 | 2 |
| Sandbox file utilities | 6 | 6 | 0 |
| Server entry file | 5 | 1 | 2 |

The comparison separates two uses of the same file. The OAuth handler is a lead for the 12
classes that named it in 3 of 3 runs, all of them authentication, access control and exposure
classes, and a hotspot for the 10 that named it in 2 of 3, which is close to the rate of the
control with no class. The sandbox container app is a lead for command injection and five path
classes. With 12 control runs a file named in 3 of 3 class runs clears the test even when two
control runs named it, so this is a weak filter. Thirty control runs make it a stricter one.

The reference check. Nine classes have reference files from the hand-checked findings. A
reference file was named by at least one run for 6 of the 9. At the agreement threshold 3 classes
held one. Command injection named the sandbox container app in 3 of 3 runs, which is a lead.
Insufficiently protected credentials and session expiration named the OAuth handler in 2 of 3,
which is at the control rate, so those two reach the driver only as hotspots. The 44 lift classes
have not been checked by hand.

The earlier 14-class round does not fully agree, and the difference is run-to-run variation on
the same classes. There, command injection named two container tool files in 3 of 3 runs and
session expiration named the OAuth helper utilities in 3 of 3. In the 145-class sweep the same
two classes named those files in 0 or 1 of 3 runs. Three runs per class is too few to settle
which files a class reliably produces, which is why the default is now five.

The plan. `antares plan` on the same commit selected 50 of 944 candidate classes. Of those, 45
are in the benchmark catalog and were already in the sweep. The other 5 (CWE-117, 384, 521, 640,
798) were run afterwards, and the 45 were reused with `--resume`.

| | All 145 | The 50 planned classes |
|---|---|---|
| Lift | 44 (30%) | 20 (40%) |
| Baseline only | 18 | 5 |
| No agreed file | 83 | 25 |
| Reference classes included | 9 | 7 |

The plan cut the sweep to a third and kept 7 of the 9 reference classes. Whether it also picks
better classes depends on the scoring rule, and these runs cannot settle it.

| Scoring rule | Classes with lift, all 145 | Classes with lift, planned 50 |
|---|---|---|
| First rule. Any file a single control run had named was dropped for every class. | 33 (23%) | 12 (24%) |
| Current rule. A file counts when the class names it at a higher rate than the controls. | 44 (30%) | 20 (40%) |

The planner favours authentication, access control and path classes for this repository. Those
are the classes that name the OAuth handler and the sandbox container app in every run. The first
rule threw both files out because a control run had named them, so the planned classes looked no
better than the rest. The current rule keeps a file for a class that names it in every run, so
the planned classes look better. With 12 control runs the current rule is lenient, and 27 of the
44 lift classes in the full sweep were still outside the plan. The comparison needs the 5-run,
30-control data before either reading is safe. The driver's worklist for the planned sweep at
this point is 20 classes and 6 hotspot files.

### The planned sweep at 5 runs and 30 control runs

The planned 50 classes were then topped up with `--resume` to the current defaults, 5 runs per
class and six control queries at 5 runs each. Agreement is 3 of 5.

| Measure | Result |
|---|---|
| Class runs | 250, of which 248 ended with a submission |
| Commands per run | 13.7 of the 15 allowed |
| Submitted paths | 770, of which 141 (18%) do not exist |
| Control runs | 30, all ended with a submission. None answered "no vulnerability found" |
| Files named by a control run | 41. The most named was the server entry file, in 4 of 30 runs |
| Files a control query agreed on | None |
| Classes with an agreed source file | 22 of 50 |
| Classes whose agreed file cleared the comparison | 22 of 22 |
| Hotspot files | 0 |
| Distinct lead files across the 22 classes | 9 |

Thirty control runs changed the reading of the controls. At 3 runs the control with no class
named the OAuth handler, the OAuth router and the server entry file in 2 of 3 runs each, which
looked like a default answer. At 5 runs it agreed on nothing, and across all 30 control runs the
OAuth handler and router were named twice each. The model always submits something for a
nonsense question, but it does not submit the same thing. The earlier default answer was a
small-sample effect.

With control rates that low, every file that 3 of 5 class runs agreed on cleared the comparison,
so on this target the agreement threshold did the filtering and the controls confirmed it. The
leads still cluster. Ten classes point at the OAuth handler, five at the sandbox container app,
four at the OAuth helper utilities, three at the OAuth router and three at the sandbox file
utilities. The model sends authentication and access classes to the OAuth files and path and
command classes to the sandbox files. That is a coarse topic match, and it is not the same as
telling one weakness from another inside a file.

The reference check at 5 runs. Seven of the planned classes have reference files. A reference
file was named by at least one run for 4 of the 7. Only command injection reached agreement,
naming the sandbox container app in 4 of 5 runs, and it is a lead. Insufficiently protected
credentials named the OAuth handler and router in 2 of 5 runs each, down from 2 of 3, and no
longer agrees. The 22 leads have not been checked by hand.

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

### Step 4. Check the report

The driver can quote code that does not exist. `verify_report.py` looks up every citation and
every quoted piece of code in the report in the target's source. No model is involved.

```
python3 verify_report.py
```

It reads the report and target named in `.antares-target`, prints one summary line, and writes
`report-check.md` and `report-check.json` beside the report. `--report` and `--repo` point it at
other files. The exit status is 1 when anything fails.

| Verdict for a quote | Meaning |
|---|---|
| `verified` | Every quoted line is in the cited file, at or near the cited line. |
| `wrong-line` | Every quoted line is in the cited file, somewhere else. |
| `partial` | Some quoted lines are in the cited file and some are not. |
| `elsewhere` | The quoted lines are in another file of the repository. |
| `not-found` | The quoted lines are not in the repository. |
| `no-file` | The cited file is not in the repository. |

Matching ignores indentation and line breaks, and a line the driver shortened with an ellipsis
is matched piece by piece. Citations are also listed when they name a file that does not exist
or a line past the end of the file.

The rule file has the driver run the script itself, correct or downgrade what fails, and copy
the summary line into the report. Run it again yourself when the driver has finished, since the
driver's copy of the line is one more thing it can get wrong. Read only the findings whose
quotes are `verified` or `wrong-line`.

The script answers one question, whether the report quotes code that exists where it says. It
does not judge whether a finding is right, and a wrong dismissal of real code passes it.

What the rule file enforces.

| Rule | Reason |
|---|---|
| Read `leads.json`, state how many classes were searched and how many have a lead, and check the count at the end | A driver that read the long results file in pieces stopped after 9 of 14 queries and reported it as complete. |
| Review only classes with a lead | The driver's work has to be bounded. Classes with no agreed file, or with only files the controls name as often, are reported as not investigated by class. |
| Review each hotspot once, for any weakness | The model names these files whatever the class, so the class adds nothing. In the worked example they still held every reference file that two runs agreed on. |
| Read every candidate source file in full | A driver limited to excerpts dismissed a file after quoting two safe cookies and missed a third, unsafe one 75 lines away. |
| Run its own search for every class it reviews | The listed files are a starting point, and the weakness is often in a neighbouring file. |
| Check every instance before dismissing, and list what was read and searched | Dismissals were the driver's weakest output. |
| Open nothing under `results/` except `leads.json`, and nothing under `queries/` | Those folders hold scoring answers. |
| Write each query to the report before starting the next | A stalled session keeps its finished work. |
| Quote only from an open file, then run `verify_report.py` and fix or downgrade what fails | One run produced 14 confirmed findings whose quoted code was not in the repository. |

Cline settings. Allow file reads in the workspace. Keep command execution on manual approval.
Deny anything that builds, installs, or runs code from the target.

## 10. Safety boundaries

- The model writes shell commands. The container is the boundary. It has no network, a read-only
  root, a read-only mount of the target, and no added capabilities.
- Command output is escaped before it re-enters the prompt. A target file that contains Granite
  role tokens or a closing `tool_response` tag cannot forge a turn. Cisco's Antares CLI escapes
  the same sequences.
- A command allowlist is not a boundary. The benchmark's own allowlist lets `find -exec` and `awk`
  through. The harness has no allowlist mode and no fallback that runs commands on the host. It
  stops when Docker is not answering.
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
| Control-token escaping in `antares_locate.py` | Adapted from the Antares CLI's `inference/granite.py` (Apache 2.0). No other CLI code is included. |
| Model weights | Not included. Obtained from `fdtn-ai/antares-1b` under its own license. |
| Antares CLI and its CWE database | Not included. Optional, installed separately. `make_queries.py` only reads the JSON its `plan` command prints. |
| Targets, results, transcripts, plans | Not included. They are written under `targets/`, `results/` and `queries/<name>*.json` on your machine, and the `.gitignore` keeps them, the weights and a local copy of the CLI out of a repository. |

The project is not affiliated with or endorsed by Cisco.

## 12. Sources

- Antares-350M weights and model card https://huggingface.co/fdtn-ai/antares-350m
- Antares-1B weights and model card https://huggingface.co/fdtn-ai/antares-1b
- Antares model collection https://huggingface.co/collections/fdtn-ai/antares
- llama.cpp converter https://github.com/ggml-org/llama.cpp
- Official benchmark harness https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark
- Official quickstart https://github.com/cisco-foundation-ai/cookbook/blob/main/1_quickstarts/Quickstart_Antares.md
- Independent Mac reproduction of Antares-1B https://github.com/juliogomez/antares
- Official Antares CLI (`antares-cli`, Cisco Foundation AI, Apache-2.0), optional, used here for `antares plan`. In the `assets` folder of https://huggingface.co/fdtn-ai/antares-1b
- Project CodeGuard donation announcement https://www.oasis-open.org/2026/02/09/cisco-donates-project-codeguard-to-coalition-for-secure-ai
