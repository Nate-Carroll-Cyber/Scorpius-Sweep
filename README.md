![Scorpius Sweep](assets/scorpius-sweep-banner.jpg)

# Scorpius Sweep

A local, two-model verification harness for Cisco's Antares-1B using Ollama and Cline.

Antares-1B is a small model from Cisco Foundation AI that locates vulnerable files in a repository
by running shell commands. It is not a chat model and cannot drive Cline. Scorpius Sweep runs it
behind a loop that reproduces Cisco's benchmark protocol, executes its commands in a sandbox with
no network, and sweeps the repository for every CWE class in the benchmark. A second, general model
in Cline then reads the files it names and confirms or dismisses each lead.

`RUNBOOK.md` is the full procedure, with results from a worked example. This page is the map.

## Run it

```
./setup.sh <git-url> [commit-or-ref]            # once per machine; or a path to a local checkout
./run_review.sh --device cpu                    # sweep the recorded target
./run_review.sh <git-url-or-path> --device cpu  # sweep a different target
```

Then start Cline in this folder and send the task in section 9 of the runbook.

## Requirements

Python 3.9 or newer, Ollama, Docker, and the Antares-1B weights converted to GGUF and registered in
Ollama as `antares-1b` (runbook section 6). The weights are gated on Hugging Face and are not part
of this project.

## Layout

| Path | Purpose |
|---|---|
| `antares_locate.py` | The agent loop. Builds the prompt, talks to Ollama, runs the model's commands in a sandbox, ranks files across runs. Standard library only. |
| `setup.sh` | Checks Python, Ollama and the model, fetches the target, runs the tests, builds the sandbox image, runs one smoke query. |
| `run_review.sh` | Sweeps a target. Takes a git URL or path, or reuses the recorded one. |
| `queries/all.json` | All 145 CWE classes from Cisco's benchmark. The default query set. |
| `queries/cwe-catalog.json`, `make_queries.py` | Build your own query file from CWE IDs you choose. |
| `Dockerfile` | Sandbox image: Ubuntu 24.04 with `rg` and `tree`. |
| `.clinerules/scorpius-sweep.md` | The rule the driver model follows in Cline. |
| `tests/test_harness.py` | 148 checks: hostile commands against the sandbox, parser cases, and the loop against a mock Ollama server. |
| `RUNBOOK.md` | Setup, protocol, weight conversion, worked example, Cline steps, safety boundaries. |
| `LICENSE`, `NOTICE` | Apache 2.0, with attribution to Cisco's benchmark harness and MITRE CWE. |
| `assets/` | The project banner. |

## What to expect

Antares is a lead generator. On the worked example Antares-1B named a known-relevant file on 5 of
14 hand-picked CWE classes, and the driver model confirmed one finding without help. Treat every
result as a lead that a person must verify.

## License

Apache 2.0. See `LICENSE` and `NOTICE`. Not affiliated with or endorsed by Cisco.
