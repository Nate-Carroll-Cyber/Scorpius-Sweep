#!/usr/bin/env bash
# One-time setup for a target: check Ollama, pull the model, fetch the target, run the tests, smoke-test the model.
#
#   ./setup.sh <git-url> [commit-or-ref]     clone into targets/<name> (pinned to the commit or ref if given)
#   ./setup.sh <path-to-local-checkout>      use an existing directory as the target
#   ./setup.sh                               reuse the target recorded in .antares-target
#
# run_review.sh accepts the same target arguments, so setup only has to be run once per machine.
#
# Queries: queries/<name>.json if it exists, else queries/all.json. Override with ANTARES_QUERIES=path.
# Model: the Ollama model named by ANTARES_MODEL (default antares-1b). See RUNBOOK.md section 6.
set -euo pipefail
cd "$(dirname "$0")"
ENV_MODEL="${ANTARES_MODEL:-}"
SRC="${1:-}"
REF="${2:-}"

if [ -z "$SRC" ]; then
  [ -f .antares-target ] || { sed -n '2,8p' "$0"; exit 2; }
  # shellcheck disable=SC1091
  . ./.antares-target
else
  SRC="${SRC%/}"
  # The name becomes a folder under targets/ and results/, so keep only safe characters.
  TARGET_NAME="$(basename "${SRC%.git}" | tr -c 'A-Za-z0-9._\n-' '_')"
  case "$TARGET_NAME" in ""|.|..|-*) echo "cannot derive a safe target name from: $SRC"; exit 2;; esac
  if [ -d "$SRC" ]; then
    TARGET_DIR="$(cd "$SRC" && pwd)"
    TARGET_URL=""
  else
    TARGET_DIR="targets/$TARGET_NAME"
    TARGET_URL="$SRC"
  fi
  QUERIES="${ANTARES_QUERIES:-}"
  if [ -z "$QUERIES" ]; then
    if [ -f "queries/$TARGET_NAME.json" ]; then QUERIES="queries/$TARGET_NAME.json"; else QUERIES="queries/all.json"; fi
  fi
  OUT_DIR="results/$TARGET_NAME"
fi
[ -f "$QUERIES" ] || { echo "queries file not found: $QUERIES"; exit 2; }
# Model: ANTARES_MODEL wins, then the one recorded for this target, then the default.
MODEL="${ENV_MODEL:-${MODEL:-antares-1b}}"

echo "== target =="
if [ -n "${TARGET_URL:-}" ] && [ ! -d "$TARGET_DIR/.git" ]; then
  mkdir -p "$TARGET_DIR"
  git -C "$TARGET_DIR" init -q
  git -C "$TARGET_DIR" remote add origin "$TARGET_URL"
  git -C "$TARGET_DIR" fetch -q --depth 1 origin "${REF:-HEAD}"
  git -C "$TARGET_DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
[ -d "$TARGET_DIR" ] || { echo "target directory not found: $TARGET_DIR"; exit 1; }
COMMIT="$(git -C "$TARGET_DIR" rev-parse --short HEAD 2>/dev/null || echo "not a git checkout")"
echo "target $TARGET_NAME at $TARGET_DIR ($COMMIT)"
echo "queries $QUERIES"
{
  printf 'TARGET_NAME=%q\n' "$TARGET_NAME"
  printf 'TARGET_DIR=%q\n' "$TARGET_DIR"
  printf 'TARGET_URL=%q\n' "${TARGET_URL:-}"
  printf 'QUERIES=%q\n' "$QUERIES"
  printf 'OUT_DIR=%q\n' "$OUT_DIR"
  printf 'MODEL=%q\n' "$MODEL"
} > .antares-target

if [ "${ANTARES_TARGET_ONLY:-}" = "1" ]; then exit 0; fi

echo "== python =="
python3 -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9 or newer is required"; print(sys.version.split()[0])'

echo "== ollama =="
command -v ollama >/dev/null || { echo "ollama is not installed: https://ollama.com/download"; exit 1; }
curl -fsS http://localhost:11434/api/version || { echo; echo "Ollama is not answering on localhost:11434. Start the Ollama app or run: ollama serve"; exit 1; }
echo
if ollama show "$MODEL" >/dev/null 2>&1; then
  echo "model $MODEL is registered in Ollama"
elif ! ollama pull "$MODEL"; then
  echo "Model '$MODEL' is not in Ollama and could not be pulled."
  echo "Create it from the official weights (RUNBOOK.md section 6), or set ANTARES_MODEL to an existing Ollama model."
  exit 1
fi

echo "== harness tests =="
python3 tests/test_harness.py

echo "== sandbox =="
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  docker build -q -t antares-sandbox . >/dev/null
  echo "docker sandbox image antares-sandbox built"
else
  echo "docker is not answering; the allowlist sandbox will be used (the model's 'find -exec' commands are refused there)"
fi

FIRST="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["id"])' "$QUERIES")"
SMOKE="$OUT_DIR/smoke"

echo "== probe: which device the model answers on =="
if ! python3 antares_locate.py --repo "$TARGET_DIR" --queries "$QUERIES" --only "$FIRST" --probe --model "$MODEL" --out "$SMOKE"; then
  echo "The model did not produce a usable tool call on any device. The attempts are in $SMOKE/probe.json."
  exit 1
fi
DEVICE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["device"])' "$SMOKE/chosen.json")

echo "== smoke test: one query, one run =="
python3 antares_locate.py --repo "$TARGET_DIR" --queries "$QUERIES" --only "$FIRST" --runs 1 --device "$DEVICE" --model "$MODEL" --out "$SMOKE"
echo
echo "Start of the transcript:"
head -c 1500 "$SMOKE/transcripts/$FIRST.run1.jsonl"
echo
echo
echo "Next: ./run_review.sh   (results go to $OUT_DIR)"
