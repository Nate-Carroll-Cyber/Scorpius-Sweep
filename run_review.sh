#!/usr/bin/env bash
# Run every query against a target, five runs each, then the control queries.
#
#   ./run_review.sh <git-url> [commit-or-ref] [options]     clone into targets/<name> and review it
#   ./run_review.sh <path-to-local-checkout> [options]      review an existing directory
#   ./run_review.sh [options]                               review the target recorded by the last run or by setup.sh
#
# Options pass through to antares_locate.py and override the recorded values, e.g.
#   --device cpu   --runs 5   --only cwe-89   --resume   --model antares-1b   --out results/<name>-test
#
# --all sweeps every class in queries/all.json whatever query file is recorded. No plan and no CLI are needed.
#
# The control queries in queries/controls.json run after the sweep. leads.json keeps a file for a class only
# when the class named it at a higher rate than the control runs did. Finished control runs in <out>/controls are reused. --controls FILE uses another
# control set, --rerun-controls runs them again, --no-controls skips them.
set -euo pipefail
cd "$(dirname "$0")"

# A first argument that is not an option names the target. A second one is the commit or ref.
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
  TARGET_ARG="$1"; shift
  REF_ARG=""
  if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then REF_ARG="$1"; shift; fi
  ANTARES_TARGET_ONLY=1 ./setup.sh "$TARGET_ARG" $REF_ARG
fi

[ -f .antares-target ] || { echo "no target given. Usage: ./run_review.sh <git-url-or-path> [commit-or-ref] [options]"; exit 2; }
# shellcheck disable=SC1091
. ./.antares-target
MODEL="${ANTARES_MODEL:-${MODEL:-antares-1b}}"
# --model, --out and --queries on the command line win over the recorded values. Pick them up so the banner is accurate.
ARGS=()
CONTROLS="queries/controls.json"
while [ $# -gt 0 ]; do
  case "$1" in
    --controls) CONTROLS="$2"; shift 2;;
    --controls=*) CONTROLS="${1#--controls=}"; shift;;
    --no-controls) CONTROLS=""; shift;;
    --all) QUERIES="queries/all.json"; shift;;
    --model) MODEL="$2"; shift 2;;
    --model=*) MODEL="${1#--model=}"; shift;;
    --out) OUT_DIR="$2"; shift 2;;
    --out=*) OUT_DIR="${1#--out=}"; shift;;
    --queries) QUERIES="$2"; shift 2;;
    --queries=*) QUERIES="${1#--queries=}"; shift;;
    *) ARGS+=("$1"); shift;;
  esac
done
if [ -n "$CONTROLS" ]; then ARGS+=(--controls "$CONTROLS"); fi
echo "target $TARGET_NAME ($TARGET_DIR), queries $QUERIES, controls ${CONTROLS:-none}, model $MODEL, output $OUT_DIR"
python3 antares_locate.py --repo "$TARGET_DIR" --queries "$QUERIES" --model "$MODEL" --runs 5 --out "$OUT_DIR" ${ARGS[@]+"${ARGS[@]}"}
