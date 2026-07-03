#!/usr/bin/env bash
# Regenerate figures from results/ and compile the paper to paper.pdf.
set -euo pipefail

PAPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PAPER_DIR/../.." && pwd)"

# Prefer the project venv Python if present, else fall back to python3.
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
else
    PYTHON="python3"
fi

echo "==> Regenerating figures from results/"
"$PYTHON" "$PAPER_DIR/generate_figures.py"

echo "==> Compiling paper.tex with tectonic"
if ! command -v tectonic >/dev/null 2>&1; then
    echo "ERROR: tectonic not found. Install it (e.g. 'brew install tectonic')." >&2
    exit 1
fi
tectonic "$PAPER_DIR/paper.tex"

echo "==> Done: $PAPER_DIR/paper.pdf"
