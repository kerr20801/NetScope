#!/bin/bash
# NetScope Matrix & Sequential Triage Launcher for macOS & Linux
# Pure POSIX shell script, zero-dependency

PORT=8900
URL="http://localhost:${PORT}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================================="
echo " Starting NetScope - Network Matrix & Sequential Triage..."
echo " Platform: macOS / Linux"
echo " Target URL: ${URL}"
echo "=========================================================="

if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
else
    echo "Error: Python 3 is required to run NetScope on macOS/Linux."
    exit 1
fi

# Run python server in background
cd "${SCRIPT_DIR}"
${PY_BIN} server.py
