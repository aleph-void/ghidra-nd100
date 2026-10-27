#!/usr/bin/env bash
# emu-diff.sh <cases.txt> <outdir> : run the cases of nd_diff.py in Ghidra's emulator
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); source "$HERE/env.sh"
CASES=$(readlink -f "$1"); OUTD=$(readlink -m "$2"); mkdir -p "$OUTD"
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/nd-emu.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT; mkdir -p "$PROJ/p"
head -c 131072 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ/p" p -import "$PROJ/zero.bin" -loader BinaryLoader -processor ND-100:BE:16:default \
	-noanalysis -scriptPath "$HERE" -postScript NdEmuTest.java "$CASES" "$OUTD/emu.txt" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { grep -E "ERROR|Exception|SCRIPT" "$PROJ/log.txt" | head -20 >&2; exit 1; }
[[ -s $OUTD/emu.txt ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head >&2; exit 1; }
tail -1 "$OUTD/emu.txt"
