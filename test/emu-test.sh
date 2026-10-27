#!/usr/bin/env bash
# emu-test.sh [--broken] [outdir] : the committed differential cases (test/emu/cases.txt: programs recorded from nd100x) in
# Ghidra's emulator. With --broken a copy with one wrong expectation must report exactly that case.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BROKEN=0; [[ ${1:-} == --broken ]] && { BROKEN=1; shift; }
OUTD=$(readlink -m "${1:-${TMPDIR:-/tmp}/nd100-emu}"); mkdir -p "$OUTD"
CASES=$HERE/emu/cases.txt
if ((BROKEN)); then
	python3 - "$CASES" "$OUTD/broken.txt" <<'P'
import sys
done = False; out = []
for ln in open(sys.argv[1]).read().split('\n'):
    if not done and ln.startswith('state '):
        f = ln.split(); f[1] = '%04x' % (int(f[1], 16) ^ 1); ln = ' '.join(f); done = True
    out.append(ln)
open(sys.argv[2], 'w').write('\n'.join(out))
P
	"$HERE/emu-diff.sh" "$OUTD/broken.txt" "$OUTD/b" >/dev/null || true
	grep -c ^FAIL "$OUTD/b/emu.txt" | grep -qx 1 && grep -q "^FAIL c1_0:" "$OUTD/b/emu.txt" && echo "broken expectation detected (c1_0)" || { echo "broken expectation NOT detected"; exit 1; }
else
	"$HERE/emu-diff.sh" "$CASES" "$OUTD"
	grep -q " 0 failed" "$OUTD/emu.txt"
fi
