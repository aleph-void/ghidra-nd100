#!/usr/bin/env bash
# ND-100 module tests:  test/run-tests.sh [outdir]
#   1. nd100.slaspec compiles
#   2. differential p-code cases (test/emu/cases.txt: ~4900 programs recorded from nd100x: register operations, memory
#      references, immediate adds, all 2048 shift words, multiply/divide, skips, bit operations, jumps, mixed programs;
#      registers after every instruction) in Ghidra's emulator, and a copy with one wrong expectation (must be the only failure).
#      Programs that reach a hardware pcodeop (floating point, normalize, I/O) are skipped and reported.
#   3. every-entry decode test (CoverageCheck.java)
#   4. with ND100X=<nd100x binary>: decode differential, all 65536 words against nd100x (nd_oracle.py, nd_decode_cmp.py)
# Environment: GHIDRA_INSTALL_DIR (Ghidra whose Ghidra/Processors/ND-100 is, or links to, this directory), JAVA_HOME.
# TMPDIR must not contain a path component starting with a dot.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); MOD=$(cd "$HERE/.." && pwd)
source "$HERE/env.sh"
OUT=$(readlink -m "${1:-${TMPDIR:-/tmp}/nd100-tests}"); mkdir -p "$OUT"
rc=0
echo "== 1. compile"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/nd100.slaspec" >"$OUT/sleigh.log" 2>&1 || true
grep ERROR "$OUT/sleigh.log" && rc=1
ls -l "$MOD"/data/languages/nd100.sla | awk '{print "   " $5, $9}'
echo "== 2. emulator (differential against recorded nd100x runs)"
"$HERE/emu-test.sh" "$OUT" || rc=1
"$HERE/emu-test.sh" --broken "$OUT" || rc=1
tail -1 "$OUT/emu.txt" | sed 's/^/   /'
echo "== 3. every-entry decode test"
head -c 64 /dev/zero >"$OUT/zero.bin"
for seed in 1 2; do
	GHIDRA_TEST_SETTINGS="$OUT/set$seed" "$HERE/ghidra-script.sh" raw ND-100:BE:16:default "$OUT/zero.bin" CoverageCheck.java "$OUT/cov_$seed.txt" 256 "$seed" &
done
wait
tot=$(sed -n 's/^coverage: \([0-9]*\) constructors.*/\1/p' "$OUT/cov_1.txt")
(cat "$OUT"/cov_*.txt | grep '^unreached' || true) | sort | uniq -c | awk '$1==2' | sed 's/^/   /'
un=$( ( (cat "$OUT"/cov_*.txt | grep '^unreached' || true) | sort | uniq -c | awk '$1==2' || true) | wc -l)
echo "   $((tot - $( (cat "$OUT"/cov_*.txt | grep '^unreached' || true) | sort | uniq -c | awk '$1==2' | wc -l)))/$tot constructors reached "
((un == 0)) || rc=1
if [[ -n ${ND100X:-} ]]; then
	echo "== 4. decode differential against nd100x (all 65536 words)"
	python3 "$HERE/nd_oracle.py" "$OUT/words.txt"
	python3 -c "import struct;open('$OUT/words.bin','wb').write(b''.join(struct.pack('>H',w) for w in range(65536)))"
	"$HERE/ghidra-slots.sh" ND-100:BE:16:default "$OUT/words.bin" 2 "$OUT/ghidra.txt"
	python3 "$HERE/nd_decode_cmp.py" "$OUT/words.txt" "$OUT/ghidra.txt" | head -40 | sed 's/^/   /'
fi
((rc == 0)) && echo "all tests passed" || echo "FAILURES"
exit $rc
