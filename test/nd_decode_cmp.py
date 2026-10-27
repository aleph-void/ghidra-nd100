#!/usr/bin/env python3
"""Compare Ghidra's decode of all 65536 words with the disassembly of nd100x (GPL emulator, black box).
  nd_decode_cmp.py <oracle words.txt> <ghidra dump (DumpSlots, slot 2)>
oracle line: "<word octal> <addr> <word octal> <mnemonic> <operands...>"  (first line of nd100x -t -n 1)
ghidra line: "<byte offset hex> <len> <text>"   (offset/2 = word)
Prints agreement on the mnemonic and buckets every difference."""
import sys, re, collections

def main(orc, gh):
    oracle = {}
    for ln in open(orc):
        f = ln.split()
        if len(f) < 4:
            oracle[int(f[0], 8)] = None
            continue
        oracle[int(f[0], 8)] = (f[3], ' '.join(f[4:]))
    ghidra = {}
    for ln in open(gh):
        off, n, text = ln.rstrip('\n').split(' ', 2)
        off = int(off, 16)
        if off % 2 or off // 2 >= 65536:
            continue
        ghidra[off // 2] = (None, None) if n == '0' else (text.split(' ')[0], text)
    same = diff = 0
    buckets = collections.defaultdict(list)
    for w in range(65536):
        o = oracle.get(w); g = ghidra.get(w)
        if o is None:
            buckets['oracle: no output'].append(w); continue
        if g[0] is None:
            buckets['ghidra undefined, oracle %s' % o[0]].append(w); continue
        if g[0].upper() == o[0].upper():
            same += 1
        else:
            buckets['%s (ghidra) vs %s (nd100x)' % (g[0], o[0])].append(w)
    print('mnemonic agreement %d / 65536' % same)
    for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print('%6d  %-45s e.g. %06o  ghidra [%s] oracle [%s]' % (len(v), k, v[0], ghidra[v[0]][1], oracle.get(v[0])))
    return 0

if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:3]))
