#!/usr/bin/env python3
"""Compare Ghidra's decode of all 65536 words with the disassembly of nd100x (GPL emulator, black box).
  nd_decode_cmp.py <oracle words.txt> <ghidra dump (DumpSlots, slot 2)>
oracle line: "<word octal> <addr> <word octal> <mnemonic> <operands...>"  (first line of nd100x -t -n 1)
ghidra line: "<byte offset hex> <len> <text>"   (offset/2 = word)
Prints agreement on the mnemonic and buckets every difference."""
import sys, re, collections

REASONS = [
    # (ghidra mnemonic or None for undefined, oracle mnemonic prefix, reason)
    (None, 'UNDEF', 'both undefined (nd100x prints UNDEF)'),
    (None, 'USER', 'nd100x decodes the user-microcode blocks USER0-USER9 (64 words each); not in nd100-definitions or its notes: left undefined'),
    (None, 'LBYT', 'nd100x decodes the whole 64-word block; the YAML opcode is the single word 142200 (16-bit mask)'),
    (None, 'SBYT', 'nd100x decodes the whole 64-word block; the YAML opcode is the single word 142600 (16-bit mask)'),
    (None, 'GECO', 'nd100x decodes the whole 64-word block; the YAML opcode is the single word 142700 (16-bit mask)'),
    (None, 'MIX3', 'nd100x decodes the whole 64-word block; the YAML opcode is the single word 143200 (16-bit mask)'),
    (None, 'MOVEW', 'nd100x decodes 1431xx beyond the YAML mask 1111_1111_1111_1000 (143100-143107)'),
    (None, 'WGLOB', 'nd100x decodes 140520-140577 as WGLOB; the YAML opcode is the single word 140500'),
    (None, 'TRA', 'bits 4-5 are outside the YAML 12-bit mask (selector 0-15); nd100x decodes the wider range'),
    (None, 'TRR', 'bits 4-5 are outside the YAML 12-bit mask (selector 0-15); nd100x decodes the wider range'),
    (None, 'MCL', 'bits 4-5 are outside the YAML 12-bit mask (selector 0-15); nd100x decodes the wider range'),
    (None, 'MST', 'bits 4-5 are outside the YAML 12-bit mask (selector 0-15); nd100x decodes the wider range'),
    (None, 'SRB', 'YAML mask is 10 bits (152400-152477); nd100x also decodes 152500-152577'),
    (None, 'LRB', 'YAML mask is 10 bits (152600-152677); nd100x also decodes 152700-152777'),
    (None, 'ROP', 'RADD with the undefined AD field 3 (147400-147777): not defined by the YAML; nd100x executes it as a no-op'),
    ('SACB', 'SASB', 'nd100x names 1407x3 SASB; the YAML lists SACB at 140703'),
    ('LBITP', 'WGLOB', 'nd100x prints WGLOB for 140511/140512; the YAML lists LBITP and SBIT there'),
    ('SBIT', 'WGLOB', 'nd100x prints WGLOB for 140511/140512; the YAML lists LBITP and SBIT there'),
    ('CHREENTPAGES', 'CHREENT-PAGES', 'spelling of the mnemonic'),
    (None, 'ERR', 'nd100x does not return a trace for this word (it hangs the one-instruction run)'),
]

def reason(gm, om):
    if om == 'ERR':
        return REASONS[-1][2]
    for g, o, why in REASONS:
        if (g is None and gm is None or g is not None and gm == g) and om.upper().startswith(o):
            return why
    return None

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
        ghidra[off // 2] = None if n == '0' else text
    same = 0
    buckets = collections.defaultdict(list)
    unexplained = []
    for w in range(65536):
        o = oracle.get(w)
        om = o[0] if o else 'ERR'
        if om.startswith("'"):
            om = 'ERR'
        g = ghidra.get(w)
        gm = g.split(' ')[0] if g else None
        if gm and gm.upper() == om.upper():
            same += 1
            continue
        why = reason(gm, om)
        if why:
            buckets[why].append(w)
        else:
            unexplained.append(w)
    both_undef = len(buckets.get('both undefined (nd100x prints UNDEF)', []))
    print('words 65536: mnemonic agreement %d, both undefined %d, explained differences %d, UNEXPLAINED %d' % (
        same, both_undef, sum(len(v) for v in buckets.values()) - both_undef, len(unexplained)))
    for why, v in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print('%6d  %s   (e.g. %06o)' % (len(v), why, v[0]))
    for w in unexplained[:30]:
        print('UNEXPLAINED %06o ghidra [%s] nd100x %s' % (w, ghidra.get(w), oracle.get(w)))
    return 1 if unexplained else 0

if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:3]))
