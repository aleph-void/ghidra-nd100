#!/usr/bin/env python3
"""Differential p-code test: random programs run in nd100x (GPL emulator, black box) and, via NdEmuTest.java, in Ghidra's emulator.
  nd_diff.py gen <out cases.txt> <count> <seed> [<nd100x binary>] [<words oracle file>]
Each program: 24 instructions at word address 0x100 (words chosen from classes of the instruction set that touch only the
registers, the status register and data memory), initial A D T X B L STS random, B = 0x4000 and X = 0x5000 so that
B- and X-relative accesses stay out of the code; the registers after every instruction are taken from the nd100x trace."""
import sys, os, random, subprocess, struct, re

NDX = os.environ.get('ND100X', os.path.expanduser('~/.cache/ghidra-rare-scratch/community-verify/ND100/nd100x/build_release/bin/nd100x'))

def bpun(words, start):
    data = b''.join(struct.pack('>H', w) for w in words)
    return b'%o\r\n0!' % start + struct.pack('>HH', start, len(words)) + data + struct.pack('>H', sum(words) & 0xFFFF) + struct.pack('>H', 0)

# instruction word pools (octal ranges), from the layout of the instruction set
def pool(kind):
    r = random.choice
    if kind == 'rop':        # register operations 144000-147377 (not the undefined 147400+); no jumps (dr=P) and no SWAP into P
        while True:
            w = random.randrange(0o144000, 0o147400)
            if (w & 7) == 2 or (w < 0o144400 and ((w >> 3) & 7) == 2):
                continue
            if 0o145000 <= w < 0o145400 and (w & 0o300) == 0o200:   # REXO CM1 (no CLD): nd100x computes an OR, the project's YAML an XOR
                continue
            return w
    if kind == 'mem':
        op = r([0o000000, 0o004000, 0o010000, 0o014000, 0o020000, 0o024000, 0o040000, 0o044000, 0o050000, 0o054000,
                0o060000, 0o064000, 0o070000, 0o074000, 0o120000])
        mode = r([0o0400, 0o1000, 0o1400, 0o2000, 0o2400, 0o3000])   # B-relative, X-indexed, B+X ... (bits 10-8, no P-relative store)
        return op | mode | random.randrange(0, 16)
    if kind == 'imm':        # 17xxxx: AAA/AAB/AAT/AAX/SAA... add immediate to register
        return random.randrange(0o170000, 0o174000)
    if kind == 'shift':
        return random.randrange(0o154000, 0o160000)
    if kind == 'skp':
        return r([0o140000, 0o140400, 0o141000, 0o141400, 0o142000, 0o142400, 0o143000, 0o143400]) | random.randrange(0o100)
    if kind == 'mul':
        return r([0o141200, 0o141600]) | random.randrange(0o100)
    raise ValueError(kind)

def run_nd(words, init, steps):
    path = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'nddiff_%d.bpun' % os.getpid())
    # program at 0x100; also preload registers: run a small prologue? registers are set by the program itself
    open(path, 'wb').write(bpun(words, 0o400))
    r = subprocess.run([NDX, '--boot=bpun', '--image=' + path, '--cputype=ND110CX', '-t', '-n', str(steps)], capture_output=True, text=True, timeout=60)
    states = []
    for ln in r.stderr.splitlines():
        m = re.search(r' A=([0-7]+) D=([0-7]+) T=([0-7]+) X=([0-7]+) B=([0-7]+) L=([0-7]+) P=([0-7]+) STS=([0-9A-Fa-f]+)', ln)
        if m:
            g = m.groups()
            states.append([int(x, 8) for x in g[:7]] + [int(g[7], 16)])
    return states

def gen(out, count, seed, only=None):
    random.seed(seed)
    n = 24
    with open(out, 'w') as f:
        made = 0
        for k in range(count):
            kinds = [only] * n if only else random.choices(['rop', 'mem', 'imm', 'shift', 'skp', 'mul'], [8, 6, 3, 3, 1, 1], k=n)
            body = [pool(kd) for kd in kinds]
            total = 6 + n                       # prologue (6 words) + body; the literals follow
            lits = [random.randrange(65536) for _ in range(5)]
            lits[3] = 0x4000                    # B (data accesses of B-relative modes stay clear of the code)
            def ld(op, idx, lit):               # P-relative load of literal 'lit' (displacement is signed 8 bits)
                return op | (((total + lit) - idx) & 0xFF)
            # LDA lit0; LDT lit1; LDX lit2; LDA lit3; RADD CLD SA,DB (A -> B); LDA lit4
            prog = [ld(0o044000, 0, 0), ld(0o050000, 1, 1), ld(0o054000, 2, 2), ld(0o044000, 3, 3),
                    0o146100 | (5 << 3) | 3, ld(0o044000, 5, 4)] + body + lits
            steps = 6 + n
            sts = run_nd(prog, None, steps)
            if len(sts) < steps + 1:
                continue
            f.write('case r%d\ncode %s\ninit %s\nsteps %d\n' % (k, ' '.join('%04x' % w for w in prog), ' '.join('%04x' % x for x in sts[0]), steps))
            for s in sts[1:steps + 1]:
                f.write('state %s\n' % ' '.join('%04x' % x for x in s))
            f.write('end\n')
            made += 1
    print('%d programs' % made)

if __name__ == '__main__':
    if sys.argv[1] == 'gen':
        gen(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5] if len(sys.argv) > 5 else None)
