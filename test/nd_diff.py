#!/usr/bin/env python3
"""Differential p-code test: random programs run in nd100x (GPL emulator, black box) and, via NdEmuTest.java, in Ghidra's emulator.
  nd_diff.py gen <out cases.txt> <count> <seed> [<nd100x binary>] [<words oracle file>]
Each program: 24 instructions at word address 0x100 (words chosen from classes of the instruction set that touch only the
registers, the status register and data memory), initial A D T X B L STS random, B = 0x4000 and X = 0x5000 so that
B- and X-relative accesses stay out of the code; the registers after every instruction are taken from the nd100x trace."""
import sys, os, random, subprocess, struct, re

PAD = 60
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
    if kind == 'jmp':        # forward P-relative jumps and links, 1-6 words ahead
        return r([0o124000, 0o134000, 0o130000, 0o130400, 0o131000, 0o131400, 0o132000, 0o132400, 0o133000, 0o133400]) | random.randrange(1, 7)
    if kind == 'mixed':
        return pool(r(['rop', 'rop', 'mem', 'mem', 'imm', 'shift', 'skp', 'mul', 'bit', 'jmp']))
    if kind == 'bit':        # bit operations 174000-177777
        while True:
            w = random.randrange(0o174000, 0o200000)
            if (w & 7) == 0 and ((w >> 3) & 15) >= 8:     # STS bits 8-15 select the program level (register set): not modelled
                continue
            return w
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
    r = subprocess.run([NDX, '--boot=bpun', '--image=' + path, '--cputype=ND110CX', '-t', '-n', str(steps)], capture_output=True, text=True, timeout=10)
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
            kinds = [only] * n if only else random.choices(['rop', 'mem', 'imm', 'shift', 'skp', 'mul', 'bit', 'jmp'], [8, 6, 3, 3, 2, 1, 3, 2], k=n)
            body = [pool(kd) for kd in kinds]
            total = 6 + n + PAD                 # prologue (6 words) + body + zero padding (STZ, harmless if reached by a jump); the literals follow
            lits = [random.randrange(65536) for _ in range(5)]
            lits[3] = 0x4000                    # B (data accesses of B-relative modes stay clear of the code)
            def ld(op, idx, lit):               # P-relative load of literal 'lit' (displacement is signed 8 bits)
                return op | (((total + lit) - idx) & 0xFF)
            # LDA lit0; LDT lit1; LDX lit2; LDA lit3; RADD CLD SA,DB (A -> B); LDA lit4
            prog = [ld(0o044000, 0, 0), ld(0o050000, 1, 1), ld(0o054000, 2, 2), ld(0o044000, 3, 3),
                    0o146100 | (5 << 3) | 3, ld(0o044000, 5, 4)] + body + [0] * PAD + lits
            steps = 6 + n
            try:
                sts = run_nd(prog, None, steps)
            except subprocess.TimeoutExpired:
                continue        # an instruction that hangs the emulator run (halt/wait): no recorded states
            if len(sts) < steps + 1:
                continue
            f.write('case r%d\ncode %s\ninit %s\nsteps %d\n' % (k, ' '.join('%04x' % w for w in prog), ' '.join('%04x' % x for x in sts[0]), steps))
            for s in sts[1:steps + 1]:
                f.write('state %s\n' % ' '.join('%04x' % x for x in s))
            f.write('end\n')
            made += 1
    print('%d programs' % made)

def gen_shift_all(out):
    """every shift word 154000-157777 once (value set by word, link flag M before the shift 0 or 1)"""
    vals = [(0x8001, 0x1234, 0x4321), (0xA5C3, 0x5A3C, 0x0F0F)]
    from multiprocessing import Pool
    jobs = [(w, vals[w & 1], (w >> 1) & 1) for w in range(0o154000, 0o160000)]
    with Pool(6) as p:
        res = p.map(_shift_prog, jobs, chunksize=20)
    with open(out, 'w') as f:
        for w, prog, steps, sts in res:
            f.write('case sh%06o\ncode %s\ninit %s\nsteps %d\n' % (w, ' '.join('%04x' % x for x in prog), ' '.join('%04x' % x for x in sts[0]), steps))
            for st in sts[1:steps + 1]:
                f.write('state %s\n' % ' '.join('%04x' % x for x in st))
            f.write('end\n')
    print('%d programs' % len(res))

def _shift_prog(job):
    w, (a, t, d), m = job
    if m:      # LDA 8000; SHA 1 sets the link flag M
        prog = [0o044000 | 7, 0o154401, 0o044000 | 6, 0o050000 | 6, 0o054000 | 6, 0o146100 | (7 << 3) | 1, w, 0x8000, a, t, d]
        steps = 7
    else:
        prog = [0o044000 | 5, 0o050000 | 5, 0o054000 | 5, 0o146100 | (7 << 3) | 1, w, a, t, d]
        steps = 5
    return (w, prog, steps, run_nd(prog, None, steps))

def _md_prog(job):
    op, a, t, d = job
    prog = [0o044000 | 5, 0o050000 | 5, 0o054000 | 5, 0o146100 | (7 << 3) | 1, op, a, t, d]
    return (op, a, t, d, prog, run_nd(prog, None, 5))

def gen_muldiv(out):
    """RMPY and RDIV over special values and random pairs (A=a, T=t, D=d before the instruction)"""
    random.seed(77)
    vals = [0, 1, 2, 3, 0x7fff, 0x8000, 0x8001, 0xffff, 0xfffe, 0x4000, 0x00ff, 0x1234, 0xa5c3]
    rmpy = 0o141200 | (6 << 3) | 5      # RMPY ST DA
    rdiv = 0o141600 | (6 << 3)          # RDIV ST
    jobs = [(rmpy, a, t, 0x1111) for a in vals for t in vals]
    jobs += [(rmpy, random.randrange(65536), random.randrange(65536), 0) for _ in range(150)]
    jobs += [(rdiv, a, t, d) for a in vals for d in (0, 1, 0x8000, 0xffff, 0x1234) for t in vals]
    jobs += [(rdiv, random.randrange(65536), random.randrange(1, 65536), random.randrange(65536)) for _ in range(300)]
    from multiprocessing import Pool
    with Pool(6) as p:
        res = p.map(_md_prog, jobs, chunksize=20)
    with open(out, 'w') as f:
        for i, (op, a, t, d, prog, sts) in enumerate(res):
            f.write('case %s%d\ncode %s\ninit %s\nsteps 5\n' % ('rmpy' if op < 0o141400 else 'rdiv', i, ' '.join('%04x' % x for x in prog), ' '.join('%04x' % x for x in sts[0])))
            for st in sts[1:6]:
                f.write('state %s\n' % ' '.join('%04x' % x for x in st))
            f.write('end\n')
    print('%d programs' % len(res))

if __name__ == '__main__':
    if sys.argv[1] == 'muldiv':
        gen_muldiv(sys.argv[2])
    elif sys.argv[1] == 'shiftall':
        gen_shift_all(sys.argv[2])
    elif sys.argv[1] == 'gen':
        gen(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5] if len(sys.argv) > 5 else None)
