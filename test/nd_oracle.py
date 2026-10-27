#!/usr/bin/env python3
# nd_oracle.py <out words.txt> : run every 16-bit word as the first instruction under nd100x (GPL emulator, black box;
# ND110CX model) and record its disassembly (the trace line). Needs ND100X=<nd100x binary>; takes about 12 minutes.
import struct, subprocess, sys, os
from multiprocessing import Pool
BIN=os.environ['ND100X']
TMP=os.environ.get('TMPDIR','/tmp')
def bpun(words, start=0):
    data=b''.join(struct.pack('>H',w) for w in words)
    return b'%o\r\n0!'%start + struct.pack('>HH',start,len(words))+data+struct.pack('>H',sum(words)&0xFFFF)+struct.pack('>H',0)
def work(rng):
    lo,hi=rng
    path=os.path.join(TMP,'nd_oracle_%d_%d.bpun'%(os.getpid(),lo))
    out=[]
    for w in range(lo,hi):
        open(path,'wb').write(bpun([w,0,0]))
        try:
            r=subprocess.run([BIN,'--boot=bpun','--image='+path,'--cputype=ND110CX','-t','-n','1'],capture_output=True,text=True,timeout=10)
            line=r.stderr.splitlines()[0] if r.stderr else (r.stdout.splitlines()[0] if r.stdout else '')
        except Exception as e:
            line='ERR %s'%e
        out.append('%06o %s'%(w,line[:60].rstrip()))
    return out
if __name__=='__main__':
    chunks=[(i,i+1024) for i in range(0,65536,1024)]
    with Pool(6) as p, open(sys.argv[1],'w') as f:
        for res in p.imap(work,chunks):
            f.write('\n'.join(res)+'\n'); f.flush()
