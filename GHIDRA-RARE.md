# Ghidra-Rare notes: ND-100

Verification of RetroCoreLabs/ghidra-nd100 (Norsk Data ND-100 / ND-110, language `ND-100:BE:16:default`, unchanged) to the
Ghidra-Rare bar ([docs/VERIFICATION.md](https://github.com/aleph-void/Ghidra-Rare/blob/main/docs/VERIFICATION.md)). Credits and
changes: `CREDITS.md`. Built and tested with Ghidra 12.1.3, 12.1.4 and 12.2 (`tools/build-module.sh --standard`).
The extension name is ND100.

**The language files are generated** (C# generator + `nd100-definitions`). The fixes were made directly in the generated
files; regenerating them from upstream's generator would undo them. They should be ported to the generator/YAML.

## Specs that compile

`ND-100/data/languages/nd100.slaspec` (the module) compiles. In the repository, the other two `.slaspec` files are generator
inputs/outputs, not module specs: `src/.../Ghidra/ND-100/data/languages/nd100.slaspec` compiles (a stale copy of an older generator
output, 7 KB .sla, without the shift tables and the extended instructions) and `src/.../Templates/nd100-base.slaspec` does not
(it is a template: its last line is `# PLACEHOLDER_INSTRUCTIONS`, the generator substitutes the instruction constructors;
without them SLEIGH has nothing to compile: "No output produced"). That template was not changed.

## Running the tests

```
GHIDRA_INSTALL_DIR=<ghidra with this directory linked as Ghidra/Processors/ND-100> [ND100X=<nd100x binary>] test/run-tests.sh [outdir]
```
`ND100X` enables the decode differential (nd100x built with `make release`; runs 65536 times, about 12 minutes). Regenerate the
recorded cases with `test/nd_diff.py gen` (needs `ND100X`).

## Results

| Area | Result |
|---|---|
| Decode | nd100x (`--cputype=ND110CX`, execution trace as disassembler) is the reference; all 65536 words: **63466 agree on the mnemonic** (96.8%). The rest: 486+256 words that nd100x decodes as UNDEF/ROP-NOOP (undefined combinations) and 64x10 USERn ranges (user microcode), where Ghidra decodes nothing; `RADD AD1 CM1` is called RSUB by nd100x (alias spelling, 64 words); 60 words decoded as IDENT beyond its 4 valid levels; and **gaps**: SRB/LRB (128), LBYT/SBYT/GECO/MIX3/MOVEW (about 300 words with operand variants), WGLOB and the TRA/TRR/MCL/MST register selectors above those the module names (48 each). `reached/total` constructors 265/272: the 7 unreached are `jmp_addr` modes that JMP/JPL never use (dead constructors). |
| Semantics | 400 programs (`test/emu/cases.txt`: 150 register operations, 150 memory references (STZ STA STT STX STD LDD LDA LDT LDX MIN ADD SUB AND ORA MPY with B/X-relative and indirect modes), 100 immediate adds AAA/AAB/AAT/AAX and the S-forms), 24 instructions each, registers A D T X B L P STS compared with nd100x after **every** instruction: 400/400 identical (9600 instruction steps). A copy with one wrong expectation reports exactly that case. Before the fixes none of 300 mixed programs passed. |
| Real code | None: no freely licensed ND-100 binary exists in the upstream (the MAC.BPUN was removed; nd100x's ND images/diagnostics are Norsk Data software and were not used). The BPUN/PROG/BRF loaders and the Java analyzers were not exercised. |
| Spec files | cspec/pspec/opinion as upstream (not changed or checked). |

### Fixed (all found by the differential)

- Every flag access was wrong: `STS[6,6]` is six bits starting at bit 6 in SLEIGH (a write of the carry flag cleared bits 6-11).
- Dynamic/static overflow bits (4/5) were swapped.
- Register 0 of register operations is zero (it was mapped to STS); P reads as the next instruction's address and a result written to P
  jumps; RAND/REXO/RORA were undefined with CLD/CM1 (576 words); SWAP semantics; RADD with the undefined AD field.
- SKP, RMPY, RDIV with register 0; the link register of JPL-type jumps held a byte address.

### Doesn't work (remaining)

- **Shift instructions** (SHT/SHA/SHD/SAD): the M flag (last bit shifted out) and the ROT/ZIN/LIN right-shift variants differ from
  nd100x (22 of 100 programs match; informational `test/emu/cases_shift.txt`). Not fixed for lack of time and of an arbiter beyond the emulator.
- **SKP and mixed programs** (`cases_other.txt`, 89 of 160 pass, 40 skipped): jumps (JMP/JPL/JAP..) and the extended
  instructions (TRA/TRR/MCL/MST selectors, LBYT/SBYT, MOVEW, GECO, MIX3, SRB/LRB, WGLOB) are not equivalent yet.
- **RMPY/RDIV flags** (C of RMPY/RDIV, Z error flag) differ from nd100x in the cases tried.
- Floating point instructions (FAD/FSB/FMU/FDV, denormalise) and I/O, MMU, privileged instructions are pcodeops; they cannot be emulated.
- **REXO with CM1 and without CLD**: nd100x computes `dr OR ~sr` while the project's YAML (and the vendor naming) says XOR with the
  complement; the module follows the YAML, and the cases exclude this combination. Not settled without the ND-100 reference manual.
- Writes of register operations into P are checked only by hand (nd100x shows jumps to address 0 as P=ffff); no random programs.

### Unverified

- The loaders (BPUN, PROG, BRF), the analyzers, the pspec/cspec, the I/O device map, MMU behaviour, the manual PDF index, and the ND-110/120 extension instructions' semantics (decode only).
