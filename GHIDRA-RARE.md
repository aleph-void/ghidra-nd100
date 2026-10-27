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
| Decode | nd100x (`--cputype=ND110CX`, execution trace as disassembler) is the reference; all 65536 words: **63530 agree on the mnemonic, 546 both undefined, 1460 explained differences, 0 unexplained** (`test/nd_decode_cmp.py` buckets every difference with a reason). Second source for the buckets: the nd100-definitions YAML (its opcode masks are exact). The buckets are nd100x behaviour that the YAML does not describe, so they are **not implemented**: nd100x decodes whole 64-word blocks for LBYT/SBYT/GECO/MIX3 (YAML: a single word), MOVEW 1431xx, the TRA/TRR/MCL/MST selectors 16-63, the second halves of SRB/LRB, WGLOB 140520-140577 (and prints WGLOB for 140511/140512 where the YAML has LBITP/SBIT), SASB for 1407x3 (YAML: SACB), the user-microcode blocks USER0-USER9 (512 words), RADD with AD=3 (a no-op in nd100x, undefined in the YAML), and hangs on 5 words (150410 150412 174360 174560 176160). `RADD AD1 CM1` is RSUB in nd100x (alias constructor added); IDENT exists only for its 4 valid levels. Constructors reached by a decode of generated words: **285/285** (the 7 dead `jmp_addr` constructors were removed). |
| Semantics | `test/emu/cases.txt`: **4912 programs** recorded from nd100x, registers A D T X B L P STS compared after **every** instruction in Ghidra's emulator, 4910 identical, 0 differ, 2 skipped (they reach the floating-point pcodeops). Sets: 400 register ops / memory references / immediate adds; all 2048 shift words (SHT SHD SHA SAD, ROT/ZIN/LIN, left and right, M flag, 32-bit forms, counts 0 and 32) in both M states; 1464 RMPY/RDIV programs (flags included); 200 skips (all 8 SKP conditions); 200 bit-operation programs (BSET BSKP BSTC BSTA BLDC BLDA BANC BAND BORC BORA with all registers, including P and register 0 = STS); 200 jump programs (JMP JPL JAP JAN JAZ JXN ... in P-relative mode); 200 mixed programs; 200 shift programs. A copy with one wrong expectation reports exactly that case. Before the fixes none of 300 mixed programs passed. |
| Real code | None: no freely licensed ND-100 binary exists in the upstream (the MAC.BPUN was removed; nd100x's ND images/diagnostics are Norsk Data software and were not used). The BPUN/PROG/BRF loaders and the Java analyzers were not exercised. |
| Spec files | cspec/pspec/opinion as upstream (not changed or checked). |

### Fixed (all found by the differential)

- Every flag access was wrong: `STS[6,6]` is six bits starting at bit 6 in SLEIGH (a write of the carry flag cleared bits 6-11); now `STS[n,1]`.
- Dynamic/static overflow bits (4/5) were swapped; static overflow is sticky.
- Register 0 of register operations is zero (STS for the bit operations); P reads as the next instruction's address and a result written to P
  jumps; RAND/REXO/RORA were undefined with CLD/CM1 (576 words); SWAP semantics; RADD with the undefined AD field; RSUB alias.
- Shifts: count 0 and 32 do nothing; right shifts are a left shift by 64-count; ROT/ZIN/LIN; M = last bit shifted out; LIN's link-in is the initial M.
- RMPY/RDIV: sign-and-magnitude arithmetic, the C / dynamic / static overflow flags when the result is negative, divide-by-zero and quotient overflow (Z, A and D as in nd100x).
- Bit operations: all 16 constructors rewritten (K flag = STS bit 2 semantics, writes to P jump), IDENT per level, JMP address modes (7 dead constructors removed),
  SKP, JPL link value (word address), JAZ no longer writes the carry flag (YAML and nd100x agree: no flags).

### Doesn't work / not modelled

- Floating point instructions (FAD/FSB/FMU/FDV), normalize/denormalize, SRB and I/O, MMU, privileged instructions are pcodeops; they cannot be emulated (programs reaching them are skipped by the harness).
- STS bits 8-15 (the program level, register banks) are not modelled: the module has one register set.
- nd100x quirk: JPL with the B+X address mode does not set L in nd100x (the YAML says L always receives P+1); the module follows the YAML and the jump pool of the tests uses P-relative modes only.
- **REXO with CM1 and without CLD**: nd100x computes `dr OR ~sr` while the project's YAML (and the vendor naming) says XOR with the complement; the module follows the YAML, and the cases exclude this combination. No third source was found.
- The cases avoid programs whose cumulative jumps land on a word of the explained decode buckets above.

### Unverified

- The loaders (BPUN, PROG, BRF), the analyzers, the pspec/cspec, the I/O device map, MMU behaviour, the manual PDF index, and the ND-110/120 extension instructions' semantics (decode only).
