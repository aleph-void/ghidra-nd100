// Differential p-code check for the ND-100 module: runs programs in Ghidra's emulator and compares the registers after
// every instruction with the states recorded from nd100x (black box, GPL emulator) by test/nd_diff.py.
// Case file: case <name> / code <hex words, loaded at word address 0x100> / init <A D T X B L STS hex> / steps <n> /
//   state <A D T X B L P STS hex> (n lines: the registers after step 1..n) / end
// Script args: <cases file> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class NdEmuTest extends GhidraScript {
	private static final String[] REGS = { "A", "D", "T", "X", "B", "L", "P", "STS" };

	private static class Case {
		String name;
		byte[] code;
		long[] init = new long[8];
		int steps;
		List<long[]> states = new ArrayList<>();
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				String[] f = line.trim().split("\\s+");
				if (f[0].isEmpty() || f[0].startsWith("#")) {
					continue;
				}
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						break;
					case "code":
						c.code = new byte[2 * (f.length - 1)];
						for (int i = 1; i < f.length; i++) {
							int w = Integer.parseInt(f[i], 16);
							c.code[2 * (i - 1)] = (byte) (w >> 8);
							c.code[2 * (i - 1) + 1] = (byte) w;
						}
						break;
					case "init":
						for (int i = 1; i < f.length; i++) {
							c.init[i - 1] = Long.parseLong(f[i], 16);
						}
						break;
					case "steps":
						c.steps = Integer.parseInt(f[1]);
						break;
					case "state": {
						long[] s = new long[8];
						for (int i = 1; i < f.length; i++) {
							s[i - 1] = Long.parseLong(f[i], 16);
						}
						c.states.add(s);
						break;
					}
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException(line);
				}
			}
		}
		return cases;
	}

	private String run(Case c) throws Exception {
		ghidra.program.model.address.AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address start = sp.getAddress(0x100L * sp.getAddressableUnitSize());   // addresses are words: byte offset = 2 * word
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			// code and data are written through the emulator: its addresses are words, two bytes (big endian) per address
			emu.writeMemory(start, new byte[0x400]);
			emu.writeMemory(start, c.code);
			for (int i = 0; i < 8; i++) {
				if (!REGS[i].equals("P")) {
					emu.writeRegister(REGS[i], c.init[i]);
				}
			}
			emu.writeRegister(emu.getPCRegister(), 0x100);
			for (int k = 0; k < c.steps; k++) {
				byte[] iw = emu.readMemory(emu.getExecutionAddress(), 2);
				String word = String.format("%06o", ((iw[0] & 0xff) << 8) | (iw[1] & 0xff));
				if (!emu.step(monitor)) {
					return "step " + (k + 1) + " (instruction " + word + "): emulation error " + emu.getLastError();
				}
				long[] want = c.states.get(k);
				StringBuilder bad = new StringBuilder();
				for (int i = 0; i < 8; i++) {
					long got = emu.readRegister(REGS[i]).longValue() & 0xFFFF;
					if (got != want[i]) {
						bad.append(String.format(" %s=%04x(expected %04x)", REGS[i], got, want[i]));
					}
				}
				if (bad.length() > 0) {
					return "step " + (k + 1) + " (instruction " + word + ")" + bad;
				}
			}
			return null;
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		PrintStream out = new PrintStream(a[1]);
		int pass = 0, fail = 0, skip = 0;
		for (Case c : load(a[0])) {
			String err = run(c);
			if (err != null && err.contains("Unimplemented CALLOTHER")) {
				skip++;
				out.println("SKIP " + c.name + ": " + err);
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, %d skipped (hardware pcodeop)%n", currentProgram.getLanguageID(), pass, fail, skip);
		out.close();
	}
}
