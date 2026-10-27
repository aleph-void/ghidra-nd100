// Disassemble from the program start (flow following) and print each instruction with its p-code.
// Script args: [count]
//@category Testing
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
public class DumpDis extends GhidraScript {
	protected void run() throws Exception {
		Address a = currentProgram.getMinAddress();
		disassemble(a);
		int n = getScriptArgs().length > 0 ? Integer.parseInt(getScriptArgs()[0]) : 4;
		Instruction i = getInstructionAt(a);
		for (int k = 0; k < n && i != null; k++) {
			println("== " + i.getAddress() + " " + i + "   ctx=" + currentProgram.getProgramContext().getRegisterValue(currentProgram.getLanguage().getContextBaseRegister(), i.getAddress()));
			for (PcodeOp op : i.getPcode()) {
				println("   " + op);
			}
			i = i.getNext();
		}
	}
}
