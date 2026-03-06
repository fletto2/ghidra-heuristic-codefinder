/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * P-code level pattern matching for cross-architecture heuristics (Tier 2).
 * Matches prologue/epilogue sequences, tail calls, interrupt handlers, and
 * common idioms expressed as P-code operation patterns rather than raw bytes.
 */
public class PcodePatternMatcher {

	private final Program program;
	private final Register stackPointer;

	public PcodePatternMatcher(Program program) {
		this.program = program;
		this.stackPointer = program.getCompilerSpec().getStackPointer();
	}

	/**
	 * H24: Detect function prologue — stack frame setup.
	 * Pattern: SP = INT_SUB SP, const; STORE [SP+off], reg (repeated)
	 */
	public boolean isPrologue(Instruction[] instrs, int startIdx) {
		if (stackPointer == null || startIdx >= instrs.length) return false;

		Varnode spVarnode = getVarnode(stackPointer);
		boolean foundSpSub = false;
		int storeCount = 0;

		for (int i = startIdx; i < Math.min(startIdx + 8, instrs.length); i++) {
			PcodeOp[] pcode = instrs[i].getPcode();
			for (PcodeOp op : pcode) {
				if (isSpSub(op, spVarnode)) {
					foundSpSub = true;
				}
				if (foundSpSub && op.getOpcode() == PcodeOp.STORE) {
					Varnode addr = op.getInput(1);
					if (isStackRelative(addr, pcode, spVarnode)) {
						storeCount++;
					}
				}
			}
		}
		return foundSpSub && storeCount >= 1;
	}

	/**
	 * H25: Detect function epilogue — stack frame teardown.
	 * Pattern: LOAD from stack (repeated); SP = INT_ADD SP, const; RETURN
	 */
	public boolean isEpilogue(Instruction[] instrs, int endIdx) {
		if (stackPointer == null || endIdx < 0) return false;

		Varnode spVarnode = getVarnode(stackPointer);
		boolean foundReturn = false;
		boolean foundSpAdd = false;
		int loadCount = 0;

		int start = Math.max(0, endIdx - 7);
		for (int i = start; i <= endIdx; i++) {
			PcodeOp[] pcode = instrs[i].getPcode();
			for (PcodeOp op : pcode) {
				if (op.getOpcode() == PcodeOp.RETURN) {
					foundReturn = true;
				}
				if (isSpAdd(op, spVarnode)) {
					foundSpAdd = true;
				}
				if (op.getOpcode() == PcodeOp.LOAD) {
					Varnode addr = op.getInput(1);
					if (isStackRelative(addr, pcode, spVarnode)) {
						loadCount++;
					}
				}
			}
		}
		return foundReturn && (foundSpAdd || loadCount >= 1);
	}

	/**
	 * H26: Detect tail call — unconditional branch to known function entry.
	 * BRANCH to known function, no CBRANCH after it in same block.
	 */
	public boolean isTailCall(PcodeOp[] pcode, Set<Address> functionEntries) {
		for (int i = 0; i < pcode.length; i++) {
			PcodeOp op = pcode[i];
			if (op.getOpcode() == PcodeOp.BRANCH) {
				Varnode target = op.getInput(0);
				if (target.isAddress() && functionEntries.contains(target.getAddress())) {
					// Check no CBRANCH after this
					boolean hasCbranchAfter = false;
					for (int j = i + 1; j < pcode.length; j++) {
						if (pcode[j].getOpcode() == PcodeOp.CBRANCH) {
							hasCbranchAfter = true;
							break;
						}
					}
					if (!hasCbranchAfter) return true;
				}
			}
		}
		return false;
	}

	/**
	 * H29: Detect interrupt handler prologue — register saves without
	 * preceding CALL (hardware-dispatched entry point).
	 */
	public boolean isInterruptPrologue(Instruction[] instrs, int startIdx) {
		if (stackPointer == null || startIdx >= instrs.length) return false;

		Varnode spVarnode = getVarnode(stackPointer);
		int storeCount = 0;
		boolean hasArithmetic = false;

		for (int i = startIdx; i < Math.min(startIdx + 6, instrs.length); i++) {
			PcodeOp[] pcode = instrs[i].getPcode();
			for (PcodeOp op : pcode) {
				if (op.getOpcode() == PcodeOp.STORE) {
					Varnode addr = op.getInput(1);
					if (isStackRelative(addr, pcode, spVarnode)) {
						storeCount++;
					}
				}
				int opc = op.getOpcode();
				if (opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_SUB ||
					opc == PcodeOp.INT_AND || opc == PcodeOp.INT_OR) {
					hasArithmetic = true;
				}
			}
		}
		// Interrupt handlers typically save 3+ registers before doing any work
		return storeCount >= 3 && !hasArithmetic;
	}

	/**
	 * H18: Detect redundant/idempotent P-code operations.
	 * Returns fraction of ops that are COPY rX,rX or equivalent.
	 */
	public double redundantOpFraction(PcodeOp[] pcode) {
		if (pcode.length == 0) return 0.0;
		int redundant = 0;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.COPY) {
				Varnode out = op.getOutput();
				Varnode in = op.getInput(0);
				if (out != null && in != null &&
					out.getOffset() == in.getOffset() &&
					out.getSize() == in.getSize() &&
					out.getSpace() == in.getSpace()) {
					redundant++;
				}
			}
		}
		return (double) redundant / pcode.length;
	}

	/**
	 * H16: Compute P-code operation class entropy.
	 * Maps ops to 10 functional classes, computes Shannon entropy.
	 */
	public double pcodeClassEntropy(PcodeOp[] pcode) {
		if (pcode.length == 0) return 0.0;
		int[] classCounts = new int[10];
		for (PcodeOp op : pcode) {
			classCounts[opcodeToClass(op.getOpcode())]++;
		}
		return shannonEntropy(classCounts, pcode.length);
	}

	/**
	 * H31: Collect callee-save register set from prologue/epilogue pairs.
	 */
	public Set<Varnode> getCalleeSaveRegs(Instruction[] instrs) {
		Set<Varnode> saved = new HashSet<>();
		if (stackPointer == null) return saved;

		Varnode spVarnode = getVarnode(stackPointer);
		for (Instruction instr : instrs) {
			PcodeOp[] pcode = instr.getPcode();
			for (PcodeOp op : pcode) {
				if (op.getOpcode() == PcodeOp.STORE && isStackRelative(op.getInput(1), pcode, spVarnode)) {
					Varnode val = op.getInput(2);
					if (val != null && val.isRegister()) {
						saved.add(val);
					}
				}
			}
		}
		return saved;
	}

	// --- Helpers ---

	private Varnode getVarnode(Register reg) {
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize());
	}

	private boolean isSpSub(PcodeOp op, Varnode sp) {
		if (op.getOpcode() != PcodeOp.INT_SUB) return false;
		Varnode out = op.getOutput();
		Varnode in0 = op.getInput(0);
		return out != null && matchesReg(out, sp) && matchesReg(in0, sp);
	}

	private boolean isSpAdd(PcodeOp op, Varnode sp) {
		if (op.getOpcode() != PcodeOp.INT_ADD) return false;
		Varnode out = op.getOutput();
		Varnode in0 = op.getInput(0);
		return out != null && matchesReg(out, sp) && matchesReg(in0, sp);
	}

	private boolean matchesReg(Varnode v, Varnode reg) {
		return v.getSpace() == reg.getSpace() && v.getOffset() == reg.getOffset();
	}

	private boolean isStackRelative(Varnode addr, PcodeOp[] context, Varnode sp) {
		// Check if address is SP-relative (directly or via INT_ADD/INT_SUB temp)
		if (matchesReg(addr, sp)) return true;
		// Check if addr is a unique that was computed from SP
		if (addr.isUnique()) {
			for (PcodeOp op : context) {
				Varnode out = op.getOutput();
				if (out != null && out.getOffset() == addr.getOffset() && out.isUnique()) {
					if (op.getOpcode() == PcodeOp.INT_ADD || op.getOpcode() == PcodeOp.INT_SUB) {
						Varnode in0 = op.getInput(0);
						if (matchesReg(in0, sp)) return true;
					}
				}
			}
		}
		return false;
	}

	private int opcodeToClass(int opcode) {
		switch (opcode) {
			case PcodeOp.LOAD: return 0;
			case PcodeOp.STORE: return 1;
			case PcodeOp.COPY: return 2;
			case PcodeOp.INT_ADD: case PcodeOp.INT_SUB:
			case PcodeOp.INT_MULT: case PcodeOp.INT_DIV: case PcodeOp.INT_SDIV:
			case PcodeOp.INT_REM: case PcodeOp.INT_SREM:
				return 3; // Arithmetic
			case PcodeOp.INT_AND: case PcodeOp.INT_OR: case PcodeOp.INT_XOR:
			case PcodeOp.INT_NEGATE: case PcodeOp.INT_2COMP:
				return 4; // Logic
			case PcodeOp.INT_EQUAL: case PcodeOp.INT_NOTEQUAL:
			case PcodeOp.INT_LESS: case PcodeOp.INT_SLESS:
			case PcodeOp.INT_LESSEQUAL: case PcodeOp.INT_SLESSEQUAL:
				return 5; // Compare
			case PcodeOp.INT_LEFT: case PcodeOp.INT_RIGHT: case PcodeOp.INT_SRIGHT:
				return 6; // Shift
			case PcodeOp.BRANCH: case PcodeOp.CBRANCH: case PcodeOp.BRANCHIND:
				return 7; // Branch
			case PcodeOp.CALL: case PcodeOp.CALLIND: case PcodeOp.RETURN:
				return 8; // Call/Return
			default:
				return 9; // Other (conversions, booleans, float, etc.)
		}
	}

	static double shannonEntropy(int[] counts, int total) {
		if (total == 0) return 0.0;
		double entropy = 0.0;
		for (int c : counts) {
			if (c > 0) {
				double p = (double) c / total;
				entropy -= p * Math.log(p) / Math.log(2.0);
			}
		}
		return entropy;
	}
}
