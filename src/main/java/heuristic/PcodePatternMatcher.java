/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

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
	 * Patterns:
	 *   - SP = INT_SUB SP, const; STORE [SP+off], reg (68000, ARM, Z80)
	 *   - SP = INT_ADD SP, negative_const; STORE [SP+off], reg (MIPS addiu sp,sp,-N)
	 *   - STORE [SP-off], reg (pre-decrement); SP = INT_SUB SP, N (ARM STMDB)
	 *   - mflr r0; stwu r1, -N(r1) (PowerPC — COPY from LR + SP alloc)
	 */
	public boolean isPrologue(Instruction[] instrs, int startIdx) {
		if (stackPointer == null || startIdx >= instrs.length) return false;

		Varnode spVarnode = getVarnode(stackPointer);
		boolean foundSpAlloc = false;
		boolean foundLrSave = false;
		int storeCount = 0;

		// Get link register (return address register) for COPY-from-LR detection
		Register lrReg = getLinkRegister();
		Varnode lrVarnode = lrReg != null ? getVarnode(lrReg) : null;

		for (int i = startIdx; i < Math.min(startIdx + 8, instrs.length); i++) {
			PcodeOp[] pcode = instrs[i].getPcode();
			for (PcodeOp op : pcode) {
				if (isSpAlloc(op, spVarnode)) {
					foundSpAlloc = true;
				}
				// Count stack-relative stores (before or after SP adjustment)
				if (op.getOpcode() == PcodeOp.STORE) {
					Varnode addr = op.getInput(1);
					if (isStackRelative(addr, pcode, spVarnode)) {
						storeCount++;
					}
				}
				// Detect COPY from link/return-address register (PPC mflr r0)
				if (op.getOpcode() == PcodeOp.COPY && lrVarnode != null) {
					Varnode in = op.getInput(0);
					if (in != null && matchesReg(in, lrVarnode)) {
						foundLrSave = true;
					}
				}
			}
		}
		// Classic: SP alloc + stack store. PPC variant: LR save + SP alloc.
		return foundSpAlloc && (storeCount >= 1 || foundLrSave);
	}

	/**
	 * H25: Detect function epilogue — stack frame teardown.
	 * Patterns:
	 *   - LOAD from stack (repeated); SP = INT_ADD SP, const; RETURN
	 *   - SP = INT_SUB SP, negative_const (MIPS addiu sp,sp,N); RETURN (jr ra)
	 *   - LOAD [SP+off] into multiple regs; SP adjust; RETURN (ARM LDMIA)
	 */
	public boolean isEpilogue(Instruction[] instrs, int endIdx) {
		if (stackPointer == null || endIdx < 0) return false;

		Varnode spVarnode = getVarnode(stackPointer);
		boolean foundReturn = false;
		boolean foundSpDealloc = false;
		int loadCount = 0;

		int start = Math.max(0, endIdx - 7);
		for (int i = start; i <= endIdx; i++) {
			PcodeOp[] pcode = instrs[i].getPcode();
			for (PcodeOp op : pcode) {
				if (op.getOpcode() == PcodeOp.RETURN) {
					foundReturn = true;
				}
				if (isSpDealloc(op, spVarnode)) {
					foundSpDealloc = true;
				}
				if (op.getOpcode() == PcodeOp.LOAD) {
					Varnode addr = op.getInput(1);
					if (isStackRelative(addr, pcode, spVarnode)) {
						loadCount++;
					}
				}
			}
		}
		return foundReturn && (foundSpDealloc || loadCount >= 1);
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

	/**
	 * Fast raw-byte pre-filter for prologue scan. Checks if bytes at addr
	 * match known prologue instruction encodings for the current architecture.
	 * Returns true if the bytes COULD be a prologue (worth full P-code check).
	 * This avoids expensive pseudo-disassembly for most non-prologue addresses.
	 */
	public boolean quickPrologueByteCheck(Address addr) {
		Memory memory = program.getMemory();
		String proc = program.getLanguage().getProcessor().toString();
		boolean bigEndian = program.getLanguage().isBigEndian();

		try {
			byte[] b = new byte[4];
			memory.getBytes(addr, b);

			if (proc.contains("MIPS")) {
				if (bigEndian) {
					// addiu sp, sp, -N: 0x27BD + negative 16-bit imm (high bit set)
					if (b[0] == 0x27 && b[1] == (byte) 0xBD && (b[2] & 0x80) != 0) return true;
					// sw ra, N(sp): 0xAFBFXXXX — saves return address (non-leaf indicator)
					// Often the first instruction when addiu is in a branch delay slot
					if (b[0] == (byte) 0xAF && b[1] == (byte) 0xBF) return true;
				} else {
					if (b[2] == (byte) 0xBD && b[3] == 0x27 && (b[1] & 0x80) != 0) return true;
					// sw ra, N(sp) LE: 0xXXXXBFAF
					if (b[2] == (byte) 0xBF && b[3] == (byte) 0xAF) return true;
				}
				return false;
			}

			if (proc.contains("PowerPC")) {
				if (bigEndian) {
					// stwu r1, -N(r1): 0x9421XXXX with negative displacement
					if (b[0] == (byte) 0x94 && b[1] == 0x21 && (b[2] & 0x80) != 0) return true;
					// mflr r0: 0x7C0802A6 — very common PPC prologue start (88% mwcc -O4)
					if (b[0] == 0x7C && b[1] == 0x08 && b[2] == 0x02 && b[3] == (byte) 0xA6) return true;
				} else {
					if (b[2] == 0x21 && b[3] == (byte) 0x94 && (b[1] & 0x80) != 0) return true;
					// mflr r0 LE: 0xA6020807C
					if (b[0] == (byte) 0xA6 && b[1] == 0x02 && b[2] == 0x08 && b[3] == 0x7C) return true;
				}
				return false;
			}

			if (proc.contains("ARM")) {
				// Check if this could be Thumb or ARM mode
				// ARM32 STMDB sp!, {regs}: 0xE92DXXXX
				if (bigEndian) {
					if (b[0] == (byte) 0xE9 && b[1] == 0x2D) return true;
				} else {
					if (b[3] == (byte) 0xE9 && b[2] == 0x2D) return true;
					// Thumb PUSH {regs, lr}: 0xB5XX (little-endian stored as XX B5)
					if (b[1] == (byte) 0xB5) return true;
					// Thumb PUSH {regs}: 0xB4XX
					if (b[1] == (byte) 0xB4) return true;
				}
				return false;
			}

			if (proc.contains("SuperH") || proc.contains("SH-2") || proc.contains("SH-4")) {
				// SH: sts.l pr, @-r15: 0x4F22 (save return address)
				// mov.l Rn, @-r15: 0x2Fn6 (save register)
				if (bigEndian) {
					if (b[0] == 0x4F && b[1] == 0x22) return true;
					if ((b[0] & 0xF0) == 0x20 && (b[0] & 0x0F) == 0x0F && (b[1] & 0x0F) == 0x06) return true;
				} else {
					if (b[1] == 0x4F && b[0] == 0x22) return true;
					if ((b[1] & 0xF0) == 0x20 && (b[1] & 0x0F) == 0x0F && (b[0] & 0x0F) == 0x06) return true;
				}
				return false;
			}

			// For 68000: LINK An, #-N: 0x4E50-0x4E57 (LINK A0-A7)
			// or MOVEM.L regs, -(SP): 0x48E7XXXX
			if (proc.contains("68")) {
				// Always big-endian
				int word = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
				if (word >= 0x4E50 && word <= 0x4E57) return true; // LINK
				if (word == 0x48E7) return true; // MOVEM.L regs, -(SP)
				return false;
			}

			// For architectures without known byte patterns, fall through to
			// full P-code check (this will be slow, so we return true sparingly)
			// Unknown arch: skip quick check, let P-code handle it
			return true;

		} catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * H24b: Check if a given address looks like a function prologue by
	 * pseudo-disassembling a few instructions at that address.
	 * Used by the prologue scan pass to discover function starts in undefined regions.
	 *
	 * Caller should use quickPrologueByteCheck() first as a fast pre-filter.
	 */
	public boolean isPrologueAt(PseudoDisassembler pseudo, Address addr) {
		if (stackPointer == null) return false;
		Memory memory = program.getMemory();
		if (!memory.contains(addr)) return false;

		// Pseudo-disassemble up to 8 instructions
		Instruction[] instrs = new Instruction[8];
		Address current = addr;
		int count = 0;

		for (int i = 0; i < 8; i++) {
			if (!memory.contains(current)) break;
			try {
				PseudoInstruction pi = pseudo.disassemble(current);
				if (pi == null) break;
				instrs[i] = pi;
				count++;
				current = current.add(pi.getLength());
			} catch (Exception e) {
				break;
			}
		}
		if (count < 2) return false;

		Instruction[] trimmed = new Instruction[count];
		System.arraycopy(instrs, 0, trimmed, 0, count);
		return isPrologue(trimmed, 0);
	}

	// --- Helpers ---

	private Varnode getVarnode(Register reg) {
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize());
	}

	/**
	 * Get the link register (return address register) for the current architecture.
	 * PPC: LR, MIPS: ra, ARM: lr, SH: PR, 68000: null (uses stack).
	 */
	private Register getLinkRegister() {
		String proc = program.getLanguage().getProcessor().toString();
		String[] candidates;
		if (proc.contains("PowerPC")) {
			candidates = new String[]{"LR", "lr"};
		} else if (proc.contains("MIPS")) {
			candidates = new String[]{"ra", "RA"};
		} else if (proc.contains("ARM")) {
			candidates = new String[]{"lr", "LR", "r14"};
		} else if (proc.contains("SuperH") || proc.contains("SH-2") || proc.contains("SH-4")) {
			candidates = new String[]{"pr", "PR"};
		} else {
			return null;
		}
		for (String name : candidates) {
			Register reg = program.getRegister(name);
			if (reg != null) return reg;
		}
		return null;
	}

	/**
	 * Detect stack allocation: SP = INT_SUB SP, const OR SP = INT_ADD SP, negative_const.
	 * The latter covers MIPS `addiu sp, sp, -N` which Ghidra lifts as INT_ADD with
	 * a sign-extended negative immediate.
	 */
	private boolean isSpAlloc(PcodeOp op, Varnode sp) {
		Varnode out = op.getOutput();
		if (out == null || !matchesReg(out, sp)) return false;
		Varnode in0 = op.getInput(0);
		if (!matchesReg(in0, sp)) return false;

		if (op.getOpcode() == PcodeOp.INT_SUB) {
			// SP = INT_SUB SP, positive_const — classic stack alloc
			Varnode in1 = op.getInput(1);
			if (in1 != null && in1.isConstant() && in1.getOffset() > 0) return true;
		}
		if (op.getOpcode() == PcodeOp.INT_ADD) {
			// SP = INT_ADD SP, negative_const — MIPS addiu sp,sp,-N
			Varnode in1 = op.getInput(1);
			if (in1 != null && in1.isConstant()) {
				long val = in1.getOffset();
				int spSize = sp.getSize();
				// Check if high bit is set (negative in sign-extended representation)
				long signBit = 1L << (spSize * 8 - 1);
				if ((val & signBit) != 0 && val != 0) return true;
			}
		}
		return false;
	}

	/**
	 * Detect stack deallocation: SP = INT_ADD SP, positive_const OR
	 * SP = INT_SUB SP, negative_const (unusual but possible).
	 */
	private boolean isSpDealloc(PcodeOp op, Varnode sp) {
		Varnode out = op.getOutput();
		if (out == null || !matchesReg(out, sp)) return false;
		Varnode in0 = op.getInput(0);
		if (!matchesReg(in0, sp)) return false;

		if (op.getOpcode() == PcodeOp.INT_ADD) {
			Varnode in1 = op.getInput(1);
			if (in1 != null && in1.isConstant()) {
				long val = in1.getOffset();
				int spSize = sp.getSize();
				long signBit = 1L << (spSize * 8 - 1);
				// Positive constant = stack dealloc
				if ((val & signBit) == 0 && val > 0) return true;
			}
		}
		if (op.getOpcode() == PcodeOp.INT_SUB) {
			// Unusual but handle it
			Varnode in1 = op.getInput(1);
			if (in1 != null && in1.isConstant()) {
				long val = in1.getOffset();
				int spSize = sp.getSize();
				long signBit = 1L << (spSize * 8 - 1);
				if ((val & signBit) != 0 && val != 0) return true;
			}
		}
		return false;
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
