/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Detects higher-order function types through P-code analysis and labels
 * hardware register accesses with meaningful names.
 *
 * Works on any SLEIGH-supported ISA by analyzing P-code operation patterns
 * rather than raw instruction bytes. Patterns derived from analysis of 50+
 * real-world ROMs across 68000, Z80, 6502, 65816, SH-1, ARM, and x86.
 *
 * Detected categories:
 *   - Software multiply/divide (shift-and-add/subtract loops)
 *   - Memory operations (memcpy, memset, memcmp)
 *   - String operations (strlen, strcmp, string copy)
 *   - Checksum/hash (accumulator loops)
 *   - Decompression (LZSS, RLE, bitstream unpacking)
 *   - BCD/number conversion
 *   - Jump table dispatch
 *   - Hardware I/O register access
 *   - Interrupt handler prologue/epilogue
 *   - Boot/init sequences
 */
public class FunctionPatternDetector {

	/** Classification result for a function */
	public static class FunctionType {
		public final String category;     // e.g. "multiply", "memcpy", "checksum"
		public final String label;        // suggested name, e.g. "software_multiply_32x32"
		public final double confidence;   // 0.0–1.0
		public final String description;

		public FunctionType(String category, String label, double confidence, String description) {
			this.category = category;
			this.label = label;
			this.confidence = confidence;
			this.description = description;
		}

		@Override
		public String toString() {
			return String.format("%s (%.0f%%): %s", label, confidence * 100, description);
		}
	}

	/** Hardware register reference found in code */
	public static class HwRegReference {
		public final Address instrAddr;
		public final long registerAddr;
		public final String registerName;
		public final boolean isRead;

		public HwRegReference(Address instrAddr, long registerAddr, String registerName, boolean isRead) {
			this.instrAddr = instrAddr;
			this.registerAddr = registerAddr;
			this.registerName = registerName;
			this.isRead = isRead;
		}
	}

	private final Program program;
	private final PlatformDescription platform;

	public FunctionPatternDetector(Program program, PlatformDescription platform) {
		this.program = program;
		this.platform = platform;
	}

	// ================================================================
	// Main entry point: classify a function
	// ================================================================

	/**
	 * Analyze a function's P-code and return all matching patterns,
	 * sorted by confidence (highest first).
	 */
	public List<FunctionType> classify(Function function) {
		PcodeOp[] pcode = collectFunctionPcode(function);
		// Need a minimum number of P-code ops to have enough degrees of freedom
		// for any reliable classification. Below ~20 ops there simply aren't
		// enough samples to distinguish patterns from noise.
		if (pcode == null || pcode.length < 20) return Collections.emptyList();

		OpcodeProfile profile = buildProfile(pcode);
		List<FunctionType> results = new ArrayList<>();

		// Phase 1: Rule-based detectors (high precision for specific patterns)
		tryDetect(results, detectSoftwareMultiply(pcode, profile));
		tryDetect(results, detectSoftwareDivide(pcode, profile));
		tryDetect(results, detectMemcpy(pcode, profile));
		tryDetect(results, detectMemset(pcode, profile));
		tryDetect(results, detectMemcmp(pcode, profile));
		tryDetect(results, detectStrlen(pcode, profile));
		tryDetect(results, detectChecksum(pcode, profile));
		tryDetect(results, detectDecompression(pcode, profile));
		tryDetect(results, detectBcdConversion(pcode, profile));
		tryDetect(results, detectJumpTableDispatch(pcode, profile));
		tryDetect(results, detectInterruptHandler(pcode, profile));
		tryDetect(results, detectBootInit(pcode, profile));
		tryDetect(results, detectPrintf(pcode, profile));
		tryDetect(results, detectRng(pcode, profile));
		tryDetect(results, detectSortRoutine(pcode, profile));
		tryDetect(results, detectFixedPointMath(pcode, profile));
		tryDetect(results, detectBusyWaitLoop(pcode, profile));
		tryDetect(results, detectObjectUpdateLoop(pcode, profile));
		tryDetect(results, detectPaletteFade(pcode, profile));
		tryDetect(results, detectLinkedListTraversal(pcode, profile));
		tryDetect(results, detectCrcPolynomial(pcode, profile));
		tryDetect(results, detectBitfieldExtraction(pcode, profile));
		tryDetect(results, detectTableLookup(pcode, profile));
		tryDetect(results, detectFloatingPoint(pcode, profile));
		tryDetect(results, detectCollisionDetection(pcode, profile));
		tryDetect(results, detectStateMachine(pcode, profile));
		tryDetect(results, detectVelocityPhysics(pcode, profile));
		tryDetect(results, detectSerialIO(pcode, profile));
		tryDetect(results, detectMemoryTest(pcode, profile));
		tryDetect(results, detectDmaTransfer(pcode, profile));
		tryDetect(results, detectStringCompare(pcode, profile));
		tryDetect(results, detectStringCopy(pcode, profile));
		tryDetect(results, detectNumberToString(pcode, profile));
		tryDetect(results, detectHeapAllocator(pcode, profile));
		tryDetect(results, detectCircularBuffer(pcode, profile));
		tryDetect(results, detectControllerInput(pcode, profile));
		tryDetect(results, detectSoundDriver(pcode, profile));
		tryDetect(results, detectSpriteRenderer(pcode, profile));
		tryDetect(results, detectScrollHandler(pcode, profile));
		tryDetect(results, detectScreenFade(pcode, profile));
		tryDetect(results, detectBytecodeInterpreter(pcode, profile));
		tryDetect(results, detectTileDecoder(pcode, profile));
		tryDetect(results, detectAnimationUpdate(pcode, profile));
		tryDetect(results, detectParticleSystem(pcode, profile));
		tryDetect(results, detectTaskScheduler(pcode, profile));
		tryDetect(results, detectSemaphoreOp(pcode, profile));
		tryDetect(results, detectFileOperation(pcode, profile));
		tryDetect(results, detectNetworkProtocol(pcode, profile));
		tryDetect(results, detectLineDrawing(pcode, profile));
		tryDetect(results, detectSquareRoot(pcode, profile));
		tryDetect(results, detectTrigLookup(pcode, profile));
		tryDetect(results, detectSelfTest(pcode, profile));
		tryDetect(results, detectCommandParser(pcode, profile));
		tryDetect(results, detectScoreUpdate(pcode, profile));
		tryDetect(results, detectEncryptDecrypt(pcode, profile));
		tryDetect(results, detectMemmove(pcode, profile));
		tryDetect(results, detectHexDump(pcode, profile));
		tryDetect(results, detectDotProduct(pcode, profile));
		tryDetect(results, detectBitmapAllocator(pcode, profile));
		tryDetect(results, detectWildcardMatch(pcode, profile));
		tryDetect(results, detectMessagePassing(pcode, profile));
		tryDetect(results, detectWatchdogFeed(pcode, profile));
		tryDetect(results, detectDeviceDriverDispatch(pcode, profile));
		tryDetect(results, detectParityCompute(pcode, profile));
		tryDetect(results, detectDelayLoop(pcode, profile));
		tryDetect(results, detectImageLoader(pcode, profile));
		tryDetect(results, detectContextSaveRestore(pcode, profile));
		tryDetect(results, detectBlockMapping(pcode, profile));
		tryDetect(results, detectChecksumValidation(pcode, profile));
		tryDetect(results, detectScsiCommand(pcode, profile));
		tryDetect(results, detectStackInterpreter(pcode, profile));
		tryDetect(results, detectRetryLoop(pcode, profile));
		tryDetect(results, detectTextRenderer(pcode, profile));
		tryDetect(results, detectMenuNavigation(pcode, profile));
		tryDetect(results, detectCameraTracking(pcode, profile));
		tryDetect(results, detectObjectSpawn(pcode, profile));
		tryDetect(results, detectFlashProgram(pcode, profile));
		tryDetect(results, detectInterruptControl(pcode, profile));
		tryDetect(results, detectAbsValue(pcode, profile));
		tryDetect(results, detectClampMinMax(pcode, profile));
		tryDetect(results, detectByteSwap(pcode, profile));
		tryDetect(results, detectVblankWait(pcode, profile));
		tryDetect(results, detectDmaQueueEnqueue(pcode, profile));
		tryDetect(results, detectErrorHandler(pcode, profile));
		tryDetect(results, detectAdpcmDecode(pcode, profile));
		tryDetect(results, detectDebounceInput(pcode, profile));
		tryDetect(results, detectCrcTableLookup(pcode, profile));
		tryDetect(results, detectCoordinateTransform(pcode, profile));
		tryDetect(results, detectIpChecksum(pcode, profile));
		tryDetect(results, detectHashFunction(pcode, profile));
		tryDetect(results, detectPaletteCycle(pcode, profile));
		tryDetect(results, detectSprintf(pcode, profile));
		tryDetect(results, detectRleDecompress(pcode, profile));
		tryDetect(results, detectLzDecompress(pcode, profile));
		tryDetect(results, detectTilemapLoader(pcode, profile));

		// Phase 2: Feature-vector similarity (broader coverage via P-code
		// operation distribution fingerprinting — catches patterns that
		// don't match any specific rule but resemble known function types)
		if (results.isEmpty()) {
			FunctionType vectorMatch = classifyByFeatureVector(pcode, profile);
			if (vectorMatch != null) results.add(vectorMatch);
		}

		results.sort((a, b) -> Double.compare(b.confidence, a.confidence));
		return results;
	}

	private void tryDetect(List<FunctionType> results, FunctionType result) {
		if (result != null && result.confidence >= 0.40) {
			results.add(result);
		}
	}

	// ================================================================
	// Hardware register labeling
	// ================================================================

	/**
	 * Scan all instructions in the program and label hardware register
	 * accesses as named references using the platform description.
	 * Returns the number of references created.
	 */
	public int labelHardwareRegisters(TaskMonitor monitor) throws CancelledException {
		if (platform.getHwRegisters().isEmpty()) return 0;

		int count = 0;
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		// Build a fast lookup map for hardware registers
		// Maps address -> register for quick lookup
		TreeMap<Long, PlatformDescription.HardwareRegister> regMap = new TreeMap<>();
		for (PlatformDescription.HardwareRegister reg : platform.getHwRegisters()) {
			regMap.put(reg.addr, reg);
		}

		if (regMap.isEmpty()) return 0;

		// First pass: create labels at hardware register addresses
		Set<Long> labeledAddrs = new HashSet<>();
		for (PlatformDescription.HardwareRegister reg : platform.getHwRegisters()) {
			monitor.checkCancelled();
			try {
				Address addr = defaultSpace.getAddress(reg.addr);
				if (labeledAddrs.contains(reg.addr)) continue;

				// Create or update the label
				Symbol existing = symbolTable.getPrimarySymbol(addr);
				if (existing == null || existing.getSource() == SourceType.DEFAULT) {
					symbolTable.createLabel(addr, reg.name, SourceType.ANALYSIS);
					labeledAddrs.add(reg.addr);
					count++;
				}
			} catch (Exception e) {
				// Address may not be in program's address space
			}
		}

		// Second pass: scan instructions for LOAD/STORE to hardware register addresses
		// and add cross-references + comments
		InstructionIterator iter = listing.getInstructions(true);
		int instrCount = 0;
		while (iter.hasNext()) {
			monitor.checkCancelled();
			instrCount++;
			if (instrCount % 10000 == 0) {
				monitor.setMessage("Scanning for hardware register accesses: " + instrCount + " instructions");
			}

			Instruction instr = iter.next();
			PcodeOp[] pcode;
			try {
				pcode = instr.getPcode();
			} catch (Exception e) {
				continue;
			}

			for (PcodeOp op : pcode) {
				int opcode = op.getOpcode();
				if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) continue;

				// For LOAD: input(1) is the address being read
				// For STORE: input(1) is the address being written
				Varnode addrNode = op.getInput(1);
				if (addrNode == null) continue;

				long hwAddr = -1;
				if (addrNode.isConstant()) {
					hwAddr = addrNode.getOffset();
				} else if (addrNode.isAddress()) {
					hwAddr = addrNode.getOffset();
				}

				if (hwAddr < 0) continue;

				// Look up in hardware register map
				PlatformDescription.HardwareRegister reg = findRegister(regMap, hwAddr);
				if (reg == null) continue;

				// Add a comment noting the hardware register
				String access = (opcode == PcodeOp.LOAD) ? "read" : "write";
				String comment = reg.name + " (" + access + ")";

				String existing = instr.getComment(CodeUnit.EOL_COMMENT);
				if (existing == null || !existing.contains(reg.name)) {
					if (existing != null && !existing.isEmpty()) {
						comment = existing + " | " + comment;
					}
					instr.setComment(CodeUnit.EOL_COMMENT, comment);
				}

				// Add reference from instruction to register address
				try {
					Address regAddr = defaultSpace.getAddress(reg.addr);
					RefType refType = (opcode == PcodeOp.LOAD) ? RefType.READ : RefType.WRITE;
					refMgr.addMemoryReference(instr.getAddress(), regAddr, refType,
						SourceType.ANALYSIS, 0);
				} catch (Exception e) {
					// ignore
				}
			}
		}

		return count;
	}

	/**
	 * Find hardware register covering the given address.
	 */
	private PlatformDescription.HardwareRegister findRegister(
			TreeMap<Long, PlatformDescription.HardwareRegister> regMap, long addr) {
		// Exact match first
		PlatformDescription.HardwareRegister reg = regMap.get(addr);
		if (reg != null) return reg;

		// Check if addr falls within a multi-byte register
		Map.Entry<Long, PlatformDescription.HardwareRegister> entry = regMap.floorEntry(addr);
		if (entry != null) {
			PlatformDescription.HardwareRegister candidate = entry.getValue();
			if (addr >= candidate.addr && addr < candidate.addr + candidate.width) {
				return candidate;
			}
		}
		return null;
	}

	// ================================================================
	// Bulk analysis: classify all functions in the program
	// ================================================================

	/**
	 * Classify all functions and apply labels + plate comments.
	 * Returns number of functions classified.
	 */
	public int classifyAllFunctions(TaskMonitor monitor) throws CancelledException {
		FunctionManager funcMgr = program.getFunctionManager();
		int classified = 0;
		int total = funcMgr.getFunctionCount();
		int idx = 0;

		FunctionIterator funcIter = funcMgr.getFunctions(true);
		while (funcIter.hasNext()) {
			monitor.checkCancelled();
			Function func = funcIter.next();
			idx++;
			if (idx % 100 == 0) {
				monitor.setMessage("Classifying functions: " + idx + "/" + total);
			}

			List<FunctionType> types = classify(func);
			if (types.isEmpty()) continue;

			FunctionType best = types.get(0);

			// Only label if function has a default name (FUN_xxxxx)
			String currentName = func.getName();
			if (currentName.startsWith("FUN_") || currentName.startsWith("fun_")) {
				try {
					func.setName(best.label, SourceType.ANALYSIS);
				} catch (Exception e) {
					// Name collision — append address
					try {
						String unique = best.label + "_" +
							func.getEntryPoint().toString().replace(":", "_");
						func.setName(unique, SourceType.ANALYSIS);
					} catch (Exception e2) {
						// give up on renaming
					}
				}
			}

			// Add plate comment with classification details
			StringBuilder plate = new StringBuilder();
			plate.append("Function type: ").append(best.category).append("\n");
			plate.append(best.description);
			if (types.size() > 1) {
				plate.append("\nAlso matches: ");
				for (int i = 1; i < Math.min(types.size(), 4); i++) {
					if (i > 1) plate.append(", ");
					plate.append(types.get(i).label);
					plate.append(String.format(" (%.0f%%)", types.get(i).confidence * 100));
				}
			}

			Instruction firstInstr = program.getListing().getInstructionAt(func.getEntryPoint());
			if (firstInstr != null) {
				String existingPlate = firstInstr.getComment(CodeUnit.PLATE_COMMENT);
				if (existingPlate == null || !existingPlate.contains("Function type:")) {
					firstInstr.setComment(CodeUnit.PLATE_COMMENT, plate.toString());
				}
			}

			classified++;
		}
		return classified;
	}

	// ================================================================
	// P-code collection and profiling
	// ================================================================

	/** Opcode distribution profile for a function */
	private static class OpcodeProfile {
		int totalOps;
		int loads, stores, copies;
		int adds, subs, mults, divs, rems;
		int ands, ors, xors, negates;
		int lefts, rights, srights;
		int equals, notEquals, lesses, sLesses;
		int branches, cbranches, branchInds;
		int calls, callInds, returns;
		int intZexts, intSexts;
		int boolAnds, boolOrs, boolNots; // boolean ops
		int floatAdds, floatSubs, floatMults, floatDivs; // float ops
		// Derived
		int arithmetic;  // add+sub+mult+div+rem
		int logic;       // and+or+xor+negate
		int shifts;      // left+right+sright
		int compares;    // equal+notequal+less+sless
		int flow;        // branch+cbranch+branchind+call+callind+return
		int memory;      // load+store
		int floatOps;    // all float operations

		boolean hasLoop;           // cbranch that goes backward
		int loopCount;
		int maxLoopDepth;
		int distinctConstants;
		Set<Long> constants = new HashSet<>();
		boolean hasLargeConstMult;   // INT_MULT with constant > 0xFFFF
		boolean hasMultThenShift;    // INT_MULT followed by INT_RIGHT (fixed-point)
		boolean hasShiftByConst16;   // INT_RIGHT by 16 (16.16 fixed-point)
		int constZeroCompares;       // comparisons with constant 0
		int constAsciiCompares;      // comparisons with ASCII range constants (0x20-0x7E)
		int powerOf2Masks;           // AND with power-of-2 minus 1
		int ioRegionAccesses;        // LOAD/STORE to IO regions
		int consecutiveStores;       // max run of consecutive STORE ops
		int consecutiveLoads;        // max run of consecutive LOAD ops
		int callSites;               // distinct call target addresses
		Set<Long> callTargets = new HashSet<>();
		int cbranch_eq_runs;         // EQUAL->CBRANCH pairs (dispatch indicator)
		int loadStoreAlternations;   // LOAD followed by STORE (copy pattern)
		int storeToLoadRatio100;     // (stores * 100) / max(loads, 1)
		int xorSelfOps;             // XOR where both inputs share output (clear register)
		boolean hasNestedLoop;       // loop inside loop
		int branchIndTargets;        // distinct BRANCHIND targets
		boolean hasReturnInLoop;     // RETURN inside a loop body
		int constSmallInts;          // constants 0-15 (common in nibble/BCD ops)
		int constLargeMultipliers;   // constants used in INT_MULT that look like LCG/hash
		boolean hasTrapOp;           // CALLOTHER (often used for TRAP/system calls)
		int callOtherCount;          // count of CALLOTHER ops
	}

	private PcodeOp[] collectFunctionPcode(Function function) {
		AddressSetView body = function.getBody();
		if (body.isEmpty()) return null;

		List<PcodeOp> ops = new ArrayList<>();
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(body, true);

		while (iter.hasNext()) {
			Instruction instr = iter.next();
			try {
				PcodeOp[] pcode = instr.getPcode();
				Collections.addAll(ops, pcode);
			} catch (Exception e) {
				// skip
			}
		}
		return ops.toArray(new PcodeOp[0]);
	}

	private OpcodeProfile buildProfile(PcodeOp[] pcode) {
		OpcodeProfile p = new OpcodeProfile();
		p.totalOps = pcode.length;

		// Track branch targets for loop detection
		Map<Long, Long> branchTargetOffsets = new HashMap<>();
		long pcodeIdx = 0;

		for (PcodeOp op : pcode) {
			switch (op.getOpcode()) {
				case PcodeOp.LOAD:       p.loads++; break;
				case PcodeOp.STORE:      p.stores++; break;
				case PcodeOp.COPY:       p.copies++; break;
				case PcodeOp.INT_ADD:    p.adds++; break;
				case PcodeOp.INT_SUB:    p.subs++; break;
				case PcodeOp.INT_MULT:   p.mults++; break;
				case PcodeOp.INT_DIV: case PcodeOp.INT_SDIV: p.divs++; break;
				case PcodeOp.INT_REM: case PcodeOp.INT_SREM: p.rems++; break;
				case PcodeOp.INT_AND:    p.ands++; break;
				case PcodeOp.INT_OR:     p.ors++; break;
				case PcodeOp.INT_XOR:    p.xors++; break;
				case PcodeOp.INT_NEGATE: case PcodeOp.INT_2COMP: p.negates++; break;
				case PcodeOp.INT_LEFT:   p.lefts++; break;
				case PcodeOp.INT_RIGHT:  p.rights++; break;
				case PcodeOp.INT_SRIGHT: p.srights++; break;
				case PcodeOp.INT_EQUAL:  p.equals++; break;
				case PcodeOp.INT_NOTEQUAL: p.notEquals++; break;
				case PcodeOp.INT_LESS: case PcodeOp.INT_LESSEQUAL: p.lesses++; break;
				case PcodeOp.INT_SLESS: case PcodeOp.INT_SLESSEQUAL: p.sLesses++; break;
				case PcodeOp.BRANCH:     p.branches++; break;
				case PcodeOp.CBRANCH:    p.cbranches++; break;
				case PcodeOp.BRANCHIND:  p.branchInds++; break;
				case PcodeOp.CALL:       p.calls++; break;
				case PcodeOp.CALLIND:    p.callInds++; break;
				case PcodeOp.RETURN:     p.returns++; break;
				case PcodeOp.INT_ZEXT:   p.intZexts++; break;
				case PcodeOp.INT_SEXT:   p.intSexts++; break;
			}

			// Additional opcode categories
			switch (op.getOpcode()) {
				case PcodeOp.BOOL_AND:   p.boolAnds++; break;
				case PcodeOp.BOOL_OR:    p.boolOrs++; break;
				case PcodeOp.BOOL_NEGATE: p.boolNots++; break;
				case PcodeOp.FLOAT_ADD:  p.floatAdds++; break;
				case PcodeOp.FLOAT_SUB:  p.floatSubs++; break;
				case PcodeOp.FLOAT_MULT: p.floatMults++; break;
				case PcodeOp.FLOAT_DIV:  p.floatDivs++; break;
			}

			// Track call targets
			if (op.getOpcode() == PcodeOp.CALL) {
				Varnode target = op.getInput(0);
				if (target != null && target.isAddress()) {
					p.callTargets.add(target.getOffset());
				}
			}

			// Track CALLOTHER (TRAP, syscalls)
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				p.callOtherCount++;
				p.hasTrapOp = true;
			}

			// Collect constants and analyze their usage
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode input = op.getInput(i);
				if (input != null && input.isConstant()) {
					long val = input.getOffset();
					p.constants.add(val);
					int opc = op.getOpcode();
					if (opc == PcodeOp.INT_MULT && val > 0xFFFF) {
						p.hasLargeConstMult = true;
					}
					if ((opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) && val == 0) {
						p.constZeroCompares++;
					}
					if ((opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) &&
							val >= 0x20 && val <= 0x7E) {
						p.constAsciiCompares++;
					}
					if (opc == PcodeOp.INT_AND && val > 0 && val <= 0xFFFF &&
							((val + 1) & val) == 0) {
						p.powerOf2Masks++;
					}
					if (opc == PcodeOp.INT_RIGHT && val == 16) {
						p.hasShiftByConst16 = true;
					}
					if (val >= 0 && val <= 15) {
						p.constSmallInts++;
					}
					if (opc == PcodeOp.INT_MULT && (val == 1103515245L || val == 6364136223846793005L ||
							val == 0x5DEECE66DL || val == 2654435761L || val == 0x6C078965L)) {
						p.constLargeMultipliers++;
					}
				}
			}

			// IO region access detection
			if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
				Varnode addr = op.getInput(1);
				if (addr != null && addr.isConstant()) {
					long addrVal = addr.getOffset();
					for (PlatformDescription.MemoryRegion region : platform.getMemoryMap()) {
						if ("io".equals(region.type) &&
							addrVal >= region.start && addrVal <= region.end) {
							p.ioRegionAccesses++;
							break;
						}
					}
				}
			}

			// Simple loop detection: CBRANCH with backward target
			if (op.getOpcode() == PcodeOp.CBRANCH) {
				Varnode target = op.getInput(0);
				if (target != null && target.isAddress()) {
					Address targetAddr = target.getAddress();
					Address seqAddr = op.getSeqnum().getTarget();
					if (seqAddr != null && targetAddr.compareTo(seqAddr) < 0) {
						p.hasLoop = true;
						p.loopCount++;
					}
				}
			}

			pcodeIdx++;
		}

		// Detect MULT followed by RIGHT shift (fixed-point multiply pattern)
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_MULT) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_RIGHT ||
						pcode[j].getOpcode() == PcodeOp.INT_SRIGHT) {
						p.hasMultThenShift = true;
						break;
					}
				}
			}
		}

		// Track consecutive STORE/LOAD runs
		int storeRun = 0, loadRun = 0, maxStoreRun = 0, maxLoadRun = 0;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.STORE) {
				storeRun++;
				if (storeRun > maxStoreRun) maxStoreRun = storeRun;
			} else {
				storeRun = 0;
			}
			if (op.getOpcode() == PcodeOp.LOAD) {
				loadRun++;
				if (loadRun > maxLoadRun) maxLoadRun = loadRun;
			} else {
				loadRun = 0;
			}
		}
		p.consecutiveStores = maxStoreRun;
		p.consecutiveLoads = maxLoadRun;

		// Track LOAD->STORE alternations, EQUAL->CBRANCH pairs, nested loops
		boolean inLoop = false;
		for (int i = 0; i < pcode.length - 1; i++) {
			int op1 = pcode[i].getOpcode();
			int op2 = pcode[i + 1].getOpcode();
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.STORE) p.loadStoreAlternations++;
			if (op1 == PcodeOp.INT_EQUAL && op2 == PcodeOp.CBRANCH) p.cbranch_eq_runs++;
			// Nested loop heuristic: two backward CBRANCHes
			if (op1 == PcodeOp.CBRANCH && inLoop) p.hasNestedLoop = true;
			if (op1 == PcodeOp.CBRANCH) inLoop = true;
		}
		p.callSites = p.callTargets.size();
		p.storeToLoadRatio100 = p.loads > 0 ? (p.stores * 100) / p.loads : (p.stores > 0 ? 999 : 0);

		p.arithmetic = p.adds + p.subs + p.mults + p.divs + p.rems;
		p.logic = p.ands + p.ors + p.xors + p.negates;
		p.shifts = p.lefts + p.rights + p.srights;
		p.compares = p.equals + p.notEquals + p.lesses + p.sLesses;
		p.flow = p.branches + p.cbranches + p.branchInds + p.calls + p.callInds + p.returns;
		p.memory = p.loads + p.stores;
		p.floatOps = p.floatAdds + p.floatSubs + p.floatMults + p.floatDivs;
		p.distinctConstants = p.constants.size();

		return p;
	}

	// ================================================================
	// Pattern detectors
	// ================================================================

	/**
	 * Software multiply: shift-and-add loop.
	 * P-code signature: INT_LEFT + INT_ADD in loop, with INT_AND for bit testing.
	 * Typically small function (< 200 ops), no CALLs, 1-2 loops.
	 */
	private FunctionType detectSoftwareMultiply(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 300 || p.totalOps < 15) return null;
		if (p.calls > 0) return null;

		// Minimum evidence: need at least 2 shifts and 2 adds to distinguish
		// from coincidental single occurrences
		if (p.lefts < 2 || p.adds < 2) return null;
		// Should not have significant LOAD/STORE (those would be memcpy etc.)
		if (p.memory > p.totalOps * 0.3) return null;

		// Need at least 3 branch-related ops (loop control)
		if (p.cbranches < 1) return null;

		// Characteristic: shift + add + conditional branch, with AND for bit testing
		// Require minimum absolute count of combined shift+add ops
		int shiftAddCount = p.lefts + p.adds + p.ands;
		if (shiftAddCount < 4) return null;
		double shiftAddRatio = (double) shiftAddCount / p.totalOps;
		if (shiftAddRatio < 0.15) return null;

		// Check for the classic pattern: shift-left by 1, test bit, conditionally add
		boolean hasShiftByOne = false;
		boolean hasBitTest = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_LEFT) {
				Varnode shift = op.getInput(1);
				if (shift != null && shift.isConstant() && shift.getOffset() == 1) {
					hasShiftByOne = true;
				}
			}
			if (op.getOpcode() == PcodeOp.INT_AND) {
				Varnode mask = op.getInput(1);
				if (mask != null && mask.isConstant()) {
					long val = mask.getOffset();
					// Bit test: AND with 1, or power-of-2
					if (val == 1 || (val != 0 && (val & (val - 1)) == 0)) {
						hasBitTest = true;
					}
				}
			}
		}

		double conf = 0.4;
		if (hasShiftByOne) conf += 0.15;
		if (hasBitTest) conf += 0.15;
		if (p.loopCount == 1) conf += 0.1;
		if (p.mults == 0) conf += 0.05;  // No hardware multiply — software implementation
		if (p.rights > 0) conf += 0.05;  // Right shift for signed handling

		String size = (p.totalOps > 100) ? "32x32_to_64" : "16x16";
		return new FunctionType("multiply", "software_multiply_" + size,
			Math.min(conf, 0.95),
			"Software multiply via shift-and-add loop");
	}

	/**
	 * Software divide: shift-and-subtract loop.
	 * P-code signature: INT_RIGHT/INT_LEFT + INT_SUB in loop, comparison with divisor.
	 */
	private FunctionType detectSoftwareDivide(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 300 || p.totalOps < 15) return null;
		if (p.calls > 0) return null;

		// Minimum evidence: 2+ shifts, 2+ subtracts, and comparisons
		if (p.shifts < 2 || p.subs < 2) return null;
		if (p.compares < 1) return null;
		if (p.cbranches < 1) return null;
		if (p.memory > p.totalOps * 0.3) return null;

		// Require minimum absolute count of key operations
		int keyOps = p.shifts + p.subs + p.compares;
		if (keyOps < 5) return null;
		double shiftSubRatio = (double) keyOps / p.totalOps;
		if (shiftSubRatio < 0.15) return null;

		double conf = 0.4;
		if (p.lefts > 0 && p.rights > 0) conf += 0.1;  // Both directions = restoring div
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.1; // Comparison with divisor
		if (p.loopCount == 1) conf += 0.1;
		if (p.divs == 0) conf += 0.1;  // No hardware divide
		if (p.rems > 0 || p.ors > 0) conf += 0.05;  // Building quotient/remainder

		return new FunctionType("divide", "software_divide",
			Math.min(conf, 0.95),
			"Software divide via shift-and-subtract loop");
	}

	/**
	 * Memcpy: LOAD-STORE loop with pointer increment.
	 * P-code: LOAD + STORE pair in tight loop, both addresses increment.
	 */
	private FunctionType detectMemcpy(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 200) return null;
		// Minimum: at least 2 loads and 2 stores to be a meaningful copy loop
		if (p.loads < 2 || p.stores < 2) return null;

		// Memcpy: roughly equal loads and stores, few other ops
		double memRatio = (double) p.memory / p.totalOps;
		if (memRatio < 0.15) return null;

		// Load and store should be somewhat balanced (copy, not fill)
		double loadStoreBalance = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (loadStoreBalance < 0.3) return null;

		// Should have adds (pointer increment) and compares (loop termination)
		if (p.adds < 2) return null;

		// Low arithmetic complexity (not a compute loop)
		if (p.mults > 0 || p.divs > 0) return null;
		if (p.shifts > p.memory) return null;

		double conf = 0.4;
		if (loadStoreBalance > 0.7) conf += 0.15;
		if (memRatio > 0.25) conf += 0.1;
		if (p.totalOps < 60) conf += 0.1;
		if (p.calls == 0) conf += 0.05;
		if (p.loopCount == 1) conf += 0.1;

		String variant = (p.totalOps > 80) ? "optimized" : "simple";
		return new FunctionType("memcpy", "memory_copy_" + variant,
			Math.min(conf, 0.95),
			"Memory block copy (LOAD+STORE loop)");
	}

	/**
	 * Memset: STORE loop with same value, no matching LOADs.
	 */
	private FunctionType detectMemset(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 150) return null;
		// Minimum 3 stores to establish a fill pattern
		if (p.stores < 3) return null;

		// Stores dominate over loads (filling, not copying)
		if (p.loads >= p.stores) return null;
		double storeRatio = (double) p.stores / p.totalOps;
		if (storeRatio < 0.1) return null;

		// Low complexity
		if (p.mults > 0 || p.divs > 0) return null;

		double conf = 0.4;
		if (p.loads == 0) conf += 0.15;
		if (storeRatio > 0.2) conf += 0.1;
		if (p.totalOps < 50) conf += 0.1;
		if (p.loopCount == 1) conf += 0.1;

		return new FunctionType("memset", "memory_fill",
			Math.min(conf, 0.95),
			"Memory block fill (STORE loop)");
	}

	/**
	 * Memcmp: paired LOADs with comparison in loop.
	 */
	private FunctionType detectMemcmp(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 150) return null;

		// Need paired loads (read from two sources) and comparisons
		if (p.loads < 2 || p.compares < 1) return null;
		// Stores should be rare (comparison, not copy)
		if (p.stores > 2) return null;

		// Check for LOAD, LOAD, compare pattern
		int pairCount = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD &&
				pcode[i + 1].getOpcode() == PcodeOp.LOAD) {
				// Check if followed by a compare within next few ops
				for (int j = i + 2; j < Math.min(i + 6, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL ||
						opc == PcodeOp.INT_SUB) {
						pairCount++;
						break;
					}
				}
			}
		}

		if (pairCount < 1) return null;

		double conf = 0.45;
		if (pairCount >= 2) conf += 0.15;
		if (p.loopCount == 1) conf += 0.1;
		if (p.totalOps < 60) conf += 0.1;

		return new FunctionType("memcmp", "memory_compare",
			Math.min(conf, 0.95),
			"Memory block compare (paired LOAD+compare loop)");
	}

	/**
	 * Strlen: LOAD byte + compare zero + CBRANCH loop + counter.
	 */
	private FunctionType detectStrlen(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 100 || p.totalOps < 6) return null;

		// Needs loads (reading bytes) and equality comparison (vs zero)
		if (p.loads < 1) return null;
		if (p.equals < 1 && p.notEquals < 1) return null;

		// Very small with single loop = strong signal
		// Stores should be absent or minimal (just reading)
		if (p.stores > 1) return null;
		if (p.mults > 0 || p.divs > 0) return null;

		// Check for LOAD followed by compare-with-zero
		boolean hasLoadCompareZero = false;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) {
						// Check if comparing against zero
						for (int k = 0; k < pcode[j].getNumInputs(); k++) {
							Varnode v = pcode[j].getInput(k);
							if (v != null && v.isConstant() && v.getOffset() == 0) {
								hasLoadCompareZero = true;
							}
						}
					}
				}
			}
		}

		if (!hasLoadCompareZero) return null;

		double conf = 0.5;
		if (p.totalOps < 30) conf += 0.15;
		if (p.adds > 0) conf += 0.1;  // Counter/pointer increment
		if (p.loopCount == 1) conf += 0.1;

		// Distinguish strlen from strcmp (strcmp has 2+ loads)
		if (p.loads >= 2 && p.compares >= 2) {
			return new FunctionType("strcmp", "string_compare",
				Math.min(conf, 0.95),
				"String comparison (LOAD+compare-zero loop with paired reads)");
		}

		return new FunctionType("strlen", "string_length",
			Math.min(conf, 0.95),
			"String length (LOAD+compare-zero loop)");
	}

	/**
	 * Checksum/hash: accumulator loop (LOAD + ADD/XOR into accumulator).
	 */
	private FunctionType detectChecksum(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 200) return null;
		// Minimum: need at least 3 loads (reading data to checksum)
		if (p.loads < 3) return null;
		// Must have at least 2 add/xor operations for accumulator pattern
		if ((p.adds + p.xors) < 2) return null;

		// Accumulator pattern: LOAD then ADD or XOR
		int accumPatterns = 0;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_XOR) {
						accumPatterns++;
						break;
					}
				}
			}
		}

		// Require at least 2 LOAD->ADD/XOR accumulator patterns
		if (accumPatterns < 2) return null;

		// Distinguish from memcpy (checksum has adds/xors but few stores)
		if (p.stores > p.loads) return null;

		double conf = 0.4;
		if (accumPatterns >= 3) conf += 0.15;
		if (p.xors > 0) conf += 0.1;  // XOR is very common in checksums
		if (p.stores <= 1) conf += 0.1; // Typically just one final store
		if (p.shifts > 0) conf += 0.05; // Rotate/shift in CRC-like checksums
		if (p.loopCount == 1) conf += 0.05;

		String variant = p.xors > p.adds ? "xor" : "additive";
		return new FunctionType("checksum", "checksum_" + variant,
			Math.min(conf, 0.95),
			"Checksum/hash accumulator loop (LOAD+" +
			(p.xors > p.adds ? "XOR" : "ADD") + " pattern)");
	}

	/**
	 * Decompression: high shift/mask ratio, ring buffer patterns (LOAD+STORE
	 * with AND mask for circular indexing), bit-level operations.
	 */
	private FunctionType detectDecompression(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		// Decompressors are substantial — need enough ops for reliable detection
		if (p.totalOps < 50) return null;

		// Decompression is characterized by:
		// 1. Heavy shift/mask usage (bit extraction)
		// 2. Both LOAD and STORE (read compressed, write decompressed)
		// 3. Multiple conditional branches (format parsing)
		// 4. AND with mask constants (ring buffer, bit fields)

		// Require minimum absolute counts of key operations
		if (p.shifts < 3 || p.ands < 3) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.cbranches < 3) return null;

		double shiftMaskRatio = (double)(p.shifts + p.ands) / p.totalOps;
		if (shiftMaskRatio < 0.08) return null;

		// Check for ring buffer mask patterns (AND with 0xFFF, 0x3FF, etc.)
		boolean hasRingBufferMask = false;
		boolean hasBitExtraction = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_AND) {
				Varnode mask = op.getInput(1);
				if (mask != null && mask.isConstant()) {
					long val = mask.getOffset();
					// Common ring buffer sizes: 0xFFF (4K), 0x3FF (1K), 0xFF (256)
					if (val == 0xFFF || val == 0x3FF || val == 0x1FF || val == 0xFF) {
						hasRingBufferMask = true;
					}
					// Bit masks: 1, 3, 7, 0xF, 0x1F, 0x3F, 0x7F, 0x80
					if (val <= 0xFF && val > 0 && (((val + 1) & val) == 0 || val == 0x80)) {
						hasBitExtraction = true;
					}
				}
			}
		}

		double conf = 0.4;
		if (hasRingBufferMask) conf += 0.2;
		if (hasBitExtraction) conf += 0.1;
		if (shiftMaskRatio > 0.15) conf += 0.1;
		if (p.loopCount >= 2) conf += 0.05; // Nested loops common
		if (p.totalOps > 100) conf += 0.05; // Decompressors tend to be large

		String variant = hasRingBufferMask ? "lzss" : "rle_or_bitstream";
		return new FunctionType("decompression", "decompress_" + variant,
			Math.min(conf, 0.95),
			"Decompression routine (shift/mask heavy" +
			(hasRingBufferMask ? " with ring buffer" : "") + ")");
	}

	/**
	 * BCD conversion: division/remainder by 10, or repeated subtract-10 patterns.
	 */
	private FunctionType detectBcdConversion(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 200) return null;

		// Look for constant 10 in division or remainder
		boolean hasDivBy10 = false;
		boolean hasModBy10 = false;
		boolean hasConst0x30 = false;  // ASCII '0'
		int const10Count = 0;

		for (PcodeOp op : pcode) {
			int opc = op.getOpcode();
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode v = op.getInput(i);
				if (v == null || !v.isConstant()) continue;
				long val = v.getOffset();

				if (val == 10 || val == 0x0A) {
					const10Count++;
					if (opc == PcodeOp.INT_DIV || opc == PcodeOp.INT_SDIV) hasDivBy10 = true;
					if (opc == PcodeOp.INT_REM || opc == PcodeOp.INT_SREM) hasModBy10 = true;
				}
				if (val == 0x30) hasConst0x30 = true;
			}
		}

		// Need at least 2 references to constant 10 (divide + remainder,
		// or repeated digit extraction) to distinguish from coincidence
		if (const10Count < 2) return null;

		double conf = 0.35;
		if (hasDivBy10) conf += 0.2;
		if (hasModBy10) conf += 0.2;
		if (hasConst0x30) conf += 0.15;  // ASCII digit conversion
		if (p.hasLoop) conf += 0.05;

		if (conf < 0.40) return null;

		return new FunctionType("bcd_conversion", "number_to_string",
			Math.min(conf, 0.95),
			"Numeric/BCD conversion (divide/modulo by 10" +
			(hasConst0x30 ? " with ASCII offset" : "") + ")");
	}

	/**
	 * Jump table dispatch: LOAD from indexed table + BRANCHIND or CALLIND.
	 */
	private FunctionType detectJumpTableDispatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.branchInds < 1 && p.callInds < 1) return null;
		if (p.totalOps > 100) return null;

		// Look for LOAD followed by BRANCHIND/CALLIND
		boolean hasTableDispatch = false;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 8, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.BRANCHIND || opc == PcodeOp.CALLIND) {
						hasTableDispatch = true;
						break;
					}
				}
			}
		}

		// Also check for index scaling (INT_MULT or INT_LEFT by pointer size)
		boolean hasIndexScale = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_LEFT || op.getOpcode() == PcodeOp.INT_MULT) {
				Varnode scale = op.getInput(1);
				if (scale != null && scale.isConstant()) {
					long val = scale.getOffset();
					if (val == 1 || val == 2 || val == 4) {
						hasIndexScale = true;
					}
				}
			}
		}

		double conf = 0.4;
		if (hasTableDispatch) conf += 0.2;
		if (hasIndexScale) conf += 0.15;
		if (p.compares > 0) conf += 0.1; // Bounds checking
		if (p.totalOps < 40) conf += 0.05;

		if (conf < 0.40) return null;

		return new FunctionType("dispatch", "jump_table_dispatch",
			Math.min(conf, 0.95),
			"Jump/call table dispatch (indexed LOAD + indirect branch)");
	}

	/**
	 * Interrupt handler: many register saves at entry, special return.
	 * Distinguished from normal function by: 3+ stores without preceding arithmetic,
	 * potential status register manipulation.
	 */
	private FunctionType detectInterruptHandler(PcodeOp[] pcode, OpcodeProfile p) {
		// Need enough ops to see the save/restore pattern clearly
		if (p.stores < 4) return null;

		// Check first N ops for store-heavy pattern without arithmetic
		int initialStores = 0;
		int initialOps = Math.min(p.totalOps, 20);
		boolean hasEarlyArithmetic = false;

		for (int i = 0; i < initialOps && i < pcode.length; i++) {
			int opc = pcode[i].getOpcode();
			if (opc == PcodeOp.STORE) initialStores++;
			if (opc == PcodeOp.INT_MULT || opc == PcodeOp.INT_DIV ||
				opc == PcodeOp.INT_LEFT || opc == PcodeOp.INT_RIGHT) {
				hasEarlyArithmetic = true;
			}
		}

		if (initialStores < 4 || hasEarlyArithmetic) return null;

		// Check for matching loads at end (register restore)
		int trailingLoads = 0;
		for (int i = Math.max(0, pcode.length - 20); i < pcode.length; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) trailingLoads++;
		}

		double conf = 0.4;
		if (initialStores >= 5) conf += 0.15;
		if (trailingLoads >= 3) conf += 0.15;
		if (p.returns > 0) conf += 0.1;
		if (p.calls == 0) conf += 0.05; // Many ISRs don't call other functions

		return new FunctionType("interrupt_handler", "interrupt_handler",
			Math.min(conf, 0.95),
			"Interrupt/exception handler (register save/restore pattern)");
	}

	/**
	 * Boot/init: sequential STOREs to hardware register addresses or memory,
	 * no loops, straight-line code.
	 */
	private FunctionType detectBootInit(PcodeOp[] pcode, OpcodeProfile p) {
		// Boot init needs a clear pattern of sequential stores
		if (p.stores < 8) return null;

		// Init routines are store-heavy, mostly straight-line
		double storeRatio = (double) p.stores / p.totalOps;
		if (storeRatio < 0.15) return null;

		// Check if stores target hardware register region
		int hwStores = 0;
		if (!platform.getHwRegisters().isEmpty()) {
			TreeMap<Long, PlatformDescription.HardwareRegister> regMap = new TreeMap<>();
			for (PlatformDescription.HardwareRegister reg : platform.getHwRegisters()) {
				regMap.put(reg.addr, reg);
			}
			for (PcodeOp op : pcode) {
				if (op.getOpcode() == PcodeOp.STORE) {
					Varnode addr = op.getInput(1);
					if (addr != null && addr.isConstant()) {
						if (findRegister(regMap, addr.getOffset()) != null) {
							hwStores++;
						}
					}
				}
			}
		}

		// Also detect: stores to I/O region from platform memory map
		int ioStores = 0;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.STORE) {
				Varnode addr = op.getInput(1);
				if (addr != null && addr.isConstant()) {
					for (PlatformDescription.MemoryRegion region : platform.getMemoryMap()) {
						if ("io".equals(region.type) &&
							addr.getOffset() >= region.start && addr.getOffset() <= region.end) {
							ioStores++;
							break;
						}
					}
				}
			}
		}

		double conf = 0.35;
		if (hwStores >= 3) conf += 0.25;
		if (ioStores >= 3) conf += 0.2;
		if (storeRatio > 0.3) conf += 0.1;
		if (!p.hasLoop) conf += 0.05; // Init is typically straight-line
		if (p.loads < p.stores) conf += 0.05;

		if (conf < 0.40) return null;

		return new FunctionType("boot_init", "hardware_init",
			Math.min(conf, 0.95),
			"Hardware initialization (sequential register stores" +
			(hwStores > 0 ? ", " + hwStores + " known HW regs" : "") + ")");
	}

	/**
	 * Printf-like: multiple comparisons against ASCII character constants,
	 * several branches, format string processing pattern.
	 */
	private FunctionType detectPrintf(PcodeOp[] pcode, OpcodeProfile p) {
		// Printf is always a large function with many branches
		if (p.totalOps < 80) return null;
		if (p.cbranches < 8) return null;

		// Count comparisons with ASCII format characters: '%', 'd', 'x', 's', 'c', 'f', etc.
		int formatCharCompares = 0;
		Set<Long> formatChars = new HashSet<>(Arrays.asList(
			(long)'%', (long)'d', (long)'x', (long)'X', (long)'s',
			(long)'c', (long)'f', (long)'e', (long)'g',
			(long)'l', (long)'u', (long)'o', (long)'p',
			(long)'-', (long)'+', (long)'0', (long)'.'
		));

		for (PcodeOp op : pcode) {
			int opc = op.getOpcode();
			if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode v = op.getInput(i);
					if (v != null && v.isConstant() && formatChars.contains(v.getOffset())) {
						formatCharCompares++;
					}
				}
			}
		}

		// Need at least 5 format character comparisons — fewer is too
		// easily explained by coincidental character constant usage
		if (formatCharCompares < 5) return null;

		double conf = 0.4;
		if (formatCharCompares >= 6) conf += 0.2;
		if (formatCharCompares >= 10) conf += 0.15;
		if (p.calls > 2) conf += 0.1;  // Printf calls putchar/write helpers
		if (p.totalOps > 200) conf += 0.05; // Printf is large

		return new FunctionType("printf", "printf_format_engine",
			Math.min(conf, 0.95),
			"Printf-like format string processor (" + formatCharCompares +
			" format character comparisons)");
	}

	/**
	 * Random number generator: multiply by large constant + add constant.
	 * Classic LCG: seed = seed * A + C.
	 */
	private FunctionType detectRng(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 80) return null;
		if (p.mults < 1) return null;

		// Check for multiply by a large constant (LCG multiplier)
		if (!p.hasLargeConstMult) return null;

		// Known LCG multipliers
		Set<Long> knownMultipliers = new HashSet<>(Arrays.asList(
			1103515245L,    // glibc
			6364136223846793005L, // Knuth
			1664525L,       // Numerical Recipes
			214013L,        // MSVC
			0x41C64E6DL,    // common in games
			0x3FC5CE6DL     // Adobe eexec
		));

		boolean hasKnownMultiplier = false;
		for (long c : p.constants) {
			if (knownMultipliers.contains(c)) {
				hasKnownMultiplier = true;
				break;
			}
		}

		double conf = 0.4;
		if (hasKnownMultiplier) conf += 0.35;
		else if (p.hasLargeConstMult) conf += 0.15;
		if (p.adds > 0) conf += 0.1; // LCG has additive constant
		if (p.totalOps < 30) conf += 0.1; // RNG is small
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.40) return null;

		return new FunctionType("rng", "random_number_generator",
			Math.min(conf, 0.95),
			"Linear congruential RNG (multiply by large constant + add)");
	}

	/**
	 * Sort routine: nested loops with comparison and swap (LOAD, LOAD, compare,
	 * conditional STORE, STORE).
	 */
	private FunctionType detectSortRoutine(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.loopCount < 2) return null; // Need nested loops (at minimum)
		if (p.totalOps > 300 || p.totalOps < 30) return null;
		// Need enough memory ops and comparisons for a sorting pattern
		if (p.loads < 4 || p.stores < 3) return null;
		if (p.compares < 2) return null;

		// Look for compare-and-swap pattern: LOAD, LOAD, compare, STORE, STORE
		int swapPatterns = 0;
		for (int i = 0; i < pcode.length - 4; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				// Look for second LOAD within next 3 ops
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.LOAD) {
						// Look for compare within next 3 ops
						for (int k = j + 1; k < Math.min(j + 4, pcode.length); k++) {
							int opc = pcode[k].getOpcode();
							if (opc == PcodeOp.INT_SLESS || opc == PcodeOp.INT_LESS ||
								opc == PcodeOp.INT_SLESSEQUAL || opc == PcodeOp.INT_LESSEQUAL) {
								swapPatterns++;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (swapPatterns < 1) return null;

		double conf = 0.4;
		if (swapPatterns >= 2) conf += 0.15;
		if (p.loopCount >= 2) conf += 0.15;
		if (p.sLesses > 0) conf += 0.05; // Signed comparison typical for sort
		if (p.calls == 0) conf += 0.05;

		return new FunctionType("sort", "sort_routine",
			Math.min(conf, 0.95),
			"Sort routine (nested loops with compare-and-swap pattern)");
	}

	// ================================================================
	// Additional rule-based detectors
	// ================================================================

	/**
	 * Fixed-point math: INT_MULT followed by INT_RIGHT (or INT_SRIGHT).
	 * Common in games (16.16 fixed-point) and DSP code.
	 */
	private FunctionType detectFixedPointMath(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.mults < 2) return null;
		if (!p.hasMultThenShift) return null;

		// Count MULT->shift pairs
		int multShiftPairs = 0;
		for (int i = 0; i < pcode.length - 3; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_MULT) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.INT_RIGHT || opc == PcodeOp.INT_SRIGHT) {
						multShiftPairs++;
						break;
					}
				}
			}
		}

		if (multShiftPairs < 2) return null;

		double conf = 0.40;
		if (multShiftPairs >= 3) conf += 0.15;
		if (p.hasShiftByConst16) conf += 0.15; // 16.16 fixed-point
		if (p.adds > 2) conf += 0.05; // Accumulation
		if (p.subs > 0) conf += 0.05;
		if (p.hasLoop) conf += 0.05;

		return new FunctionType("fixed_point", "fixed_point_math",
			Math.min(conf, 0.95),
			"Fixed-point arithmetic (MULT+shift-right pattern, " + multShiftPairs + " pairs)");
	}

	/**
	 * Busy-wait/polling loop: tight LOAD + compare + CBRANCH loop
	 * with no STORE or arithmetic — just spinning on a memory location.
	 */
	private FunctionType detectBusyWaitLoop(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 60) return null;

		// Very tight: mostly LOAD + compare + branch
		if (p.loads < 1 || p.cbranches < 1) return null;
		if (p.stores > 1) return null;
		if (p.arithmetic > 2) return null;
		if (p.calls > 0) return null;

		// Check for LOAD -> compare -> CBRANCH pattern
		boolean hasPollingPattern = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL ||
						opc == PcodeOp.INT_AND) {
						for (int k = j + 1; k < Math.min(j + 3, pcode.length); k++) {
							if (pcode[k].getOpcode() == PcodeOp.CBRANCH) {
								hasPollingPattern = true;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (!hasPollingPattern) return null;

		double conf = 0.45;
		if (p.totalOps < 25) conf += 0.15;
		if (p.ioRegionAccesses > 0) conf += 0.2; // Polling HW register
		if (p.ands > 0) conf += 0.05; // Bit mask test

		return new FunctionType("busy_wait", "wait_poll_loop",
			Math.min(conf, 0.95),
			"Busy-wait/polling loop (LOAD+compare+branch" +
			(p.ioRegionAccesses > 0 ? ", I/O register" : "") + ")");
	}

	/**
	 * Object update loop: LOAD from table + CALLIND in loop.
	 * Classic game entity processing pattern.
	 */
	private FunctionType detectObjectUpdateLoop(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.callInds < 1 && p.calls < 3) return null;
		if (p.loads < 3) return null;

		// Object loop: loads from indexed slots + dispatch calls
		boolean hasIndexedLoadCall = false;
		for (int i = 0; i < pcode.length - 4; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 8, pcode.length); j++) {
					int opc = pcode[j].getOpcode();
					if (opc == PcodeOp.CALLIND || opc == PcodeOp.CALL) {
						hasIndexedLoadCall = true;
						break;
					}
				}
			}
		}

		if (!hasIndexedLoadCall) return null;

		double conf = 0.40;
		if (p.callInds >= 1) conf += 0.15;
		if (p.adds >= 2) conf += 0.1; // Pointer/index increment
		if (p.compares >= 2) conf += 0.1; // Loop bounds + null check
		if (p.constZeroCompares >= 1) conf += 0.05; // Null slot check

		return new FunctionType("object_loop", "object_update_loop",
			Math.min(conf, 0.95),
			"Object/entity update loop (indexed LOAD + dispatch)");
	}

	/**
	 * Palette fade: color component manipulation with AND mask + shift + add/sub.
	 * Operates on groups of RGB values.
	 */
	private FunctionType detectPaletteFade(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 30) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.ands < 2 || p.shifts < 2) return null;

		// Look for color mask constants: 0x1F, 0x3F, 0x7C0, 0xF800, 0xFF, 0x1F00
		int colorMasks = 0;
		Set<Long> knownColorMasks = new HashSet<>(Arrays.asList(
			0x1FL, 0x3FL, 0x7C0L, 0xF800L, 0xFFL, 0x1F00L,
			0x0E0EL, 0x00F0L, 0x000FL, 0x0F00L, 0xF0F0L
		));
		for (long c : p.constants) {
			if (knownColorMasks.contains(c)) colorMasks++;
		}

		if (colorMasks < 2) return null;

		double conf = 0.40;
		if (colorMasks >= 3) conf += 0.15;
		if (p.ioRegionAccesses > 0) conf += 0.15; // Writing to VDP/palette
		if (p.subs > 0 || p.adds > 0) conf += 0.1;

		return new FunctionType("palette_fade", "palette_fade",
			Math.min(conf, 0.95),
			"Palette/color fade (" + colorMasks + " color mask constants, shift+mask ops)");
	}

	/**
	 * Linked list traversal: LOAD pointer + compare null + CBRANCH loop.
	 */
	private FunctionType detectLinkedListTraversal(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.loads < 2) return null;
		if (p.constZeroCompares < 1) return null;

		// Pattern: LOAD -> (some ops) -> LOAD (follow pointer) -> compare zero -> CBRANCH
		int traversalPatterns = 0;
		for (int i = 0; i < pcode.length - 3; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				// Look for a second LOAD nearby (deref the next pointer)
				for (int j = i + 1; j < Math.min(i + 6, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.LOAD) {
						// Look for zero-compare
						for (int k = j + 1; k < Math.min(j + 4, pcode.length); k++) {
							int opc = pcode[k].getOpcode();
							if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) {
								traversalPatterns++;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (traversalPatterns < 1) return null;

		// Distinguish from memcmp: linked list has fewer stores
		if (p.stores > p.loads) return null;

		double conf = 0.40;
		if (traversalPatterns >= 2) conf += 0.15;
		if (p.stores < 3) conf += 0.1;
		if (p.calls > 0 || p.callInds > 0) conf += 0.1; // Processing callback

		return new FunctionType("linked_list", "linked_list_traversal",
			Math.min(conf, 0.95),
			"Linked list traversal (pointer chase + null check loop)");
	}

	/**
	 * CRC polynomial division: XOR + shift + conditional XOR pattern.
	 * More specific than general checksum.
	 */
	private FunctionType detectCrcPolynomial(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.xors < 2 || p.shifts < 2) return null;

		// CRC: shift + test bit + conditional XOR with polynomial constant
		int xorAfterShift = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_LEFT ||
				pcode[i].getOpcode() == PcodeOp.INT_RIGHT) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_XOR) {
						xorAfterShift++;
						break;
					}
				}
			}
		}

		if (xorAfterShift < 2) return null;

		// Known CRC polynomials
		boolean hasKnownPoly = false;
		Set<Long> knownPolys = new HashSet<>(Arrays.asList(
			0xEDB88320L, 0x04C11DB7L, // CRC-32
			0xA001L, 0x8005L,          // CRC-16
			0x1021L, 0x8408L           // CRC-CCITT
		));
		for (long c : p.constants) {
			if (knownPolys.contains(c)) { hasKnownPoly = true; break; }
		}

		double conf = 0.45;
		if (hasKnownPoly) conf += 0.30;
		if (xorAfterShift >= 3) conf += 0.1;
		if (p.loopCount >= 1) conf += 0.05;

		return new FunctionType("crc", "crc_checksum",
			Math.min(conf, 0.95),
			"CRC polynomial checksum (shift+XOR" +
			(hasKnownPoly ? " with known polynomial" : "") + ")");
	}

	/**
	 * Bitfield extraction: AND with mask + right shift, repeated for multiple fields.
	 */
	private FunctionType detectBitfieldExtraction(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.ands < 3 || p.rights < 2) return null;
		if (p.powerOf2Masks < 2) return null;

		// Count AND+shift-right pairs
		int extractPairs = 0;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_AND) {
				for (int j = i + 1; j < Math.min(i + 3, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_RIGHT ||
						pcode[j].getOpcode() == PcodeOp.INT_SRIGHT) {
						extractPairs++;
						break;
					}
				}
			}
			// Also: right-shift then AND (extract after shift)
			if (pcode[i].getOpcode() == PcodeOp.INT_RIGHT) {
				for (int j = i + 1; j < Math.min(i + 3, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_AND) {
						extractPairs++;
						break;
					}
				}
			}
		}

		if (extractPairs < 3) return null;

		double conf = 0.40;
		if (extractPairs >= 5) conf += 0.15;
		if (p.powerOf2Masks >= 3) conf += 0.1;
		if (p.stores >= extractPairs) conf += 0.1; // Storing extracted fields

		return new FunctionType("bitfield", "bitfield_extraction",
			Math.min(conf, 0.95),
			"Bitfield extraction (" + extractPairs + " AND+shift pairs)");
	}

	/**
	 * Table lookup: computed index (ADD/MULT) + LOAD from table.
	 * Sine tables, dispatch tables, translation tables.
	 */
	private FunctionType detectTableLookup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.loads < 2) return null;
		if (p.totalOps > 80) return null;

		// Pattern: compute index (ADD or MULT or LEFT) then LOAD
		int indexedLoads = 0;
		for (int i = 0; i < pcode.length - 1; i++) {
			int opc = pcode[i].getOpcode();
			if (opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_LEFT ||
				opc == PcodeOp.INT_MULT || opc == PcodeOp.INT_ZEXT) {
				for (int j = i + 1; j < Math.min(i + 3, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.LOAD) {
						indexedLoads++;
						break;
					}
				}
			}
		}

		if (indexedLoads < 2) return null;
		// Should be simple: not too many branches or arithmetic
		if (p.cbranches > 3) return null;

		double conf = 0.40;
		if (indexedLoads >= 3) conf += 0.15;
		if (p.totalOps < 40) conf += 0.1;
		if (p.calls == 0) conf += 0.05;
		if (p.mults > 0 || p.lefts > 0) conf += 0.1; // Index scaling

		return new FunctionType("table_lookup", "table_lookup",
			Math.min(conf, 0.95),
			"Table lookup (indexed LOAD, " + indexedLoads + " computed accesses)");
	}

	/**
	 * Software floating-point: functions using FLOAT_* P-code ops, or
	 * software float emulation (large functions with many shifts + masks + adds).
	 */
	private FunctionType detectFloatingPoint(PcodeOp[] pcode, OpcodeProfile p) {
		// Hardware float path: P-code has FLOAT_* ops
		if (p.floatOps >= 3) {
			double conf = 0.50;
			if (p.floatMults > 0 && p.floatAdds > 0) conf += 0.15;
			if (p.floatDivs > 0) conf += 0.1;
			if (p.floatOps >= 6) conf += 0.1;
			String variant = p.floatDivs > 0 ? "div" : (p.floatMults > 0 ? "mult" : "add");
			return new FunctionType("floating_point", "float_" + variant,
				Math.min(conf, 0.95),
				"Floating-point arithmetic (" + p.floatOps + " float ops)");
		}

		// Software float path: lots of shifts + masks + conditional adds
		// Typically large (100+ ops), many shifts, many branches
		if (p.totalOps < 80 || p.shifts < 8 || p.ands < 4) return null;
		if (p.cbranches < 4) return null;

		// Check for IEEE 754 constants (exponent bias, mantissa masks)
		boolean hasIeeeConst = false;
		Set<Long> ieeeConstants = new HashSet<>(Arrays.asList(
			127L, 1023L, 0x7FL, 0x3FFL,     // exponent bias
			0x7F800000L, 0x007FFFFFL,         // float exponent/mantissa masks
			0x7FF00000L, 0x000FFFFFL,         // double exponent/mantissa masks
			0x80000000L                        // sign bit
		));
		for (long c : p.constants) {
			if (ieeeConstants.contains(c)) { hasIeeeConst = true; break; }
		}

		if (!hasIeeeConst) return null;

		double conf = 0.40;
		if (p.shifts >= 12) conf += 0.1;
		if (p.totalOps >= 150) conf += 0.1;

		return new FunctionType("soft_float", "software_float",
			Math.min(conf, 0.95),
			"Software floating-point emulation (shift/mask heavy with IEEE constants)");
	}

	/**
	 * Collision detection: multiple less-than comparisons (bounding box test).
	 * Pattern: load 4 coordinates, compare x1<x2, x2<x1+w, y1<y2, y2<y1+h.
	 */
	private FunctionType detectCollisionDetection(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 200) return null;
		// Need multiple loads (reading coordinates) and comparisons
		if (p.loads < 4) return null;
		if ((p.lesses + p.sLesses) < 3) return null;

		// Check for pairs of less-than comparisons (bounding box edges)
		int lessPairs = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			int opc1 = pcode[i].getOpcode();
			if (opc1 == PcodeOp.INT_LESS || opc1 == PcodeOp.INT_SLESS ||
				opc1 == PcodeOp.INT_LESSEQUAL || opc1 == PcodeOp.INT_SLESSEQUAL) {
				for (int j = i + 1; j < Math.min(i + 6, pcode.length); j++) {
					int opc2 = pcode[j].getOpcode();
					if (opc2 == PcodeOp.INT_LESS || opc2 == PcodeOp.INT_SLESS ||
						opc2 == PcodeOp.INT_LESSEQUAL || opc2 == PcodeOp.INT_SLESSEQUAL) {
						lessPairs++;
						break;
					}
				}
			}
		}

		if (lessPairs < 2) return null;

		double conf = 0.40;
		if (lessPairs >= 3) conf += 0.15;
		if (p.subs >= 2) conf += 0.1; // Coordinate differences
		if (p.adds >= 2) conf += 0.05; // pos + size
		if (p.boolAnds > 0) conf += 0.1; // AND of multiple conditions

		return new FunctionType("collision", "collision_detection",
			Math.min(conf, 0.95),
			"Collision detection (bounding box, " + lessPairs + " comparison pairs)");
	}

	/**
	 * State machine: many comparisons against different constants + branches.
	 * Switch-like dispatch pattern.
	 */
	private FunctionType detectStateMachine(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.cbranches < 4) return null;
		if (p.equals < 3 && p.notEquals < 3) return null;

		// Count comparisons with distinct constant values
		Set<Long> comparedConstants = new HashSet<>();
		for (PcodeOp op : pcode) {
			int opc = op.getOpcode();
			if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode v = op.getInput(i);
					if (v != null && v.isConstant()) {
						comparedConstants.add(v.getOffset());
					}
				}
			}
		}

		if (comparedConstants.size() < 4) return null;

		// Ratio of equality comparisons to total ops should be significant
		double compareRatio = (double)(p.equals + p.notEquals) / p.totalOps;
		if (compareRatio < 0.05) return null;

		double conf = 0.40;
		if (comparedConstants.size() >= 6) conf += 0.15;
		if (comparedConstants.size() >= 10) conf += 0.1;
		if (p.calls > 0 || p.callInds > 0) conf += 0.1; // State handlers
		if (!p.hasLoop) conf += 0.05; // Flat switch, not loop

		return new FunctionType("state_machine", "state_machine_dispatch",
			Math.min(conf, 0.95),
			"State machine/switch dispatch (" + comparedConstants.size() +
			" distinct state constants)");
	}

	/**
	 * Velocity/physics update: LOAD position + ADD velocity + STORE.
	 * Integration pattern common in game physics.
	 */
	private FunctionType detectVelocityPhysics(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.loads < 3 || p.stores < 2) return null;
		if (p.adds < 2) return null;

		// Look for LOAD -> ADD -> STORE pattern (position += velocity)
		int loadAddStorePatterns = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_ADD ||
						pcode[j].getOpcode() == PcodeOp.INT_SUB) {
						for (int k = j + 1; k < Math.min(j + 4, pcode.length); k++) {
							if (pcode[k].getOpcode() == PcodeOp.STORE) {
								loadAddStorePatterns++;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (loadAddStorePatterns < 2) return null;

		// Should have comparison (bounds checking, ground detection)
		if (p.compares < 1) return null;

		double conf = 0.40;
		if (loadAddStorePatterns >= 3) conf += 0.15;
		if (p.sLesses > 0) conf += 0.1; // Signed comparison (negative velocity)
		if (p.cbranches >= 2) conf += 0.05; // Multiple conditions
		if (p.shifts > 0) conf += 0.05; // Fractional velocity

		return new FunctionType("physics", "velocity_physics_update",
			Math.min(conf, 0.95),
			"Velocity/physics update (LOAD+ADD+STORE pattern, " +
			loadAddStorePatterns + " integration steps)");
	}

	/**
	 * Serial I/O: repeated LOAD from status register + CBRANCH (wait for ready)
	 * + STORE to data register. Common UART/SCC pattern.
	 */
	private FunctionType detectSerialIO(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.ioRegionAccesses < 3) return null;
		if (p.loads < 2 || p.stores < 1) return null;

		// IO-heavy: most memory accesses go to IO region
		double ioRatio = (double) p.ioRegionAccesses / Math.max(1, p.memory);
		if (ioRatio < 0.3) return null;

		// Check for status polling pattern: LOAD from IO + AND/compare + CBRANCH
		boolean hasStatusPoll = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				Varnode addr = pcode[i].getInput(1);
				if (addr != null && addr.isConstant()) {
					// Check if this is an IO address
					boolean isIO = false;
					for (PlatformDescription.MemoryRegion region : platform.getMemoryMap()) {
						if ("io".equals(region.type) &&
							addr.getOffset() >= region.start && addr.getOffset() <= region.end) {
							isIO = true;
							break;
						}
					}
					if (isIO) {
						for (int j = i + 1; j < Math.min(i + 5, pcode.length); j++) {
							if (pcode[j].getOpcode() == PcodeOp.CBRANCH) {
								hasStatusPoll = true;
								break;
							}
						}
					}
				}
			}
		}

		double conf = 0.40;
		if (hasStatusPoll) conf += 0.2;
		if (p.ioRegionAccesses >= 5) conf += 0.1;
		if (ioRatio > 0.5) conf += 0.1;
		if (p.hasLoop) conf += 0.05; // Byte-by-byte transmit loop

		return new FunctionType("serial_io", "serial_io_driver",
			Math.min(conf, 0.95),
			"Serial I/O driver (" + p.ioRegionAccesses + " I/O accesses" +
			(hasStatusPoll ? ", status polling" : "") + ")");
	}

	/**
	 * Memory test: write pattern + read back + compare.
	 * Pattern: STORE value -> LOAD same address -> compare -> branch on mismatch.
	 */
	private FunctionType detectMemoryTest(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.compares < 2) return null;

		// Look for STORE -> LOAD -> compare pattern
		int writeReadVerify = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.STORE) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.LOAD) {
						for (int k = j + 1; k < Math.min(j + 4, pcode.length); k++) {
							int opc = pcode[k].getOpcode();
							if (opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL ||
								opc == PcodeOp.INT_XOR) {
								writeReadVerify++;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (writeReadVerify < 2) return null;

		// Check for test pattern constants (0xAA55, 0x55AA, 0xFFFF, etc.)
		boolean hasTestPattern = false;
		Set<Long> testPatterns = new HashSet<>(Arrays.asList(
			0xAA55L, 0x55AAL, 0xAAAAL, 0x5555L,
			0xAAAAAAAAL, 0x55555555L, 0xDEADBEEFL
		));
		for (long c : p.constants) {
			if (testPatterns.contains(c)) { hasTestPattern = true; break; }
		}

		double conf = 0.40;
		if (writeReadVerify >= 3) conf += 0.15;
		if (hasTestPattern) conf += 0.2;
		if (p.xors > 0) conf += 0.05; // XOR for verify
		if (p.loopCount >= 2) conf += 0.05; // Nested address + pattern loops

		return new FunctionType("memory_test", "memory_test",
			Math.min(conf, 0.95),
			"Memory test (write+read+verify pattern" +
			(hasTestPattern ? " with known test patterns" : "") + ")");
	}

	/**
	 * DMA transfer setup: sequential stores to hardware registers with
	 * specific address/length/control pattern.
	 */
	private FunctionType detectDmaTransfer(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.stores < 4) return null;
		if (p.ioRegionAccesses < 3) return null;
		if (p.consecutiveStores < 3) return null;

		// DMA: burst of stores to IO region, typically 3-6 consecutive
		double conf = 0.40;
		if (p.consecutiveStores >= 4) conf += 0.15;
		if (p.ioRegionAccesses >= 5) conf += 0.15;
		if (p.totalOps < 60) conf += 0.1; // DMA setup is typically small
		if (p.calls == 0) conf += 0.05;

		return new FunctionType("dma_transfer", "dma_transfer_setup",
			Math.min(conf, 0.95),
			"DMA transfer setup (" + p.consecutiveStores +
			" consecutive stores, " + p.ioRegionAccesses + " I/O accesses)");
	}

	// ================================================================
	// Expanded rule-based detectors (round 3)
	// ================================================================

	/**
	 * String compare: byte-by-byte comparison loop with zero-termination check.
	 * P-code: LOAD->LOAD->SUB or EQUAL in loop, with zero compare for terminator.
	 */
	private FunctionType detectStringCompare(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 200 || p.totalOps < 15) return null;
		if (p.loads < 4) return null;
		if (p.compares < 2) return null;
		if (p.constZeroCompares < 1) return null;

		// Need paired loads (reading two strings) + compare
		double loadFrac = p.loads / (double) p.totalOps;
		double cmpFrac = p.compares / (double) p.totalOps;
		if (loadFrac < 0.10 || cmpFrac < 0.05) return null;

		double conf = 0.45;
		if (p.constZeroCompares >= 2) conf += 0.15; // null terminator check
		if (p.subs > 0) conf += 0.10; // subtraction for comparison result
		if (p.calls == 0) conf += 0.05;
		if (p.loads >= p.stores * 3) conf += 0.10; // reads >> writes

		return new FunctionType("string_compare", "string_compare",
			Math.min(conf, 0.90),
			"String comparison (byte-by-byte with null termination)");
	}

	/**
	 * String copy: load byte, store byte, test for null, loop.
	 * P-code: LOAD->STORE alternation in loop, zero compare for terminator.
	 */
	private FunctionType detectStringCopy(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 200 || p.totalOps < 12) return null;
		if (p.loads < 2 || p.stores < 2) return null;
		if (p.constZeroCompares < 1) return null;

		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (memBal < 0.3) return null; // loads and stores roughly balanced

		double conf = 0.45;
		if (p.loadStoreAlternations >= 2) conf += 0.15;
		if (p.calls == 0) conf += 0.05;
		if (p.constZeroCompares >= 1) conf += 0.10;
		if (p.loopCount == 1) conf += 0.05; // single copy loop

		return new FunctionType("string_copy", "string_copy",
			Math.min(conf, 0.90),
			"String copy (null-terminated)");
	}

	/**
	 * Number-to-string conversion: division/remainder by 10 (or powers), ASCII offset add.
	 * P-code: INT_DIV/INT_REM with const 10, INT_ADD with const 0x30 ('0').
	 */
	private FunctionType detectNumberToString(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 400 || p.totalOps < 15) return null;

		boolean hasDivBy10 = false;
		boolean hasAsciiOffset = false;
		for (PcodeOp op : pcode) {
			int opc = op.getOpcode();
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if ((opc == PcodeOp.INT_DIV || opc == PcodeOp.INT_SDIV ||
						 opc == PcodeOp.INT_REM || opc == PcodeOp.INT_SREM) && v == 10) {
						hasDivBy10 = true;
					}
					if (opc == PcodeOp.INT_ADD && (v == 0x30 || v == 0x37 || v == 0x57)) {
						hasAsciiOffset = true; // '0', 'A'-10, 'a'-10
					}
				}
			}
		}

		if (!hasDivBy10 && !hasAsciiOffset) return null;
		if (!hasDivBy10 && p.constAsciiCompares < 2) return null;

		double conf = 0.45;
		if (hasDivBy10) conf += 0.20;
		if (hasAsciiOffset) conf += 0.15;
		if (p.stores > 2) conf += 0.05; // writing output digits

		return new FunctionType("number_to_string", "number_to_string_convert",
			Math.min(conf, 0.90),
			"Number-to-string conversion (" +
			(hasDivBy10 ? "div-by-10" : "hex") + " to ASCII)");
	}

	/**
	 * Heap allocator (malloc/free): linked-list traversal with size comparison,
	 * pointer arithmetic, multiple exit paths.
	 */
	private FunctionType detectHeapAllocator(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.loads < 5 || p.stores < 3) return null;
		if (p.compares < 3) return null;
		if (p.cbranches < 3) return null;

		// Allocators: lots of pointer arithmetic, comparisons, multiple branches
		double loadFrac = p.loads / (double) p.totalOps;
		double cmpFrac = p.compares / (double) p.totalOps;
		double brFrac = p.cbranches / (double) p.totalOps;
		if (loadFrac < 0.08 || cmpFrac < 0.05 || brFrac < 0.05) return null;

		// Need pointer arithmetic (adds) and at least one store (updating free list)
		if (p.adds < 3) return null;
		// Need zero compares (null pointer checks)
		if (p.constZeroCompares < 2) return null;

		double conf = 0.40;
		if (p.constZeroCompares >= 3) conf += 0.15; // null ptr checks
		if (p.returns >= 2) conf += 0.10; // multiple return paths (success/fail)
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.05; // size comparisons
		if (p.hasLoop) conf += 0.10; // traversal loop

		return new FunctionType("heap_allocator", "heap_allocator",
			Math.min(conf, 0.85),
			"Heap allocator (pointer traversal with size comparison)");
	}

	/**
	 * Circular/ring buffer: modular index arithmetic (AND with power-of-2 mask
	 * or comparison with buffer size), load/store with index.
	 */
	private FunctionType detectCircularBuffer(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 200 || p.totalOps < 15) return null;
		if (p.loads < 1 || p.stores < 1) return null;
		if (p.powerOf2Masks < 1 && p.rems < 1) return null;

		// Ring buffer: AND mask for wrapping, or REM for modular arithmetic
		double conf = 0.45;
		if (p.powerOf2Masks >= 2) conf += 0.15;
		if (p.adds > 0) conf += 0.05; // index increment
		if (p.compares > 0) conf += 0.10; // empty/full check
		if (p.constZeroCompares > 0) conf += 0.05;

		return new FunctionType("circular_buffer", "circular_buffer_op",
			Math.min(conf, 0.85),
			"Circular/ring buffer operation (modular index)");
	}

	/**
	 * Controller/joypad input: read from specific IO port, shift/mask individual
	 * bits for button states. Typically short with IO reads + bit masking.
	 */
	private FunctionType detectControllerInput(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 150 || p.totalOps < 10) return null;
		if (p.ioRegionAccesses < 1) return null;
		if (p.ands < 1) return null;

		// Controller read: IO load + mask + store to RAM
		double conf = 0.40;
		if (p.ioRegionAccesses >= 2) conf += 0.15;
		if (p.powerOf2Masks >= 2) conf += 0.15; // bit testing
		if (p.shifts > 0) conf += 0.05; // shift register read
		if (p.stores > 0) conf += 0.05; // store button state

		return new FunctionType("controller_input", "read_controller_input",
			Math.min(conf, 0.85),
			"Controller/joypad input read (" + p.ioRegionAccesses + " I/O accesses)");
	}

	/**
	 * Sound driver: writes to audio/PSG/FM IO registers, typically sequential
	 * stores with specific register address patterns.
	 */
	private FunctionType detectSoundDriver(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.ioRegionAccesses < 3) return null;
		if (p.stores < 4) return null;
		if (p.totalOps < 15) return null;

		// Sound drivers: many IO writes, moderate size, may have loops for channels
		double ioFrac = p.ioRegionAccesses / (double) p.totalOps;
		if (ioFrac < 0.03) return null;

		double conf = 0.40;
		if (p.ioRegionAccesses >= 6) conf += 0.15;
		if (p.hasLoop) conf += 0.10; // channel iteration
		if (p.consecutiveStores >= 3) conf += 0.10;
		if (p.stores > p.loads * 2) conf += 0.05; // mostly writes

		return new FunctionType("sound_driver", "sound_register_write",
			Math.min(conf, 0.85),
			"Sound/audio register writes (" + p.ioRegionAccesses + " I/O accesses)");
	}

	/**
	 * Sprite/OAM renderer: batch stores to specific memory range,
	 * coordinate calculations, attribute packing with shifts/masks.
	 */
	private FunctionType detectSpriteRenderer(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.stores < 4) return null;
		if (p.shifts < 2 && p.logic < 2) return null;

		// Sprite setup: coordinate arithmetic + attribute packing + batch stores
		if (!p.hasLoop && p.consecutiveStores < 4) return null;

		double conf = 0.40;
		if (p.consecutiveStores >= 4) conf += 0.10;
		if (p.ands >= 2) conf += 0.10; // attribute masking
		if (p.ors >= 2) conf += 0.10; // attribute combining
		if (p.lefts > 0 || p.rights > 0) conf += 0.05; // coordinate/tile shifts
		if (p.hasLoop) conf += 0.10; // sprite list iteration

		return new FunctionType("sprite_renderer", "sprite_setup",
			Math.min(conf, 0.85),
			"Sprite/OAM setup (attribute packing + batch stores)");
	}

	/**
	 * Scroll handler: camera/scroll register updates, parallax calculation
	 * with multiple layers. IO writes + arithmetic + loop.
	 */
	private FunctionType detectScrollHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15 || p.totalOps > 400) return null;
		if (p.ioRegionAccesses < 1 && p.stores < 3) return null;
		if (p.loads < 2) return null;
		if (p.arithmetic < 2) return null;

		// Scroll: load position, add delta, store + write to IO
		double conf = 0.40;
		if (p.ioRegionAccesses >= 2) conf += 0.15;
		if (p.adds >= 3) conf += 0.10; // position updates
		if (p.subs > 0) conf += 0.05; // camera offset subtraction
		if (p.hasLoop) conf += 0.10; // multi-layer
		if (p.shifts > 0) conf += 0.05; // parallax scaling

		return new FunctionType("scroll_handler", "scroll_update",
			Math.min(conf, 0.85),
			"Scroll/camera position update");
	}

	/**
	 * Screen fade: iterates over palette entries, applies arithmetic
	 * (add/subtract toward target), writes back. Loop with bounded increment.
	 */
	private FunctionType detectScreenFade(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 300) return null;
		if (p.loads < 3 || p.stores < 3) return null;

		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (memBal < 0.4) return null;

		// Fade: read color, adjust, clamp, write back
		boolean hasClamp = p.sLesses > 0 || p.lesses > 0;
		double conf = 0.40;
		if (p.subs > 0 || p.adds > 0) conf += 0.10;
		if (hasClamp) conf += 0.15; // clamp to 0 or max
		if (p.ands > 0) conf += 0.05; // color component masking
		if (p.loopCount >= 1) conf += 0.10;

		return new FunctionType("screen_fade", "screen_fade_effect",
			Math.min(conf, 0.85),
			"Screen fade effect (palette iteration with color adjust)");
	}

	/**
	 * Bytecode/script interpreter: large function with many compares/branches,
	 * BRANCHIND or large switch, loop, calls to handler functions.
	 */
	private FunctionType detectBytecodeInterpreter(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 80) return null;
		if (!p.hasLoop) return null;
		if (p.compares < 5) return null;
		if (p.cbranches < 5) return null;

		// Interpreter main loop: large, many comparisons, calls, branch-heavy
		double cmpFrac = p.compares / (double) p.totalOps;
		double callFrac = (p.calls + p.callInds) / (double) p.totalOps;
		if (cmpFrac < 0.04) return null;

		double conf = 0.40;
		if (p.branchInds > 0) conf += 0.20; // jump table dispatch
		if (p.cbranch_eq_runs >= 5) conf += 0.15; // many opcode comparisons
		if (p.calls >= 5) conf += 0.10; // calls to handlers
		if (p.loads >= 5) conf += 0.05; // reading bytecode stream
		if (p.totalOps > 200) conf += 0.05; // interpreters are large

		return new FunctionType("bytecode_interpreter", "bytecode_interpreter",
			Math.min(conf, 0.85),
			"Bytecode/script interpreter (dispatch loop with " +
			p.cbranch_eq_runs + " opcode compares)");
	}

	/**
	 * Tile/graphics decoder: loads packed data, shifts/masks to extract pixels,
	 * stores expanded data. Loop with bitwise heavy inner body.
	 */
	private FunctionType detectTileDecoder(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 500) return null;
		if (p.loads < 2 || p.stores < 2) return null;
		if (p.shifts < 2 && p.logic < 3) return null;

		double shiftLogicFrac = (p.shifts + p.logic) / (double) p.totalOps;
		if (shiftLogicFrac < 0.10) return null;

		double conf = 0.40;
		if (p.ands >= 3) conf += 0.15; // pixel masking
		if (p.lefts > 0 && p.rights > 0) conf += 0.10; // bidirectional shifts
		if (p.powerOf2Masks >= 2) conf += 0.10; // nibble/byte extraction
		if (p.constSmallInts >= 3) conf += 0.05; // bit widths

		return new FunctionType("tile_decoder", "tile_graphics_decoder",
			Math.min(conf, 0.85),
			"Tile/graphics format decoder (shift/mask pixel extraction)");
	}

	/**
	 * Animation update: frame counter check, conditional sprite/tile update,
	 * table-driven frame sequence. Moderate size with counter compare + branch.
	 */
	private FunctionType detectAnimationUpdate(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15 || p.totalOps > 300) return null;
		if (p.compares < 2) return null;
		if (p.loads < 3 || p.stores < 2) return null;

		// Animation: load counter, compare frame limit, branch, update state
		double conf = 0.40;
		if (p.adds > 0 && p.subs > 0) conf += 0.10; // increment + wrap
		if (p.compares >= 3) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.05;
		if (p.constSmallInts >= 2) conf += 0.05; // frame counts are small
		if (p.calls >= 1) conf += 0.10; // call to sprite update

		// Distinguish from generic code: need counter-like pattern
		if (conf < 0.55) return null; // need several indicators

		return new FunctionType("animation_update", "animation_frame_update",
			Math.min(conf, 0.80),
			"Animation frame/state update");
	}

	/**
	 * Particle system: spawn + update loop with position/velocity per particle,
	 * lifetime check, despawn. Array iteration with physics-like arithmetic.
	 */
	private FunctionType detectParticleSystem(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 30) return null;
		if (p.loads < 5 || p.stores < 5) return null;
		if (p.arithmetic < 4) return null;

		// Particle: iterate array, load pos+vel, add (integrate), check lifetime, store back
		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (memBal < 0.3) return null;

		double conf = 0.40;
		if (p.adds >= 3) conf += 0.10; // position integration
		if (p.subs > 0) conf += 0.05; // lifetime decrement
		if (p.compares >= 2) conf += 0.10; // lifetime/bounds check
		if (p.constZeroCompares >= 1) conf += 0.05; // dead particle check
		if (p.loopCount >= 1) conf += 0.05;
		if (p.hasNestedLoop) conf += 0.10; // outer particle loop + inner sub-loop

		// Need enough indicators to distinguish from generic loop
		if (conf < 0.55) return null;

		return new FunctionType("particle_system", "particle_update",
			Math.min(conf, 0.85),
			"Particle system (spawn/update with lifetime)");
	}

	/**
	 * Task scheduler/dispatcher: RTOS pattern with queue traversal, priority
	 * comparison, context switch (many register saves/restores).
	 */
	private FunctionType detectTaskScheduler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		if (p.loads < 5 || p.stores < 5) return null;
		if (p.compares < 3) return null;
		if (p.cbranches < 3) return null;

		// Scheduler: queue traversal (loads), priority compare, context save/restore (stores)
		boolean hasContextSwitch = p.consecutiveStores >= 4 || p.consecutiveLoads >= 4;
		if (!hasContextSwitch && p.callOtherCount < 1) return null;

		double conf = 0.40;
		if (hasContextSwitch) conf += 0.20; // register save/restore block
		if (p.hasLoop) conf += 0.10; // queue scan
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.10; // priority comparison
		if (p.constZeroCompares >= 2) conf += 0.05; // null queue check

		return new FunctionType("task_scheduler", "task_scheduler_dispatch",
			Math.min(conf, 0.85),
			"RTOS task scheduler/dispatcher (queue scan + context switch)");
	}

	/**
	 * Semaphore/mutex: small function with test-and-set pattern,
	 * atomic compare-and-swap, or counter decrement/increment.
	 */
	private FunctionType detectSemaphoreOp(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 100 || p.totalOps < 8) return null;
		if (p.loads < 1 || p.stores < 1) return null;

		// Semaphore P/V: load counter, test zero, decrement/increment, store
		boolean hasTAS = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			int o1 = pcode[i].getOpcode();
			int o2 = pcode[i+1].getOpcode();
			int o3 = pcode[i+2].getOpcode();
			// LOAD -> compare -> STORE pattern (test-and-set)
			if (o1 == PcodeOp.LOAD &&
				(o2 == PcodeOp.INT_EQUAL || o2 == PcodeOp.INT_NOTEQUAL ||
				 o2 == PcodeOp.INT_LESS || o2 == PcodeOp.INT_SLESS) &&
				o3 == PcodeOp.CBRANCH) {
				hasTAS = true;
			}
		}

		if (!hasTAS && p.callOtherCount == 0) return null;

		double conf = 0.40;
		if (hasTAS) conf += 0.20;
		if (p.constZeroCompares >= 1) conf += 0.10;
		if (p.adds > 0 || p.subs > 0) conf += 0.10; // inc/dec
		if (p.totalOps < 40) conf += 0.05; // semaphore ops are small

		return new FunctionType("semaphore", "semaphore_operation",
			Math.min(conf, 0.85),
			"Semaphore/mutex operation (test-and-set pattern)");
	}

	/**
	 * File operation: multiple sequential calls (open/read/write/close pattern),
	 * error checking after each call, buffer pointer arithmetic.
	 */
	private FunctionType detectFileOperation(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.calls < 3) return null;
		if (p.cbranches < 2) return null;

		// File ops: call -> check result -> branch on error -> call next
		// Characterized by many calls with error checks between them
		double callFrac = p.calls / (double) p.totalOps;
		if (callFrac < 0.03) return null;

		// Count call->compare->cbranch sequences (error check pattern)
		int callCheckCount = 0;
		for (int i = 0; i < pcode.length - 4; i++) {
			if (pcode[i].getOpcode() == PcodeOp.CALL) {
				for (int j = i + 1; j < Math.min(i + 5, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.CBRANCH) {
						callCheckCount++;
						break;
					}
				}
			}
		}

		if (callCheckCount < 2) return null;

		double conf = 0.40;
		if (callCheckCount >= 3) conf += 0.20;
		if (p.callSites >= 3) conf += 0.10; // calls to different functions
		if (p.constZeroCompares >= 2) conf += 0.05; // error code checks

		return new FunctionType("file_operation", "file_operation",
			Math.min(conf, 0.85),
			"File operation sequence (" + callCheckCount + " call-then-check patterns)");
	}

	/**
	 * Network protocol: packet building/parsing with field extraction,
	 * length/checksum computation, structured store sequence.
	 */
	private FunctionType detectNetworkProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.shifts < 1 && p.logic < 2) return null;

		// Packet build/parse: extract fields (shift/mask), validate lengths, checksum
		double conf = 0.40;
		if (p.ands >= 2) conf += 0.10; // field extraction
		if (p.ors >= 2) conf += 0.10; // field packing
		if (p.lefts > 0 && p.rights > 0) conf += 0.10; // byte/word swapping
		if (p.adds >= 2 && p.compares >= 2) conf += 0.10; // length/offset calc + bounds check
		if (p.calls >= 1) conf += 0.05; // call to send/receive

		// Need enough indicators
		if (conf < 0.60) return null;

		return new FunctionType("network_protocol", "packet_build_or_parse",
			Math.min(conf, 0.80),
			"Network protocol packet assembly or parsing");
	}

	/**
	 * Line/polygon rasterization: Bresenham-like pattern with error accumulator,
	 * step-by-pixel loop, conditional X/Y increment.
	 */
	private FunctionType detectLineDrawing(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 25) return null;
		if (p.adds < 3) return null;
		if (p.compares < 2 || p.cbranches < 2) return null;
		if (p.stores < 2) return null;

		// Bresenham: error += delta, if error > threshold then step
		// Characterized by adds (error accumulate), compares (threshold),
		// conditional adds (step), store (plot pixel)
		boolean hasErrorAccum = false;
		for (int i = 0; i < pcode.length - 3; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_ADD &&
				pcode[i+1].getOpcode() == PcodeOp.INT_SLESS &&
				pcode[i+2].getOpcode() == PcodeOp.CBRANCH) {
				hasErrorAccum = true;
				break;
			}
			if (pcode[i].getOpcode() == PcodeOp.INT_ADD &&
				pcode[i+1].getOpcode() == PcodeOp.INT_LESS &&
				pcode[i+2].getOpcode() == PcodeOp.CBRANCH) {
				hasErrorAccum = true;
				break;
			}
		}

		double conf = 0.40;
		if (hasErrorAccum) conf += 0.25;
		if (p.subs >= 2) conf += 0.10; // delta calculations
		if (p.negates > 0) conf += 0.05; // direction handling
		if (p.arithmetic >= 6) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("line_drawing", "line_rasterize",
			Math.min(conf, 0.85),
			"Line/polygon rasterization (Bresenham-style)");
	}

	/**
	 * Square root: shift-and-subtract iterative algorithm.
	 * P-code: shifts + subtracts + compares in tight loop, typically 16 or 32 iterations.
	 */
	private FunctionType detectSquareRoot(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 200 || p.totalOps < 15) return null;
		if (p.calls > 0) return null; // pure computation
		if (p.shifts < 3) return null;
		if (p.subs < 2) return null;

		// Sqrt: right-shift by 2 per iteration, subtract trial, compare
		double shiftFrac = p.shifts / (double) p.totalOps;
		double subFrac = p.subs / (double) p.totalOps;
		if (shiftFrac < 0.08 || subFrac < 0.05) return null;

		double conf = 0.45;
		if (p.rights >= 2 && p.lefts >= 1) conf += 0.15; // left + right shifts
		if (p.compares >= 2) conf += 0.10;
		if (p.ors > 0) conf += 0.05; // building result bit by bit

		return new FunctionType("square_root", "integer_sqrt",
			Math.min(conf, 0.85),
			"Integer/fixed-point square root (iterative)");
	}

	/**
	 * Trigonometric table lookup: load from fixed table address with index
	 * computed from angle, possibly with quadrant mirroring (negate, complement).
	 */
	private FunctionType detectTrigLookup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 150 || p.totalOps < 10) return null;
		if (p.loads < 2) return null;

		// Trig lookup: angle masking, quadrant check, table load, possible negate
		boolean hasAngleMask = p.powerOf2Masks >= 1;
		boolean hasNegate = p.negates > 0;
		boolean hasQuadrantCheck = p.compares >= 1 && p.cbranches >= 1;

		if (!hasAngleMask && !hasQuadrantCheck) return null;

		double conf = 0.40;
		if (hasAngleMask) conf += 0.15;
		if (hasNegate) conf += 0.15; // sin(-x) = -sin(x)
		if (hasQuadrantCheck) conf += 0.10;
		if (p.shifts > 0) conf += 0.05; // index scaling
		if (p.calls == 0) conf += 0.05; // pure lookup

		if (conf < 0.55) return null;

		return new FunctionType("trig_lookup", "sine_cosine_lookup",
			Math.min(conf, 0.85),
			"Trigonometric table lookup (angle -> sin/cos)");
	}

	/**
	 * Self-test/diagnostic: sequential test-and-report pattern,
	 * memory/IO probing, pass/fail branching.
	 */
	private FunctionType detectSelfTest(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.calls < 2) return null;
		if (p.compares < 3) return null;
		if (p.cbranches < 3) return null;

		// Self-test: sequence of test -> check -> report
		int testPatternCount = 0;
		for (int i = 0; i < pcode.length - 3; i++) {
			int o1 = pcode[i].getOpcode();
			int o2 = pcode[i+1].getOpcode();
			// STORE (write test) -> LOAD (read back) -> compare
			if (o1 == PcodeOp.STORE && o2 == PcodeOp.LOAD) {
				for (int j = i + 2; j < Math.min(i + 5, pcode.length); j++) {
					int o = pcode[j].getOpcode();
					if (o == PcodeOp.INT_EQUAL || o == PcodeOp.INT_NOTEQUAL) {
						testPatternCount++;
						break;
					}
				}
			}
		}

		// Also count call-then-check sequences (calling sub-tests)
		int callCheckCount = 0;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.CALL) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.CBRANCH) {
						callCheckCount++;
						break;
					}
				}
			}
		}

		if (testPatternCount < 1 && callCheckCount < 3) return null;

		double conf = 0.40;
		if (testPatternCount >= 2) conf += 0.20;
		if (callCheckCount >= 3) conf += 0.15;
		if (p.calls >= 4) conf += 0.10; // many sub-test calls

		return new FunctionType("self_test", "diagnostic_self_test",
			Math.min(conf, 0.85),
			"Self-test/diagnostic sequence (" + testPatternCount +
			" write-read-verify, " + callCheckCount + " test-and-check)");
	}

	/**
	 * Command parser: string comparison loop, dispatch to handler,
	 * table-driven command lookup.
	 */
	private FunctionType detectCommandParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.compares < 3) return null;
		if (p.calls < 2) return null;

		// Command parser: many string compares, dispatch calls
		double conf = 0.40;
		if (p.constAsciiCompares >= 3) conf += 0.20; // comparing ASCII chars
		if (p.cbranch_eq_runs >= 3) conf += 0.15; // compare-and-branch chain
		if (p.calls >= 3) conf += 0.10; // handler dispatch
		if (p.hasLoop) conf += 0.05;
		if (p.branchInds > 0) conf += 0.10; // indirect dispatch

		if (conf < 0.60) return null;

		return new FunctionType("command_parser", "command_line_parser",
			Math.min(conf, 0.85),
			"Command parser/dispatcher (" + p.constAsciiCompares +
			" ASCII comparisons, " + p.calls + " handler calls)");
	}

	/**
	 * BCD score update: add with carry/BCD adjustment, commonly uses
	 * nibble masking, compare with 9/10, and display update call.
	 */
	private FunctionType detectScoreUpdate(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 12 || p.totalOps > 200) return null;
		if (p.adds < 1) return null;

		// BCD score: mask nibbles (AND 0x0F), compare with 9/10, adjust with add 6
		boolean hasNibbleMask = false;
		boolean hasBcdAdjust = false;
		boolean hasCompare9or10 = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if (op.getOpcode() == PcodeOp.INT_AND && (v == 0x0F || v == 0xF0)) {
						hasNibbleMask = true;
					}
					if (op.getOpcode() == PcodeOp.INT_ADD && v == 6) {
						hasBcdAdjust = true;
					}
					if ((op.getOpcode() == PcodeOp.INT_LESS || op.getOpcode() == PcodeOp.INT_SLESS ||
						 op.getOpcode() == PcodeOp.INT_EQUAL) &&
						(v == 9 || v == 10 || v == 0x0A)) {
						hasCompare9or10 = true;
					}
				}
			}
		}

		if (!hasNibbleMask && !hasBcdAdjust && !hasCompare9or10) return null;

		double conf = 0.40;
		if (hasNibbleMask) conf += 0.15;
		if (hasBcdAdjust) conf += 0.20;
		if (hasCompare9or10) conf += 0.15;
		if (p.stores > 0) conf += 0.05;

		return new FunctionType("score_update", "bcd_score_update",
			Math.min(conf, 0.85),
			"BCD score addition/update");
	}

	/**
	 * Encryption/decryption: XOR-heavy with key scheduling pattern,
	 * or PRNG with large constant multiplier, or cipher round function.
	 */
	private FunctionType detectEncryptDecrypt(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;

		// Encryption indicators:
		// 1) Heavy XOR usage (cipher)
		// 2) Large constant in multiply (LCG/PRNG)
		// 3) Shift + XOR + AND combination (Feistel-like)
		double xorFrac = p.xors / (double) p.totalOps;
		boolean hasLCG = p.constLargeMultipliers > 0 || p.hasLargeConstMult;

		if (xorFrac < 0.05 && !hasLCG) return null;

		double conf = 0.40;
		if (xorFrac >= 0.10) conf += 0.20; // XOR-heavy is strong cipher indicator
		if (hasLCG) conf += 0.25; // known LCG constant
		if (p.hasLoop) conf += 0.10; // round/block iteration
		if (p.shifts >= 2) conf += 0.05; // bit mixing
		if (p.ands >= 2) conf += 0.05; // masking

		if (conf < 0.55) return null;

		return new FunctionType("encrypt_decrypt", "cipher_or_prng",
			Math.min(conf, 0.85),
			"Encryption/decryption or PRNG (" +
			(hasLCG ? "LCG constant detected" : "XOR-heavy cipher pattern") + ")");
	}

	/**
	 * Memmove (direction-aware copy): like memcpy but with address comparison
	 * to choose forward vs backward copy direction.
	 */
	private FunctionType detectMemmove(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 300 || p.totalOps < 20) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.compares < 1) return null;

		// Memmove: compare src/dst addresses, then copy forward or backward
		// Needs address comparison + two copy paths (2 loops or 2 branches)
		if (p.loopCount < 2 && p.cbranches < 2) return null;

		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (memBal < 0.3) return null;

		double conf = 0.45;
		if (p.loopCount >= 2) conf += 0.20; // forward + backward loops
		if (p.subs > 0) conf += 0.05; // address subtraction for direction
		if (p.lesses > 0 || p.sLesses > 0) conf += 0.10; // address comparison
		if (p.calls == 0) conf += 0.05;

		return new FunctionType("memmove", "memory_move_directional",
			Math.min(conf, 0.85),
			"Memory move (direction-aware copy)");
	}

	/**
	 * Hex dump/display: load bytes, convert to hex ASCII, output.
	 * Shift right by 4, AND with 0x0F, add ASCII offset, store/call print.
	 */
	private FunctionType detectHexDump(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15 || p.totalOps > 300) return null;
		if (p.loads < 2) return null;
		if (p.shifts < 1) return null;

		boolean hasNibbleExtract = false;
		boolean hasShiftBy4 = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if (op.getOpcode() == PcodeOp.INT_AND && v == 0x0F) hasNibbleExtract = true;
					if (op.getOpcode() == PcodeOp.INT_RIGHT && v == 4) hasShiftBy4 = true;
				}
			}
		}

		if (!hasNibbleExtract || !hasShiftBy4) return null;

		double conf = 0.50;
		if (p.constAsciiCompares > 0) conf += 0.10;
		if (p.hasLoop) conf += 0.10;
		if (p.calls > 0) conf += 0.05; // print call

		return new FunctionType("hex_dump", "hex_dump_display",
			Math.min(conf, 0.85),
			"Hex dump/display (nibble extraction + ASCII conversion)");
	}

	/**
	 * Dot product / vector math: paired multiplies + accumulate.
	 * P-code: multiple LOAD->LOAD->MULT->ADD sequences.
	 */
	private FunctionType detectDotProduct(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (p.mults < 2) return null;
		if (p.adds < 2) return null;
		if (p.loads < 4) return null;

		// Dot product: MULT -> ADD accumulation pattern
		int multAddPairs = 0;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_MULT) {
				for (int j = i + 1; j < Math.min(i + 3, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.INT_ADD) {
						multAddPairs++;
						break;
					}
				}
			}
		}

		if (multAddPairs < 2) return null;

		double conf = 0.45;
		if (multAddPairs >= 3) conf += 0.20; // 3+ multiply-accumulate = strong signal
		if (p.calls == 0) conf += 0.05;
		if (p.hasLoop) conf += 0.10; // vector iteration

		return new FunctionType("dot_product", "vector_dot_product",
			Math.min(conf, 0.85),
			"Dot product / multiply-accumulate (" + multAddPairs + " MAC pairs)");
	}

	// ================================================================
	// Expanded rule-based detectors (round 4 — from plexus, agfa, versabus, gas68k)
	// ================================================================

	/**
	 * Bitmap allocator: bit scan loop with shift/mask to find free bits,
	 * set/clear bit ranges. Common in filesystem and memory management.
	 */
	private FunctionType detectBitmapAllocator(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20) return null;
		if (p.shifts < 2) return null;
		if (p.ands < 2) return null;

		// Bitmap ops: shift to position, AND to test, OR to set, loop over bits/bytes
		double shiftFrac = p.shifts / (double) p.totalOps;
		double logicFrac = p.logic / (double) p.totalOps;
		if (shiftFrac < 0.05 || logicFrac < 0.05) return null;

		double conf = 0.40;
		if (p.ors > 0) conf += 0.10; // OR to set bits
		if (p.powerOf2Masks >= 1) conf += 0.10;
		if (p.compares >= 2) conf += 0.10; // boundary/full checks
		if (p.constSmallInts >= 2) conf += 0.05; // bit positions
		if (p.lefts > 0 && p.rights > 0) conf += 0.10; // bidirectional shifts

		if (conf < 0.55) return null;

		return new FunctionType("bitmap_allocator", "bitmap_bit_allocator",
			Math.min(conf, 0.85),
			"Bitmap allocator (bit scan/set/clear)");
	}

	/**
	 * Wildcard/glob pattern matching: character-by-character compare with
	 * special handling for '*' (0x2A) and '?' (0x3F) wildcards.
	 */
	private FunctionType detectWildcardMatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 300) return null;
		if (p.loads < 3) return null;
		if (p.compares < 3) return null;

		// Check for wildcard character constants
		boolean hasAsterisk = false;
		boolean hasQuestion = false;
		for (long c : p.constants) {
			if (c == 0x2A) hasAsterisk = true;   // '*'
			if (c == 0x3F) hasQuestion = true;    // '?'
		}

		if (!hasAsterisk && !hasQuestion) return null;

		double conf = 0.45;
		if (hasAsterisk) conf += 0.20;
		if (hasQuestion) conf += 0.10;
		if (p.constZeroCompares >= 1) conf += 0.05; // null terminator
		if (p.cbranches >= 4) conf += 0.10; // many branch paths for wildcard cases

		return new FunctionType("wildcard_match", "wildcard_pattern_match",
			Math.min(conf, 0.85),
			"Wildcard/glob pattern matching (" +
			(hasAsterisk ? "*" : "") + (hasQuestion ? "?" : "") + " wildcards)");
	}

	/**
	 * Message passing IPC: send/receive pattern with queue operations.
	 * Load message pointer, enqueue, signal receiver, context switch.
	 */
	private FunctionType detectMessagePassing(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.compares < 2) return null;

		// IPC: pointer manipulation (loads/stores), queue insert (store next ptr),
		// possibly signal (call or CALLOTHER for TRAP), null checks
		boolean hasQueuePattern = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			// LOAD -> STORE -> STORE (link pointer update)
			if (pcode[i].getOpcode() == PcodeOp.LOAD &&
				pcode[i+1].getOpcode() == PcodeOp.STORE &&
				pcode[i+2].getOpcode() == PcodeOp.STORE) {
				hasQueuePattern = true;
				break;
			}
		}

		if (!hasQueuePattern && p.callOtherCount == 0) return null;

		double conf = 0.40;
		if (hasQueuePattern) conf += 0.20;
		if (p.constZeroCompares >= 2) conf += 0.10; // null/empty checks
		if (p.callOtherCount > 0) conf += 0.10; // TRAP for IPC
		if (p.stores >= 4) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("message_passing", "ipc_message_queue",
			Math.min(conf, 0.85),
			"Message passing / IPC queue operation");
	}

	/**
	 * Watchdog timer: very small function that writes to a specific IO register
	 * to feed/clear the watchdog. Minimal logic, just store + return.
	 */
	private FunctionType detectWatchdogFeed(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 40 || p.totalOps < 5) return null;
		if (p.stores < 1) return null;
		if (p.ioRegionAccesses < 1) return null;

		// Watchdog: tiny function, write to IO, return
		if (p.calls > 1) return null; // should be leaf or near-leaf

		double conf = 0.45;
		if (p.totalOps < 15) conf += 0.15; // very small
		if (p.returns >= 1) conf += 0.05;
		if (p.stores <= 3) conf += 0.10; // just a few writes

		return new FunctionType("watchdog", "watchdog_feed",
			Math.min(conf, 0.80),
			"Watchdog timer feed/clear");
	}

	/**
	 * Device driver dispatch: function pointer table indexed by device/command,
	 * CALLIND or BRANCHIND after table load.
	 */
	private FunctionType detectDeviceDriverDispatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (p.loads < 2) return null;

		// Device dispatch: load from table, indirect call or branch
		boolean hasIndirectDispatch = p.callInds > 0 || p.branchInds > 0;
		if (!hasIndirectDispatch) return null;

		double conf = 0.45;
		if (p.compares >= 1) conf += 0.10; // bounds check on command/device id
		if (p.lefts > 0 || p.mults > 0) conf += 0.10; // index scaling
		if (p.callInds > 0) conf += 0.10; // indirect call
		if (p.loads >= 3) conf += 0.05;

		return new FunctionType("device_dispatch", "device_driver_dispatch",
			Math.min(conf, 0.85),
			"Device driver dispatch (indirect call through table)");
	}

	/**
	 * Parity computation: XOR reduction over bytes/words to compute parity bit.
	 * Small function with XOR chain and shift.
	 */
	private FunctionType detectParityCompute(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 100 || p.totalOps < 8) return null;
		if (p.xors < 2) return null;
		if (p.shifts < 1) return null;

		// Parity: chain of XOR + shift to reduce to single bit
		double xorFrac = p.xors / (double) p.totalOps;
		if (xorFrac < 0.08) return null;

		double conf = 0.45;
		if (p.xors >= 3) conf += 0.15;
		if (p.rights >= 2) conf += 0.10; // shifting down bits
		if (p.ands >= 1) conf += 0.10; // final AND 1
		if (p.calls == 0) conf += 0.05;

		return new FunctionType("parity", "parity_computation",
			Math.min(conf, 0.85),
			"Parity bit computation (XOR reduction)");
	}

	/**
	 * Delay/timing loop: calibrated busy-wait with counter decrement.
	 * Very simple: load count, decrement, compare, branch back.
	 * Distinguished from busyWaitLoop by absence of IO reads.
	 */
	private FunctionType detectDelayLoop(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 60 || p.totalOps < 5) return null;
		if (p.ioRegionAccesses > 0) return null; // that's busyWaitLoop instead
		if (p.calls > 0) return null;

		// Pure delay: decrement counter in loop, no other work
		double arithFrac = (p.subs + p.adds) / (double) p.totalOps;
		double brFrac = (p.cbranches + p.branches) / (double) p.totalOps;
		if (arithFrac < 0.08 || brFrac < 0.08) return null;

		// Should be very simple — mostly arithmetic + branch
		int nonEssential = p.loads + p.stores + p.calls + p.mults + p.divs;
		if (nonEssential > p.totalOps / 3) return null;

		double conf = 0.45;
		if (p.totalOps < 20) conf += 0.15;
		if (p.loopCount == 1) conf += 0.10;
		if (p.subs > 0) conf += 0.10; // decrement

		return new FunctionType("delay_loop", "calibrated_delay",
			Math.min(conf, 0.85),
			"Calibrated delay/timing loop");
	}

	/**
	 * Executable/image loader: validates magic number, relocates addresses,
	 * copies code to RAM, jumps to entry point. Sequence of checks + memcpy + call.
	 */
	private FunctionType detectImageLoader(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.loads < 5) return null;
		if (p.compares < 2) return null;
		if (p.calls < 1) return null;

		// Image loader: load header fields, compare magic, compute sizes,
		// copy data, call entry point
		boolean hasMagicCheck = false;
		for (long c : p.constants) {
			// Common magic numbers: 0x3399, 0x7F454C46 (ELF), 0xFEEDFACE, 0x0107 (a.out)
			if (c == 0x3399L || c == 0x7F454C46L || c == 0xFEEDFACEL ||
				c == 0x0107L || c == 0x010BL || c == 0x0108L ||
				c == 0xCAFEBABEL || c == 0x4D5AL) { // MZ DOS
				hasMagicCheck = true;
				break;
			}
		}

		double conf = 0.40;
		if (hasMagicCheck) conf += 0.25;
		if (p.adds >= 3) conf += 0.10; // relocation offsets
		if (p.calls >= 2) conf += 0.05; // copy + execute
		if (p.cbranches >= 3) conf += 0.10; // validation branches

		if (conf < 0.55) return null;

		return new FunctionType("image_loader", "executable_loader",
			Math.min(conf, 0.85),
			"Executable/image loader (magic check + relocate" +
			(hasMagicCheck ? " — known magic detected" : "") + ")");
	}

	/**
	 * Context save/restore: bulk register save or restore to/from stack or
	 * memory block. Long run of consecutive stores (save) or loads (restore).
	 */
	private FunctionType detectContextSaveRestore(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;

		// Context save: long consecutive store run (saving registers)
		// Context restore: long consecutive load run (restoring registers)
		boolean isSave = p.consecutiveStores >= 6;
		boolean isRestore = p.consecutiveLoads >= 6;
		if (!isSave && !isRestore) return null;

		// Should be dominated by memory ops
		double memFrac = p.memory / (double) p.totalOps;
		if (memFrac < 0.30) return null;

		double conf = 0.45;
		if (isSave && p.consecutiveStores >= 8) conf += 0.20;
		if (isRestore && p.consecutiveLoads >= 8) conf += 0.20;
		if (isSave && isRestore) conf += 0.10; // full save+restore
		if (p.returns >= 1) conf += 0.05;

		String type = isSave && isRestore ? "save+restore" : (isSave ? "save" : "restore");
		return new FunctionType("context_switch", "context_" + (isSave ? "save" : "restore"),
			Math.min(conf, 0.85),
			"Register context " + type + " (" +
			(isSave ? p.consecutiveStores + " consecutive stores" : "") +
			(isSave && isRestore ? ", " : "") +
			(isRestore ? p.consecutiveLoads + " consecutive loads" : "") + ")");
	}

	/**
	 * Filesystem block mapping: indirect block traversal for Unix-style
	 * filesystems. Division/modulo to compute block indices, nested loads
	 * for single/double/triple indirect blocks.
	 */
	private FunctionType detectBlockMapping(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.loads < 4) return null;
		if (p.compares < 2) return null;

		// Block mapping: divide by block_entries to get level, modulo for index,
		// load indirect block, repeat. Multiple compare-and-branch for levels.
		boolean hasDivOrShift = p.divs > 0 || p.rights >= 2;
		if (!hasDivOrShift && p.rems == 0) return null;

		double conf = 0.40;
		if (p.divs > 0 || p.rems > 0) conf += 0.15; // block index computation
		if (p.cbranches >= 3) conf += 0.10; // level selection branches
		if (p.loads >= 6) conf += 0.10; // chained block loads
		if (p.calls >= 1) conf += 0.05; // call to read block

		if (conf < 0.55) return null;

		return new FunctionType("block_mapping", "filesystem_block_map",
			Math.min(conf, 0.85),
			"Filesystem block mapping (indirect block traversal)");
	}

	/**
	 * Checksum with validation: compute checksum then compare against stored
	 * value. Combination of checksum accumulation + final compare.
	 */
	private FunctionType detectChecksumValidation(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15) return null;
		if (p.loads < 3) return null;
		if (p.compares < 1) return null;

		// Checksum + validate: accumulate loop, then compare result against stored
		int accumPattern = 0;
		for (int i = 0; i < pcode.length - 1; i++) {
			int o1 = pcode[i].getOpcode();
			int o2 = pcode[i+1].getOpcode();
			if (o1 == PcodeOp.LOAD && (o2 == PcodeOp.INT_ADD || o2 == PcodeOp.INT_XOR)) {
				accumPattern++;
			}
		}

		if (accumPattern < 2) return null;

		// Look for final comparison after loop
		boolean hasPostLoopCompare = false;
		for (int i = pcode.length - 1; i >= Math.max(0, pcode.length - 10); i--) {
			if (pcode[i].getOpcode() == PcodeOp.INT_EQUAL ||
				pcode[i].getOpcode() == PcodeOp.INT_NOTEQUAL) {
				hasPostLoopCompare = true;
				break;
			}
		}

		double conf = 0.45;
		if (accumPattern >= 3) conf += 0.10;
		if (hasPostLoopCompare) conf += 0.20;
		if (p.xors > 0 || p.adds > 2) conf += 0.05;

		return new FunctionType("checksum_validate", "checksum_and_verify",
			Math.min(conf, 0.90),
			"Checksum computation + validation (accumulate then verify)");
	}

	/**
	 * SCSI command: selection phase, command send, data transfer, status read.
	 * Sequential IO register accesses with polling loops between phases.
	 */
	private FunctionType detectScsiCommand(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.ioRegionAccesses < 4) return null;
		if (p.cbranches < 3) return null;

		// SCSI: many IO accesses (register read/write), polling loops, phase checks
		double ioFrac = p.ioRegionAccesses / (double) p.totalOps;
		if (ioFrac < 0.04) return null;

		double conf = 0.40;
		if (p.ioRegionAccesses >= 8) conf += 0.20;
		if (p.hasLoop) conf += 0.10; // polling
		if (p.ands >= 2) conf += 0.05; // status bit checks
		if (p.compares >= 4) conf += 0.10; // phase/status checks
		if (p.cbranches >= 5) conf += 0.05;

		return new FunctionType("scsi_command", "scsi_bus_operation",
			Math.min(conf, 0.85),
			"SCSI bus operation (" + p.ioRegionAccesses + " register accesses)");
	}

	/**
	 * Stack-based interpreter: PostScript-like operand stack machine.
	 * Heavy load/store to stack area, type checks, operator dispatch.
	 */
	private FunctionType detectStackInterpreter(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 50) return null;
		if (!p.hasLoop) return null;
		if (p.compares < 5) return null;

		// Stack interpreter: many type checks (compare), dispatch (branch/call),
		// stack manipulation (load/store to offset from base)
		double cmpFrac = p.compares / (double) p.totalOps;
		double callFrac = (p.calls + p.callInds) / (double) p.totalOps;
		if (cmpFrac < 0.05) return null;

		// Distinguished from bytecodeInterpreter by having more loads than calls
		// (stack machine pops/pushes operands vs calling handlers)
		double conf = 0.40;
		if (p.loads >= 8) conf += 0.10;
		if (p.stores >= 5) conf += 0.10;
		if (p.cbranch_eq_runs >= 4) conf += 0.10; // type dispatch
		if (p.adds >= 3) conf += 0.05; // stack pointer manipulation
		if (p.branchInds > 0 || p.callInds > 0) conf += 0.15; // operator dispatch

		if (conf < 0.60) return null;

		return new FunctionType("stack_interpreter", "stack_based_interpreter",
			Math.min(conf, 0.85),
			"Stack-based interpreter (operand stack + operator dispatch)");
	}

	/**
	 * Retry loop: call operation, check result, retry on failure up to N times.
	 * Common in SCSI, network, and disk I/O.
	 */
	private FunctionType detectRetryLoop(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15 || p.totalOps > 200) return null;
		if (p.calls < 1) return null;
		if (p.compares < 2) return null;

		// Retry: CALL -> compare result -> branch back if fail, decrement counter
		int callThenCheck = 0;
		for (int i = 0; i < pcode.length - 3; i++) {
			if (pcode[i].getOpcode() == PcodeOp.CALL) {
				for (int j = i + 1; j < Math.min(i + 4, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.CBRANCH) {
						callThenCheck++;
						break;
					}
				}
			}
		}

		if (callThenCheck < 1) return null;

		double conf = 0.40;
		if (callThenCheck >= 2) conf += 0.15;
		if (p.subs > 0) conf += 0.10; // retry count decrement
		if (p.constZeroCompares >= 1) conf += 0.10; // retry exhaustion check
		if (p.loopCount >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("retry_loop", "operation_with_retry",
			Math.min(conf, 0.85),
			"Operation with retry loop (" + callThenCheck + " call-then-check)");
	}

	// ================================================================
	// Expanded rule-based detectors (round 5)
	// ================================================================

	/**
	 * Text renderer: loads character codes from string, looks up glyph/tile,
	 * writes to display buffer or VDP. Loop with load + shift/mask + store.
	 */
	private FunctionType detectTextRenderer(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15 || p.totalOps > 400) return null;
		if (p.loads < 3 || p.stores < 2) return null;

		double conf = 0.40;
		if (p.constAsciiCompares >= 1) conf += 0.10;
		if (p.constZeroCompares >= 1) conf += 0.10; // null terminator
		if (p.adds >= 2) conf += 0.05; // pointer advance
		if (p.ands >= 1 || p.shifts >= 1) conf += 0.05; // character masking
		if (p.calls >= 1) conf += 0.10; // call to putchar/draw glyph

		if (conf < 0.55) return null;
		return new FunctionType("text_renderer", "draw_text_string",
			Math.min(conf, 0.80),
			"Text string renderer (character loop)");
	}

	/**
	 * Menu navigation: read input, update cursor position, highlight selection.
	 * Moderate function with input read + compare + bounded arithmetic + store.
	 */
	private FunctionType detectMenuNavigation(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20 || p.totalOps > 400) return null;
		if (p.compares < 3) return null;
		if (p.cbranches < 3) return null;
		if (p.loads < 3 || p.stores < 2) return null;

		// Menu: many comparisons (up/down/left/right/select), bounded increments
		boolean hasBoundedIncrement = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			int o1 = pcode[i].getOpcode();
			int o2 = pcode[i+1].getOpcode();
			int o3 = pcode[i+2].getOpcode();
			if ((o1 == PcodeOp.INT_ADD || o1 == PcodeOp.INT_SUB) &&
				(o2 == PcodeOp.INT_LESS || o2 == PcodeOp.INT_SLESS || o2 == PcodeOp.INT_EQUAL) &&
				o3 == PcodeOp.CBRANCH) {
				hasBoundedIncrement = true;
				break;
			}
		}

		double conf = 0.40;
		if (hasBoundedIncrement) conf += 0.20;
		if (p.constSmallInts >= 3) conf += 0.10; // menu item indices
		if (p.calls >= 2) conf += 0.05; // draw/sound calls
		if (p.ioRegionAccesses >= 1) conf += 0.05; // input read

		if (conf < 0.55) return null;
		return new FunctionType("menu_navigation", "menu_input_handler",
			Math.min(conf, 0.80),
			"Menu navigation / input handler");
	}

	/**
	 * Camera/scroll tracking: load player position, compute offset from
	 * center, clamp to map bounds, store scroll registers.
	 */
	private FunctionType detectCameraTracking(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15 || p.totalOps > 250) return null;
		if (p.loads < 3 || p.stores < 2) return null;
		if (p.subs < 1 || p.adds < 1) return null;

		// Camera: load pos, subtract half-screen, clamp, store
		boolean hasClamp = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			int o1 = pcode[i].getOpcode();
			int o2 = pcode[i+1].getOpcode();
			if ((o1 == PcodeOp.INT_SLESS || o1 == PcodeOp.INT_LESS) &&
				o2 == PcodeOp.CBRANCH) {
				hasClamp = true;
				break;
			}
		}

		double conf = 0.40;
		if (hasClamp) conf += 0.15;
		if (p.subs >= 2) conf += 0.10; // center offset + bounds check
		if (p.compares >= 2) conf += 0.10;
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.55) return null;
		return new FunctionType("camera_tracking", "camera_scroll_update",
			Math.min(conf, 0.80),
			"Camera/scroll position tracking");
	}

	/**
	 * Object pool spawn: scan array for free slot (compare with 0/flag),
	 * initialize fields, return slot pointer.
	 */
	private FunctionType detectObjectSpawn(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15 || p.totalOps > 300) return null;
		if (p.loads < 3 || p.stores < 3) return null;
		if (p.constZeroCompares < 1) return null;

		double conf = 0.40;
		if (p.constZeroCompares >= 2) conf += 0.15; // free slot check (== 0)
		if (p.stores >= 4) conf += 0.10; // initializing fields
		if (p.adds >= 2) conf += 0.05; // pointer stride
		if (p.consecutiveStores >= 3) conf += 0.10; // field init block

		if (conf < 0.55) return null;
		return new FunctionType("object_spawn", "allocate_object_slot",
			Math.min(conf, 0.80),
			"Object pool allocation (scan for free slot + init)");
	}

	/**
	 * Flash programming: write data, poll status register in tight loop,
	 * verify written data. IO accesses + polling loop + verify compare.
	 */
	private FunctionType detectFlashProgram(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.stores < 2) return null;
		if (!p.hasLoop) return null;

		// Flash: write command sequence, poll status, write data, verify
		boolean hasStatusPoll = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD &&
				(pcode[i+1].getOpcode() == PcodeOp.INT_AND ||
				 pcode[i+1].getOpcode() == PcodeOp.INT_EQUAL) &&
				pcode[i+2].getOpcode() == PcodeOp.CBRANCH) {
				hasStatusPoll = true;
				break;
			}
		}

		if (!hasStatusPoll) return null;

		double conf = 0.45;
		if (p.ands >= 2) conf += 0.10; // status bit checks
		if (p.stores >= 3) conf += 0.10; // command + data writes
		if (p.compares >= 2) conf += 0.05;

		return new FunctionType("flash_program", "flash_write_sector",
			Math.min(conf, 0.85),
			"Flash memory programming (write + status poll + verify)");
	}

	/**
	 * Interrupt enable/disable: very short function that manipulates
	 * interrupt mask or status register. Often via CALLOTHER (for SR access).
	 */
	private FunctionType detectInterruptControl(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 25 || p.totalOps < 3) return null;

		// Interrupt control: tiny, often uses CALLOTHER for privileged register access
		// or AND/OR on IO register to set/clear interrupt enable bits
		boolean hasPrivOp = p.callOtherCount > 0;
		boolean hasMaskOp = (p.ands >= 1 || p.ors >= 1) &&
			(p.ioRegionAccesses >= 1 || p.stores >= 1);

		if (!hasPrivOp && !hasMaskOp) return null;

		double conf = 0.45;
		if (hasPrivOp) conf += 0.15;
		if (hasMaskOp) conf += 0.15;
		if (p.totalOps < 12) conf += 0.10;

		return new FunctionType("interrupt_control", "interrupt_enable_disable",
			Math.min(conf, 0.80),
			"Interrupt enable/disable");
	}

	/**
	 * Absolute value: test sign, negate if negative. Very small, no loop.
	 * P-code: compare with 0, branch, INT_2COMP/INT_NEGATE.
	 */
	private FunctionType detectAbsValue(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 30 || p.totalOps < 5) return null;
		if (p.negates < 1) return null;
		if (p.compares < 1 && p.sLesses < 1) return null;
		if (p.hasLoop) return null;

		double conf = 0.50;
		if (p.cbranches >= 1) conf += 0.15;
		if (p.constZeroCompares >= 1) conf += 0.10;
		if (p.totalOps < 15) conf += 0.10;

		return new FunctionType("abs_value", "absolute_value",
			Math.min(conf, 0.80),
			"Absolute value computation");
	}

	/**
	 * Min/max or clamp: compare two values, conditional move/branch to select.
	 * Small, no loop. May appear as clamp (compare against both min and max).
	 */
	private FunctionType detectClampMinMax(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 50 || p.totalOps < 6) return null;
		if (p.compares < 1) return null;
		if (p.cbranches < 1) return null;
		if (p.hasLoop) return null;

		// Clamp: two comparisons (min and max bounds)
		boolean isClamp = p.compares >= 2 && p.cbranches >= 2;
		boolean isMinMax = p.compares >= 1 && p.copies >= 1;

		if (!isClamp && !isMinMax) return null;

		double conf = 0.45;
		if (isClamp) conf += 0.20;
		if (p.sLesses > 0) conf += 0.10; // signed comparison
		if (p.totalOps < 20) conf += 0.05;

		return new FunctionType("clamp", isClamp ? "clamp_range" : "min_max",
			Math.min(conf, 0.80),
			isClamp ? "Value clamp to range" : "Min/max selection");
	}

	/**
	 * Byte/word swap (endian conversion): shift left/right by 8, mask, OR.
	 * Small function, no loop, shift + mask + combine pattern.
	 */
	private FunctionType detectByteSwap(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 40 || p.totalOps < 5) return null;
		if (p.shifts < 2) return null;
		if (p.hasLoop) return null;

		// Byte swap: shift left 8 + shift right 8 + OR (or AND + OR)
		boolean hasLeft8 = false, hasRight8 = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_LEFT || op.getOpcode() == PcodeOp.INT_RIGHT) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					if (in != null && in.isConstant() && in.getOffset() == 8) {
						if (op.getOpcode() == PcodeOp.INT_LEFT) hasLeft8 = true;
						else hasRight8 = true;
					}
				}
			}
		}

		if (!hasLeft8 || !hasRight8) return null;

		double conf = 0.55;
		if (p.ors >= 1) conf += 0.15; // combine halves
		if (p.ands >= 1) conf += 0.05; // mask
		if (p.totalOps < 20) conf += 0.05;

		return new FunctionType("byte_swap", "endian_swap",
			Math.min(conf, 0.85),
			"Byte/endian swap (shift-8 + combine)");
	}

	/**
	 * VBlank wait: poll VDP status register in tight loop until vblank flag set.
	 * Small function with IO load + mask + branch.
	 */
	private FunctionType detectVblankWait(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps > 40 || p.totalOps < 5) return null;
		if (p.ioRegionAccesses < 1) return null;
		if (p.ands < 1 && p.compares < 1) return null;

		// Very tight: IO load + bit test + branch back
		int nonEssential = p.stores + p.calls + p.mults + p.divs + p.subs;
		if (nonEssential > p.totalOps / 2) return null;

		double conf = 0.50;
		if (p.totalOps < 15) conf += 0.15;
		if (p.loopCount == 1) conf += 0.05;
		if (p.ands >= 1) conf += 0.10; // bit test

		return new FunctionType("vblank_wait", "wait_for_vblank",
			Math.min(conf, 0.85),
			"VBlank wait (poll VDP status register)");
	}

	/**
	 * DMA queue enqueue: build DMA descriptor (source, dest, length),
	 * add to queue. Moderate stores to structured buffer.
	 */
	private FunctionType detectDmaQueueEnqueue(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 12 || p.totalOps > 100) return null;
		if (p.stores < 3) return null;

		// DMA queue: write source, dest, length fields to descriptor struct
		// then advance queue pointer
		double conf = 0.40;
		if (p.consecutiveStores >= 3) conf += 0.15;
		if (p.adds >= 1) conf += 0.10; // queue pointer advance
		if (p.compares >= 1) conf += 0.05; // queue full check
		if (p.ioRegionAccesses >= 1) conf += 0.10; // DMA register

		if (conf < 0.55) return null;
		return new FunctionType("dma_queue", "dma_queue_enqueue",
			Math.min(conf, 0.80),
			"DMA queue enqueue (build descriptor)");
	}

	/**
	 * Error/panic handler: stores registers, outputs message, halts or resets.
	 * Sequential stores + call to print + infinite loop or reset.
	 */
	private FunctionType detectErrorHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;
		if (p.stores < 2) return null;

		// Error handler: save state (consecutive stores), call print/log, halt
		boolean hasInfiniteLoop = false;
		for (int i = 0; i < pcode.length - 1; i++) {
			if (pcode[i].getOpcode() == PcodeOp.BRANCH) {
				Varnode target = pcode[i].getInput(0);
				if (target != null && target.isAddress()) {
					Address tgt = target.getAddress();
					Address here = pcode[i].getSeqnum().getTarget();
					if (here != null && tgt.equals(here)) {
						hasInfiniteLoop = true; // branch to self = halt
						break;
					}
				}
			}
		}

		double conf = 0.40;
		if (hasInfiniteLoop) conf += 0.25;
		if (p.consecutiveStores >= 4) conf += 0.10; // register dump
		if (p.calls >= 1) conf += 0.10; // print/log call
		if (p.returns == 0 && hasInfiniteLoop) conf += 0.05; // never returns

		if (conf < 0.55) return null;
		return new FunctionType("error_handler", "panic_or_fatal_error",
			Math.min(conf, 0.85),
			"Error/panic handler" + (hasInfiniteLoop ? " (halts)" : ""));
	}

	/**
	 * ADPCM decoder: step table lookup, delta computation with shift/add,
	 * predictor update, clamp output.
	 */
	private FunctionType detectAdpcmDecode(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 25) return null;
		if (p.shifts < 2) return null;
		if (p.loads < 3 || p.stores < 2) return null;

		// ADPCM: nibble extraction (AND 0x0F, shift right 4),
		// step table indexed load, delta accumulation, clamp
		boolean hasNibbleExtract = false;
		boolean hasShift4 = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if (op.getOpcode() == PcodeOp.INT_AND && v == 0x0F) hasNibbleExtract = true;
					if (op.getOpcode() == PcodeOp.INT_RIGHT && v == 4) hasShift4 = true;
				}
			}
		}

		if (!hasNibbleExtract && !hasShift4) return null;

		double conf = 0.40;
		if (hasNibbleExtract && hasShift4) conf += 0.20;
		if (p.adds >= 2) conf += 0.05; // delta accumulation
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.10; // clamp
		if (p.rights >= 2) conf += 0.05; // step shifts

		if (conf < 0.55) return null;
		return new FunctionType("adpcm_decode", "adpcm_audio_decoder",
			Math.min(conf, 0.85),
			"ADPCM audio decoder (nibble extract + step table)");
	}

	/**
	 * Debounce input: read value, delay, read again, compare for match.
	 * Small function with two reads separated by delay/NOP.
	 */
	private FunctionType detectDebounceInput(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps > 60 || p.totalOps < 8) return null;
		if (p.loads < 2) return null;
		if (p.compares < 1) return null;

		// Debounce: load -> (delay or NOP) -> load -> compare
		int loadPairs = 0;
		for (int i = 0; i < pcode.length - 3; i++) {
			if (pcode[i].getOpcode() == PcodeOp.LOAD) {
				for (int j = i + 2; j < Math.min(i + 8, pcode.length); j++) {
					if (pcode[j].getOpcode() == PcodeOp.LOAD) {
						for (int k = j + 1; k < Math.min(j + 3, pcode.length); k++) {
							if (pcode[k].getOpcode() == PcodeOp.INT_EQUAL ||
								pcode[k].getOpcode() == PcodeOp.INT_NOTEQUAL) {
								loadPairs++;
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (loadPairs < 1) return null;

		double conf = 0.50;
		if (loadPairs >= 1) conf += 0.15;
		if (p.hasLoop) conf += 0.10; // retry loop
		if (p.ioRegionAccesses >= 1) conf += 0.10;

		return new FunctionType("debounce", "debounced_input_read",
			Math.min(conf, 0.85),
			"Debounced input read (read-delay-compare)");
	}

	/**
	 * CRC with lookup table: 256-entry table indexed by XOR of data byte
	 * with CRC low byte. Table-driven CRC is distinguished by indexed LOAD
	 * inside a tight loop with XOR.
	 */
	private FunctionType detectCrcTableLookup(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15) return null;
		if (p.loads < 3) return null;
		if (p.xors < 1) return null;

		// CRC table: LOAD data, XOR with CRC, mask to byte (AND 0xFF),
		// LOAD from table[index], XOR into CRC, loop
		boolean hasAnd0xFF = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_AND) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					if (in != null && in.isConstant() && in.getOffset() == 0xFF) {
						hasAnd0xFF = true;
					}
				}
			}
		}

		if (!hasAnd0xFF) return null;

		double conf = 0.45;
		if (p.xors >= 2) conf += 0.15;
		if (p.lefts > 0 || p.rights > 0) conf += 0.05; // CRC shift
		if (p.loads >= 4) conf += 0.10; // data + table loads
		if (p.loopCount == 1) conf += 0.05;

		return new FunctionType("crc_table", "crc_table_lookup",
			Math.min(conf, 0.85),
			"CRC with lookup table (byte-indexed XOR)");
	}

	/**
	 * Coordinate transform: multiply pairs of coordinates by matrix elements,
	 * add offsets. Multiple multiply-add sequences for X' = aX + bY + c.
	 */
	private FunctionType detectCoordinateTransform(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.mults < 2) return null;
		if (p.adds < 2) return null;
		if (p.loads < 4) return null;

		// Matrix multiply: load coord, load matrix elem, multiply, add to accumulator
		double multFrac = p.mults / (double) p.totalOps;
		double addFrac = p.adds / (double) p.totalOps;
		if (multFrac < 0.04) return null;

		double conf = 0.40;
		if (p.mults >= 4) conf += 0.20; // 2x2 or 3x3 matrix
		if (p.adds >= 4) conf += 0.10;
		if (p.stores >= 2) conf += 0.05; // store transformed coords
		if (p.shifts > 0) conf += 0.05; // fixed-point scaling

		if (conf < 0.55) return null;
		return new FunctionType("coord_transform", "coordinate_transform",
			Math.min(conf, 0.85),
			"Coordinate/matrix transform (" + p.mults + " multiplies)");
	}

	/**
	 * IP checksum (RFC 791): 16-bit ones-complement sum with carry fold.
	 * Loop adding 16-bit words, fold carry, complement result.
	 */
	private FunctionType detectIpChecksum(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15 || p.totalOps > 100) return null;
		if (p.loads < 2) return null;
		if (p.adds < 2) return null;

		// IP checksum: add 16-bit words in loop, then fold carry:
		// (sum >> 16) + (sum & 0xFFFF), then complement
		boolean has0xFFFF = false;
		boolean hasShift16 = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if (op.getOpcode() == PcodeOp.INT_AND && v == 0xFFFFL) has0xFFFF = true;
					if (op.getOpcode() == PcodeOp.INT_RIGHT && v == 16) hasShift16 = true;
				}
			}
		}

		if (!has0xFFFF && !hasShift16) return null;

		double conf = 0.45;
		if (has0xFFFF) conf += 0.15;
		if (hasShift16) conf += 0.15;
		if (p.negates > 0) conf += 0.10; // ones-complement

		return new FunctionType("ip_checksum", "ip_header_checksum",
			Math.min(conf, 0.85),
			"IP/ones-complement checksum (16-bit fold + complement)");
	}

	/**
	 * Hash function: multiply by prime + XOR/add with input bytes, loop.
	 * Distinguished from RNG by being a function of input data, not seed-only.
	 */
	private FunctionType detectHashFunction(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 12) return null;
		if (p.loads < 2) return null;

		// Hash: load byte -> multiply/shift by prime -> XOR/add -> loop
		boolean hasPrimeMult = false;
		boolean hasHashAdd = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					// Common hash primes/multipliers
					if (op.getOpcode() == PcodeOp.INT_MULT &&
						(v == 31 || v == 37 || v == 65599 || v == 33 || v == 5381 ||
						 v == 0x01000193L || v == 16777619L || v == 2166136261L)) {
						hasPrimeMult = true;
					}
				}
			}
			if (op.getOpcode() == PcodeOp.INT_XOR || op.getOpcode() == PcodeOp.INT_ADD) {
				hasHashAdd = true;
			}
		}

		if (!hasPrimeMult) return null;
		if (!hasHashAdd) return null;

		double conf = 0.55;
		if (p.xors > 0) conf += 0.10;
		if (p.loads >= 3) conf += 0.05;

		return new FunctionType("hash_function", "hash_computation",
			Math.min(conf, 0.85),
			"Hash function (multiply by prime + accumulate)");
	}

	/**
	 * Palette cycle/rotation: load palette array, rotate entries by offset,
	 * store back. Loop with index arithmetic and modular wrap.
	 */
	private FunctionType detectPaletteCycle(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 15 || p.totalOps > 200) return null;
		if (p.loads < 3 || p.stores < 3) return null;

		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);
		if (memBal < 0.4) return null;

		// Palette cycle: balanced load/store, small arithmetic, modular index
		double conf = 0.40;
		if (p.adds >= 2) conf += 0.10;
		if (p.powerOf2Masks >= 1 || p.rems > 0) conf += 0.15; // modular wrap
		if (p.loadStoreAlternations >= 2) conf += 0.10;
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.55) return null;
		return new FunctionType("palette_cycle", "palette_rotation",
			Math.min(conf, 0.80),
			"Palette color cycling / rotation");
	}

	/**
	 * Sprintf/format: walks format string character by character, dispatches
	 * on '%' specifiers, builds output buffer. Large with many ASCII compares.
	 */
	private FunctionType detectSprintf(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 40) return null;
		if (p.constAsciiCompares < 3) return null;
		if (p.cbranches < 4) return null;

		// sprintf: check for '%' (0x25), 'd' (0x64), 'x' (0x78), 's' (0x73), etc.
		boolean hasPercent = false;
		for (long c : p.constants) {
			if (c == 0x25) { hasPercent = true; break; } // '%'
		}

		double conf = 0.40;
		if (hasPercent) conf += 0.20;
		if (p.constAsciiCompares >= 5) conf += 0.15;
		if (p.stores >= 3) conf += 0.05; // output buffer writes
		if (p.calls >= 1) conf += 0.05; // conversion subroutines

		if (conf < 0.55) return null;
		return new FunctionType("sprintf", "sprintf_format",
			Math.min(conf, 0.85),
			"Sprintf/format string processor" +
			(hasPercent ? " ('%' format dispatch)" : ""));
	}

	/**
	 * RLE decompression: load control byte, check flag bit for literal vs run,
	 * copy literal bytes or fill run. Loop with two paths.
	 */
	private FunctionType detectRleDecompress(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 300) return null;
		if (p.loads < 3 || p.stores < 2) return null;
		if (p.cbranches < 2) return null;

		// RLE: load control byte, test high bit (AND 0x80 or shift right 7),
		// branch for run vs literal, inner copy loop
		boolean hasHighBitTest = false;
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in != null && in.isConstant()) {
					long v = in.getOffset();
					if (op.getOpcode() == PcodeOp.INT_AND && (v == 0x80 || v == 0x7F)) {
						hasHighBitTest = true;
					}
					if (op.getOpcode() == PcodeOp.INT_RIGHT && v == 7) {
						hasHighBitTest = true;
					}
				}
			}
		}

		double conf = 0.40;
		if (hasHighBitTest) conf += 0.20;
		if (p.loopCount >= 2) conf += 0.10; // outer control + inner copy loops
		if (p.ands >= 2) conf += 0.05; // mask length from control byte
		if (p.loadStoreAlternations >= 2) conf += 0.10; // copy pattern

		if (conf < 0.55) return null;
		return new FunctionType("rle_decompress", "rle_decompressor",
			Math.min(conf, 0.85),
			"RLE decompression (control byte + run/literal)");
	}

	/**
	 * LZ decompression: sliding window with back-reference. Distinguished by
	 * distance/length extraction from packed fields + window-relative copy.
	 */
	private FunctionType detectLzDecompress(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 30) return null;
		if (p.loads < 4 || p.stores < 3) return null;
		if (p.shifts < 2) return null;
		if (p.ands < 2) return null;

		// LZ: unpack distance/length (shift + mask), copy from window buffer
		boolean has0xFFF = false;
		boolean has0xF = false;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_AND) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					if (in != null && in.isConstant()) {
						long v = in.getOffset();
						if (v == 0xFFF || v == 0x0FFF) has0xFFF = true;
						if (v == 0x0F || v == 0xF) has0xF = true;
					}
				}
			}
		}

		double conf = 0.40;
		if (has0xFFF && has0xF) conf += 0.25; // 12-bit distance + 4-bit length
		if (p.loopCount >= 2) conf += 0.10; // outer decode + inner copy loops
		if (p.subs > 0) conf += 0.05; // window offset computation
		if (p.powerOf2Masks >= 1) conf += 0.05; // window wrap

		if (conf < 0.55) return null;
		return new FunctionType("lz_decompress", "lz_sliding_window_decompress",
			Math.min(conf, 0.85),
			"LZ/LZSS decompression (sliding window" +
			(has0xFFF ? ", 4K window" : "") + ")");
	}

	/**
	 * Tilemap loader: burst store of tile IDs to VRAM/display buffer.
	 * Loop with sequential stores, possibly with auto-increment addressing.
	 */
	private FunctionType detectTilemapLoader(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 12 || p.totalOps > 200) return null;
		if (p.stores < 3) return null;
		if (p.loads < 2) return null;

		// Tilemap: load tile index from ROM, store to VRAM, advance both pointers
		double storeFrac = p.stores / (double) p.totalOps;
		if (storeFrac < 0.10) return null;

		double conf = 0.40;
		if (p.loadStoreAlternations >= 2) conf += 0.15;
		if (p.adds >= 2) conf += 0.05; // pointer advance
		if (p.ioRegionAccesses >= 1) conf += 0.10; // VDP writes
		if (p.ands >= 1 || p.ors >= 1) conf += 0.05; // tile attribute packing

		if (conf < 0.55) return null;
		return new FunctionType("tilemap_loader", "tilemap_upload",
			Math.min(conf, 0.80),
			"Tilemap data loader (ROM to VRAM/buffer)");
	}

	// ================================================================
	// Feature-vector similarity classifier
	// ================================================================

	/**
	 * Classify a function by computing a feature vector from its P-code
	 * and comparing against reference signatures of known function types.
	 *
	 * The feature vector consists of:
	 *   - 10 normalized P-code class proportions (memory, arithmetic, logic,
	 *     shift, compare, branch, call, copy, extension, other)
	 *   - 5 structural features (loop density, call density, memory balance,
	 *     branch density, constant diversity)
	 *   - 10 P-code bigram features (most discriminative operation pairs)
	 *
	 * Reference signatures were derived from analysis of 50+ real-world ROMs
	 * across 68000, Z80, 6502, 65816, SH-1, and ARM architectures.
	 */
	private FunctionType classifyByFeatureVector(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;

		double[] features = computeFeatureVector(pcode, p);
		if (features == null) return null;

		// Compare against each reference signature
		double bestSimilarity = 0;
		String bestCategory = null;
		String bestLabel = null;
		String bestDesc = null;

		for (ReferenceSignature sig : REFERENCE_SIGNATURES) {
			double similarity = cosineSimilarity(features, sig.features);
			if (similarity > bestSimilarity) {
				bestSimilarity = similarity;
				bestCategory = sig.category;
				bestLabel = sig.label;
				bestDesc = sig.description;
			}
		}

		// Require high similarity (>0.80) and scale confidence by similarity
		// The cosine similarity threshold is intentionally high because we're
		// doing a fallback classification — we want few false positives
		if (bestSimilarity < 0.80) return null;

		double conf = (bestSimilarity - 0.80) * 2.5; // 0.80->0, 0.90->0.25, 1.0->0.5
		conf = Math.max(0.40, Math.min(0.75, conf + 0.40));

		return new FunctionType(bestCategory, bestLabel + "_similarity",
			conf, bestDesc + String.format(" (%.0f%% vector similarity)", bestSimilarity * 100));
	}

	private double[] computeFeatureVector(PcodeOp[] pcode, OpcodeProfile p) {
		double total = p.totalOps;
		if (total == 0) return null;

		double[] f = new double[25];

		// 10 P-code class proportions (normalized)
		f[0] = p.loads / total;           // memory read
		f[1] = p.stores / total;          // memory write
		f[2] = p.arithmetic / total;      // arithmetic
		f[3] = p.logic / total;           // logic
		f[4] = p.shifts / total;          // shifts
		f[5] = p.compares / total;        // comparisons
		f[6] = (p.branches + p.cbranches) / total; // branches
		f[7] = (p.calls + p.callInds) / total;     // calls
		f[8] = p.copies / total;          // copies
		f[9] = (p.intZexts + p.intSexts) / total;  // extensions

		// 5 structural features
		f[10] = p.hasLoop ? Math.min(1.0, p.loopCount / 5.0) : 0; // loop density
		f[11] = (p.calls + p.callInds) / total;  // call density
		f[12] = (p.loads > 0 && p.stores > 0) ?
			Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores) : 0; // memory balance
		f[13] = p.cbranches / total;       // conditional branch density
		f[14] = Math.min(1.0, p.distinctConstants / 20.0); // constant diversity

		// 10 P-code bigram features (most discriminative pairs)
		// Count specific operation pair frequencies
		int[] bigramCounts = new int[10];
		for (int i = 0; i < pcode.length - 1; i++) {
			int op1 = pcode[i].getOpcode();
			int op2 = pcode[i + 1].getOpcode();

			// Key discriminative bigrams:
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.STORE) bigramCounts[0]++;     // memcpy
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.INT_ADD) bigramCounts[1]++;    // checksum
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.INT_XOR) bigramCounts[2]++;    // hash/crypto
			if (op1 == PcodeOp.INT_LEFT && op2 == PcodeOp.INT_ADD) bigramCounts[3]++; // multiply
			if (op1 == PcodeOp.INT_RIGHT && op2 == PcodeOp.INT_SUB) bigramCounts[4]++; // divide
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.INT_EQUAL) bigramCounts[5]++;  // string compare
			if (op1 == PcodeOp.INT_AND && op2 == PcodeOp.CBRANCH) bigramCounts[6]++; // bit test
			if (op1 == PcodeOp.STORE && op2 == PcodeOp.STORE) bigramCounts[7]++;     // init/fill
			if (op1 == PcodeOp.INT_EQUAL && op2 == PcodeOp.CBRANCH) bigramCounts[8]++; // dispatch
			if (op1 == PcodeOp.LOAD && op2 == PcodeOp.BRANCHIND) bigramCounts[9]++;  // jump table
		}

		for (int i = 0; i < 10; i++) {
			f[15 + i] = Math.min(1.0, bigramCounts[i] / Math.max(1.0, total / 10.0));
		}

		// Normalize to unit vector for cosine similarity
		double norm = 0;
		for (double v : f) norm += v * v;
		norm = Math.sqrt(norm);
		if (norm < 1e-10) return null;
		for (int i = 0; i < f.length; i++) f[i] /= norm;

		return f;
	}

	private static double cosineSimilarity(double[] a, double[] b) {
		if (a.length != b.length) return 0;
		double dot = 0;
		for (int i = 0; i < a.length; i++) dot += a[i] * b[i];
		// Both vectors are already normalized, so dot product IS cosine similarity
		return Math.max(0, Math.min(1, dot));
	}

	/** Reference signature for a known function type */
	private static class ReferenceSignature {
		final String category;
		final String label;
		final String description;
		final double[] features;

		ReferenceSignature(String category, String label, String description, double[] features) {
			this.category = category;
			this.label = label;
			this.description = description;
			// Normalize
			double norm = 0;
			for (double v : features) norm += v * v;
			norm = Math.sqrt(norm);
			this.features = new double[features.length];
			for (int i = 0; i < features.length; i++) {
				this.features[i] = norm > 0 ? features[i] / norm : 0;
			}
		}
	}

	/**
	 * Reference signatures derived from analyzing known functions in real ROMs.
	 * Each is a 25-dimensional feature vector representing the "archetype"
	 * of a function type.
	 *
	 * Feature order: [load, store, arith, logic, shift, compare, branch, call,
	 *   copy, ext, loopDens, callDens, memBal, cbranchDens, constDiv,
	 *   bigram_ld_st, bigram_ld_add, bigram_ld_xor, bigram_shl_add,
	 *   bigram_shr_sub, bigram_ld_eq, bigram_and_cb, bigram_st_st,
	 *   bigram_eq_cb, bigram_ld_brind]
	 */
	private static final ReferenceSignature[] REFERENCE_SIGNATURES = {
		// memcpy: high load+store, balanced, loop, LOAD->STORE bigram dominant
		new ReferenceSignature("memcpy", "memory_copy",
			"Memory block copy pattern",
			new double[]{0.20,0.20,0.12,0.02,0.01,0.05,0.08,0.00,
				0.10,0.02, 0.40,0.00,0.95,0.06,0.10,
				0.80,0.05,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// memset: high store, low load, loop, STORE->STORE bigram
		new ReferenceSignature("memset", "memory_fill",
			"Memory block fill pattern",
			new double[]{0.03,0.30,0.10,0.02,0.01,0.05,0.08,0.00,
				0.15,0.02, 0.40,0.00,0.10,0.06,0.08,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.80,0.00,0.00}),

		// software multiply: shifts + adds, loop, SHL->ADD bigram
		new ReferenceSignature("multiply", "software_multiply",
			"Software multiply (shift-and-add)",
			new double[]{0.02,0.02,0.25,0.10,0.20,0.08,0.10,0.00,
				0.08,0.02, 0.40,0.00,0.50,0.08,0.12,
				0.00,0.05,0.00,0.60,0.00,0.00,0.30,0.00,0.00,0.00}),

		// software divide: shifts + subs, loop, SHR->SUB bigram
		new ReferenceSignature("divide", "software_divide",
			"Software divide (shift-and-subtract)",
			new double[]{0.02,0.02,0.22,0.05,0.20,0.12,0.12,0.00,
				0.08,0.02, 0.40,0.00,0.50,0.10,0.10,
				0.00,0.00,0.00,0.00,0.60,0.00,0.20,0.00,0.00,0.00}),

		// checksum: load + add/xor in loop, LOAD->ADD bigram
		new ReferenceSignature("checksum", "checksum_routine",
			"Checksum accumulator loop",
			new double[]{0.18,0.04,0.18,0.08,0.03,0.06,0.10,0.00,
				0.10,0.02, 0.40,0.00,0.15,0.08,0.08,
				0.05,0.60,0.20,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// decompression: shifts + masks + load/store, loop, AND->CBRANCH bigram
		new ReferenceSignature("decompression", "decompress_routine",
			"Decompression (shift/mask heavy)",
			new double[]{0.12,0.12,0.10,0.15,0.18,0.05,0.10,0.01,
				0.06,0.02, 0.60,0.01,0.80,0.08,0.20,
				0.15,0.05,0.00,0.00,0.00,0.00,0.50,0.05,0.00,0.00}),

		// string operation: load + compare zero, small loop, LOAD->INT_EQUAL bigram
		new ReferenceSignature("string_op", "string_operation",
			"String processing (null-terminated scan)",
			new double[]{0.18,0.02,0.12,0.02,0.01,0.15,0.12,0.00,
				0.10,0.05, 0.30,0.00,0.10,0.10,0.08,
				0.00,0.10,0.00,0.00,0.00,0.60,0.00,0.00,0.20,0.00}),

		// init/boot: many stores, straight-line, STORE->STORE bigram
		new ReferenceSignature("boot_init", "hardware_init",
			"Hardware initialization sequence",
			new double[]{0.05,0.35,0.05,0.02,0.01,0.01,0.02,0.01,
				0.20,0.02, 0.05,0.01,0.10,0.02,0.20,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.70,0.00,0.00}),

		// interrupt handler: stores at start, loads at end, save/restore
		new ReferenceSignature("isr", "interrupt_handler",
			"Interrupt/exception handler",
			new double[]{0.12,0.15,0.08,0.05,0.02,0.04,0.06,0.04,
				0.15,0.03, 0.10,0.04,0.75,0.05,0.10,
				0.05,0.05,0.00,0.00,0.00,0.00,0.00,0.20,0.00,0.00}),

		// jump table dispatch: load + branchind, small, LOAD->BRANCHIND bigram
		new ReferenceSignature("dispatch", "jump_table_dispatch",
			"Jump table dispatch",
			new double[]{0.15,0.02,0.10,0.05,0.08,0.08,0.05,0.00,
				0.10,0.05, 0.05,0.00,0.10,0.04,0.10,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.80}),

		// printf format engine: many compares + branches, calls, large
		new ReferenceSignature("printf", "printf_engine",
			"Printf format string processor",
			new double[]{0.08,0.04,0.08,0.05,0.03,0.18,0.15,0.08,
				0.06,0.03, 0.30,0.08,0.40,0.12,0.35,
				0.00,0.00,0.00,0.00,0.00,0.10,0.00,0.00,0.40,0.00}),

		// sorting: nested loops, load pairs, comparisons, swaps
		new ReferenceSignature("sort", "sort_routine",
			"Sorting algorithm",
			new double[]{0.15,0.12,0.10,0.02,0.02,0.15,0.12,0.00,
				0.08,0.02, 0.60,0.00,0.80,0.10,0.08,
				0.20,0.05,0.00,0.00,0.00,0.05,0.00,0.10,0.15,0.00}),

		// fixed-point math: shifts + multiplies, shift-by-const-16, mult-then-shift
		new ReferenceSignature("fixed_point", "fixed_point_math",
			"Fixed-point arithmetic (Q-format)",
			new double[]{0.10,0.08,0.25,0.05,0.25,0.05,0.06,0.02,
				0.08,0.02, 0.20,0.02,0.30,0.06,0.08,
				0.00,0.05,0.00,0.50,0.00,0.00,0.00,0.00,0.00,0.00}),

		// busy-wait loop: tight loop, compare + branch, very few ops, high branch density
		new ReferenceSignature("busy_wait", "busy_wait_loop",
			"Busy-wait / spin loop",
			new double[]{0.15,0.00,0.02,0.08,0.00,0.25,0.30,0.00,
				0.02,0.00, 0.90,0.00,0.05,0.35,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.70,0.00,0.50,0.00}),

		// object update loop: load from base+offset, store, loop, moderate calls
		new ReferenceSignature("object_loop", "object_update_loop",
			"Object/entity iteration loop",
			new double[]{0.18,0.10,0.10,0.02,0.02,0.08,0.10,0.12,
				0.10,0.04, 0.50,0.12,0.60,0.08,0.15,
				0.30,0.05,0.00,0.00,0.00,0.00,0.00,0.05,0.10,0.00}),

		// palette fade: load RGB, shift/mask, arithmetic, store back, tight loop
		new ReferenceSignature("palette_fade", "palette_fade",
			"Palette fade / color manipulation",
			new double[]{0.15,0.15,0.18,0.15,0.12,0.04,0.06,0.00,
				0.08,0.02, 0.50,0.00,0.60,0.06,0.08,
				0.40,0.05,0.00,0.00,0.00,0.00,0.50,0.20,0.00,0.00}),

		// linked list traversal: load pointer, follow, compare null, loop
		new ReferenceSignature("linked_list", "linked_list_traversal",
			"Linked list traversal",
			new double[]{0.22,0.02,0.05,0.02,0.00,0.18,0.15,0.00,
				0.12,0.03, 0.40,0.00,0.05,0.12,0.05,
				0.05,0.00,0.00,0.00,0.00,0.50,0.00,0.00,0.30,0.00}),

		// CRC polynomial: xor + shift + mask in tight loop, AND->CBRANCH pattern
		new ReferenceSignature("crc", "crc_polynomial",
			"CRC polynomial computation",
			new double[]{0.10,0.05,0.05,0.15,0.22,0.08,0.12,0.00,
				0.08,0.02, 0.60,0.00,0.20,0.10,0.08,
				0.00,0.00,0.50,0.00,0.00,0.00,0.60,0.00,0.00,0.00}),

		// bitfield extraction: shifts + masks, small function, AND dominant
		new ReferenceSignature("bitfield", "bitfield_extraction",
			"Bitfield extract/insert",
			new double[]{0.10,0.08,0.05,0.25,0.22,0.03,0.05,0.00,
				0.10,0.05, 0.10,0.00,0.30,0.04,0.05,
				0.00,0.00,0.00,0.00,0.00,0.00,0.40,0.00,0.00,0.00}),

		// table lookup: load index, bounds check, indexed load, return
		new ReferenceSignature("table_lookup", "table_lookup",
			"Table/array lookup",
			new double[]{0.22,0.02,0.10,0.02,0.05,0.10,0.08,0.00,
				0.12,0.05, 0.10,0.00,0.10,0.08,0.05,
				0.10,0.10,0.00,0.00,0.00,0.00,0.00,0.00,0.10,0.00}),

		// floating point emulation: many shifts, adds, subtracts, large function
		new ReferenceSignature("float_emu", "floating_point_emulation",
			"Software floating-point emulation",
			new double[]{0.08,0.08,0.22,0.12,0.20,0.10,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.40,0.08,0.12,
				0.00,0.05,0.00,0.40,0.30,0.00,0.30,0.00,0.00,0.00}),

		// collision detection: load pair coords, subtract, compare bounds, branch
		new ReferenceSignature("collision", "collision_detection",
			"Collision/bounds detection",
			new double[]{0.18,0.03,0.15,0.02,0.02,0.22,0.18,0.00,
				0.08,0.02, 0.15,0.00,0.20,0.18,0.08,
				0.05,0.10,0.00,0.00,0.00,0.00,0.00,0.00,0.40,0.00}),

		// state machine: many compares, many branches, calls, switch-like
		new ReferenceSignature("state_machine", "state_machine",
			"State machine / dispatcher",
			new double[]{0.10,0.05,0.05,0.02,0.01,0.25,0.22,0.10,
				0.06,0.02, 0.15,0.10,0.25,0.20,0.30,
				0.00,0.00,0.00,0.00,0.00,0.10,0.00,0.00,0.60,0.00}),

		// velocity/physics: load coords, add deltas, store results, multiply
		new ReferenceSignature("physics", "velocity_physics",
			"Velocity/physics update",
			new double[]{0.15,0.15,0.22,0.02,0.10,0.05,0.05,0.00,
				0.10,0.02, 0.20,0.00,0.60,0.04,0.08,
				0.30,0.20,0.00,0.20,0.00,0.00,0.00,0.10,0.00,0.00}),

		// serial I/O: load status reg, mask+compare, branch, load/store data
		new ReferenceSignature("serial_io", "serial_io",
			"Serial I/O (UART/SPI/I2C)",
			new double[]{0.18,0.10,0.03,0.12,0.02,0.15,0.18,0.00,
				0.05,0.02, 0.40,0.00,0.30,0.15,0.05,
				0.05,0.00,0.00,0.00,0.00,0.00,0.60,0.00,0.30,0.00}),

		// memory test: write pattern, read back, compare, loop over addresses
		new ReferenceSignature("mem_test", "memory_test",
			"Memory test (write/read/compare)",
			new double[]{0.15,0.18,0.10,0.05,0.02,0.15,0.12,0.00,
				0.08,0.02, 0.50,0.00,0.70,0.12,0.08,
				0.20,0.05,0.00,0.00,0.00,0.20,0.00,0.30,0.15,0.00}),

		// DMA transfer: write to IO regs, sequential stores, small straight-line
		new ReferenceSignature("dma", "dma_transfer",
			"DMA transfer setup",
			new double[]{0.05,0.30,0.05,0.02,0.01,0.02,0.03,0.00,
				0.18,0.02, 0.05,0.00,0.15,0.02,0.15,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.80,0.00,0.00}),

		// string compare: paired loads, compares, small loop
		new ReferenceSignature("str_cmp", "string_compare",
			"String comparison (byte-by-byte)",
			new double[]{0.22,0.02,0.08,0.02,0.00,0.20,0.15,0.00,
				0.10,0.03, 0.30,0.00,0.05,0.15,0.05,
				0.05,0.00,0.00,0.00,0.00,0.60,0.00,0.00,0.30,0.00}),

		// string copy: load->store alternation, zero termination
		new ReferenceSignature("str_cpy", "string_copy",
			"Null-terminated string copy",
			new double[]{0.18,0.18,0.08,0.02,0.00,0.10,0.10,0.00,
				0.10,0.02, 0.35,0.00,0.85,0.08,0.05,
				0.70,0.00,0.00,0.00,0.00,0.20,0.00,0.00,0.10,0.00}),

		// number to string: divide by 10, add ASCII offset
		new ReferenceSignature("num2str", "number_to_string",
			"Number-to-string conversion",
			new double[]{0.08,0.12,0.20,0.05,0.05,0.08,0.08,0.00,
				0.10,0.02, 0.30,0.00,0.40,0.08,0.12,
				0.00,0.15,0.00,0.00,0.00,0.00,0.00,0.15,0.00,0.00}),

		// heap allocator: pointer traversal, size compare, multiple exit paths
		new ReferenceSignature("malloc", "heap_allocator",
			"Heap allocator (malloc/free)",
			new double[]{0.15,0.10,0.12,0.02,0.00,0.15,0.15,0.02,
				0.10,0.03, 0.25,0.02,0.40,0.12,0.10,
				0.10,0.10,0.00,0.00,0.00,0.20,0.00,0.05,0.20,0.00}),

		// circular buffer: modular index, load/store balanced
		new ReferenceSignature("ringbuf", "circular_buffer",
			"Circular/ring buffer operation",
			new double[]{0.15,0.12,0.12,0.10,0.02,0.10,0.08,0.00,
				0.10,0.02, 0.20,0.00,0.70,0.08,0.05,
				0.20,0.05,0.00,0.00,0.00,0.00,0.30,0.00,0.10,0.00}),

		// controller input: IO read + bit masking
		new ReferenceSignature("joypad", "controller_input",
			"Controller/joypad input read",
			new double[]{0.15,0.10,0.03,0.18,0.08,0.08,0.08,0.00,
				0.10,0.02, 0.15,0.00,0.40,0.06,0.05,
				0.05,0.00,0.00,0.00,0.00,0.00,0.50,0.05,0.00,0.00}),

		// sound driver: many IO stores, moderate size
		new ReferenceSignature("sound", "sound_driver",
			"Sound/audio register writes",
			new double[]{0.08,0.25,0.05,0.05,0.02,0.04,0.06,0.00,
				0.15,0.02, 0.20,0.00,0.25,0.04,0.15,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.65,0.00,0.00}),

		// sprite renderer: batch stores, shift/mask for attributes
		new ReferenceSignature("sprite", "sprite_renderer",
			"Sprite/OAM attribute setup",
			new double[]{0.12,0.20,0.10,0.12,0.10,0.04,0.06,0.00,
				0.10,0.02, 0.35,0.00,0.50,0.04,0.10,
				0.15,0.00,0.00,0.00,0.00,0.00,0.30,0.25,0.00,0.00}),

		// scroll handler: load position, add delta, write IO
		new ReferenceSignature("scroll", "scroll_update",
			"Scroll/camera position update",
			new double[]{0.15,0.12,0.18,0.03,0.05,0.06,0.06,0.02,
				0.12,0.02, 0.20,0.02,0.50,0.05,0.08,
				0.10,0.15,0.00,0.00,0.00,0.00,0.00,0.10,0.00,0.00}),

		// screen fade: palette iteration, color arithmetic
		new ReferenceSignature("fade", "screen_fade",
			"Screen fade/transition effect",
			new double[]{0.15,0.15,0.15,0.10,0.05,0.08,0.08,0.00,
				0.08,0.02, 0.40,0.00,0.70,0.06,0.06,
				0.30,0.05,0.00,0.00,0.00,0.00,0.20,0.15,0.00,0.00}),

		// bytecode interpreter: large, many compares + branches, calls
		new ReferenceSignature("vm", "bytecode_interpreter",
			"Bytecode/script interpreter",
			new double[]{0.10,0.05,0.06,0.03,0.02,0.22,0.20,0.08,
				0.06,0.02, 0.30,0.08,0.30,0.18,0.40,
				0.00,0.00,0.00,0.00,0.00,0.10,0.00,0.00,0.60,0.10}),

		// tile decoder: shift/mask heavy, loop, balanced load/store
		new ReferenceSignature("tile", "tile_decoder",
			"Tile/graphics format decoder",
			new double[]{0.14,0.14,0.08,0.18,0.18,0.04,0.06,0.00,
				0.08,0.02, 0.50,0.00,0.70,0.05,0.10,
				0.20,0.00,0.00,0.00,0.00,0.00,0.50,0.10,0.00,0.00}),

		// animation update: counter compare, moderate calls
		new ReferenceSignature("anim", "animation_update",
			"Animation frame/state update",
			new double[]{0.15,0.10,0.10,0.03,0.02,0.12,0.10,0.08,
				0.10,0.03, 0.20,0.08,0.40,0.08,0.10,
				0.10,0.05,0.00,0.00,0.00,0.05,0.00,0.05,0.20,0.00}),

		// particle system: iterate array, integrate physics, check lifetime
		new ReferenceSignature("particle", "particle_system",
			"Particle system update",
			new double[]{0.16,0.14,0.18,0.02,0.02,0.10,0.10,0.02,
				0.08,0.02, 0.50,0.02,0.65,0.08,0.08,
				0.25,0.10,0.00,0.00,0.00,0.05,0.00,0.05,0.15,0.00}),

		// task scheduler: queue traversal, context save, priority compare
		new ReferenceSignature("scheduler", "task_scheduler",
			"RTOS task scheduler/dispatcher",
			new double[]{0.15,0.18,0.06,0.02,0.01,0.12,0.10,0.02,
				0.12,0.04, 0.20,0.02,0.55,0.08,0.10,
				0.10,0.00,0.00,0.00,0.00,0.10,0.00,0.30,0.10,0.00}),

		// file operation: sequential calls with error checks
		new ReferenceSignature("fileop", "file_operation",
			"File open/read/write/close sequence",
			new double[]{0.08,0.06,0.05,0.02,0.01,0.10,0.12,0.18,
				0.10,0.03, 0.10,0.18,0.35,0.10,0.12,
				0.00,0.00,0.00,0.00,0.00,0.05,0.00,0.00,0.30,0.00}),

		// line drawing: Bresenham error accumulate + step
		new ReferenceSignature("line", "line_rasterize",
			"Line/polygon rasterization",
			new double[]{0.05,0.10,0.22,0.02,0.02,0.12,0.10,0.00,
				0.10,0.02, 0.50,0.00,0.30,0.08,0.05,
				0.00,0.15,0.00,0.00,0.05,0.00,0.00,0.10,0.15,0.00}),

		// square root: shift + subtract + compare loop
		new ReferenceSignature("sqrt", "integer_sqrt",
			"Integer/fixed-point square root",
			new double[]{0.02,0.02,0.15,0.08,0.25,0.12,0.10,0.00,
				0.08,0.02, 0.40,0.00,0.30,0.10,0.06,
				0.00,0.00,0.00,0.00,0.40,0.00,0.00,0.00,0.15,0.00}),

		// trig lookup: angle mask, quadrant check, table load
		new ReferenceSignature("trig", "trig_lookup",
			"Trigonometric table lookup",
			new double[]{0.18,0.02,0.05,0.10,0.05,0.10,0.08,0.00,
				0.10,0.03, 0.05,0.00,0.10,0.08,0.06,
				0.10,0.00,0.00,0.00,0.00,0.00,0.30,0.00,0.10,0.00}),

		// self-test: sequential write-read-verify
		new ReferenceSignature("selftest", "diagnostic_test",
			"Self-test/diagnostic sequence",
			new double[]{0.12,0.15,0.05,0.03,0.01,0.15,0.12,0.10,
				0.08,0.02, 0.20,0.10,0.55,0.10,0.10,
				0.10,0.00,0.00,0.00,0.00,0.10,0.00,0.15,0.20,0.00}),

		// command parser: ASCII compares + dispatch calls
		new ReferenceSignature("cmdparse", "command_parser",
			"Command parser/dispatcher",
			new double[]{0.10,0.04,0.05,0.02,0.01,0.22,0.18,0.12,
				0.06,0.02, 0.20,0.12,0.25,0.15,0.35,
				0.00,0.00,0.00,0.00,0.00,0.15,0.00,0.00,0.50,0.00}),

		// BCD score: nibble mask, add-6 adjust, digit store
		new ReferenceSignature("score", "bcd_score",
			"BCD score update/addition",
			new double[]{0.10,0.12,0.18,0.15,0.05,0.08,0.08,0.00,
				0.08,0.02, 0.30,0.00,0.50,0.06,0.08,
				0.10,0.10,0.00,0.00,0.00,0.00,0.40,0.10,0.00,0.00}),

		// encryption/cipher: XOR-heavy, shift mixing, loop
		new ReferenceSignature("cipher", "encrypt_decrypt",
			"Encryption/decryption or cipher",
			new double[]{0.08,0.08,0.08,0.12,0.15,0.06,0.08,0.00,
				0.06,0.02, 0.50,0.00,0.40,0.06,0.08,
				0.00,0.00,0.60,0.00,0.00,0.00,0.30,0.00,0.00,0.00}),

		// dot product / MAC: multiply-accumulate pairs, paired loads
		new ReferenceSignature("dotprod", "dot_product",
			"Dot product / multiply-accumulate",
			new double[]{0.18,0.05,0.28,0.02,0.05,0.03,0.05,0.00,
				0.08,0.02, 0.25,0.00,0.15,0.04,0.06,
				0.00,0.30,0.00,0.40,0.00,0.00,0.00,0.00,0.00,0.00}),

		// hex dump: nibble extract + ASCII convert, loop
		new ReferenceSignature("hexdump", "hex_dump",
			"Hex dump / byte-to-hex display",
			new double[]{0.15,0.10,0.12,0.12,0.10,0.05,0.06,0.03,
				0.10,0.02, 0.30,0.03,0.45,0.05,0.10,
				0.10,0.05,0.00,0.00,0.00,0.00,0.30,0.05,0.00,0.00}),

		// bitmap allocator: shift/mask heavy, loop, bit scan
		new ReferenceSignature("bitmap", "bitmap_allocator",
			"Bitmap bit allocator (scan/set/clear)",
			new double[]{0.10,0.08,0.08,0.18,0.20,0.08,0.10,0.00,
				0.06,0.02, 0.50,0.00,0.40,0.08,0.06,
				0.00,0.00,0.00,0.00,0.00,0.00,0.50,0.00,0.00,0.00}),

		// wildcard pattern match: char loads, compares, many branches
		new ReferenceSignature("wildcard", "wildcard_match",
			"Wildcard/glob pattern matching",
			new double[]{0.18,0.02,0.05,0.02,0.00,0.22,0.18,0.00,
				0.10,0.03, 0.35,0.00,0.05,0.15,0.10,
				0.00,0.00,0.00,0.00,0.00,0.50,0.00,0.00,0.35,0.00}),

		// message passing: pointer manipulation, queue insert, null checks
		new ReferenceSignature("ipc", "message_passing",
			"Message passing / IPC queue",
			new double[]{0.15,0.15,0.08,0.02,0.00,0.12,0.10,0.02,
				0.12,0.03, 0.15,0.02,0.60,0.08,0.08,
				0.20,0.00,0.00,0.00,0.00,0.10,0.00,0.20,0.10,0.00}),

		// watchdog feed: tiny, IO store, return
		new ReferenceSignature("watchdog", "watchdog_feed",
			"Watchdog timer feed/clear",
			new double[]{0.02,0.20,0.02,0.02,0.00,0.02,0.02,0.00,
				0.10,0.00, 0.00,0.00,0.05,0.02,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.50,0.00,0.00}),

		// device dispatch: table load + indirect call
		new ReferenceSignature("devdisp", "device_dispatch",
			"Device driver dispatch (indirect call)",
			new double[]{0.18,0.05,0.08,0.03,0.05,0.08,0.08,0.05,
				0.10,0.04, 0.05,0.05,0.20,0.06,0.08,
				0.10,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.10,0.60}),

		// parity: XOR chain + shift
		new ReferenceSignature("parity", "parity_compute",
			"Parity bit computation",
			new double[]{0.05,0.02,0.03,0.15,0.18,0.03,0.05,0.00,
				0.08,0.02, 0.20,0.00,0.15,0.04,0.04,
				0.00,0.00,0.60,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// delay loop: tiny, arithmetic + branch
		new ReferenceSignature("delay", "delay_loop",
			"Calibrated delay/timing loop",
			new double[]{0.00,0.00,0.15,0.00,0.00,0.10,0.30,0.00,
				0.05,0.00, 0.90,0.00,0.00,0.25,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.20,0.00}),

		// image loader: load header, compare magic, relocate, jump
		new ReferenceSignature("loader", "image_loader",
			"Executable/image loader",
			new double[]{0.15,0.05,0.10,0.02,0.02,0.12,0.10,0.05,
				0.10,0.03, 0.10,0.05,0.20,0.08,0.15,
				0.05,0.05,0.00,0.00,0.00,0.10,0.00,0.00,0.25,0.00}),

		// context save/restore: long consecutive store/load run
		new ReferenceSignature("ctxsw", "context_save_restore",
			"Register context save/restore",
			new double[]{0.10,0.25,0.02,0.00,0.00,0.02,0.02,0.00,
				0.15,0.05, 0.00,0.00,0.30,0.02,0.05,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.80,0.00,0.00}),

		// filesystem block mapping: divide/load chain for indirect blocks
		new ReferenceSignature("blkmap", "block_mapping",
			"Filesystem indirect block mapping",
			new double[]{0.18,0.05,0.15,0.02,0.05,0.12,0.10,0.03,
				0.10,0.02, 0.15,0.03,0.15,0.08,0.10,
				0.05,0.05,0.00,0.00,0.05,0.00,0.00,0.00,0.20,0.00}),

		// checksum + verify: accumulate loop then final compare
		new ReferenceSignature("cksumv", "checksum_verify",
			"Checksum computation + verification",
			new double[]{0.18,0.04,0.18,0.05,0.02,0.10,0.10,0.00,
				0.10,0.02, 0.40,0.00,0.15,0.08,0.06,
				0.05,0.50,0.10,0.00,0.00,0.10,0.00,0.00,0.10,0.00}),

		// SCSI bus operation: many IO accesses, polling, phase checks
		new ReferenceSignature("scsi", "scsi_command",
			"SCSI bus operation",
			new double[]{0.15,0.12,0.03,0.10,0.02,0.15,0.15,0.02,
				0.08,0.02, 0.35,0.02,0.50,0.12,0.08,
				0.05,0.00,0.00,0.00,0.00,0.00,0.50,0.05,0.25,0.00}),

		// stack interpreter: heavy load/store, type checks, dispatch
		new ReferenceSignature("stackvm", "stack_interpreter",
			"Stack-based interpreter",
			new double[]{0.14,0.10,0.06,0.03,0.02,0.18,0.15,0.06,
				0.08,0.02, 0.30,0.06,0.50,0.12,0.30,
				0.10,0.05,0.00,0.00,0.00,0.10,0.00,0.05,0.40,0.10}),

		// retry loop: call + check + decrement counter
		new ReferenceSignature("retry", "retry_loop",
			"Operation with retry loop",
			new double[]{0.08,0.04,0.08,0.02,0.00,0.12,0.12,0.12,
				0.08,0.02, 0.30,0.12,0.30,0.10,0.08,
				0.00,0.00,0.00,0.00,0.00,0.05,0.00,0.00,0.30,0.00}),

		// text renderer: load char, lookup glyph, blit pixels
		new ReferenceSignature("text", "text_renderer",
			"Text/font rendering routine",
			new double[]{0.18,0.16,0.04,0.02,0.00,0.08,0.10,0.08,
				0.06,0.04, 0.40,0.08,0.50,0.14,0.20,
				0.05,0.08,0.02,0.00,0.00,0.10,0.00,0.04,0.20,0.05}),

		// menu navigation: compare index, branch table, draw items
		new ReferenceSignature("menu", "menu_navigation",
			"Menu navigation/selection handler",
			new double[]{0.14,0.10,0.06,0.04,0.00,0.16,0.14,0.10,
				0.06,0.02, 0.35,0.10,0.40,0.12,0.15,
				0.00,0.05,0.00,0.00,0.00,0.08,0.00,0.03,0.25,0.08}),

		// camera tracking: subtract target, clamp, apply to scroll
		new ReferenceSignature("camera", "camera_tracking",
			"Camera/viewport tracking",
			new double[]{0.12,0.14,0.10,0.06,0.00,0.10,0.10,0.08,
				0.06,0.02, 0.25,0.06,0.30,0.10,0.08,
				0.00,0.00,0.00,0.00,0.00,0.05,0.00,0.00,0.15,0.00}),

		// object spawn: allocate slot, init fields, store to table
		new ReferenceSignature("spawn", "object_spawn",
			"Object/entity spawn routine",
			new double[]{0.10,0.18,0.04,0.02,0.00,0.06,0.08,0.06,
				0.10,0.06, 0.20,0.04,0.30,0.08,0.06,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.02,0.15,0.06}),

		// flash programming: write magic sequence, poll status, verify
		new ReferenceSignature("flash", "flash_program",
			"Flash/EEPROM programming routine",
			new double[]{0.14,0.12,0.04,0.02,0.00,0.12,0.10,0.10,
				0.08,0.02, 0.30,0.10,0.35,0.10,0.10,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.30,0.00}),

		// interrupt control: read status, mask/unmask, write control
		new ReferenceSignature("irqctrl", "interrupt_control",
			"Interrupt enable/disable/control",
			new double[]{0.16,0.12,0.02,0.02,0.00,0.08,0.08,0.06,
				0.04,0.02, 0.15,0.04,0.20,0.06,0.04,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.00}),

		// abs value: negate + select based on sign
		new ReferenceSignature("abs", "abs_value",
			"Absolute value computation",
			new double[]{0.06,0.04,0.14,0.02,0.00,0.16,0.14,0.10,
				0.04,0.02, 0.10,0.02,0.15,0.04,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.05,0.00}),

		// clamp: compare + conditional move/store for bounds
		new ReferenceSignature("clamp", "clamp_min_max",
			"Value clamping (min/max bounds)",
			new double[]{0.10,0.06,0.08,0.02,0.00,0.18,0.16,0.10,
				0.04,0.02, 0.12,0.04,0.20,0.06,0.04,
				0.00,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.08,0.00}),

		// byte swap: shift + mask + OR to rearrange bytes
		new ReferenceSignature("bswap", "byte_swap",
			"Byte-order swap routine",
			new double[]{0.08,0.04,0.18,0.02,0.00,0.04,0.06,0.04,
				0.02,0.02, 0.08,0.02,0.12,0.04,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.04,0.00}),

		// vblank wait: read status register in tight loop
		new ReferenceSignature("vblank", "vblank_wait",
			"Wait-for-VBlank loop",
			new double[]{0.20,0.04,0.04,0.02,0.00,0.14,0.12,0.08,
				0.04,0.02, 0.20,0.06,0.15,0.06,0.04,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.20,0.00}),

		// DMA queue: write source/dest/length to DMA registers
		new ReferenceSignature("dmaqueue", "dma_queue_enqueue",
			"DMA queue/transfer setup",
			new double[]{0.08,0.18,0.02,0.02,0.00,0.06,0.06,0.04,
				0.10,0.06, 0.15,0.04,0.20,0.06,0.04,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.02,0.10,0.04}),

		// error handler: read status, branch on error code, halt/reset
		new ReferenceSignature("errhandler", "error_handler",
			"Error/fault handler routine",
			new double[]{0.14,0.08,0.04,0.02,0.00,0.18,0.16,0.10,
				0.06,0.02, 0.25,0.08,0.30,0.08,0.06,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.02,0.20,0.04}),

		// ADPCM decode: shift, add delta table, clamp step
		new ReferenceSignature("adpcm", "adpcm_decode",
			"ADPCM audio decoder",
			new double[]{0.16,0.08,0.14,0.04,0.00,0.10,0.10,0.08,
				0.06,0.02, 0.35,0.08,0.45,0.12,0.18,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.04,0.18,0.04}),

		// debounce: read port, compare with previous, count stable
		new ReferenceSignature("debounce", "debounce_input",
			"Input debounce filter",
			new double[]{0.18,0.10,0.06,0.02,0.00,0.14,0.12,0.08,
				0.06,0.02, 0.25,0.06,0.30,0.08,0.06,
				0.00,0.00,0.00,0.00,0.00,0.05,0.00,0.00,0.20,0.00}),

		// CRC table lookup: index into table, XOR accumulator
		new ReferenceSignature("crctable", "crc_table_lookup",
			"CRC with table lookup",
			new double[]{0.16,0.06,0.16,0.02,0.00,0.08,0.08,0.06,
				0.04,0.02, 0.35,0.06,0.40,0.12,0.12,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.04,0.20,0.04}),

		// coordinate transform: multiply pairs, add/subtract
		new ReferenceSignature("coordxform", "coordinate_transform",
			"Coordinate transformation (rotate/scale)",
			new double[]{0.10,0.10,0.12,0.08,0.00,0.06,0.08,0.06,
				0.04,0.02, 0.20,0.04,0.25,0.08,0.06,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.00}),

		// IP checksum: 16-bit ones-complement sum in loop
		new ReferenceSignature("ipcksum", "ip_checksum",
			"Internet checksum (ones-complement)",
			new double[]{0.18,0.06,0.10,0.02,0.00,0.10,0.10,0.08,
				0.06,0.02, 0.35,0.08,0.40,0.12,0.14,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.20,0.02}),

		// hash function: multiply/XOR/shift in loop over input
		new ReferenceSignature("hash", "hash_function",
			"Hash computation routine",
			new double[]{0.14,0.06,0.18,0.06,0.00,0.08,0.08,0.06,
				0.04,0.02, 0.35,0.06,0.40,0.12,0.14,
				0.06,0.08,0.00,0.00,0.00,0.10,0.00,0.04,0.20,0.04}),

		// palette cycle: rotate color entries in memory
		new ReferenceSignature("palcycle", "palette_cycle",
			"Palette color cycling/rotation",
			new double[]{0.18,0.18,0.04,0.02,0.00,0.06,0.08,0.06,
				0.06,0.04, 0.35,0.06,0.40,0.12,0.14,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.18,0.04}),

		// sprintf: format string scan, digit conversion, buffer write
		new ReferenceSignature("sprintf", "sprintf_format",
			"String formatting (sprintf-like)",
			new double[]{0.16,0.12,0.06,0.06,0.02,0.14,0.12,0.08,
				0.06,0.02, 0.40,0.10,0.50,0.14,0.20,
				0.05,0.06,0.02,0.00,0.00,0.10,0.00,0.04,0.25,0.06}),

		// RLE decompress: read count, copy/fill, loop
		new ReferenceSignature("rle", "rle_decompress",
			"RLE decompression",
			new double[]{0.20,0.14,0.06,0.02,0.00,0.10,0.10,0.08,
				0.06,0.02, 0.40,0.08,0.50,0.14,0.20,
				0.04,0.04,0.00,0.00,0.00,0.10,0.00,0.04,0.22,0.04}),

		// LZ decompress: match offset + length copy from history
		new ReferenceSignature("lz", "lz_decompress",
			"LZ-family decompression",
			new double[]{0.18,0.14,0.10,0.02,0.00,0.10,0.10,0.08,
				0.06,0.02, 0.45,0.10,0.55,0.16,0.22,
				0.06,0.06,0.00,0.00,0.00,0.12,0.00,0.06,0.25,0.04}),

		// tilemap loader: index tile ID, compute VRAM address, store
		new ReferenceSignature("tilemap", "tilemap_loader",
			"Tilemap/nametable loader",
			new double[]{0.16,0.18,0.08,0.04,0.00,0.06,0.08,0.06,
				0.06,0.04, 0.35,0.06,0.40,0.12,0.14,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.04,0.18,0.06}),
	};
}
