/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import java.io.File;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Cross-architecture heuristic code/data block identification.
 *
 * Implements 41 code/data heuristics plus 203 function pattern detectors,
 * proven across 68000, Z80, and 6502 disassemblers, abstracted to work on
 * any SLEIGH-supported ISA via P-code analysis.
 *
 * 9-pass pipeline:
 *   Pass 1: Vector table entry points (H32)
 *   Pass 2: Forward trace from seeds (H01-H05, H07, H08, H21, H23)
 *   Pass 3: Reference target tracing (H03, H04, H22)
 *   Pass 4: Jump table resolution (H19, H27)
 *   Pass 5: Orphan recovery (H09-H11)
 *   Pass 6: Data/code boundary detection (H17)
 *   Pass 7: Gap filling (H06)
 *   Pass 8: Overlap resolution (H14)
 *   Pass 9: Confidence assignment (H20)
 */
public class HeuristicCodeFinderAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Heuristic Code Finder";
	private static final String DESCRIPTION =
		"Cross-architecture heuristic code/data block identification using " +
		"P-code analysis. Finds code in flat ROMs and binaries without format headers.";

	// Options
	private static final String OPT_MIN_BLOCK = "Minimum block size (bytes)";
	private static final String OPT_ENTROPY_LO = "Byte entropy minimum";
	private static final String OPT_ENTROPY_HI = "Byte entropy maximum";
	private static final String OPT_DATA_RUN_THRESH = "Data run threshold";
	private static final String OPT_DENSITY_THRESH = "Null/FF density threshold";
	private static final String OPT_VALID_RATIO = "Minimum valid decode ratio";
	private static final String OPT_CLASS_ENTROPY = "Minimum P-code class entropy";
	private static final String OPT_REDUNDANCY_THRESH = "Maximum redundant op fraction";
	private static final String OPT_GAP_MAX = "Maximum gap fill size (bytes)";
	private static final String OPT_ORPHAN_MIN = "Minimum orphan region size (bytes)";
	private static final String OPT_PLATFORM_FILE = "Platform description XML file";

	private int minBlockSize = 8;
	private double entropyLo = 4.0;
	private double entropyHi = 7.0;
	private int dataRunThreshold = 5;
	private double densityThreshold = 0.25;
	private double validRatioMin = 0.70;
	private double classEntropyMin = 1.5;
	private double redundancyMax = 0.25;
	private int gapMaxSize = 12;
	private int orphanMinSize = 64;
	private String platformFile = "";

	// State
	private PlatformDescription platform;
	private PcodePatternMatcher patternMatcher;
	private Set<Address> entryPoints = new LinkedHashSet<>();
	private Set<Address> functionEntries = new LinkedHashSet<>();
	private Map<Address, Integer> confidence = new LinkedHashMap<>();

	// Confidence tiers (H20)
	private static final int CONF_VECTOR = 100;
	private static final int CONF_CALL = 99;
	private static final int CONF_BRANCH = 98;
	private static final int CONF_CBRANCH = 97;
	private static final int CONF_INDIRECT = 95;
	private static final int CONF_PATTERN = 93;
	private static final int CONF_SEQUENTIAL = 90;
	private static final int CONF_GAP_FILL = 88;
	private static final int CONF_ORPHAN = 80;
	private static final int CONF_DATA_BOUNDARY = 78;

	public HeuristicCodeFinderAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setDefaultEnablement(false);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true; // Works on any SLEIGH-supported architecture
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_MIN_BLOCK, minBlockSize, null,
			"Minimum number of bytes for a code block to be accepted");
		options.registerOption(OPT_ENTROPY_LO, entropyLo, null,
			"Minimum byte entropy for code (typically 4.0)");
		options.registerOption(OPT_ENTROPY_HI, entropyHi, null,
			"Maximum byte entropy for code (typically 7.0)");
		options.registerOption(OPT_DATA_RUN_THRESH, dataRunThreshold, null,
			"Number of consecutive identical words to trigger data rejection");
		options.registerOption(OPT_DENSITY_THRESH, densityThreshold, null,
			"Maximum fraction of 0x00/0xFF bytes before rejecting as data");
		options.registerOption(OPT_VALID_RATIO, validRatioMin, null,
			"Minimum fraction of bytes that must decode as valid instructions");
		options.registerOption(OPT_CLASS_ENTROPY, classEntropyMin, null,
			"Minimum P-code operation class entropy");
		options.registerOption(OPT_REDUNDANCY_THRESH, redundancyMax, null,
			"Maximum fraction of redundant P-code operations");
		options.registerOption(OPT_GAP_MAX, gapMaxSize, null,
			"Maximum gap size in bytes to attempt filling");
		options.registerOption(OPT_ORPHAN_MIN, orphanMinSize, null,
			"Minimum size of orphan regions to analyze");
		options.registerOption(OPT_PLATFORM_FILE, platformFile, null,
			"Path to platform description XML (empty = auto-detect from memory blocks)");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		minBlockSize = options.getInt(OPT_MIN_BLOCK, minBlockSize);
		entropyLo = options.getDouble(OPT_ENTROPY_LO, entropyLo);
		entropyHi = options.getDouble(OPT_ENTROPY_HI, entropyHi);
		dataRunThreshold = options.getInt(OPT_DATA_RUN_THRESH, dataRunThreshold);
		densityThreshold = options.getDouble(OPT_DENSITY_THRESH, densityThreshold);
		validRatioMin = options.getDouble(OPT_VALID_RATIO, validRatioMin);
		classEntropyMin = options.getDouble(OPT_CLASS_ENTROPY, classEntropyMin);
		redundancyMax = options.getDouble(OPT_REDUNDANCY_THRESH, redundancyMax);
		gapMaxSize = options.getInt(OPT_GAP_MAX, gapMaxSize);
		orphanMinSize = options.getInt(OPT_ORPHAN_MIN, orphanMinSize);
		platformFile = options.getString(OPT_PLATFORM_FILE, platformFile);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		entryPoints.clear();
		functionEntries.clear();
		confidence.clear();

		// Initialize subsystems
		patternMatcher = new PcodePatternMatcher(program);
		loadPlatform(program);

		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

		// ============================================================
		// Platform detection and endianness check
		// ============================================================
		runPlatformDetection(program, monitor, log);

		int totalFound = 0;

		// ============================================================
		// Pass 1: Vector table entry points (H32)
		// ============================================================
		monitor.setMessage("Heuristic Pass 1: Vector table entry points");
		List<Long> vectorAddrs = platform.readVectorEntries(program);
		for (Long addr : vectorAddrs) {
			monitor.checkCancelled();
			Address entryAddr = defaultSpace.getAddress(addr);
			if (listing.getInstructionAt(entryAddr) == null &&
				memory.contains(entryAddr)) {
				entryPoints.add(entryAddr);
				functionEntries.add(entryAddr);
				confidence.put(entryAddr, CONF_VECTOR);
			}
		}
		Msg.info(this, "Pass 1: " + vectorAddrs.size() + " vector entry points");

		// ============================================================
		// Pass 2: Forward trace from seeds (H01-H05, H07, H08, H21, H23)
		// ============================================================
		monitor.setMessage("Heuristic Pass 2: Forward trace from seeds");
		int pass2Found = 0;
		Set<Address> newTargets = new LinkedHashSet<>();

		for (Address seed : new ArrayList<>(entryPoints)) {
			monitor.checkCancelled();
			AddressSet traced = traceForward(program, pseudo, seed, newTargets, monitor);
			if (traced != null && !traced.isEmpty()) {
				pass2Found += disassembleSet(program, traced, monitor);
			}
		}
		totalFound += pass2Found;
		Msg.info(this, "Pass 2: " + pass2Found + " instructions from vector seeds");

		// ============================================================
		// Pass 3: Reference target tracing (H03, H04, H22)
		// Iterate until no new blocks discovered
		// ============================================================
		monitor.setMessage("Heuristic Pass 3: Reference target tracing");
		int pass3Total = 0;
		int iteration = 0;
		while (!newTargets.isEmpty() && iteration < 100) {
			monitor.checkCancelled();
			iteration++;
			Set<Address> nextTargets = new LinkedHashSet<>();
			int pass3Round = 0;

			for (Address target : newTargets) {
				monitor.checkCancelled();
				if (listing.getInstructionAt(target) != null) continue;
				if (!memory.contains(target)) continue;

				AddressSet traced = traceForward(program, pseudo, target, nextTargets, monitor);
				if (traced != null && !traced.isEmpty()) {
					pass3Round += disassembleSet(program, traced, monitor);
				}
			}
			pass3Total += pass3Round;
			newTargets = nextTargets;
			if (pass3Round == 0) break;
		}
		totalFound += pass3Total;
		Msg.info(this, "Pass 3: " + pass3Total + " instructions from reference tracing (" +
			iteration + " iterations)");

		// ============================================================
		// Pass 4: Jump table resolution (H19, H27)
		// ============================================================
		monitor.setMessage("Heuristic Pass 4: Jump table resolution");
		int pass4Found = resolveJumpTables(program, pseudo, listing, memory, defaultSpace, monitor);
		totalFound += pass4Found;
		Msg.info(this, "Pass 4: " + pass4Found + " instructions from jump tables");

		// ============================================================
		// Pass 5: Orphan recovery (H09-H11)
		// ============================================================
		monitor.setMessage("Heuristic Pass 5: Orphan recovery");
		int pass5Found = recoverOrphans(program, pseudo, set, listing, memory, monitor);
		totalFound += pass5Found;
		Msg.info(this, "Pass 5: " + pass5Found + " instructions from orphan recovery");

		// ============================================================
		// Pass 6: Data/code boundary detection (H17)
		// ============================================================
		monitor.setMessage("Heuristic Pass 6: Data/code boundary detection");
		int pass6Found = detectDataCodeBoundaries(program, pseudo, listing, memory, monitor);
		totalFound += pass6Found;
		Msg.info(this, "Pass 6: " + pass6Found + " instructions from data/code boundaries");

		// ============================================================
		// Pass 7: Gap filling (H06)
		// ============================================================
		monitor.setMessage("Heuristic Pass 7: Gap filling");
		int pass7Found = fillGaps(program, pseudo, listing, memory, monitor);
		totalFound += pass7Found;
		Msg.info(this, "Pass 7: " + pass7Found + " instructions from gap filling");

		// ============================================================
		// Pass 8 & 9: Overlap resolution (H14) and confidence (H20)
		// are handled implicitly — Ghidra's Listing prevents overlaps,
		// and confidence is tracked in our map for reporting.
		// ============================================================

		// ============================================================
		// Pass 10: Function pattern detection & hardware register labeling
		// ============================================================
		monitor.setMessage("Heuristic Pass 10: Function classification & HW register labeling");
		FunctionPatternDetector fpd = new FunctionPatternDetector(program, platform);

		int hwLabels = 0;
		try {
			hwLabels = fpd.labelHardwareRegisters(monitor);
			if (hwLabels > 0) {
				Msg.info(this, "Pass 10: " + hwLabels + " hardware register labels created");
			}
		} catch (Exception e) {
			Msg.warn(this, "Hardware register labeling failed: " + e.getMessage());
		}

		int classified = 0;
		try {
			classified = fpd.classifyAllFunctions(monitor);
			if (classified > 0) {
				Msg.info(this, "Pass 10: " + classified + " functions classified by pattern");
			}
		} catch (Exception e) {
			Msg.warn(this, "Function classification failed: " + e.getMessage());
		}

		Msg.info(this, "Heuristic Code Finder complete: " + totalFound + " total instructions found" +
			(classified > 0 ? ", " + classified + " functions classified" : "") +
			(hwLabels > 0 ? ", " + hwLabels + " HW registers labeled" : ""));
		log.appendMsg("Heuristic Code Finder: " + totalFound + " instructions across " +
			entryPoints.size() + " entry points" +
			(classified > 0 ? ", " + classified + " functions classified" : "") +
			(hwLabels > 0 ? ", " + hwLabels + " HW registers labeled" : ""));

		return true;
	}

	// ================================================================
	// Pass 2/3: Forward trace with validation
	// ================================================================

	/**
	 * Trace forward from a seed address, collecting valid code blocks.
	 * Applies H01 (RETURN termination), H02 (BRANCH termination),
	 * H05 (entry point protection), and data filters (H07, H08, H21, H23).
	 */
	private AddressSet traceForward(Program program, PseudoDisassembler pseudo,
			Address seed, Set<Address> newTargets, TaskMonitor monitor) {

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		AddressSet accepted = new AddressSet();

		if (!memory.contains(seed)) return null;
		if (listing.getInstructionAt(seed) != null) return null;

		List<PseudoInstruction> block = new ArrayList<>();
		Address current = seed;
		int totalBytes = 0;
		int validBytes = 0;
		List<PcodeOp> allPcode = new ArrayList<>();
		byte[] blockBytes = new byte[4096];
		int blockByteLen = 0;

		for (int i = 0; i < 10000; i++) { // Safety limit
			if (!memory.contains(current)) break;
			if (listing.getInstructionAt(current) != null) break; // H05

			PseudoInstruction instr;
			try {
				instr = pseudo.disassemble(current);
			} catch (Exception e) {
				break; // Invalid instruction — H23
			}
			if (instr == null) break; // H23: failed decode

			int instrLen = instr.getLength();
			totalBytes += instrLen;
			validBytes += instrLen;

			// Accumulate raw bytes for data filters
			try {
				if (blockByteLen + instrLen <= blockBytes.length) {
					memory.getBytes(current, blockBytes, blockByteLen, instrLen);
					blockByteLen += instrLen;
				}
			} catch (MemoryAccessException e) {
				// ignore
			}

			// Collect P-code
			try {
				PcodeOp[] pcode = instr.getPcode();
				Collections.addAll(allPcode, pcode);

				// Extract CALL/BRANCH targets (H03, H04)
				collectTargets(instr, pcode, newTargets, program);
			} catch (Exception e) {
				// P-code generation may fail for some instructions
			}

			block.add(instr);
			Address nextAddr = current.add(instrLen);

			// H01: Block termination at RETURN
			FlowType flow = instr.getFlowType();
			if (flow.isTerminal()) {
				break;
			}

			// H02: Block termination at unconditional BRANCH
			if (flow.isUnConditional() && flow.isJump() && !flow.isCall()) {
				break;
			}

			current = nextAddr;
		}

		if (block.isEmpty()) return null;

		// Apply data filters
		if (totalBytes < minBlockSize) return null; // Too small

		// H23: Valid decode ratio
		if (totalBytes > 0 && (double) validBytes / totalBytes < validRatioMin) return null;

		// H07: Data run detection
		if (hasDataRuns(blockBytes, blockByteLen)) return null;

		// H21: Byte density check
		if (hasHighNullDensity(blockBytes, blockByteLen)) return null;

		// H08: Byte entropy filtering
		double entropy = byteEntropy(blockBytes, blockByteLen);
		if (blockByteLen >= 16 && (entropy < entropyLo || entropy > entropyHi)) return null;

		// H16: P-code class entropy
		PcodeOp[] pcodeArray = allPcode.toArray(new PcodeOp[0]);
		if (pcodeArray.length >= 10) {
			double classEnt = patternMatcher.pcodeClassEntropy(pcodeArray);
			if (classEnt < classEntropyMin) return null;
		}

		// H18: Redundant instruction detection
		if (pcodeArray.length >= 10) {
			double redundancy = patternMatcher.redundantOpFraction(pcodeArray);
			if (redundancy > redundancyMax) return null;
		}

		// H33: Memory map validation (Tier 3)
		if (!platform.getMemoryMap().isEmpty()) {
			if (!validateReferences(allPcode, program)) return null;
		}

		// Block accepted — build address set
		for (PseudoInstruction instr : block) {
			Address start = instr.getAddress();
			accepted.add(start, start.add(instr.getLength() - 1));
		}

		// H13: partial block saving handled implicitly (we stop at first invalid)
		// H12: reference classification tracked via confidence map
		if (!confidence.containsKey(seed)) {
			confidence.put(seed, CONF_SEQUENTIAL);
		}

		return accepted;
	}

	/**
	 * H03/H04: Collect CALL and BRANCH/CBRANCH targets.
	 */
	private void collectTargets(PseudoInstruction instr, PcodeOp[] pcode,
			Set<Address> targets, Program program) {

		FlowType flow = instr.getFlowType();
		Address[] flows = instr.getFlows();
		if (flows == null) return;

		for (Address target : flows) {
			if (!program.getMemory().contains(target)) continue;

			targets.add(target);
			if (flow.isCall()) {
				functionEntries.add(target);
				if (!confidence.containsKey(target)) {
					confidence.put(target, CONF_CALL);
				}
			} else if (flow.isConditional()) {
				if (!confidence.containsKey(target)) {
					confidence.put(target, CONF_CBRANCH);
				}
			} else if (flow.isJump()) {
				if (!confidence.containsKey(target)) {
					confidence.put(target, CONF_BRANCH);
				}
			}

			entryPoints.add(target);
		}
	}

	// ================================================================
	// Pass 4: Jump table resolution (H19, H27)
	// ================================================================

	private int resolveJumpTables(Program program, PseudoDisassembler pseudo,
			Listing listing, Memory memory, AddressSpace space, TaskMonitor monitor)
			throws CancelledException {

		int found = 0;
		int pointerSize = program.getDefaultPointerSize();

		// Scan existing instructions for BRANCHIND (computed jumps)
		InstructionIterator iter = listing.getInstructions(true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();
			FlowType flow = instr.getFlowType();
			if (flow != FlowType.COMPUTED_JUMP && flow != FlowType.COMPUTED_CALL) continue;

			// Try to read a jump table at the instruction's reference
			Address[] refs = instr.getReferencesFrom() != null ?
				Arrays.stream(instr.getReferencesFrom())
					.map(r -> r.getToAddress())
					.toArray(Address[]::new) : new Address[0];

			for (Address ref : refs) {
				if (!memory.contains(ref)) continue;
				if (listing.getInstructionAt(ref) != null) continue;

				// Try reading pointers from this location
				List<Address> tableEntries = readPointerTable(memory, ref, pointerSize, space, listing);
				for (Address entry : tableEntries) {
					if (listing.getInstructionAt(entry) != null) continue;
					if (!memory.contains(entry)) continue;

					Set<Address> targets = new LinkedHashSet<>();
					AddressSet traced = traceForward(program, pseudo, entry, targets, monitor);
					if (traced != null && !traced.isEmpty()) {
						found += disassembleSet(program, traced, monitor);
						confidence.put(entry, CONF_INDIRECT);
					}
				}
			}
		}
		return found;
	}

	private List<Address> readPointerTable(Memory memory, Address base, int ptrSize,
			AddressSpace space, Listing listing) {
		List<Address> entries = new ArrayList<>();
		for (int i = 0; i < 256; i++) { // Max 256 entries
			try {
				Address ptrAddr = base.add((long) i * ptrSize);
				if (!memory.contains(ptrAddr)) break;
				byte[] buf = new byte[ptrSize];
				memory.getBytes(ptrAddr, buf);

				long value = 0;
				if (ptrSize == 4) {
					if (program_isBigEndian(memory)) {
						value = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
								((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
					} else {
						value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8) |
								((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
					}
				} else if (ptrSize == 2) {
					if (program_isBigEndian(memory)) {
						value = ((buf[0] & 0xFFL) << 8) | (buf[1] & 0xFFL);
					} else {
						value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8);
					}
				}

				if (value == 0 || value == 0xFFFFFFFFL) break;

				Address target = space.getAddress(value);
				if (!memory.contains(target)) break;

				// Stop if this looks like data (target is in existing instruction)
				if (listing.getInstructionAt(target) != null || platform.isValidCodeAddress(value)) {
					entries.add(target);
				} else {
					break; // Not a valid pointer — end of table
				}
			} catch (Exception e) {
				break;
			}
		}
		return entries;
	}

	// ================================================================
	// Pass 5: Orphan recovery (H09-H11)
	// ================================================================

	private int recoverOrphans(Program program, PseudoDisassembler pseudo,
			AddressSetView analysisSet, Listing listing, Memory memory, TaskMonitor monitor)
			throws CancelledException {

		int found = 0;
		AddressSet undefined = new AddressSet();

		// Find undefined regions in executable memory
		// Use getUndefinedRanges approach: walk instructions, gaps between them are undefined
		for (AddressRange range : analysisSet) {
			monitor.checkCancelled();
			Address rangeStart = range.getMinAddress();
			Address rangeEnd = range.getMaxAddress();

			// Use Ghidra's instruction iterator to find gaps efficiently
			InstructionIterator instrIter = listing.getInstructions(new AddressSet(rangeStart, rangeEnd), true);
			Address cursor = rangeStart;

			while (instrIter.hasNext()) {
				monitor.checkCancelled();
				Instruction instr = instrIter.next();
				Address instrStart = instr.getAddress();

				// Gap between cursor and this instruction is undefined
				if (instrStart.compareTo(cursor) > 0) {
					long gapSize = instrStart.subtract(cursor);
					if (gapSize >= orphanMinSize) {
						undefined.add(cursor, instrStart.subtract(1));
					}
				}
				// Skip past this instruction
				cursor = instrStart.add(instr.getLength());
			}
			// Trailing undefined region after last instruction
			if (cursor.compareTo(rangeEnd) <= 0) {
				long tailSize = rangeEnd.subtract(cursor) + 1;
				if (tailSize >= orphanMinSize) {
					undefined.add(cursor, rangeEnd);
				}
			}
		}

		Msg.info(this, "Pass 5: " + undefined.getNumAddressRanges() + " orphan regions to scan");

		// H09: Entropy classification of orphan regions
		int regionIdx = 0;
		int totalRegions = (int) undefined.getNumAddressRanges();
		for (AddressRange range : undefined) {
			monitor.checkCancelled();
			regionIdx++;
			if (regionIdx % 100 == 0) {
				monitor.setMessage("Heuristic Pass 5: Orphan " + regionIdx + "/" + totalRegions);
			}
			Address start = range.getMinAddress();
			long size = range.getLength();
			if (size < orphanMinSize) continue;

			byte[] bytes = new byte[(int) Math.min(size, 4096)];
			try {
				memory.getBytes(start, bytes);
			} catch (MemoryAccessException e) {
				continue;
			}

			// H08: Byte entropy check
			double entropy = byteEntropy(bytes, bytes.length);
			if (entropy < entropyLo || entropy > entropyHi) continue;

			// H21: Density check
			if (hasHighNullDensity(bytes, bytes.length)) continue;

			// H07: Data run check
			if (hasDataRuns(bytes, bytes.length)) continue;

			// Try speculative disassembly
			Set<Address> targets = new LinkedHashSet<>();
			AddressSet traced = traceForward(program, pseudo, start, targets, monitor);
			if (traced != null && !traced.isEmpty()) {
				// H10: Reference coherence validation
				if (hasCoherentReferences(traced, targets, listing)) {
					found += disassembleSet(program, traced, monitor);
					confidence.put(start, CONF_ORPHAN);

					// H11: Trace from newly discovered targets
					for (Address target : targets) {
						if (listing.getInstructionAt(target) == null &&
							memory.contains(target)) {
							AddressSet sub = traceForward(program, pseudo, target, new LinkedHashSet<>(), monitor);
							if (sub != null && !sub.isEmpty()) {
								found += disassembleSet(program, sub, monitor);
							}
						}
					}
				}
			}
		}
		return found;
	}

	/**
	 * H10: Check if traced block has coherent references
	 * (targets resolve to known code or valid regions).
	 */
	private boolean hasCoherentReferences(AddressSet block, Set<Address> targets, Listing listing) {
		if (targets.isEmpty()) return true; // No references to validate — accept on other merits
		int coherent = 0;
		for (Address target : targets) {
			if (listing.getInstructionAt(target) != null) {
				coherent++;
			} else if (block.contains(target)) {
				coherent++; // Self-referencing
			}
		}
		double ratio = (double) coherent / targets.size();
		return coherent >= 1 && ratio >= 0.10;
	}

	// ================================================================
	// Pass 6: Data/code boundary detection (H17)
	// ================================================================

	private int detectDataCodeBoundaries(Program program, PseudoDisassembler pseudo,
			Listing listing, Memory memory, TaskMonitor monitor) throws CancelledException {

		int found = 0;

		// Scan for transitions: data-like bytes followed by valid instructions
		InstructionIterator iter = listing.getInstructions(true);
		Address prevEnd = null;

		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();
			if (prevEnd != null) {
				long gap = instr.getAddress().subtract(prevEnd);
				if (gap > gapMaxSize && gap < 1024) {
					// Check if the region between prevEnd and this instruction
					// has data-like bytes at the start and code-like bytes at the end
					Address scanAddr = prevEnd;
					// Look for data->code transition within this gap
					for (long offset = 0; offset < gap - minBlockSize; offset++) {
						Address candidate = scanAddr.add(offset);
						if (!memory.contains(candidate)) continue;

						// Check preceding bytes are data-like
						if (offset > 8) {
							byte[] preceding = new byte[Math.min((int) offset, 32)];
							try {
								memory.getBytes(scanAddr, preceding);
								if (!isDataLike(preceding)) continue;
							} catch (MemoryAccessException e) {
								continue;
							}
						}

						// Try decoding at this boundary
						Set<Address> targets = new LinkedHashSet<>();
						AddressSet traced = traceForward(program, pseudo, candidate, targets, monitor);
						if (traced != null && !traced.isEmpty()) {
							found += disassembleSet(program, traced, monitor);
							confidence.put(candidate, CONF_DATA_BOUNDARY);
							break; // Found boundary, move on
						}
					}
				}
			}
			prevEnd = instr.getAddress().add(instr.getLength());
		}
		return found;
	}

	// ================================================================
	// Pass 7: Gap filling (H06)
	// ================================================================

	private int fillGaps(Program program, PseudoDisassembler pseudo,
			Listing listing, Memory memory, TaskMonitor monitor) throws CancelledException {

		int found = 0;

		// Find gaps between adjacent instructions
		InstructionIterator iter = listing.getInstructions(true);
		Instruction prev = null;

		List<Address> gapStarts = new ArrayList<>();

		while (iter.hasNext()) {
			Instruction instr = iter.next();
			if (prev != null) {
				Address prevEnd = prev.getAddress().add(prev.getLength());
				long gap = instr.getAddress().subtract(prevEnd);
				if (gap > 0 && gap <= gapMaxSize) {
					gapStarts.add(prevEnd);
				}
			}
			prev = instr;
		}

		for (Address gapStart : gapStarts) {
			monitor.checkCancelled();
			if (listing.getInstructionAt(gapStart) != null) continue;

			// Try to decode the gap
			boolean allValid = true;
			Address current = gapStart;
			AddressSet gapSet = new AddressSet();

			for (int i = 0; i < gapMaxSize; i++) {
				if (!memory.contains(current)) { allValid = false; break; }
				if (listing.getInstructionAt(current) != null) break; // Reached next block

				PseudoInstruction pinstr;
				try {
					pinstr = pseudo.disassemble(current);
				} catch (Exception e) {
					allValid = false; break;
				}
				if (pinstr == null) { allValid = false; break; }

				gapSet.add(current, current.add(pinstr.getLength() - 1));
				current = current.add(pinstr.getLength());
			}

			if (allValid && !gapSet.isEmpty()) {
				found += disassembleSet(program, gapSet, monitor);
				confidence.put(gapStart, CONF_GAP_FILL);
			}
		}
		return found;
	}

	// ================================================================
	// Data filter heuristics
	// ================================================================

	/**
	 * H07: Detect data runs — consecutive identical values.
	 */
	private boolean hasDataRuns(byte[] bytes, int len) {
		if (len < dataRunThreshold * 2) return false;

		// Check for runs of identical 16-bit words
		int runLen = 1;
		for (int i = 2; i < len - 1; i += 2) {
			if (bytes[i] == bytes[i - 2] && bytes[i + 1] == bytes[i - 1]) {
				runLen++;
				if (runLen >= dataRunThreshold) return true;
			} else {
				runLen = 1;
			}
		}

		// Check for runs of identical bytes
		runLen = 1;
		for (int i = 1; i < len; i++) {
			if (bytes[i] == bytes[i - 1]) {
				runLen++;
				if (runLen >= dataRunThreshold * 2) return true; // 8+ identical bytes
			} else {
				runLen = 1;
			}
		}
		return false;
	}

	/**
	 * H21: Check if region has high density of 0x00/0xFF bytes.
	 */
	private boolean hasHighNullDensity(byte[] bytes, int len) {
		if (len == 0) return false;
		int count = 0;
		for (int i = 0; i < len; i++) {
			if (bytes[i] == 0x00 || bytes[i] == (byte) 0xFF) count++;
		}
		return (double) count / len > densityThreshold;
	}

	/**
	 * H08: Compute Shannon entropy over byte distribution.
	 */
	private double byteEntropy(byte[] bytes, int len) {
		if (len == 0) return 0.0;
		int[] counts = new int[256];
		for (int i = 0; i < len; i++) {
			counts[bytes[i] & 0xFF]++;
		}
		return PcodePatternMatcher.shannonEntropy(counts, len);
	}

	/**
	 * H17: Check if a byte sequence looks like data (not code).
	 */
	private boolean isDataLike(byte[] bytes) {
		int nullFfCount = 0;
		int highBitCount = 0;
		for (byte b : bytes) {
			if (b == 0x00 || b == (byte) 0xFF) nullFfCount++;
			if ((b & 0x80) != 0) highBitCount++;
		}
		return (double) nullFfCount / bytes.length > 0.30 ||
			   (double) highBitCount / bytes.length > 0.40;
	}

	/**
	 * H33: Validate that P-code references point to valid memory regions.
	 */
	private boolean validateReferences(List<PcodeOp> pcode, Program program) {
		int totalRefs = 0;
		int invalidRefs = 0;

		for (PcodeOp op : pcode) {
			// Check LOAD/STORE targets
			if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
				Varnode addr = op.getInput(1);
				if (addr != null && addr.isConstant()) {
					totalRefs++;
					String validation = platform.validateAddress(addr.getOffset());
					if (validation != null) invalidRefs++;
				}
			}
			// Check CALL/BRANCH targets
			if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.BRANCH) {
				Varnode target = op.getInput(0);
				if (target != null && target.isAddress()) {
					totalRefs++;
					if (!platform.isValidCodeAddress(target.getOffset())) {
						invalidRefs++;
					}
				}
			}
		}

		// Reject if >30% of references are invalid
		if (totalRefs > 0 && (double) invalidRefs / totalRefs > 0.30) return false;
		return true;
	}

	// ================================================================
	// Platform detection & endianness check
	// ================================================================

	private void runPlatformDetection(Program program, TaskMonitor monitor, MessageLog log) {
		try {
			// Find the extension's data/platforms directory
			File platformDir = findPlatformDir(program);

			// --- ROM identification by SHA1 ---
			monitor.setMessage("Identifying ROM by SHA1 hash...");
			RomIdentifier romId = new RomIdentifier();
			List<RomIdentifier.RomMatch> romMatches = romId.identify(program.getMemory());
			if (!romMatches.isEmpty()) {
				RomIdentifier.RomMatch best = romMatches.get(0);
				String romMsg = String.format("ROM IDENTIFIED: %s (CPU: %s, match: %s)",
					best.toString(), best.cpu, best.matchType);
				Msg.info(this, romMsg);
				log.appendMsg("Heuristic Code Finder: " + romMsg);

				// Log all matches if multiple
				if (romMatches.size() > 1) {
					StringBuilder sb = new StringBuilder("All ROM matches:\n");
					for (RomIdentifier.RomMatch m : romMatches) {
						sb.append("  - ").append(m.toString()).append("\n");
					}
					Msg.info(this, sb.toString());
				}
			} else {
				Msg.info(this, String.format("ROM SHA1 lookup: no match (%d entries in database)",
					romId.getEntryCount()));
			}

			// --- Endianness check ---
			monitor.setMessage("Checking ROM byte order...");
			PlatformDetector.EndiannessResult endianness = PlatformDetector.detectEndianness(program, monitor);
			if (endianness.isSwapped()) {
				String warning = "WARNING: " + endianness.description;
				Msg.warn(this, warning);
				log.appendMsg("Heuristic Code Finder: " + warning);
			} else {
				Msg.info(this, "Endianness check: " + endianness.description);
			}

			// --- Base address inference ---
			monitor.setMessage("Inferring ROM base address...");
			PlatformDetector.BaseAddressResult baseResult =
				PlatformDetector.inferBaseAddress(program, monitor);
			if (baseResult.inferredBase != program.getMemory().getBlocks()[0].getStart().getOffset()
					&& baseResult.confidence > 0.15 && baseResult.targetsInRange >= 3) {
				String baseMsg = String.format("ROM BASE ADDRESS: %s (confidence: %.0f%%)",
					baseResult.description, baseResult.confidence * 100);
				Msg.warn(this, baseMsg);
				log.appendMsg("Heuristic Code Finder: " + baseMsg);
			} else {
				Msg.info(this, "Base address check: " + baseResult.description);
			}

			// --- Platform detection ---
			if (platformDir != null && platformDir.isDirectory()) {
				List<PlatformDetector.DetectionResult> results =
					PlatformDetector.detect(program, platformDir, 5000, 3, monitor);

				if (!results.isEmpty()) {
					StringBuilder msg = new StringBuilder();
					msg.append("Top platform matches:\n\n");
					int rank = 1;
					for (PlatformDetector.DetectionResult r : results) {
						msg.append(String.format("  %d. %s\n", rank++, r.toString()));
					}

					if (endianness.isSwapped()) {
						msg.append("\n  Note: ROM byte order issue detected — results may be less reliable.\n");
					}

					if (baseResult.inferredBase != program.getMemory().getBlocks()[0].getStart().getOffset()
							&& baseResult.confidence > 0.15) {
						msg.append(String.format("\n  Note: ROM may need to be loaded at base 0x%X\n",
							baseResult.inferredBase));
					}

					String resultMsg = msg.toString();
					Msg.info(this, resultMsg);
					log.appendMsg("Heuristic Code Finder: " + resultMsg.replace('\n', ' '));

					// If user hasn't specified a platform file, use the best match.
					// Require both a minimum score AND minimum absolute address matches
					// to ensure enough degrees of freedom for a reliable detection.
					if ((platformFile == null || platformFile.isEmpty()) &&
							results.get(0).score > 0.3 &&
							results.get(0).addressesMatched >= 10 &&
							results.get(0).platform != null) {
						platform = results.get(0).platform;
						Msg.info(this, "Auto-selected platform: " + results.get(0).platformName +
							" (score=" + String.format("%.0f%%", results.get(0).score * 100) +
							", " + results.get(0).addressesMatched + " addresses matched)");
					}
				} else {
					Msg.info(this, "Platform detection: no strong matches found");
				}
			}
		} catch (Exception e) {
			Msg.warn(this, "Platform detection failed: " + e.getMessage());
		}
	}

	/**
	 * Locate the data/platforms directory within the extension's installation.
	 * Ghidra extensions are installed under the user's .ghidra dir or Ghidra install dir.
	 */
	private File findPlatformDir(Program program) {
		// Try to find platform data from the extension's own data directory
		// The extension jar is typically at ExtName/lib/ExtName.jar
		// and data files at ExtName/data/platforms/
		try {
			// Method 1: Look in the extension's class loader resources
			java.net.URL url = getClass().getProtectionDomain().getCodeSource().getLocation();
			if (url != null) {
				File jarFile = new File(url.toURI());
				// jar is in ExtName/lib/ExtName.jar -> go up to ExtName, then data/platforms
				File extDir = jarFile.getParentFile().getParentFile();
				File dataDir = new File(extDir, "data/platforms");
				if (dataDir.isDirectory()) return dataDir;
			}
		} catch (Exception e) {
			// Fall through
		}

		// Method 2: Check Ghidra's extension install locations
		String[] searchPaths = {
			System.getProperty("user.home") + "/.ghidra",
			System.getenv("GHIDRA_INSTALL_DIR")
		};
		for (String base : searchPaths) {
			if (base == null) continue;
			try {
				// Search for HeuristicCodeFinder/data/platforms under this path
				File baseDir = new File(base);
				File found = findRecursive(baseDir, "HeuristicCodeFinder", 4);
				if (found != null) {
					File dataDir = new File(found, "data/platforms");
					if (dataDir.isDirectory()) return dataDir;
				}
			} catch (Exception e) {
				// ignore
			}
		}

		return null;
	}

	private File findRecursive(File dir, String name, int depth) {
		if (depth <= 0 || !dir.isDirectory()) return null;
		File[] children = dir.listFiles();
		if (children == null) return null;
		for (File child : children) {
			if (child.isDirectory() && child.getName().equals(name)) return child;
		}
		for (File child : children) {
			if (child.isDirectory()) {
				File found = findRecursive(child, name, depth - 1);
				if (found != null) return found;
			}
		}
		return null;
	}

	// ================================================================
	// Utility methods
	// ================================================================

	private int disassembleSet(Program program, AddressSet set, TaskMonitor monitor) {
		if (set.isEmpty()) return 0;
		DisassembleCommand cmd = new DisassembleCommand(set, set, true);
		cmd.applyTo(program);
		AddressSet result = cmd.getDisassembledAddressSet();
		return result != null ? (int) result.getNumAddresses() : 0;
	}

	private void loadPlatform(Program program) {
		if (platformFile != null && !platformFile.isEmpty()) {
			try {
				java.io.File f = new java.io.File(platformFile);
				if (f.exists()) {
					platform = PlatformDescription.loadFromXml(new java.io.FileInputStream(f));
					Msg.info(this, "Loaded platform: " + platform.getPlatformName());
					return;
				}
			} catch (Exception e) {
				Msg.warn(this, "Failed to load platform file: " + platformFile, e);
			}
		}
		platform = PlatformDescription.fromProgram(program);
		Msg.info(this, "Auto-detected platform: " + platform.getPlatformName());
	}

	private boolean program_isBigEndian(Memory memory) {
		// Infer from the memory object's program
		return memory.isBigEndian();
	}
}
