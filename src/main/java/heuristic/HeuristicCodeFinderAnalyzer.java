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
import ghidra.program.model.mem.MemoryBlock;
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
	private List<RomIdentifier.RomMatch> romMatches = new ArrayList<>();
	private PcodeVectorDatabase vectorDb;
	private boolean platformFromRomId = false; // true if platform loaded from ROM ID or user file
	private AddressSet dataRegions = new AddressSet(); // Regions known to be data, not code

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
		dataRegions.clear();
		platformFromRomId = false;

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

		// x86 reset vector: CPU starts execution at FFFF:0000 (8086) or
		// FFFFFFF0 (386+). Add as entry point if it falls within ROM.
		// Also parse the JMP instruction at the reset vector to extract
		// the actual entry point target address.
		String procName = program.getLanguage().getProcessor().toString();
		boolean isX86 = procName.contains("x86") || procName.contains("8086") ||
				procName.contains("8088") || procName.contains("80186") ||
				procName.contains("80286") || procName.contains("80386");
		if (isX86) {
			long resetAddr;
			boolean is386plus = procName.contains("80386") || procName.contains("80486");
			if (is386plus) {
				resetAddr = 0xFFFFFFF0L;
			} else {
				resetAddr = 0xFFFF0L; // FFFF:0000 physical
			}
			int x86Seeds = 0;
			if (memory.contains(defaultSpace.getAddress(resetAddr))) {
				vectorAddrs.add(resetAddr);
				x86Seeds++;

				// Parse the JMP at reset vector to find the actual entry point
				try {
					Address ra = defaultSpace.getAddress(resetAddr);
					byte opByte = memory.getByte(ra);
					int op = opByte & 0xFF;
					if (op == 0xEA) {
						// FAR JMP: EA oo oo ss ss (offset:segment, little-endian)
						byte[] jmpBuf = new byte[4];
						memory.getBytes(ra.add(1), jmpBuf);
						int offset = (jmpBuf[0] & 0xFF) | ((jmpBuf[1] & 0xFF) << 8);
						int segment = (jmpBuf[2] & 0xFF) | ((jmpBuf[3] & 0xFF) << 8);
						long target = ((long) segment << 4) + offset;
						if (memory.contains(defaultSpace.getAddress(target))) {
							vectorAddrs.add(target);
							x86Seeds++;
							Msg.info(this, "x86 reset JMP target: " + String.format(
								"%04X:%04X = 0x%X", segment, offset, target));
						}
					} else if (op == 0xE9) {
						// NEAR JMP: E9 ll hh (16-bit relative)
						byte[] jmpBuf = new byte[2];
						memory.getBytes(ra.add(1), jmpBuf);
						int rel = (short) ((jmpBuf[0] & 0xFF) | ((jmpBuf[1] & 0xFF) << 8));
						long target = resetAddr + 3 + rel; // PC after instruction + offset
						if (memory.contains(defaultSpace.getAddress(target))) {
							vectorAddrs.add(target);
							x86Seeds++;
						}
					} else if (op == 0xEB) {
						// SHORT JMP: EB dd (8-bit relative)
						byte rel = memory.getByte(ra.add(1));
						long target = resetAddr + 2 + rel;
						if (memory.contains(defaultSpace.getAddress(target))) {
							vectorAddrs.add(target);
							x86Seeds++;
						}
					}
				} catch (Exception e) {
					// ignore
				}
			}

			// For x86 ROMs with no reset vector in range, try the ROM start
			// (some embedded 80186/80188 systems boot from physical address 0xFFFF0
			// which maps to the start of the ROM chip)
			if (x86Seeds == 0) {
				long romStart = memory.getBlocks()[0].getStart().getOffset();
				// Check if first bytes look like valid x86 code
				try {
					Address startAddr = defaultSpace.getAddress(romStart);
					byte firstByte = memory.getByte(startAddr);
					int fb = firstByte & 0xFF;
					// Common x86 entry: JMP, CLI, MOV, XOR, PUSH
					if (fb == 0xEA || fb == 0xE9 || fb == 0xEB || fb == 0xFA ||
						fb == 0xB8 || fb == 0x33 || fb == 0x31 || fb == 0x50 ||
						fb == 0x55 || fb == 0xFC || fb == 0x90 || fb == 0xE8) {
						vectorAddrs.add(romStart);
						x86Seeds++;
						Msg.info(this, "x86 fallback: ROM start 0x" +
							Long.toHexString(romStart) + " as entry point (opcode 0x" +
							String.format("%02X", fb) + ")");
					}
				} catch (Exception e) {
					// ignore
				}
			}

			if (x86Seeds > 0) {
				Msg.info(this, "x86 entry points: " + x86Seeds + " seeds added");
			}
		}

		// ARM exception vector table: 8 entries at 0x00-0x1C.
		// Each is typically B <handler>, LDR PC,[PC,#off], or NOP (MOV Rn,Rn).
		// Read each 32-bit word; if it's a B instruction (0xEAxxxxxx) or
		// LDR PC (0xE59FFxxx), compute target and add as entry point.
		// Also add address 0x0 itself (reset vector).
		if (procName.contains("ARM") || procName.contains("arm")) {
			boolean bigEndian = memory.isBigEndian();
			long romBase = memory.getBlocks()[0].getStart().getOffset();
			int armVectorSeeds = 0;
			for (int vi = 0; vi < 8; vi++) {
				long vecAddr = romBase + vi * 4L;
				try {
					Address va = defaultSpace.getAddress(vecAddr);
					if (!memory.contains(va)) continue;
					byte[] buf = new byte[4];
					memory.getBytes(va, buf);
					long word;
					if (bigEndian) {
						word = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
							   ((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
					} else {
						word = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8) |
							   ((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
					}

					// Check for ARM B instruction: cond 1010 xxxx (0xEAxxxxxx or 0x_Axxxxxx)
					int cond = (int) ((word >> 28) & 0xF);
					int opField = (int) ((word >> 24) & 0xF);
					if (opField == 0xA && cond <= 0xE) {
						// B instruction — compute target: PC + 8 + (signed_imm24 << 2)
						int imm24 = (int) (word & 0x00FFFFFFL);
						if ((imm24 & 0x800000) != 0) imm24 |= 0xFF000000; // sign extend
						long target = vecAddr + 8 + ((long) imm24 << 2);
						if (target >= 0 && memory.contains(defaultSpace.getAddress(target))) {
							vectorAddrs.add(target);
							armVectorSeeds++;
						}
					}
					// Check for LDR PC,[PC,#offset]: 0xE59FF000 + offset
					else if ((word & 0xFFFFF000L) == 0xE59FF000L) {
						int offset = (int) (word & 0xFFF);
						// LDR PC,[PC,#off] reads from PC+8+off
						long ptrAddr = vecAddr + 8 + offset;
						try {
							Address pa = defaultSpace.getAddress(ptrAddr);
							if (memory.contains(pa)) {
								byte[] pbuf = new byte[4];
								memory.getBytes(pa, pbuf);
								long target;
								if (bigEndian) {
									target = ((pbuf[0] & 0xFFL) << 24) | ((pbuf[1] & 0xFFL) << 16) |
											 ((pbuf[2] & 0xFFL) << 8) | (pbuf[3] & 0xFFL);
								} else {
									target = (pbuf[0] & 0xFFL) | ((pbuf[1] & 0xFFL) << 8) |
											 ((pbuf[2] & 0xFFL) << 16) | ((pbuf[3] & 0xFFL) << 24);
								}
								if (target >= 0 && memory.contains(defaultSpace.getAddress(target))) {
									vectorAddrs.add(target);
									armVectorSeeds++;
								}
							}
						} catch (Exception e) { /* skip */ }
					}
				} catch (Exception e) { /* skip */ }
			}
			// Always add reset vector (address 0 or romBase) as entry point
			if (memory.contains(defaultSpace.getAddress(romBase))) {
				vectorAddrs.add(romBase);
				armVectorSeeds++;
			}
			// If no B/LDR PC vectors were found, the ROM may use a non-standard
			// header (e.g., RISC OS ROMs start with condition=0xF markers).
			// Scan the first 256 bytes for the first word with condition AL (0xE)
			// that looks like a data-processing or MOV instruction.
			if (armVectorSeeds <= 1) {
				for (int off = 4; off < 256; off += 4) {
					long scanAddr = romBase + off;
					try {
						Address sa = defaultSpace.getAddress(scanAddr);
						if (!memory.contains(sa)) continue;
						byte[] sbuf = new byte[4];
						memory.getBytes(sa, sbuf);
						long sw;
						if (bigEndian) {
							sw = ((sbuf[0] & 0xFFL) << 24) | ((sbuf[1] & 0xFFL) << 16) |
								 ((sbuf[2] & 0xFFL) << 8) | (sbuf[3] & 0xFFL);
						} else {
							sw = (sbuf[0] & 0xFFL) | ((sbuf[1] & 0xFFL) << 8) |
								 ((sbuf[2] & 0xFFL) << 16) | ((sbuf[3] & 0xFFL) << 24);
						}
						int sc = (int) ((sw >> 28) & 0xF);
						if (sc == 0xE && sw != 0xE1A00000L) { // AL condition, not NOP
							vectorAddrs.add(scanAddr);
							armVectorSeeds++;
							Msg.info(this, "ARM fallback entry at 0x" +
								Long.toHexString(scanAddr) + " (first AL instruction after header)");
							break;
						}
					} catch (Exception e) { /* skip */ }
				}
			}
			if (armVectorSeeds > 0) {
				Msg.info(this, "ARM exception vectors: " + armVectorSeeds +
					" entry points added from vector table at 0x" + Long.toHexString(romBase));
			}
		}

		// MIPS reset vector: CPU boots at 0xBFC00000 (kseg1) = physical 0x1FC00000.
		// Add the ROM base as entry point — the first instruction is the reset handler.
		// Also add standard exception handler offsets if they fall within ROM.
		if (procName.contains("MIPS")) {
			long romBase = memory.getBlocks()[0].getStart().getOffset();
			if (memory.contains(defaultSpace.getAddress(romBase))) {
				vectorAddrs.add(romBase);
				Msg.info(this, "MIPS reset vector at 0x" + Long.toHexString(romBase) +
					" added as entry point");
			}
			// MIPS exception vectors relative to ROM base (R3000/R4000 BEV=1 mode):
			// 0x000 = reset, 0x200 = TLB refill, 0x280 = XTLB refill (R4000),
			// 0x300 = cache error, 0x380 = general exception
			long[] mipsExcOffsets = { 0x200, 0x280, 0x300, 0x380 };
			for (long off : mipsExcOffsets) {
				long excAddr = romBase + off;
				if (memory.contains(defaultSpace.getAddress(excAddr))) {
					vectorAddrs.add(excAddr);
				}
			}
		}

		// PowerPC reset vector: CPU starts at 0xFFF00100 (exception vector base
		// 0xFFF00000 + 0x100 for system reset). Common exception offsets:
		// 0x100=reset, 0x200=machine check, 0x300=DSI, 0x400=ISI,
		// 0x500=external, 0x600=alignment, 0x700=program, 0x800=FPU unavail,
		// 0x900=decrementer, 0xC00=syscall
		if (procName.contains("PowerPC") || procName.contains("ppc")) {
			long romBase = memory.getBlocks()[0].getStart().getOffset();
			long romEnd = memory.getBlocks()[0].getEnd().getOffset();
			int ppcSeeds = 0;

			// Try ROM base + standard exception offsets
			long[] ppcExcOffsets = { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600,
				0x700, 0x800, 0x900, 0xC00 };
			for (long off : ppcExcOffsets) {
				long excAddr = romBase + off;
				if (excAddr <= romEnd && memory.contains(defaultSpace.getAddress(excAddr))) {
					// Check if it looks like valid PPC code (not 0x00000000 or 0xFFFFFFFF)
					try {
						byte[] buf = new byte[4];
						memory.getBytes(defaultSpace.getAddress(excAddr), buf);
						long word = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
							((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
						if (word != 0 && word != 0xFFFFFFFFL) {
							vectorAddrs.add(excAddr);
							ppcSeeds++;
						}
					} catch (Exception e) { /* skip */ }
				}
			}
			// Also add ROM base itself if it has valid-looking code
			if (memory.contains(defaultSpace.getAddress(romBase))) {
				try {
					byte[] buf = new byte[4];
					memory.getBytes(defaultSpace.getAddress(romBase), buf);
					long word = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
						((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
					if (word != 0 && word != 0xFFFFFFFFL) {
						vectorAddrs.add(romBase);
						ppcSeeds++;
					}
				} catch (Exception e) { /* skip */ }
			}
			if (ppcSeeds > 0) {
				Msg.info(this, "PowerPC exception vectors: " + ppcSeeds +
					" entry points added");
			}
		}

		// WE32100: boot sequence reads PCBP from $80, then PC from [PCBP+4].
		// Also add exception handler addresses from the vector table at $84+.
		if (procName.contains("WE32100") || procName.contains("WE32")) {
			int we32Seeds = 0;
			try {
				MemoryBlock blk = memory.getBlocks()[0];
				long romBase32 = blk.getStart().getOffset();
				long romSize32 = blk.getSize();
				if (romSize32 > 0x90) {
					byte[] buf4 = new byte[4];
					// Read PCBP from $80
					memory.getBytes(defaultSpace.getAddress(romBase32 + 0x80), buf4);
					long pcbp = ((buf4[0] & 0xFFL) << 24) | ((buf4[1] & 0xFFL) << 16) |
						((buf4[2] & 0xFFL) << 8) | (buf4[3] & 0xFFL);
					// Read PC from [PCBP+4] if PCBP is within ROM
					if (pcbp >= romBase32 && pcbp + 8 < romBase32 + romSize32) {
						memory.getBytes(defaultSpace.getAddress(pcbp + 4), buf4);
						long initPC = ((buf4[0] & 0xFFL) << 24) | ((buf4[1] & 0xFFL) << 16) |
							((buf4[2] & 0xFFL) << 8) | (buf4[3] & 0xFFL);
						if (initPC >= romBase32 && initPC < romBase32 + romSize32) {
							vectorAddrs.add(initPC);
							we32Seeds++;
						}
					}
					// Read exception handler addresses from $84 onwards (up to 64 vectors)
					Set<Long> seenVecs = new HashSet<>();
					for (int vi = 0; vi < 64 && (0x84 + vi * 4 + 4) <= romSize32; vi++) {
						memory.getBytes(defaultSpace.getAddress(romBase32 + 0x84 + vi * 4), buf4);
						long excAddr = ((buf4[0] & 0xFFL) << 24) | ((buf4[1] & 0xFFL) << 16) |
							((buf4[2] & 0xFFL) << 8) | (buf4[3] & 0xFFL);
						if (excAddr >= romBase32 && excAddr < romBase32 + romSize32 &&
							excAddr != 0 && excAddr != 0xFFFFFFFFL && seenVecs.add(excAddr)) {
							vectorAddrs.add(excAddr);
							we32Seeds++;
						}
					}
				}
			} catch (Exception e) { /* skip */ }
			if (we32Seeds > 0) {
				Msg.info(this, "WE32100 vectors: " + we32Seeds + " entry points added");
			}
		}

		// 8051: interrupt vector table at fixed addresses. Each entry contains code
		// (LJMP/AJMP), not address pointers. Add vector addresses as code entry points.
		// Vectors: 0x0000=Reset, 0x0003=INT0, 0x000B=Timer0, 0x0013=INT1,
		// 0x001B=Timer1, 0x0023=Serial, 0x002B=Timer2 (8052)
		if (procName.contains("8051") || procName.contains("8052") ||
			procName.contains("8048") || procName.contains("8049") ||
			procName.contains("80C51") || procName.contains("80C52")) {
			long[] i8051Vectors = { 0x0000, 0x0003, 0x000B, 0x0013, 0x001B, 0x0023, 0x002B };
			int i8051Seeds = 0;
			for (long vecAddr : i8051Vectors) {
				try {
					// Try CODE space first (Harvard architecture), then default space
					Address va = null;
					for (MemoryBlock blk : memory.getBlocks()) {
						Address candidate = blk.getStart().getAddressSpace().getAddress(vecAddr);
						if (blk.contains(candidate)) {
							va = candidate;
							break;
						}
					}
					if (va == null) continue;
					// Verify the location has non-FF data (not erased PROM)
					byte[] chk = new byte[1];
					memory.getBytes(va, chk);
					if ((chk[0] & 0xFF) != 0xFF) {
						vectorAddrs.add(vecAddr);
						i8051Seeds++;
					}
				} catch (Exception e) { /* skip */ }
			}
			if (i8051Seeds > 0) {
				Msg.info(this, "8051 vectors: " + i8051Seeds + " entry points added");
			}
		}

		// 8085: interrupt vector table at 0x0000 (RST 0/RESET), 0x0008 (RST 1),
		// 0x0010 (RST 2), ..., 0x0038 (RST 7), plus TRAP=0x0024,
		// RST 5.5=0x002C, RST 6.5=0x0034, RST 7.5=0x003C.
		// Each vector is a code entry point (JMP instruction at the vector address).
		if (procName.contains("8085") || procName.contains("8080")) {
			long[] i8085Vectors = { 0x0000, 0x0008, 0x0010, 0x0018, 0x0020,
				0x0024, 0x0028, 0x002C, 0x0030, 0x0034, 0x0038, 0x003C };
			int i8085Seeds = 0;
			for (long vecAddr : i8085Vectors) {
				try {
					Address va = null;
					for (MemoryBlock blk : memory.getBlocks()) {
						Address candidate = blk.getStart().getAddressSpace().getAddress(vecAddr);
						if (blk.contains(candidate)) {
							va = candidate;
							break;
						}
					}
					if (va == null) continue;
					byte[] chk = new byte[1];
					memory.getBytes(va, chk);
					if ((chk[0] & 0xFF) != 0xFF && (chk[0] & 0xFF) != 0x00) {
						vectorAddrs.add(vecAddr);
						i8085Seeds++;
					}
				} catch (Exception e) { /* skip */ }
			}
			if (i8085Seeds > 0) {
				Msg.info(this, "8085 vectors: " + i8085Seeds + " entry points added");
			}
		}

		// 6502/6809: read reset/NMI/IRQ vectors from end of ROM and add as code entry points.
		// These vectors live at fixed CPU addresses ($FFFA-$FFFF for 6502, $FFF2-$FFFF for 6809)
		// but in a small ROM they're at the end of the ROM image, which may be mapped elsewhere.
		// We read relative to the end of the ROM (like PlatformDetector does).
		boolean is6502 = procName.contains("6502") || procName.contains("65C02") ||
			procName.contains("N2A03") || procName.contains("n2a03");
		boolean is6809 = procName.contains("6809") || procName.contains("6309") ||
			procName.contains("HD6309");
		if (is6502 || is6809) {
			int vecSeeds6x = 0;
			try {
				MemoryBlock blk = memory.getBlocks()[0];
				long romBase6x = blk.getStart().getOffset();
				long romSize6x = blk.getSize();
				// 6502: 3 vectors at end-6..end-1 (NMI, RESET, IRQ), little-endian
				// 6809: 7 vectors at end-14..end-1 (SWI3,SWI2,FIRQ,IRQ,SWI,NMI,RESET), big-endian
				int numVectors = is6502 ? 3 : 7;
				int vecTableSize = numVectors * 2;
				if (romSize6x >= vecTableSize) {
					byte[] vecBuf = new byte[2];
					for (int i = 0; i < numVectors; i++) {
						long offset = romSize6x - vecTableSize + (i * 2);
						Address va = blk.getStart().add(offset);
						memory.getBytes(va, vecBuf);
						long target;
						if (is6809) {
							target = ((vecBuf[0] & 0xFF) << 8) | (vecBuf[1] & 0xFF);
						} else {
							target = (vecBuf[0] & 0xFF) | ((vecBuf[1] & 0xFF) << 8);
						}
						// Valid target: non-zero, not $FFFF, within ROM range
						if (target != 0 && target != 0xFFFFL &&
							target >= romBase6x &&
							target < romBase6x + romSize6x) {
							vectorAddrs.add(target);
							vecSeeds6x++;
						}
					}
				}
			} catch (Exception e) { /* skip */ }
			if (vecSeeds6x > 0) {
				Msg.info(this, (is6502 ? "6502" : "6809") + " vectors: " +
					vecSeeds6x + " entry points added");
			}
		}

		int vectorSeeds = 0;
		for (Long addr : vectorAddrs) {
			monitor.checkCancelled();
			Address entryAddr = defaultSpace.getAddress(addr);
			if (listing.getInstructionAt(entryAddr) == null &&
				memory.contains(entryAddr)) {
				entryPoints.add(entryAddr);
				functionEntries.add(entryAddr);
				confidence.put(entryAddr, CONF_VECTOR);
				vectorSeeds++;
			}
		}
		Msg.info(this, "Pass 1: " + vectorAddrs.size() + " vector entry points" +
			" (" + vectorSeeds + " new seeds, " + (vectorAddrs.size() - vectorSeeds) + " already disassembled)");

		// Mark 68000 vector table (0x000-0x3FF) as data — 256 x 4-byte pointers.
		// Vector entries are addresses, not code. Prevents orphan recovery and gap
		// fill from falsely disassembling pointer values as instructions.
		boolean is68k = procName.contains("68") && !procName.contains("HC") &&
			!procName.contains("6502") && !procName.contains("6809") && !procName.contains("6805");
		if (is68k) {
			long vecBase = memory.getBlocks()[0].getStart().getOffset();
			long vecTableEnd = vecBase + 0x3FF;
			try {
				Address vecStartAddr = defaultSpace.getAddress(vecBase);
				Address vecEndAddr = defaultSpace.getAddress(vecTableEnd);
				if (memory.contains(vecStartAddr) && memory.contains(vecEndAddr)) {
					dataRegions.add(vecStartAddr, vecEndAddr);
					Msg.info(this, String.format("68000 vector table 0x%X-0x%X marked as data",
						vecBase, vecTableEnd));
				}
			} catch (Exception e) { /* skip */ }
		}

		// ============================================================
		// Pass 2: Forward trace from seeds (H01-H05, H07, H08, H21, H23)
		// ============================================================
		monitor.setMessage("Heuristic Pass 2: Forward trace from seeds");
		int pass2Found = 0;
		Set<Address> newTargets = new LinkedHashSet<>();

		for (Address seed : new ArrayList<>(entryPoints)) {
			monitor.checkCancelled();
			AddressSet traced = traceForward(program, pseudo, seed, newTargets, monitor, true);
			if (traced != null && !traced.isEmpty()) {
				pass2Found += disassembleSet(program, traced, monitor);
			}
		}
		totalFound += pass2Found;
		Msg.info(this, "Pass 2: " + pass2Found + " instructions from vector seeds");

		// Collect flow targets from ALL disassembled instructions (including those
		// disassembled by Ghidra's DisassembleCommand which bypasses our collectTargets)
		int rescued = collectMissedFlowTargets(program, newTargets);
		if (rescued > 0) {
			Msg.info(this, "Pass 2 post-scan: " + rescued + " additional flow targets from Ghidra-disassembled instructions");
		}

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

				AddressSet traced = traceForward(program, pseudo, target, nextTargets, monitor, true);
				if (traced != null && !traced.isEmpty()) {
					pass3Round += disassembleSet(program, traced, monitor);
				}
			}
			pass3Total += pass3Round;
			// Also collect any flow targets from Ghidra's internal flow-following
			collectMissedFlowTargets(program, nextTargets);
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
		// Pass 8: Remove isolated code islands (false positives)
		// ============================================================
		monitor.setMessage("Heuristic Pass 8: Removing isolated code islands");
		int islandsRemoved = removeIsolatedIslands(program, listing, monitor);
		if (islandsRemoved > 0) {
			totalFound -= islandsRemoved;
			Msg.info(this, "Pass 8: " + islandsRemoved +
				" instructions removed (isolated 1-3 instruction islands with no references)");
		}

		// ============================================================
		// Pass 9 & 10: Overlap resolution (H14) and confidence (H20)
		// are handled implicitly — Ghidra's Listing prevents overlaps,
		// and confidence is tracked in our map for reporting.
		// ============================================================

		// ============================================================
		// Pass 11: Function pattern detection & hardware register labeling
		// ============================================================
		monitor.setMessage("Heuristic Pass 11: Function classification & HW register labeling");
		FunctionPatternDetector fpd = new FunctionPatternDetector(program, platform);

		// Initialize P-code vector database for structural similarity matching
		if (vectorDb == null) {
			vectorDb = new PcodeVectorDatabase();
			vectorDb.ensureLoaded();
		}
		fpd.setVectorDatabase(vectorDb);

		// Determine ROM domain from identification results or platform
		PcodeVectorDatabase.RomDomain domain;
		if (!romMatches.isEmpty()) {
			domain = PcodeVectorDatabase.classifyDomain(romMatches);
		} else {
			String cpuName = program.getLanguage().getProcessor().toString();
			domain = PcodeVectorDatabase.classifyDomainFromPlatform(cpuName, platform);
		}
		fpd.setRomDomain(domain);
		Msg.info(this, "Pass 11: ROM domain = " + domain +
			", vector DB has " + vectorDb.getSignatureCount() + " signatures");

		int hwLabels = 0;
		try {
			hwLabels = fpd.labelHardwareRegisters(monitor);
			if (hwLabels > 0) {
				Msg.info(this, "Pass 11: " + hwLabels + " hardware register labels created");
			}
		} catch (Exception e) {
			Msg.warn(this, "Hardware register labeling failed: " + e.getMessage());
		}

		int classified = 0;
		try {
			classified = fpd.classifyAllFunctions(monitor);
			if (classified > 0) {
				Msg.info(this, "Pass 11: " + classified + " functions classified by pattern");
			}
		} catch (Exception e) {
			Msg.warn(this, "Function classification failed: " + e.getMessage());
		}

		// Check for compressed/encrypted ROM: if code coverage is very low relative
		// to ROM size, the ROM is likely compressed or encrypted.
		long romSize = memory.getBlocks()[0].getSize();
		int instrSize = program.getLanguage().getInstructionAlignment();
		if (instrSize < 2) instrSize = 2;
		long maxPossible = romSize / instrSize;
		double coverage = maxPossible > 0 ? (double) totalFound / maxPossible : 0;
		if (totalFound < 100 && romSize >= 65536 && coverage < 0.01) {
			String compWarn = String.format(
				"WARNING: Very low code coverage (%.2f%%, %d instructions in %dKB ROM). " +
				"This ROM may be compressed, encrypted, or require decompression before analysis.",
				coverage * 100, totalFound, romSize / 1024);
			Msg.warn(this, compWarn);
			log.appendMsg("Heuristic Code Finder: " + compWarn);
		}

		Msg.info(this, "Heuristic Code Finder complete: " + totalFound + " total instructions found" +
			(classified > 0 ? ", " + classified + " functions classified" : "") +
			(hwLabels > 0 ? ", " + hwLabels + " HW registers labeled" : ""));
		log.appendMsg("Heuristic Code Finder: " + totalFound + " instructions across " +
			entryPoints.size() + " entry points" +
			(classified > 0 ? ", " + classified + " functions classified" : "") +
			(hwLabels > 0 ? ", " + hwLabels + " HW registers labeled" : ""));

		// Write hardware memory map as plate comment at program base address
		// for export scripts to include in output headers
		writePlatformInfo(program);

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
		return traceForward(program, pseudo, seed, newTargets, monitor, false);
	}

	private AddressSet traceForward(Program program, PseudoDisassembler pseudo,
			Address seed, Set<Address> newTargets, TaskMonitor monitor, boolean trusted) {

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

		// Apply data filters (relaxed for trusted seeds from vectors/references)
		if (!trusted && totalBytes < minBlockSize) return null;

		// H23: Valid decode ratio (always apply)
		if (totalBytes > 0 && (double) validBytes / totalBytes < validRatioMin) return null;

		// H07: Data run detection (always apply — repeated identical bytes)
		if (hasDataRuns(blockBytes, blockByteLen)) return null;

		// H21: Byte density check (skip for trusted seeds)
		if (!trusted && hasHighNullDensity(blockBytes, blockByteLen)) return null;

		// H08: Byte entropy filtering (skip for trusted seeds and small blocks)
		double entropy = byteEntropy(blockBytes, blockByteLen);
		if (!trusted && blockByteLen >= 64 && (entropy < entropyLo || entropy > entropyHi)) return null;

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

		// ARM coprocessor false positive filter: ARM7TDMI has no coprocessors,
		// so CDP/LDC/STC/MCR/MRC instructions indicate data decoded as code.
		String traceProc = program.getLanguage().getProcessor().toString();
		if (traceProc.contains("ARM") && block.size() >= 3) {
			int coprocCount = 0;
			for (PseudoInstruction pi : block) {
				String mnem = pi.getMnemonicString().toLowerCase();
				if (mnem.startsWith("cdp") || mnem.startsWith("ldc") ||
					mnem.startsWith("stc") || mnem.startsWith("mcr") ||
					mnem.startsWith("mrc") || mnem.startsWith("msr") ||
					mnem.startsWith("mrs")) {
					coprocCount++;
				}
			}
			if ((double) coprocCount / block.size() > 0.20) return null;
		}

		// Skip known data regions (e.g., 68000 vector table)
		if (dataRegions.contains(seed)) return null;

		// H33: Memory map validation (Tier 3) — skip for trusted seeds
		if (!trusted && !platform.getMemoryMap().isEmpty()) {
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

	/**
	 * Scan all disassembled instructions for flow targets that haven't been
	 * disassembled yet. This catches targets from Ghidra's DisassembleCommand
	 * flow-following, which bypasses our collectTargets() method.
	 * Also collects data references (e.g., PC-relative LEA/PEA) that point to
	 * undisassembled ROM regions — these are likely code pointers (exception
	 * handlers, callback tables, etc.).
	 */
	private int collectMissedFlowTargets(Program program, Set<Address> targets) {
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		int count = 0;

		InstructionIterator iter = listing.getInstructions(true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();

			// Collect direct flow targets (branches/calls)
			Address[] flows = instr.getFlows();
			if (flows != null) {
				for (Address target : flows) {
					if (!memory.contains(target)) continue;
					if (listing.getInstructionAt(target) != null) continue;
					if (targets.contains(target)) continue;

					targets.add(target);
					entryPoints.add(target);
					FlowType flow = instr.getFlowType();
					if (flow.isCall()) {
						functionEntries.add(target);
						if (!confidence.containsKey(target)) {
							confidence.put(target, CONF_CALL);
						}
					} else if (!confidence.containsKey(target)) {
						confidence.put(target, flow.isConditional() ? CONF_CBRANCH : CONF_BRANCH);
					}
					count++;
				}
			}

			// Collect data references that may be code pointers (LEA, PEA, etc.)
			ghidra.program.model.symbol.Reference[] refs = instr.getReferencesFrom();
			if (refs != null) {
				for (ghidra.program.model.symbol.Reference ref : refs) {
					if (ref.getReferenceType().isFlow()) continue; // already handled above
					if (!ref.getReferenceType().isData()) continue;
					Address target = ref.getToAddress();
					if (!memory.contains(target)) continue;
					if (listing.getInstructionAt(target) != null) continue;
					if (targets.contains(target)) continue;
					// Only treat as code if target is in a code-capable region
					if (!platform.isValidCodeAddress(target.getOffset())) continue;
					targets.add(target);
					entryPoints.add(target);
					if (!confidence.containsKey(target)) {
						confidence.put(target, CONF_BRANCH);
					}
					count++;
				}
			}
		}
		return count;
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

			// Skip known data regions (e.g., 68000 vector table)
			if (dataRegions.contains(start)) continue;

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

						// Skip known data regions (e.g., 68000 vector table)
						if (dataRegions.contains(candidate)) continue;

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
			if (dataRegions.contains(gapStart)) continue; // Skip known data regions

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
	// Pass 8: Isolated code island removal
	// ================================================================

	/**
	 * Remove very small code blocks (1-3 instructions) that are completely
	 * isolated: no references point to them, not adjacent to other code,
	 * and not a known entry point. These are data bytes that happen to
	 * decode as valid instructions (common with V850, ARM, MIPS).
	 */
	private int removeIsolatedIslands(Program program, Listing listing,
			TaskMonitor monitor) throws CancelledException {

		List<Address[]> toRemove = new ArrayList<>();

		InstructionIterator iter = listing.getInstructions(true);
		List<Instruction> island = new ArrayList<>();

		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = iter.next();

			if (island.isEmpty()) {
				island.add(instr);
				continue;
			}

			Instruction last = island.get(island.size() - 1);
			Address expectedNext = last.getAddress().add(last.getLength());

			if (instr.getAddress().equals(expectedNext)) {
				island.add(instr);
			} else {
				// Gap — evaluate the completed island
				evaluateIsland(program, island, toRemove);
				island.clear();
				island.add(instr);
			}
		}
		// Handle last island
		if (!island.isEmpty()) {
			evaluateIsland(program, island, toRemove);
		}

		// Remove the islands
		int removed = 0;
		for (Address[] range : toRemove) {
			try {
				listing.clearCodeUnits(range[0], range[1], false);
				removed++;
			} catch (Exception e) {
				// ignore
			}
		}
		return removed;
	}

	private void evaluateIsland(Program program, List<Instruction> island,
			List<Address[]> toRemove) {
		if (island.size() > 3) return; // Only remove very small islands

		// Check if anything references this island or it's a known entry point
		for (Instruction instr : island) {
			Address addr = instr.getAddress();
			// Check for incoming references
			ghidra.program.model.symbol.ReferenceIterator refs =
				program.getReferenceManager().getReferencesTo(addr);
			if (refs.hasNext()) return; // Has references — keep it
			// Check if it's a known high-confidence entry point (vector, call target)
			if (confidence.containsKey(addr) &&
				confidence.get(addr) >= CONF_CALL) {
				return; // Known call target — keep it
			}
			if (functionEntries.contains(addr)) return; // Function entry — keep
		}

		// No references, not a known entry point — mark for removal
		Instruction first = island.get(0);
		Instruction last = island.get(island.size() - 1);
		toRemove.add(new Address[]{
			first.getAddress(),
			last.getAddress().add(last.getLength() - 1)
		});
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
			this.romMatches = romId.identify(program.getMemory());
			if (!romMatches.isEmpty()) {
				RomIdentifier.RomMatch best = romMatches.get(0);
				String romMsg = String.format("ROM IDENTIFIED: %s (CPU: %s, match: %s)",
					best.toString(), best.cpu, best.matchType);
				Msg.info(this, romMsg);
				log.appendMsg("Heuristic Code Finder: " + romMsg);

				// Warn if this is a split/incomplete ROM.
				// Detect by: matchType "split*", non-zero slice index (offset & 3),
				// or loadType indicating byte/word-interleaved loading.
				boolean isSplit = best.matchType.startsWith("split");
				if (!isSplit && (best.romOffset & 3) != 0) isSplit = true; // non-zero slice = interleaved chip
				if (!isSplit && best.loadType != null &&
					(best.loadType.contains("bit_byte") || best.loadType.contains("bit_word"))) {
					isSplit = true;
				}
				// If the actual ROM file is larger than the MAME chip size, the file
				// is likely already interleaved/combined — suppress the split warning.
				if (isSplit && best.romSize > 0) {
					long actualSize = program.getMemory().getBlocks()[0].getSize();
					if (actualSize > best.romSize) {
						Msg.info(this, String.format(
							"ROM matched as %s (chip size %d) but file is %d bytes — " +
							"likely already interleaved, not a single chip",
							best.matchType, best.romSize, actualSize));
						isSplit = false;
					}
				}
				if (isSplit) {
					String splitWarn = String.format(
						"WARNING: This ROM is an incomplete split chip (%s, offset 0x%X). " +
						"It must be combined with its matching chip(s) before disassembly.",
						best.matchType, best.romOffset);
					Msg.warn(this, splitWarn);
					log.appendMsg("Heuristic Code Finder: " + splitWarn);
				}

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

				// Check if the ROM fills the entire address space — likely a
				// bank-switched ROM that was truncated by Ghidra's loader
				AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
				long spaceSize = space.getMaxAddress().getOffset() - space.getMinAddress().getOffset() + 1;
				Memory mem = program.getMemory();
				long loadedSize = 0;
				for (ghidra.program.model.mem.MemoryBlock b : mem.getBlocks()) {
					if (b.isInitialized()) loadedSize += b.getSize();
				}
				if (spaceSize <= 0x10000 && loadedSize == spaceSize) {
					String truncWarn = String.format(
						"WARNING: ROM fills the entire %d-bit address space (%dKB). " +
						"If the original file is larger, it uses bank switching and was " +
						"truncated by Ghidra's loader. SHA1 identification will not work. " +
						"Only the first %dKB (bank 0) is loaded.",
						space.getSize(), loadedSize / 1024, loadedSize / 1024);
					Msg.warn(this, truncWarn);
					log.appendMsg("Heuristic Code Finder: " + truncWarn);
				}
			}

			// --- Use ROM identification to load matching platform XML ---
			if (!romMatches.isEmpty() && platformDir != null && platformDir.isDirectory()) {
				String machName = romMatches.get(0).machine;
				java.io.File mameDir = new java.io.File(platformDir, "mame");
				java.io.File matchedXml = null;
				if (mameDir.isDirectory()) {
					java.io.File[] mfrDirs = mameDir.listFiles(java.io.File::isDirectory);
					if (mfrDirs != null) {
						outer:
						for (java.io.File mfrDir : mfrDirs) {
							// Try exact name first, then with manufacturer prefix
							java.io.File candidate = new java.io.File(mfrDir, machName + ".xml");
							if (candidate.exists()) {
								matchedXml = candidate;
								break;
							}
							// Try mfr + machName (e.g., att + 3b2_300 = att3b2_300.xml)
							String mfrPrefix = mfrDir.getName();
							candidate = new java.io.File(mfrDir, mfrPrefix + machName + ".xml");
							if (candidate.exists()) {
								matchedXml = candidate;
								break;
							}
							// Try mfr + "_" + machName
							candidate = new java.io.File(mfrDir, mfrPrefix + "_" + machName + ".xml");
							if (candidate.exists()) {
								matchedXml = candidate;
								break;
							}
						}
					}
				}
				if (matchedXml == null) {
					java.io.File candidate = new java.io.File(platformDir, machName + ".xml");
					if (candidate.exists()) matchedXml = candidate;
				}
				if (matchedXml != null) {
					try (java.io.FileInputStream fis = new java.io.FileInputStream(matchedXml)) {
						platform = PlatformDescription.loadFromXml(fis);
						platformFromRomId = true;
						Msg.info(this, "Loaded platform from ROM ID: " + matchedXml.getName() +
							" (" + platform.getPlatformName() + ")");
					} catch (Exception e) {
						Msg.warn(this, "Failed to load platform XML " + matchedXml + ": " + e.getMessage());
					}
				}
			}

			// --- Endianness check ---
			monitor.setMessage("Checking ROM byte order...");
			PlatformDetector.EndiannessResult endianness = PlatformDetector.detectEndianness(program, monitor);
			if (endianness.isSwapped()) {
				String warning = "WARNING: " + endianness.description;

				// WE32100: "byte-swap" usually means 4-way byte interleaving (ROM_LOAD32_BYTE),
				// not simple byte-swap. Each chip provides every 4th byte.
				String endianProc = program.getLanguage().getProcessor().toString();
				if (endianProc.contains("WE32100") || endianProc.contains("WE32")) {
					warning = "WARNING: WE32100 ROM appears to be a single chip from a " +
						"4-way byte-interleaved set (ROM_LOAD32_BYTE). The 4 chips must be " +
						"combined by interleaving bytes before analysis — simple byte-swapping " +
						"will not fix it. " + endianness.description;
				}

				Msg.warn(this, warning);
				log.appendMsg("Heuristic Code Finder: " + warning);

				// Actually byte-swap the ROM data in memory
				try {
					ghidra.program.model.mem.MemoryBlock block = program.getMemory().getBlocks()[0];
					byte[] data = new byte[(int) block.getSize()];
					program.getMemory().getBytes(block.getStart(), data);

					if (endianness.status.equals("swapped16in32") || endianness.status.equals("swapped16")) {
						// Swap bytes within each 16-bit word
						for (int si = 0; si < data.length - 1; si += 2) {
							byte tmp = data[si];
							data[si] = data[si + 1];
							data[si + 1] = tmp;
						}
					} else if (endianness.status.equals("swapped32")) {
						// Full 32-bit byte reversal
						for (int si = 0; si < data.length - 3; si += 4) {
							byte t0 = data[si], t1 = data[si + 1];
							data[si] = data[si + 3];
							data[si + 1] = data[si + 2];
							data[si + 2] = t1;
							data[si + 3] = t0;
						}
					}

					program.getMemory().setBytes(block.getStart(), data);
					Msg.info(this, String.format("Byte-swapped ROM (%s, %d bytes)",
						endianness.status, data.length));
				} catch (Exception e) {
					Msg.warn(this, "Failed to byte-swap ROM: " + e.getMessage());
				}
			} else {
				Msg.info(this, "Endianness check: " + endianness.description);
			}

			// --- Base address inference ---
			monitor.setMessage("Inferring ROM base address...");
			PlatformDetector.BaseAddressResult baseResult =
				PlatformDetector.inferBaseAddress(program, monitor);
			long currentBase = program.getMemory().getBlocks()[0].getStart().getOffset();
			if (baseResult.inferredBase != currentBase
					&& baseResult.confidence > 0.15
					&& (baseResult.targetsInRange >= 3 || baseResult.confidence >= 0.80)) {
				String baseMsg = String.format("ROM BASE ADDRESS: %s (confidence: %.0f%%)",
					baseResult.description, baseResult.confidence * 100);
				Msg.warn(this, baseMsg);
				log.appendMsg("Heuristic Code Finder: " + baseMsg);

				// Relocate memory block to inferred base address
				if (baseResult.confidence >= 0.50
						&& (baseResult.targetsInRange >= 5 || baseResult.confidence >= 0.80)) {
					try {
						ghidra.program.model.mem.MemoryBlock block =
							program.getMemory().getBlocks()[0];
						Address newBase = program.getAddressFactory()
							.getDefaultAddressSpace().getAddress(baseResult.inferredBase);
						program.getMemory().moveBlock(block, newBase, monitor);
						String relocMsg = String.format(
							"Relocated ROM from 0x%X to 0x%X (confidence %.0f%%, %d targets)",
							currentBase, baseResult.inferredBase,
							baseResult.confidence * 100, baseResult.targetsInRange);
						Msg.info(this, relocMsg);
						log.appendMsg("Heuristic Code Finder: " + relocMsg);
					} catch (Exception e) {
						Msg.warn(this, "Failed to relocate ROM: " + e.getMessage());
					}
				}
			} else {
				Msg.info(this, "Base address check: " + baseResult.description);
			}

			// x86 BIOS real mode warning: when a 32-bit x86 processor is selected
			// but the ROM has a BIOS reset vector, warn about mode mismatch
			String baseProc = program.getLanguage().getProcessor().toString();
			boolean is32bitX86 = baseProc.contains("80386") || baseProc.contains("80486") ||
				(baseProc.contains("x86") && program.getDefaultPointerSize() >= 4);
			if (is32bitX86 && baseResult.description.contains("x86 BIOS")) {
				String modeWarn = "WARNING: This ROM was loaded with a 32-bit x86 processor, " +
					"but a BIOS reset vector pattern was found. BIOS ROMs start in 16-bit " +
					"real mode. For correct disassembly, re-import with processor " +
					"\"x86:LE:16:Real Mode\".";
				Msg.warn(this, modeWarn);
				log.appendMsg("Heuristic Code Finder: " + modeWarn);
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

	/**
	 * Write platform info (ROM identification, hardware memory map) as a plate
	 * comment at the program's base address so export scripts can include it.
	 */
	private void writePlatformInfo(Program program) {
		try {
			Address baseAddr = program.getMemory().getMinAddress();
			if (baseAddr == null) return;
			Listing listing = program.getListing();

			StringBuilder plate = new StringBuilder();

			// ROM identification
			if (!romMatches.isEmpty()) {
				RomIdentifier.RomMatch best = romMatches.get(0);
				plate.append(String.format("ROM: %s\n", best.toString()));
				if (best.cpu != null && !best.cpu.isEmpty()) {
					plate.append(String.format("CPU: %s\n", best.cpu));
				}
			}

			// Platform name
			if (platform != null && platform.getPlatformName() != null &&
				!platform.getPlatformName().startsWith("auto:")) {
				plate.append(String.format("Platform: %s\n", platform.getPlatformName()));
			}

			// Hardware memory map and registers — only from ROM-identified or
			// user-specified platforms (auto-detected platforms may be wrong)
			if (platformFromRomId && platform != null) {
				if (!platform.getMemoryMap().isEmpty()) {
					plate.append("\nHardware Memory Map:\n");
					for (PlatformDescription.MemoryRegion region : platform.getMemoryMap()) {
						plate.append(String.format("  %08X-%08X  %-8s  %s\n",
							region.start, region.end, region.type, region.name));
					}
				}
				if (!platform.getHwRegisters().isEmpty()) {
					plate.append("\nHardware Registers:\n");
					int regCount = 0;
					for (PlatformDescription.HardwareRegister reg : platform.getHwRegisters()) {
						plate.append(String.format("  %08X  %s  (%s, %d-bit)\n",
							reg.addr, reg.name, reg.access, reg.width * 8));
						regCount++;
						if (regCount >= 50) {
							plate.append(String.format("  ... and %d more\n",
								platform.getHwRegisters().size() - 50));
							break;
						}
					}
				}
			}

			if (plate.length() > 0) {
				// Append to existing plate comment if any
				String existing = listing.getComment(CodeUnit.PLATE_COMMENT, baseAddr);
				String newComment = (existing != null && !existing.isEmpty())
					? existing + "\n" + plate.toString()
					: plate.toString();
				listing.setComment(baseAddr, CodeUnit.PLATE_COMMENT, newComment);
			}
		} catch (Exception e) {
			Msg.warn(this, "Failed to write platform info: " + e.getMessage());
		}
	}

	private void loadPlatform(Program program) {
		if (platformFile != null && !platformFile.isEmpty()) {
			try {
				java.io.File f = new java.io.File(platformFile);
				if (f.exists()) {
					platform = PlatformDescription.loadFromXml(new java.io.FileInputStream(f));
					platformFromRomId = true;
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
