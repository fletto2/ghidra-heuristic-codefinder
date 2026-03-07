/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Detect the most likely platform/machine by matching observed memory access
 * patterns against a library of platform descriptions.
 *
 * Algorithm:
 * 1. Collect unique addresses from P-code LOAD/STORE/CALL/BRANCH ops
 * 2. Filter candidates by CPU type
 * 3. Score each candidate: how well do observed addresses fit the memory map?
 *    - Address hits a defined region (rom/ram/io): +1
 *    - Address hits an unmapped region: -3
 *    - Address hits a hardware register exactly: +5
 *    - Address falls in gaps between defined regions: -1
 * 4. Normalize score, return top 3
 */
public class PlatformDetector {

	/** A scored candidate result. */
	public static class DetectionResult implements Comparable<DetectionResult> {
		public final String platformName;
		public final String manufacturer;
		public final String sourceFile;
		public final double score;
		public final int addressesMatched;
		public final int addressesTested;
		public final PlatformDescription platform;

		public DetectionResult(String platformName, String manufacturer, String sourceFile,
				double score, int matched, int tested, PlatformDescription platform) {
			this.platformName = platformName;
			this.manufacturer = manufacturer;
			this.sourceFile = sourceFile;
			this.score = score;
			this.addressesMatched = matched;
			this.addressesTested = tested;
			this.platform = platform;
		}

		@Override
		public int compareTo(DetectionResult o) {
			return Double.compare(o.score, this.score); // descending
		}

		@Override
		public String toString() {
			return String.format("%s/%s (%.1f%%, %d/%d addrs) [%s]",
				manufacturer, platformName, score * 100.0,
				addressesMatched, addressesTested, sourceFile);
		}
	}

	// CPU family mapping: Ghidra processor name -> set of platform cpu names
	private static final Map<String, Set<String>> CPU_FAMILY_MAP = new HashMap<>();
	static {
		CPU_FAMILY_MAP.put("68000", Set.of("68000", "68010", "68020", "68030", "68040", "68070"));
		CPU_FAMILY_MAP.put("z80", Set.of("z80", "z180", "z80n", "r800", "lr35902"));
		CPU_FAMILY_MAP.put("6502", Set.of("6502", "65c02", "n2a03", "6510", "huc6280"));
		CPU_FAMILY_MAP.put("65816", Set.of("65816"));
		CPU_FAMILY_MAP.put("ARM", Set.of("arm7_le", "arm7_be", "arm9"));
		CPU_FAMILY_MAP.put("SuperH", Set.of("sh2", "sh2a", "sh4"));
		CPU_FAMILY_MAP.put("6809", Set.of("6809", "6309"));
		CPU_FAMILY_MAP.put("6800", Set.of("6800", "6801", "6803", "6301"));
		CPU_FAMILY_MAP.put("8080", Set.of("8080", "8085"));
		CPU_FAMILY_MAP.put("8085", Set.of("8080", "8085"));
		CPU_FAMILY_MAP.put("x86", Set.of("8086", "8088", "80186", "80286", "80386", "80486", "pentium"));
		CPU_FAMILY_MAP.put("MIPS", Set.of("mips", "mips3", "r3000", "r4000", "r4600", "r5000", "vr4300"));
		CPU_FAMILY_MAP.put("PowerPC", Set.of("ppc"));
		CPU_FAMILY_MAP.put("TMS9900", Set.of("tms9900", "tms9995", "tms9980"));
		CPU_FAMILY_MAP.put("H8", Set.of("h8"));
		CPU_FAMILY_MAP.put("V60", Set.of("v60", "v70"));
		CPU_FAMILY_MAP.put("8051", Set.of("8051", "8048", "8049"));
		CPU_FAMILY_MAP.put("68HC11", Set.of("68hc11"));
		CPU_FAMILY_MAP.put("6805", Set.of("6805", "68705"));
		CPU_FAMILY_MAP.put("WE32100", Set.of("we32100", "we32200"));
	}

	/**
	 * Collect unique memory access addresses from existing instructions.
	 * Samples up to maxInstructions to keep detection fast.
	 */
	public static Set<Long> collectAccessAddresses(Program program, int maxInstructions,
			TaskMonitor monitor) {
		Set<Long> addresses = new LinkedHashSet<>();
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		long addrSpaceSize = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffset();

		InstructionIterator iter = listing.getInstructions(true);
		int count = 0;
		while (iter.hasNext() && count < maxInstructions) {
			if (monitor != null && monitor.isCancelled()) break;
			Instruction instr = iter.next();
			count++;

			try {
				PcodeOp[] pcode = instr.getPcode();
				for (PcodeOp op : pcode) {
					int opc = op.getOpcode();
					if (opc == PcodeOp.LOAD || opc == PcodeOp.STORE) {
						Varnode addr = op.getInput(1);
						if (addr != null && addr.isConstant()) {
							long val = addr.getOffset();
							if (val > 0 && val <= addrSpaceSize) {
								addresses.add(val);
							}
						}
					} else if (opc == PcodeOp.CALL || opc == PcodeOp.BRANCH) {
						Varnode target = op.getInput(0);
						if (target != null && target.isAddress()) {
							addresses.add(target.getOffset());
						}
					}
				}
			} catch (Exception e) {
				// Skip instructions with P-code errors
			}

			// Also collect explicit flow references
			Address[] flows = instr.getFlows();
			if (flows != null) {
				for (Address flow : flows) {
					addresses.add(flow.getOffset());
				}
			}
		}

		// Also sample raw pointer-sized values from ROM-like regions
		// These catch data references (jump tables, string pointers, etc.)
		int ptrSize = program.getDefaultPointerSize();
		boolean bigEndian = memory.isBigEndian();
		for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) continue;
			long blockSize = block.getSize();
			// Sample every 256 bytes, up to 1024 samples per block
			long step = Math.max(ptrSize, blockSize / 1024);
			for (long off = 0; off < blockSize - ptrSize; off += step) {
				if (addresses.size() > 10000) break;
				try {
					Address addr = block.getStart().add(off);
					byte[] buf = new byte[ptrSize];
					memory.getBytes(addr, buf);
					long value = readPointer(buf, ptrSize, bigEndian);
					// Only consider values that look like valid addresses
					if (value > 0x100 && value <= addrSpaceSize && value != 0xFFFFFFFFL) {
						addresses.add(value);
					}
				} catch (Exception e) {
					break;
				}
			}
		}

		return addresses;
	}

	private static long readPointer(byte[] buf, int size, boolean bigEndian) {
		long value = 0;
		if (size == 4) {
			if (bigEndian) {
				value = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
						((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
			} else {
				value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8) |
						((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
			}
		} else if (size == 2) {
			if (bigEndian) {
				value = ((buf[0] & 0xFFL) << 8) | (buf[1] & 0xFFL);
			} else {
				value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8);
			}
		}
		return value;
	}

	/**
	 * Score a single platform against observed addresses.
	 */
	public static double scorePlatform(PlatformDescription platform, Set<Long> observedAddresses) {
		List<PlatformDescription.MemoryRegion> map = platform.getMemoryMap();
		if (map.isEmpty()) return -1.0;

		List<PlatformDescription.HardwareRegister> hwRegs = platform.getHwRegisters();

		int hits = 0;
		int misses = 0;
		int ioHits = 0;
		int hwRegHits = 0;
		int tested = 0;

		// Pre-compute the total defined address space coverage
		long totalDefined = 0;
		for (PlatformDescription.MemoryRegion r : map) {
			totalDefined += (r.end - r.start + 1);
		}

		for (long addr : observedAddresses) {
			tested++;
			boolean matched = false;
			boolean unmapped = false;

			for (PlatformDescription.MemoryRegion region : map) {
				if (addr >= region.start && addr <= region.end) {
					matched = true;
					if ("unmapped".equals(region.type)) {
						unmapped = true;
					} else if ("io".equals(region.type)) {
						ioHits++;
					}
					break;
				}
			}

			if (unmapped) {
				misses += 3; // Strong penalty for hitting unmapped space
			} else if (matched) {
				hits++;
			} else {
				// Address not covered by any region — mild penalty
				misses++;
			}

			// Bonus for hitting exact hardware register addresses
			for (PlatformDescription.HardwareRegister reg : hwRegs) {
				if (addr >= reg.addr && addr < reg.addr + reg.width) {
					hwRegHits++;
					break;
				}
			}
		}

		if (tested == 0) return -1.0;

		// Score formula (normalized to 0.0 - 1.0):
		// Base: fraction of addresses that hit defined regions (0..1)
		// Weighted components add detail within that range:
		//   IO region hits boost slightly (distinguishes machines with same ROM/RAM)
		//   Hardware register hits boost more (very machine-specific)
		//   Misses penalize
		double hitRate = (double) hits / tested;
		double missRate = (double) misses / tested;
		double ioRate = (double) ioHits / tested;
		double hwRate = (double) hwRegHits / tested;

		// Weighted score: hitRate is the base, bonuses/penalties adjust within 0..1
		double raw = hitRate * 0.7
			+ ioRate * 0.1
			+ hwRate * 0.2
			- missRate * 0.3;

		// Degrees-of-freedom scaling: reduce confidence when we have few samples.
		// At 30 tested addresses the score is fully trusted; below that it's
		// proportionally reduced. This prevents small ROMs or early analysis
		// from producing overconfident matches.
		double sampleConfidence = Math.min(1.0, tested / 30.0);
		raw *= sampleConfidence;

		// Minimum absolute hits: if fewer than 5 addresses actually matched
		// defined regions, the match is not reliable regardless of the ratio
		if (hits < 5) raw *= 0.5;

		// Clamp to [0, 1]
		return Math.max(0.0, Math.min(1.0, raw));
	}

	/**
	 * Get the CPU family names that match this program's processor.
	 */
	public static Set<String> getCpuFamilyNames(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		String langId = program.getLanguageID().toString();

		// Try direct processor name match
		Set<String> family = CPU_FAMILY_MAP.get(processor);
		if (family != null) return family;

		// Try matching parts of the language ID
		// e.g., "68000:BE:32:MC68020" -> look for "68000"
		for (Map.Entry<String, Set<String>> entry : CPU_FAMILY_MAP.entrySet()) {
			if (langId.contains(entry.getKey()) || processor.contains(entry.getKey())) {
				return entry.getValue();
			}
		}

		// Fallback: try processor name as-is
		return Set.of(processor.toLowerCase());
	}

	/**
	 * Load platform descriptions from the extension's data/platforms/mame directory.
	 * Returns only platforms matching the given CPU family.
	 */
	public static List<PlatformCandidate> loadCandidates(File platformDir, Set<String> cpuFamily,
			TaskMonitor monitor) {
		List<PlatformCandidate> candidates = new ArrayList<>();
		if (platformDir == null || !platformDir.isDirectory()) return candidates;

		File mameDir = new File(platformDir, "mame");
		if (!mameDir.isDirectory()) return candidates;

		// Walk manufacturer subdirectories
		File[] manufacturers = mameDir.listFiles(File::isDirectory);
		if (manufacturers == null) return candidates;

		for (File mfrDir : manufacturers) {
			if (monitor != null && monitor.isCancelled()) break;
			String manufacturer = mfrDir.getName();

			File[] xmlFiles = mfrDir.listFiles((dir, name) -> name.endsWith(".xml"));
			if (xmlFiles == null) continue;

			for (File xmlFile : xmlFiles) {
				try {
					// Quick pre-filter: scan for cpu= attribute without full XML parse
					String cpuAttr = quickReadCpuAttr(xmlFile);
					if (cpuAttr == null || !cpuFamily.contains(cpuAttr)) continue;

					PlatformDescription platform = PlatformDescription.loadFromXml(
						new FileInputStream(xmlFile));
					if (platform.getMemoryMap().size() < 2) continue;

					String name = xmlFile.getName().replace(".xml", "");
					candidates.add(new PlatformCandidate(name, manufacturer, xmlFile.getName(), platform));
				} catch (Exception e) {
					// Skip unparseable files
				}
			}
		}

		// Also check top-level platform files
		File[] topLevelXmls = platformDir.listFiles((dir, name) -> name.endsWith(".xml"));
		if (topLevelXmls != null) {
			for (File xmlFile : topLevelXmls) {
				try {
					String cpuAttr = quickReadCpuAttr(xmlFile);
					if (cpuAttr == null || !cpuFamily.contains(cpuAttr)) continue;

					PlatformDescription platform = PlatformDescription.loadFromXml(
						new FileInputStream(xmlFile));
					if (platform.getMemoryMap().size() < 2) continue;

					String name = xmlFile.getName().replace(".xml", "");
					candidates.add(new PlatformCandidate(name, "", xmlFile.getName(), platform));
				} catch (Exception e) {
					// Skip
				}
			}
		}

		return candidates;
	}

	/**
	 * Quick scan of XML file to read the cpu= attribute without full parse.
	 */
	private static String quickReadCpuAttr(File xmlFile) {
		try (BufferedReader reader = new BufferedReader(new FileReader(xmlFile))) {
			// CPU attribute is on the first line: <platform name="..." cpu="...">
			String line = reader.readLine();
			if (line == null) return null;
			int idx = line.indexOf("cpu=\"");
			if (idx < 0) {
				line = reader.readLine();
				if (line == null) return null;
				idx = line.indexOf("cpu=\"");
			}
			if (idx < 0) return null;
			int start = idx + 5;
			int end = line.indexOf('"', start);
			if (end < 0) return null;
			return line.substring(start, end);
		} catch (IOException e) {
			return null;
		}
	}

	/**
	 * Run detection: collect addresses, score all candidates, return top N.
	 */
	public static List<DetectionResult> detect(Program program, File platformDir,
			int maxInstructions, int topN, TaskMonitor monitor) {

		Set<String> cpuFamily = getCpuFamilyNames(program);
		Msg.info(PlatformDetector.class, "Platform detection: CPU family = " + cpuFamily);

		// Collect observed addresses
		monitor.setMessage("Platform detection: collecting memory access addresses...");
		Set<Long> addresses = collectAccessAddresses(program, maxInstructions, monitor);
		Msg.info(PlatformDetector.class, "Platform detection: " + addresses.size() + " unique addresses collected");

		// Minimum degrees of freedom: need enough distinct addresses to
		// distinguish real memory map matches from coincidence. With fewer
		// than 30 addresses, almost any memory map will match by chance.
		if (addresses.size() < 30) {
			Msg.warn(PlatformDetector.class,
				"Too few addresses (" + addresses.size() + ") for reliable platform detection (need 30+)");
			return Collections.emptyList();
		}

		// Load candidates matching CPU family
		monitor.setMessage("Platform detection: loading platform library...");
		List<PlatformCandidate> candidates = loadCandidates(platformDir, cpuFamily, monitor);
		Msg.info(PlatformDetector.class, "Platform detection: " + candidates.size() +
			" candidate platforms for CPU family " + cpuFamily);

		if (candidates.isEmpty()) return Collections.emptyList();

		// Score each candidate
		monitor.setMessage("Platform detection: scoring " + candidates.size() + " candidates...");
		List<DetectionResult> results = new ArrayList<>();
		int scored = 0;
		for (PlatformCandidate candidate : candidates) {
			if (monitor.isCancelled()) break;
			scored++;
			if (scored % 500 == 0) {
				monitor.setMessage("Platform detection: scored " + scored + "/" + candidates.size());
			}

			double score = scorePlatform(candidate.platform, addresses);
			if (score > 0) {
				int matched = 0;
				for (long addr : addresses) {
					if (candidate.platform.validateAddress(addr) == null) matched++;
				}
				results.add(new DetectionResult(
					candidate.name, candidate.manufacturer, candidate.sourceFile,
					score, matched, addresses.size(), candidate.platform));
			}
		}

		// Sort by score descending, deduplicate by memory map signature
		Collections.sort(results);

		// Deduplicate: many GAME() entries share the same memory map
		List<DetectionResult> deduped = new ArrayList<>();
		Set<String> seenMaps = new HashSet<>();
		for (DetectionResult r : results) {
			String mapSig = mapSignature(r.platform);
			if (seenMaps.add(mapSig)) {
				deduped.add(r);
			}
			if (deduped.size() >= topN) break;
		}

		return deduped;
	}

	/**
	 * Generate a signature string for a memory map to detect duplicates.
	 */
	private static String mapSignature(PlatformDescription platform) {
		StringBuilder sb = new StringBuilder();
		for (PlatformDescription.MemoryRegion r : platform.getMemoryMap()) {
			sb.append(r.start).append('-').append(r.end).append(':').append(r.type).append(';');
		}
		return sb.toString();
	}

	// ================================================================
	// Endianness / byte-swap detection
	// ================================================================

	/** Result of endianness analysis. */
	public static class EndiannessResult {
		public final String status;      // "ok", "swapped16", "swapped32", "swapped16in32"
		public final double nativeScore;  // fraction of valid pointers in native order
		public final double swappedScore; // fraction of valid pointers in best swapped order
		public final String description;  // human-readable summary

		public EndiannessResult(String status, double nativeScore, double swappedScore, String description) {
			this.status = status;
			this.nativeScore = nativeScore;
			this.swappedScore = swappedScore;
			this.description = description;
		}

		public boolean isSwapped() { return !"ok".equals(status); }
	}

	/**
	 * Detect if the ROM appears to have wrong byte ordering.
	 *
	 * Primary strategy: count occurrences of known instruction opcodes
	 * (RTS, RTE, etc.) in native vs byte-swapped order. These opcodes
	 * appear frequently in real code, so the correct byte order will have
	 * many more hits. This is fast and reliable across architectures.
	 *
	 * Known opcode signatures per CPU family:
	 * - 68000: 0x4E75 (RTS), 0x4E73 (RTE), 0x4E71 (NOP), 0x4E74 (RTD)
	 * - Z80/8080: 0xC9 (RET), 0xC3 (JP), 0xCD (CALL) — 8-bit, no swap needed
	 * - ARM: 0xE12FFF1E (BX LR), 0xE1A0F00E (MOV PC,LR) — 32-bit
	 * - SH2: 0x000B (RTS), 0x002B (RTE), 0x0009 (NOP)
	 * - 6502: 0x60 (RTS), 0x40 (RTI) — 8-bit, no swap needed
	 *
	 * Also checks 16-bit pair swap within 32-bit words (some arcade boards).
	 */
	public static EndiannessResult detectEndianness(Program program, TaskMonitor monitor) {
		Memory memory = program.getMemory();
		int ptrSize = program.getDefaultPointerSize();
		String processor = program.getLanguage().getProcessor().toString();

		// Build opcode tables for this CPU
		int[][] nativeOpcodes;   // { opcode_byte0, opcode_byte1 } for 16-bit opcodes
		int[][] swappedOpcodes;  // same opcodes with bytes swapped
		boolean check32bit = false; // also check 32-bit word-level swaps?

		if (processor.contains("68") || processor.equals("Coldfire")) {
			// 68000 family: 16-bit instruction words, big-endian
			// RTS=0x4E75, RTE=0x4E73, NOP=0x4E71, RTD=0x4E74, TRAP=0x4E4x, JSR=0x4EB9, JMP=0x4EF9
			nativeOpcodes = new int[][] {
				{0x4E, 0x75}, // RTS
				{0x4E, 0x73}, // RTE
				{0x4E, 0x71}, // NOP
				{0x4E, 0x74}, // RTD
				{0x4E, 0xB9}, // JSR abs.L
				{0x4E, 0xF9}, // JMP abs.L
			};
			swappedOpcodes = new int[][] {
				{0x75, 0x4E}, // RTS swapped
				{0x73, 0x4E}, // RTE swapped
				{0x71, 0x4E}, // NOP swapped
				{0x74, 0x4E}, // RTD swapped
				{0xB9, 0x4E}, // JSR swapped
				{0xF9, 0x4E}, // JMP swapped
			};
		} else if (processor.contains("SuperH") || processor.contains("SH")) {
			// SH2/SH4: 16-bit instructions, big-endian
			// RTS=0x000B, RTE=0x002B, NOP=0x0009, BRA=0xAxxx, BSR=0xBxxx
			nativeOpcodes = new int[][] {
				{0x00, 0x0B}, // RTS
				{0x00, 0x2B}, // RTE
				{0x00, 0x09}, // NOP
			};
			swappedOpcodes = new int[][] {
				{0x0B, 0x00}, // RTS swapped
				{0x2B, 0x00}, // RTE swapped
				{0x09, 0x00}, // NOP swapped
			};
		} else if (processor.contains("ARM")) {
			// ARM: 32-bit instructions
			// Check for common ARM return sequences
			check32bit = true;
			nativeOpcodes = new int[][] {
				{0x4E, 0x75}, // placeholder — ARM uses 32-bit check below
			};
			swappedOpcodes = new int[][] {
				{0x75, 0x4E}, // placeholder
			};
		} else if (processor.contains("MIPS")) {
			// MIPS: 32-bit instructions
			// JR RA = 0x03E00008
			check32bit = true;
			nativeOpcodes = new int[][] {{0x00, 0x00}}; // placeholder
			swappedOpcodes = new int[][] {{0x00, 0x00}};
		} else if (processor.contains("6809") || processor.contains("6309") || processor.contains("HD6309") ||
				   processor.contains("6800") || processor.contains("6801") || processor.contains("6803") ||
				   processor.contains("68HC") || processor.contains("6805")) {
			// 6809/6800 family: 8-bit data bus — no byte-swap issues
			return new EndiannessResult("ok", 1.0, 0.0,
				"8-bit CPU — byte order not applicable");
		} else if (processor.contains("TMS9900")) {
			// TMS9900: 16-bit big-endian instructions
			// B *R11 (return) = 0x045B, RT (return) = 0x045B
			// NOP = 0x1000, LIMI = 0x0300
			nativeOpcodes = new int[][] {
				{0x04, 0x5B}, // B *R11 (return)
				{0x10, 0x00}, // NOP (JMP $+2)
				{0x03, 0x00}, // LIMI
				{0x04, 0x60}, // B @addr
			};
			swappedOpcodes = new int[][] {
				{0x5B, 0x04},
				{0x00, 0x10},
				{0x00, 0x03},
				{0x60, 0x04},
			};
		} else if (processor.contains("V60") || processor.contains("V70") || processor.contains("V810")) {
			// NEC V60/V70/V810: 16-bit or 32-bit instructions
			nativeOpcodes = new int[][] {
				{0x19, 0x00}, // RETI (V60)
			};
			swappedOpcodes = new int[][] {
				{0x00, 0x19},
			};
		} else if (processor.contains("H8")) {
			// Hitachi H8: 16-bit instructions, big-endian
			// RTS=0x5470, RTE=0x5670, NOP=0x0000
			nativeOpcodes = new int[][] {
				{0x54, 0x70}, // RTS
				{0x56, 0x70}, // RTE
			};
			swappedOpcodes = new int[][] {
				{0x70, 0x54},
				{0x70, 0x56},
			};
		} else if (processor.contains("PowerPC") || processor.contains("PPC")) {
			// PowerPC: 32-bit instructions, big-endian
			// BLR = 0x4E800020
			check32bit = true;
			nativeOpcodes = new int[][] {{0x4E, 0x80}}; // first half of BLR
			swappedOpcodes = new int[][] {{0x80, 0x4E}};
		} else if (processor.contains("WE32100") || processor.contains("WE32")) {
			// WE32100: 1-byte opcodes, big-endian data, instructions not word-aligned.
			// ROMs are 32-bit interleaved across 4 byte-wide chips — wrong chip order
			// produces byte-level permutation that completely clobbers instructions.
			// Common 16-bit aligned byte pairs in real code:
			//   0x2C 0xCC — RETG + displacement deferred mode (function epilogue)
			//   0x10 0x49 — SAVE %fp (function prologue)
			//   0x70 0x87 — CALL + byte-immediate descriptor
			//   0x70 0x84 — CALL + word-immediate descriptor
			//   0x24 0x7F — RET + absolute addressing (return then next function)
			//   0xCC 0xFC — displacement deferred + absolute deferred
			check32bit = true;
			nativeOpcodes = new int[][] {
				{0x2C, 0xCC}, // RETG + disp deferred
				{0x10, 0x49}, // SAVE %fp
				{0x70, 0x87}, // CALL + descriptor
				{0x70, 0x84}, // CALL + descriptor
				{0x24, 0x7F}, // RET + absolute
				{0xCC, 0xFC}, // disp deferred + abs deferred
			};
			swappedOpcodes = new int[][] {
				{0xCC, 0x2C},
				{0x49, 0x10},
				{0x87, 0x70},
				{0x84, 0x70},
				{0x7F, 0x24},
				{0xFC, 0xCC},
			};
		} else {
			// 8-bit CPUs (Z80, 6502, 8080) don't have byte-swap issues
			return new EndiannessResult("ok", 1.0, 0.0,
				"8-bit CPU — byte order not applicable");
		}

		// Count opcode occurrences in native and swapped order
		long nativeHits = 0;
		long swappedHits = 0;

		// For 32-bit CPUs, also check word-level swaps
		long swap32Hits = 0;
		long swap16in32Hits = 0;

		long totalWords = 0;

		for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) continue;
			if (monitor != null && monitor.isCancelled()) break;

			long blockSize = block.getSize();
			byte[] data;
			try {
				data = new byte[(int) Math.min(blockSize, 1024 * 1024)]; // Cap at 1MB per block
				memory.getBytes(block.getStart(), data);
			} catch (Exception e) {
				continue;
			}

			// Scan for 16-bit opcode patterns (-1 = wildcard byte)
			for (int off = 0; off < data.length - 1; off += 2) {
				totalWords++;
				int b0 = data[off] & 0xFF;
				int b1 = data[off + 1] & 0xFF;

				for (int[] opc : nativeOpcodes) {
					if ((opc[0] == -1 || b0 == opc[0]) && (opc[1] == -1 || b1 == opc[1])) {
						nativeHits++; break;
					}
				}
				for (int[] opc : swappedOpcodes) {
					if ((opc[0] == -1 || b0 == opc[0]) && (opc[1] == -1 || b1 == opc[1])) {
						swappedHits++; break;
					}
				}
			}

			if (check32bit) {
				boolean bigEndian = memory.isBigEndian();
				// 32-bit instruction patterns to search for
				long[] patterns32;
				if (processor.contains("MIPS")) {
					patterns32 = new long[]{ 0x03E00008L }; // JR RA
				} else if (processor.contains("PowerPC") || processor.contains("PPC")) {
					patterns32 = new long[]{ 0x4E800020L }; // BLR
				} else if (processor.contains("WE32100") || processor.contains("WE32")) {
					// WE32100: common 4-byte aligned sequences from 3B2 ROMs
					// 0x0200_0BC8 — very common (248 hits in 32K ROM)
					// 0x1049_9C4F — SAVE %fp + disp deferred (function prologue)
					// 0x2CCC_FC7F — RETG epilogue sequence
					// 0x2CCC_F87F — RETG epilogue variant
					patterns32 = new long[]{
						0x02000BC8L,
						0x10499C4FL,
						0x2CCCFC7FL,
						0x2CCCF87FL,
					};
				} else {
					patterns32 = new long[]{ 0xE12FFF1EL, 0xE1A0F00EL }; // ARM: BX LR, MOV PC,LR
				}

				for (int off = 0; off < data.length - 3; off += 4) {
					long word;
					if (bigEndian) {
						word = ((data[off] & 0xFFL) << 24) | ((data[off+1] & 0xFFL) << 16) |
							   ((data[off+2] & 0xFFL) << 8) | (data[off+3] & 0xFFL);
					} else {
						word = (data[off] & 0xFFL) | ((data[off+1] & 0xFFL) << 8) |
							   ((data[off+2] & 0xFFL) << 16) | ((data[off+3] & 0xFFL) << 24);
					}

					for (long pat : patterns32) {
						if (word == pat) nativeHits++;
					}

					// Byte-reversed
					long rev = ((word & 0xFF) << 24) | (((word >> 8) & 0xFF) << 16) |
							   (((word >> 16) & 0xFF) << 8) | ((word >> 24) & 0xFF);
					for (long pat : patterns32) {
						if (rev == pat) swap32Hits++;
					}

					// 16-bit pair swap
					long ps = ((word & 0xFFFF) << 16) | ((word >> 16) & 0xFFFF);
					for (long pat : patterns32) {
						if (ps == pat) swap16in32Hits++;
					}
				}
			}
		}

		if (totalWords < 32) {
			return new EndiannessResult("ok", 1.0, 0.0, "ROM too small to analyze endianness");
		}

		// Find best swap type
		long bestSwapHits = swappedHits;
		String bestSwapType = "swapped16";
		if (swap32Hits > bestSwapHits) { bestSwapHits = swap32Hits; bestSwapType = "swapped32"; }
		if (swap16in32Hits > bestSwapHits) { bestSwapHits = swap16in32Hits; bestSwapType = "swapped16in32"; }

		Msg.info(PlatformDetector.class, String.format(
			"Endianness opcode scan — native: %d hits, swap16: %d, swap32: %d, swap16in32: %d (%d words scanned)",
			nativeHits, swappedHits, swap32Hits, swap16in32Hits, totalWords));

		double nativeScore = (double) nativeHits;
		double swapScore = (double) bestSwapHits;

		// If swapped hits significantly outnumber native hits, ROM is likely byte-swapped.
		// Require at least 5 swapped opcode hits for a confident determination —
		// with fewer samples the ratio could be due to chance alignment.
		if (bestSwapHits > nativeHits * 2 && bestSwapHits >= 5) {
			String desc;
			switch (bestSwapType) {
				case "swapped16":
					desc = String.format("ROM bytes appear 16-bit byte-swapped " +
						"(%d return/branch opcodes found swapped vs %d native). " +
						"Each pair of bytes should be swapped before analysis.",
						bestSwapHits, nativeHits);
					break;
				case "swapped32":
					desc = String.format("ROM bytes appear 32-bit byte-reversed " +
						"(%d return/branch opcodes found reversed vs %d native). " +
						"Full 32-bit endian reversal needed.",
						bestSwapHits, nativeHits);
					break;
				case "swapped16in32":
					desc = String.format("ROM bytes appear to have 16-bit word pairs " +
						"swapped within 32-bit words (%d vs %d native).",
						bestSwapHits, nativeHits);
					break;
				default:
					desc = "Unknown byte order issue detected.";
			}
			return new EndiannessResult(bestSwapType, nativeScore, swapScore, desc);
		}

		// Native order wins or it's ambiguous
		if (nativeHits == 0 && bestSwapHits == 0) {
			return new EndiannessResult("ok", 0, 0,
				"No characteristic opcodes found — byte order inconclusive");
		}

		return new EndiannessResult("ok", nativeScore, swapScore,
			String.format("Byte order looks correct (%d native opcodes vs %d swapped)",
				nativeHits, bestSwapHits));
	}

	/** Swap bytes within each 16-bit word. */
	private static byte[] swap16(byte[] buf, int len) {
		byte[] out = new byte[len];
		for (int i = 0; i < len - 1; i += 2) {
			out[i] = buf[i + 1];
			out[i + 1] = buf[i];
		}
		return out;
	}

	// ================================================================
	// ROM base address inference
	// ================================================================

	/** Result of base address inference. */
	public static class BaseAddressResult {
		public final long inferredBase;
		public final long romSize;
		public final int targetCount;       // total absolute targets found
		public final int targetsInRange;    // targets that fall within ROM at inferred base
		public final double confidence;     // 0.0 - 1.0
		public final String description;

		public BaseAddressResult(long inferredBase, long romSize, int targetCount,
				int targetsInRange, double confidence, String description) {
			this.inferredBase = inferredBase;
			this.romSize = romSize;
			this.targetCount = targetCount;
			this.targetsInRange = targetsInRange;
			this.confidence = confidence;
			this.description = description;
		}
	}

	/**
	 * Infer the correct ROM base address by analyzing absolute jump/call targets.
	 *
	 * When a ROM is loaded at address 0 but should be at e.g. 0xE000, the absolute
	 * JMP/JSR/CALL instructions will reference addresses in the 0xE000-0xFFFF range.
	 * By finding where these targets cluster, we can infer the real base address.
	 *
	 * Algorithm:
	 * 1. Speculatively disassemble the ROM (using PseudoDisassembler)
	 * 2. Collect all absolute address operands from flow instructions
	 * 3. For each candidate base, count how many targets would fall within ROM
	 * 4. Also check raw pointer-sized values in the ROM (vector tables, jump tables)
	 * 5. The base with the most hits wins
	 */
	public static BaseAddressResult inferBaseAddress(Program program, TaskMonitor monitor) {
		Memory memory = program.getMemory();
		int ptrSize = program.getDefaultPointerSize();
		boolean bigEndian = memory.isBigEndian();
		long addrSpaceMax = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffset();

		// Get ROM size and current base
		ghidra.program.model.mem.MemoryBlock[] blocks = memory.getBlocks();
		if (blocks.length == 0) {
			return new BaseAddressResult(0, 0, 0, 0, 0, "No memory blocks");
		}
		long currentBase = blocks[0].getStart().getOffset();
		long romSize = 0;
		for (ghidra.program.model.mem.MemoryBlock b : blocks) {
			if (b.isInitialized()) romSize += b.getSize();
		}
		if (romSize < 32) {
			return new BaseAddressResult(currentBase, romSize, 0, 0, 0, "ROM too small");
		}

		// Collect absolute target addresses from:
		// 1. Existing disassembled instructions (flow references)
		// 2. Raw pointer-sized values (vector tables, jump tables)
		List<Long> targets = new ArrayList<>();

		// From instructions
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(true);
		int instrCount = 0;
		while (iter.hasNext() && instrCount < 10000) {
			if (monitor != null && monitor.isCancelled()) break;
			Instruction instr = iter.next();
			instrCount++;

			Address[] flows = instr.getFlows();
			if (flows != null) {
				for (Address flow : flows) {
					long target = flow.getOffset();
					// Only collect targets that are OUTSIDE the current ROM range
					// (targets inside the ROM at current base are relative/already correct)
					if (target < currentBase || target >= currentBase + romSize) {
						targets.add(target);
					}
				}
			}

			// Also check P-code for absolute address constants
			try {
				PcodeOp[] pcode = instr.getPcode();
				for (PcodeOp op : pcode) {
					int opc = op.getOpcode();
					if (opc == PcodeOp.CALL || opc == PcodeOp.BRANCH || opc == PcodeOp.CBRANCH) {
						Varnode v = op.getInput(0);
						if (v != null && v.isAddress()) {
							long target = v.getOffset();
							if (target < currentBase || target >= currentBase + romSize) {
								targets.add(target);
							}
						}
					}
					// LOAD/STORE with constant addresses (I/O or data references)
					if (opc == PcodeOp.LOAD || opc == PcodeOp.STORE) {
						Varnode addr = op.getInput(1);
						if (addr != null && addr.isConstant()) {
							long val = addr.getOffset();
							if (val > 0 && val <= addrSpaceMax) {
								targets.add(val);
							}
						}
					}
				}
			} catch (Exception e) {
				// skip
			}
		}

		// From raw pointer-sized values in the ROM (catches vector tables)
		for (ghidra.program.model.mem.MemoryBlock block : blocks) {
			if (!block.isInitialized()) continue;
			long blockSize = block.getSize();
			// Scan first 256 bytes densely (likely vector table), rest sparsely
			int denseLimit = (int) Math.min(256, blockSize);
			for (int off = 0; off < denseLimit && off <= blockSize - ptrSize; off += ptrSize) {
				try {
					byte[] buf = new byte[ptrSize];
					memory.getBytes(block.getStart().add(off), buf);
					long value = readPointer(buf, ptrSize, bigEndian);
					if (value > 0 && value <= addrSpaceMax && value != 0xFFFFFFFFL) {
						targets.add(value);
					}
				} catch (Exception e) { break; }
			}
			// Sparse sampling of the rest
			long step = Math.max(ptrSize, blockSize / 256);
			for (long off = denseLimit; off <= blockSize - ptrSize; off += step) {
				try {
					byte[] buf = new byte[ptrSize];
					memory.getBytes(block.getStart().add(off), buf);
					long value = readPointer(buf, ptrSize, bigEndian);
					if (value > 0 && value <= addrSpaceMax && value != 0xFFFFFFFFL) {
						targets.add(value);
					}
				} catch (Exception e) { break; }
			}
		}

		// --- x86 BIOS reset vector heuristic ---
		// x86 CPUs start execution at FFFF:0000 (physical 0xFFFF0 for 8086/286,
		// 0xFFFFFFF0 for 386+). If ROM is loaded at 0x0, we can check the reset
		// vector location (romSize - 16) for a JMP instruction. If found, the ROM
		// maps to (top_of_space - romSize).
		String processor = program.getLanguage().getProcessor().toString();
		boolean isX86 = processor.contains("x86") || processor.contains("8086") ||
			processor.contains("8088") || processor.contains("80186") ||
			processor.contains("80286") || processor.contains("80386");
		if (isX86 && currentBase == 0 && romSize >= 1024) {
			long top;
			if (processor.contains("80386") || processor.contains("80486")) {
				top = 0x100000000L;
			} else if (processor.contains("80286")) {
				top = 0x01000000L;
			} else {
				top = 0x00100000L; // 1MB for 8086/8088/80186
			}
			long x86Base = top - romSize;
			// Check if byte at (romSize - 16) is a JMP (0xEA = far jump, 0xE9 = near jump)
			try {
				Address resetAddr = blocks[0].getStart().add(romSize - 16);
				byte resetByte = memory.getByte(resetAddr);
				int opcode = resetByte & 0xFF;
				if (opcode == 0xEA || opcode == 0xE9 || opcode == 0xEB) {
					// Valid x86 JMP at reset vector location — high confidence
					return new BaseAddressResult(x86Base, romSize, 1, 1, 0.95,
						String.format("x86 BIOS: reset vector at 0x%X has JMP (0x%02X), ROM belongs at 0x%X",
							top - 16, opcode, x86Base));
				}
			} catch (Exception e) {
				// ignore
			}
		}

		if (targets.isEmpty()) {
			return new BaseAddressResult(currentBase, romSize, 0, 0, 0,
				"No absolute address references found");
		}

		// Score candidate base addresses
		// Candidates: try every romSize-aligned base where targets cluster
		// For efficiency, bucket targets into romSize-wide ranges
		Map<Long, Integer> baseCounts = new LinkedHashMap<>();
		for (long target : targets) {
			// What base would make this target fall within ROM?
			// base = target - (target % romSize), but we need target to be in [base, base+romSize)
			// Round down to alignment boundary
			long alignedBase;
			if (romSize > 0 && romSize <= addrSpaceMax) {
				// For power-of-2 ROM sizes, align naturally
				// For non-power-of-2, just subtract the offset within a ROM-sized window
				alignedBase = (target / romSize) * romSize;
			} else {
				alignedBase = 0;
			}
			if (alignedBase >= 0 && alignedBase <= addrSpaceMax - romSize + 1) {
				baseCounts.merge(alignedBase, 1, Integer::sum);
			}
		}

		// Also try common base addresses for well-known architectures
		long[] commonBases = getCommonBases(processor, romSize, addrSpaceMax);
		for (long base : commonBases) {
			if (!baseCounts.containsKey(base)) {
				baseCounts.put(base, 0);
			}
		}

		// Count targets that fall within each candidate base
		long bestBase = currentBase;
		int bestCount = 0;
		for (Map.Entry<Long, Integer> entry : baseCounts.entrySet()) {
			long candidateBase = entry.getKey();
			if (candidateBase == currentBase) continue; // skip current base

			int count = 0;
			for (long target : targets) {
				if (target >= candidateBase && target < candidateBase + romSize) {
					count++;
				}
			}
			if (count > bestCount) {
				bestCount = count;
				bestBase = candidateBase;
			}
		}

		// Also count how many targets fall in the current base range
		int currentCount = 0;
		for (long target : targets) {
			if (target >= currentBase && target < currentBase + romSize) {
				currentCount++;
			}
		}

		// Confidence: fraction of out-of-range targets explained by the new base
		int outOfRange = targets.size() - currentCount;
		double confidence = outOfRange > 0 ? (double) bestCount / outOfRange : 0;

		// Only report a different base if it's clearly better than the current one.
		// Must have more hits than current AND be significantly better
		boolean newHasMoreHits = bestCount > currentCount;
		boolean newIsMuchBetter = bestCount > currentCount * 2;
		boolean currentIsVeryWeak = currentCount < 5 && bestCount >= 5;

		// Minimum degrees of freedom: need at least 8 total target references
		// for the base address analysis to be meaningful. Fewer targets could
		// just be data values that happen to look like addresses.
		if (targets.size() < 8) {
			return new BaseAddressResult(currentBase, romSize, targets.size(),
				currentCount, 0,
				String.format("ROM base 0x%X (too few references (%d) for reliable inference)",
					currentBase, targets.size()));
		}

		if (bestBase == currentBase || bestCount < 5 || !newHasMoreHits ||
				(!newIsMuchBetter && !currentIsVeryWeak)) {
			return new BaseAddressResult(currentBase, romSize, targets.size(),
				currentCount, 0,
				String.format("ROM base 0x%X appears correct (%d/%d references in range)",
					currentBase, currentCount, targets.size()));
		}

		return new BaseAddressResult(bestBase, romSize, targets.size(),
			bestCount, confidence,
			String.format("ROM likely belongs at base 0x%X (%d/%d references point there, vs %d at current 0x%X)",
				bestBase, bestCount, targets.size(), currentCount, currentBase));
	}

	/**
	 * Common ROM base addresses for well-known CPU architectures.
	 */
	private static long[] getCommonBases(String processor, long romSize, long addrSpaceMax) {
		if (processor.contains("6502") || processor.contains("65C02")) {
			// 6502: ROMs at $8000, $C000, $E000, $F000, $F800
			return new long[]{ 0x8000L, 0xC000L, 0xE000L, 0xF000L, 0xF800L };
		} else if (processor.contains("z80") || processor.contains("Z80") ||
				   processor.contains("8080") || processor.contains("8085")) {
			// Z80: ROMs often at $0000, $4000, $8000, $C000
			return new long[]{ 0x0000L, 0x4000L, 0x8000L, 0xC000L };
		} else if (processor.contains("6809")) {
			// 6809: ROMs at $8000, $C000, $E000, $F000
			return new long[]{ 0x8000L, 0xC000L, 0xE000L, 0xF000L };
		} else if (processor.contains("68") && !processor.contains("HC")) {
			// 68000: ROMs usually at $000000 but some at $FC0000, $F80000
			return new long[]{ 0x000000L, 0xFC0000L, 0xF80000L, 0xFE0000L };
		} else if (processor.contains("ARM")) {
			// ARM: typically $00000000, $08000000 (Flash), $00800000
			return new long[]{ 0x00000000L, 0x08000000L, 0x00800000L };
		} else if (processor.contains("SuperH") || processor.contains("SH")) {
			// SH2: $00000000, $06000000, $20000000
			return new long[]{ 0x00000000L, 0x06000000L, 0x20000000L };
		} else if (processor.contains("TMS9900")) {
			// TMS9900: ROMs at $0000, $4000, $6000
			return new long[]{ 0x0000L, 0x4000L, 0x6000L };
		} else if (processor.contains("WE32100") || processor.contains("WE32")) {
			// WE32100: ROM always at $00000000 (reset reads PCBP from $80)
			return new long[]{ 0x00000000L };
		} else if (processor.contains("x86") || processor.contains("8086") ||
				   processor.contains("8088") || processor.contains("80186") ||
				   processor.contains("80286") || processor.contains("80386")) {
			// x86 BIOSes map to top of address space (reset at FFFF:0000)
			// For 16-bit real mode (8086/8088/80186): top of 1MB
			// Compute candidate bases: (address_space - romSize) aligned to romSize
			long top;
			if (processor.contains("80386") || processor.contains("80486")) {
				top = 0x100000000L; // 4GB
			} else if (processor.contains("80286")) {
				top = 0x01000000L; // 16MB
			} else {
				top = 0x00100000L; // 1MB
			}
			long base = top - romSize;
			// Also try common BIOS locations
			return new long[]{ base, 0xF0000L, 0xFC000L, 0xFE000L, 0xFF000L, 0xF8000L };
		}
		return new long[]{};
	}

	/** Internal holder for a candidate platform. */
	static class PlatformCandidate {
		final String name;
		final String manufacturer;
		final String sourceFile;
		final PlatformDescription platform;

		PlatformCandidate(String name, String manufacturer, String sourceFile,
				PlatformDescription platform) {
			this.name = name;
			this.manufacturer = manufacturer;
			this.sourceFile = sourceFile;
			this.platform = platform;
		}
	}
}
