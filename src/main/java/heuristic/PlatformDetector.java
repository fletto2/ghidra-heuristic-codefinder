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

		// Score formula:
		// Base: fraction of addresses that hit defined regions
		// Bonus: extra weight for IO hits (distinguishes machines with same ROM/RAM layout)
		// Bonus: strong bonus for hardware register hits (very specific to machine)
		// Penalty: unmapped hits
		double baseScore = (double) hits / tested;
		double ioPenalty = (double) misses / tested;
		double ioBonus = (double) ioHits / tested * 0.3;
		double hwBonus = (double) hwRegHits / tested * 2.0;

		return baseScore - ioPenalty + ioBonus + hwBonus;
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

		if (addresses.size() < 10) {
			Msg.warn(PlatformDetector.class, "Too few addresses for reliable detection");
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

		// If swapped hits significantly outnumber native hits, ROM is likely byte-swapped
		if (bestSwapHits > nativeHits * 2 && bestSwapHits >= 3) {
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
