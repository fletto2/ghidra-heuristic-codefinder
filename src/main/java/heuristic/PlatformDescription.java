/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;
import ghidra.xml.XmlElement;

import java.io.*;
import java.util.*;

/**
 * Platform description for Tier 3 heuristics (H32-H41).
 * Provides memory maps, vector tables, and hardware register addresses
 * for system-level code/data identification.
 */
public class PlatformDescription {

	public static class MemoryRegion {
		public final long start;
		public final long end;
		public final String type; // "rom", "ram", "io", "unmapped"
		public final String name;

		public MemoryRegion(long start, long end, String type, String name) {
			this.start = start;
			this.end = end;
			this.type = type;
			this.name = name;
		}
	}

	public static class VectorEntry {
		public final int index;
		public final String name;
		public final boolean isIrq;

		public VectorEntry(int index, String name, boolean isIrq) {
			this.index = index;
			this.name = name;
			this.isIrq = isIrq;
		}
	}

	public static class HardwareRegister {
		public final long addr;
		public final int width;
		public final String name;
		public final String access; // "r", "w", "rw"

		public HardwareRegister(long addr, int width, String name, String access) {
			this.addr = addr;
			this.width = width;
			this.name = name;
			this.access = access;
		}
	}

	private String platformName;
	private String cpuName;
	private List<MemoryRegion> memoryMap = new ArrayList<>();
	private List<VectorEntry> vectors = new ArrayList<>();
	private List<HardwareRegister> hwRegisters = new ArrayList<>();
	private long vectorBase = 0;
	private String vectorFormat = "abs32_be"; // abs32_be, abs32_le, abs16_le, etc.
	private int vectorEntrySize = 4;

	public String getPlatformName() { return platformName; }
	public List<MemoryRegion> getMemoryMap() { return memoryMap; }
	public List<VectorEntry> getVectors() { return vectors; }
	public List<HardwareRegister> getHwRegisters() { return hwRegisters; }
	public long getVectorBase() { return vectorBase; }
	public String getVectorFormat() { return vectorFormat; }
	public int getVectorEntrySize() { return vectorEntrySize; }

	/**
	 * H33: Check if an address falls in a valid memory region.
	 * Returns null if valid, region type string if in dead/unmapped zone.
	 */
	public String validateAddress(long addr) {
		for (MemoryRegion region : memoryMap) {
			if (addr >= region.start && addr <= region.end) {
				if ("unmapped".equals(region.type)) {
					return "unmapped:" + region.name;
				}
				return null; // valid
			}
		}
		// No region covers this address — if we have a memory map, it's unmapped
		return memoryMap.isEmpty() ? null : "unmapped:unknown";
	}

	/**
	 * H33: Check if address is suitable as a CALL/BRANCH target.
	 * Must be in ROM or RAM (executable), not I/O.
	 */
	public boolean isValidCodeAddress(long addr) {
		for (MemoryRegion region : memoryMap) {
			if (addr >= region.start && addr <= region.end) {
				return "rom".equals(region.type) || "ram".equals(region.type);
			}
		}
		return memoryMap.isEmpty(); // if no map, assume valid
	}

	/**
	 * H34: Check if address is a known hardware register.
	 */
	public HardwareRegister getHwRegister(long addr) {
		for (HardwareRegister reg : hwRegisters) {
			if (addr >= reg.addr && addr < reg.addr + reg.width) {
				return reg;
			}
		}
		return null;
	}

	/**
	 * H32: Read vector table entry points from binary.
	 */
	public List<Long> readVectorEntries(Program program) {
		List<Long> entries = new ArrayList<>();
		if (vectors.isEmpty()) return entries;

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		for (VectorEntry vec : vectors) {
			long addr = vectorBase + (long) vec.index * vectorEntrySize;
			try {
				Address memAddr = space.getAddress(addr);
				long value = 0;
				if (vectorFormat.startsWith("abs32")) {
					byte[] buf = new byte[4];
					program.getMemory().getBytes(memAddr, buf);
					if (vectorFormat.endsWith("_be")) {
						value = ((buf[0] & 0xFFL) << 24) | ((buf[1] & 0xFFL) << 16) |
								((buf[2] & 0xFFL) << 8) | (buf[3] & 0xFFL);
					} else {
						value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8) |
								((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
					}
				} else if (vectorFormat.startsWith("abs16")) {
					byte[] buf = new byte[2];
					program.getMemory().getBytes(memAddr, buf);
					if (vectorFormat.endsWith("_be")) {
						value = ((buf[0] & 0xFFL) << 8) | (buf[1] & 0xFFL);
					} else {
						value = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8);
					}
				}
				if (value != 0 && value != 0xFFFFFFFFL && isValidCodeAddress(value)) {
					entries.add(value);
				}
			} catch (Exception e) {
				// Skip unreadable vectors
			}
		}
		return entries;
	}

	/**
	 * Load platform description from XML file.
	 */
	public static PlatformDescription loadFromXml(InputStream is) throws Exception {
		PlatformDescription desc = new PlatformDescription();
		XmlPullParser parser = XmlPullParserFactory.create(is, "platform", null, false);

		while (parser.hasNext()) {
			XmlElement elem = parser.next();
			if (!elem.isStart()) continue;

			String tag = elem.getName();
			if ("platform".equals(tag)) {
				desc.platformName = elem.getAttribute("name");
				desc.cpuName = elem.getAttribute("cpu");
			} else if ("region".equals(tag)) {
				long start = parseLong(elem.getAttribute("start"));
				long end = parseLong(elem.getAttribute("end"));
				String type = elem.getAttribute("type");
				String name = elem.getAttribute("name");
				desc.memoryMap.add(new MemoryRegion(start, end, type, name));
			} else if ("vectors".equals(tag)) {
				desc.vectorBase = parseLong(elem.getAttribute("base"));
				desc.vectorFormat = elem.getAttribute("format");
				if (desc.vectorFormat.startsWith("abs32")) {
					desc.vectorEntrySize = 4;
				} else if (desc.vectorFormat.startsWith("abs16")) {
					desc.vectorEntrySize = 2;
				}
			} else if ("entry".equals(tag)) {
				int index = Integer.parseInt(elem.getAttribute("index"));
				String name = elem.getAttribute("name");
				boolean isIrq = "true".equals(elem.getAttribute("irq"));
				desc.vectors.add(new VectorEntry(index, name, isIrq));
			} else if ("reg".equals(tag)) {
				long addr = parseLong(elem.getAttribute("addr"));
				int width = Integer.parseInt(elem.getAttribute("width"));
				String name = elem.getAttribute("name");
				String access = elem.getAttribute("access");
				desc.hwRegisters.add(new HardwareRegister(addr, width, name, access));
			}
		}
		parser.dispose();
		return desc;
	}

	/**
	 * Auto-detect platform from program properties.
	 * Falls back to generating a basic description from Ghidra's memory blocks.
	 */
	public static PlatformDescription fromProgram(Program program) {
		PlatformDescription desc = new PlatformDescription();
		desc.platformName = "auto:" + program.getLanguageID().toString();
		desc.cpuName = program.getLanguage().getProcessor().toString();

		// Build memory map from Ghidra's memory blocks
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			String type;
			if (block.isVolatile()) {
				type = "io";
			} else if (block.isWrite() && !block.isExecute()) {
				type = "ram";
			} else if (block.isExecute() && !block.isWrite()) {
				type = "rom";
			} else if (block.isExecute() && block.isWrite()) {
				type = "ram";
			} else {
				type = "rom";
			}
			desc.memoryMap.add(new MemoryRegion(
				block.getStart().getOffset(),
				block.getEnd().getOffset(),
				type,
				block.getName()
			));
		}
		return desc;
	}

	private static long parseLong(String s) {
		if (s == null) return 0;
		s = s.trim();
		if (s.startsWith("0x") || s.startsWith("0X")) {
			return Long.parseUnsignedLong(s.substring(2), 16);
		}
		return Long.parseUnsignedLong(s);
	}
}
