package heuristic;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.GZIPInputStream;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import com.google.gson.*;

/**
 * Identifies ROM images by SHA1 hash against a database extracted from MAME
 * driver source files. Supports three identification modes:
 *
 * 1. Direct match — SHA1 of the whole loaded binary matches a known ROM chip
 * 2. Split-2 match — binary is split into even/odd bytes, each half is SHA1'd
 *    and matched (identifies 16-bit interleaved ROMs loaded as a merged file)
 * 3. Split-4 match — binary is split into bytes 0/1/2/3, each quarter SHA1'd
 *    (identifies 32-bit interleaved ROMs like AT&T 3B2)
 *
 * The database contains ~80,000 SHA1 hashes from MAME's code-relevant ROM
 * regions (maincpu, bootstrap, audiocpu, etc.) covering ~35,000 machines.
 */
public class RomIdentifier {

	/** Result of ROM identification */
	public static class RomMatch {
		public final String machine;       // MAME machine name (e.g. "3b2_400")
		public final String description;   // Human name (e.g. "3B2/400")
		public final String manufacturer;  // e.g. "AT&T"
		public final String cpu;           // e.g. "we32100"
		public final int romSize;          // size of the matched ROM chip
		public final int romOffset;        // byte offset in interleaved image
		public final String region;        // MAME region name (e.g. "bootstrap")
		public final String matchType;     // "direct", "split2_even", "split2_odd", "split4_0", etc.
		public final String loadType;      // ROM_LOAD type (e.g. "32bit_byte")

		public RomMatch(String machine, String description, String manufacturer,
						String cpu, int romSize, int romOffset, String region,
						String matchType, String loadType) {
			this.machine = machine;
			this.description = description;
			this.manufacturer = manufacturer;
			this.cpu = cpu;
			this.romSize = romSize;
			this.romOffset = romOffset;
			this.region = region;
			this.matchType = matchType;
			this.loadType = loadType;
		}

		@Override
		public String toString() {
			String mfr = (manufacturer != null && !manufacturer.isEmpty())
				? manufacturer + " " : "";
			return String.format("%s%s [%s] (%s, %s match, offset 0x%X)",
				mfr, description != null ? description : machine,
				cpu, region, matchType, romOffset);
		}
	}

	private Map<String, List<JsonObject>> sha1Lookup;  // sha1 -> list of entries
	private List<JsonObject> combinedGroups;            // combined ROM groups
	private Map<Integer, List<Integer>> sizeToGroups;   // total_size -> group indices
	private boolean loaded = false;

	public RomIdentifier() {
		// Lazy load
	}

	/**
	 * Load the ROM database from the extension's data directory.
	 * Called lazily on first identify() call.
	 */
	private synchronized void ensureLoaded() {
		if (loaded) return;

		sha1Lookup = new HashMap<>();

		// Find the database file in the extension's data directory
		// Try multiple locations
		String[] searchPaths = {
			"data/mame_rom_db.json.gz",
			"../data/mame_rom_db.json.gz",
		};

		InputStream is = null;
		for (String path : searchPaths) {
			is = getClass().getClassLoader().getResourceAsStream(path);
			if (is != null) break;
		}

		// Also try as a file relative to the class location
		if (is == null) {
			try {
				String classDir = getClass().getProtectionDomain()
					.getCodeSource().getLocation().getPath();
				File dataFile = new File(classDir, "../../data/mame_rom_db.json.gz");
				if (!dataFile.exists()) {
					dataFile = new File(classDir, "../data/mame_rom_db.json.gz");
				}
				if (!dataFile.exists()) {
					// Try finding relative to the extension root
					File parent = new File(classDir);
					while (parent != null && !new File(parent, "data/mame_rom_db.json.gz").exists()) {
						parent = parent.getParentFile();
					}
					if (parent != null) {
						dataFile = new File(parent, "data/mame_rom_db.json.gz");
					}
				}
				if (dataFile.exists()) {
					is = new FileInputStream(dataFile);
				}
			} catch (Exception e) {
				// ignore
			}
		}

		if (is == null) {
			Msg.warn(this, "ROM database not found (mame_rom_db.json.gz)");
			loaded = true;
			return;
		}

		try {
			GZIPInputStream gis = new GZIPInputStream(is);
			byte[] data = gis.readAllBytes();
			gis.close();

			JsonObject db = JsonParser.parseString(new String(data, "UTF-8")).getAsJsonObject();
			JsonObject sha1Map = db.getAsJsonObject("sha1");

			for (Map.Entry<String, JsonElement> entry : sha1Map.entrySet()) {
				String sha1 = entry.getKey();
				JsonArray arr = entry.getValue().getAsJsonArray();
				List<JsonObject> list = new ArrayList<>();
				for (JsonElement el : arr) {
					list.add(el.getAsJsonObject());
				}
				sha1Lookup.put(sha1, list);
			}

			// Load combined ROM groups for de-interleave matching
			combinedGroups = new ArrayList<>();
			sizeToGroups = new HashMap<>();
			JsonArray combinedArr = db.getAsJsonArray("combined");
			if (combinedArr != null) {
				for (int i = 0; i < combinedArr.size(); i++) {
					JsonObject group = combinedArr.get(i).getAsJsonObject();
					combinedGroups.add(group);
					int totalSize = group.get("z").getAsInt();
					sizeToGroups.computeIfAbsent(totalSize, k -> new ArrayList<>()).add(i);
				}
			}

			Msg.info(this, String.format("ROM database loaded: %d SHA1 entries, %d combined groups",
				sha1Lookup.size(), combinedGroups.size()));

		} catch (Exception e) {
			Msg.error(this, "Failed to load ROM database: " + e.getMessage());
		}

		loaded = true;
	}

	/**
	 * Identify a ROM image from a Ghidra Memory object.
	 * Tries direct match, then split-2, then split-4.
	 *
	 * @return List of matches (may be empty), sorted by match quality
	 */
	public List<RomMatch> identify(Memory memory) {
		ensureLoaded();
		if (sha1Lookup == null || sha1Lookup.isEmpty()) {
			return Collections.emptyList();
		}

		// Read all initialized memory into a byte array
		byte[] romData = readAllMemory(memory);
		if (romData == null || romData.length < 64) {
			return Collections.emptyList();
		}

		List<RomMatch> results = new ArrayList<>();

		// Mode 1: Direct SHA1 match on whole file
		String wholeSha1 = sha1hex(romData);
		List<RomMatch> direct = lookupSha1(wholeSha1, romData.length, "direct");
		results.addAll(direct);

		// If direct match found, return immediately — no need to try splits
		if (!results.isEmpty()) {
			Msg.info(this, "ROM identified by direct SHA1 match: " + results.get(0));
			return results;
		}

		// Mode 2: Split into 2 (even/odd bytes) — 16-bit interleave
		if (romData.length >= 128 && romData.length % 2 == 0) {
			int halfSize = romData.length / 2;
			byte[] even = new byte[halfSize];
			byte[] odd = new byte[halfSize];
			for (int i = 0; i < romData.length; i += 2) {
				even[i / 2] = romData[i];
				odd[i / 2] = romData[i + 1];
			}

			String evenSha1 = sha1hex(even);
			String oddSha1 = sha1hex(odd);

			results.addAll(lookupSha1(evenSha1, halfSize, "split2_even"));
			results.addAll(lookupSha1(oddSha1, halfSize, "split2_odd"));

			if (!results.isEmpty()) {
				Msg.info(this, "ROM identified by 16-bit split SHA1: " + results.get(0));
				return results;
			}
		}

		// Mode 3: Split into 4 (bytes 0,1,2,3) — 32-bit interleave
		if (romData.length >= 256 && romData.length % 4 == 0) {
			int quarterSize = romData.length / 4;
			byte[][] quarters = new byte[4][quarterSize];
			for (int i = 0; i < romData.length; i += 4) {
				quarters[0][i / 4] = romData[i];
				quarters[1][i / 4] = romData[i + 1];
				quarters[2][i / 4] = romData[i + 2];
				quarters[3][i / 4] = romData[i + 3];
			}

			for (int q = 0; q < 4; q++) {
				String qSha1 = sha1hex(quarters[q]);
				results.addAll(lookupSha1(qSha1, quarterSize, "split4_" + q));
			}

			if (!results.isEmpty()) {
				Msg.info(this, "ROM identified by 32-bit split SHA1: " + results.get(0));
				return results;
			}
		}

		// Mode 4: Combined group matching — de-interleave according to known layouts
		// This handles all interleave patterns from the MAME database including
		// multi-bank layouts (e.g. 4 chips with i=2 across two banks)
		if (sizeToGroups != null) {
			List<Integer> candidateGroupIndices = sizeToGroups.get(romData.length);
			if (candidateGroupIndices != null) {
				for (int gi : candidateGroupIndices) {
					JsonObject group = combinedGroups.get(gi);
					RomMatch match = tryDeinterleaveGroup(romData, group);
					if (match != null) {
						results.add(match);
						Msg.info(this, "ROM identified by combined de-interleave: " + match);
						return results;
					}
				}
			}
		}

		// Mode 5: Split into 2 words (16-bit) within 32-bit — word-interleave
		// (legacy fallback for patterns not in combined groups)
		if (romData.length >= 256 && romData.length % 4 == 0) {
			int halfSize = romData.length / 2;
			byte[] wordLo = new byte[halfSize];
			byte[] wordHi = new byte[halfSize];
			for (int i = 0; i < romData.length; i += 4) {
				wordHi[i / 2] = romData[i];
				wordHi[i / 2 + 1] = romData[i + 1];
				wordLo[i / 2] = romData[i + 2];
				wordLo[i / 2 + 1] = romData[i + 3];
			}

			String loSha1 = sha1hex(wordLo);
			String hiSha1 = sha1hex(wordHi);

			results.addAll(lookupSha1(hiSha1, halfSize, "split32word_hi"));
			results.addAll(lookupSha1(loSha1, halfSize, "split32word_lo"));

			if (!results.isEmpty()) {
				Msg.info(this, "ROM identified by 32-bit word split SHA1: " + results.get(0));
				return results;
			}
		}

		return results;
	}

	/**
	 * Look up a SHA1 hash in the database.
	 */
	private List<RomMatch> lookupSha1(String sha1, int expectedSize, String matchType) {
		List<RomMatch> results = new ArrayList<>();
		List<JsonObject> entries = sha1Lookup.get(sha1);
		if (entries == null) return results;

		for (JsonObject e : entries) {
			int size = e.get("s").getAsInt();
			// Size must match (or be close for merged files)
			if (size != expectedSize && Math.abs(size - expectedSize) > 16) {
				continue;
			}

			String machine = e.get("m").getAsString();
			String cpu = e.has("c") ? e.get("c").getAsString() : "unknown";
			String desc = e.has("d") ? e.get("d").getAsString() : machine;
			String mfr = e.has("v") ? e.get("v").getAsString() : "";
			int offset = e.has("o") ? e.get("o").getAsInt() : 0;
			String region = e.has("r") ? e.get("r").getAsString() : "";
			String loadType = e.has("lt") ? e.get("lt").getAsString() : "";

			results.add(new RomMatch(machine, desc, mfr, cpu, size, offset,
				region, matchType, loadType));
		}

		return results;
	}

	/**
	 * Try to de-interleave a ROM according to a combined group's layout
	 * and verify all chip SHA1s match.
	 */
	private RomMatch tryDeinterleaveGroup(byte[] romData, JsonObject group) {
		int interleave = group.get("i").getAsInt();
		int numChips = group.get("n").getAsInt();
		int chipSize = group.get("ck").getAsInt();

		JsonArray chipSha1s = group.getAsJsonArray("cs");
		JsonArray chipOffsets = group.getAsJsonArray("co");

		if (chipSha1s.size() != numChips || chipOffsets.size() != numChips) {
			return null;
		}

		// De-interleave: extract each chip's data from the combined ROM
		for (int ci = 0; ci < numChips; ci++) {
			int offset = chipOffsets.get(ci).getAsInt();
			String expectedSha1 = chipSha1s.get(ci).getAsString();

			int byteLane = offset % interleave;
			int base = offset - byteLane;

			byte[] chipData = new byte[chipSize];
			boolean valid = true;
			for (int si = 0; si < chipSize; si++) {
				int srcIdx = base + si * interleave + byteLane;
				if (srcIdx >= romData.length) {
					valid = false;
					break;
				}
				chipData[si] = romData[srcIdx];
			}

			if (!valid) return null;

			String actualSha1 = sha1hex(chipData);
			if (!actualSha1.equals(expectedSha1)) {
				return null; // This chip doesn't match — try next group
			}
		}

		// All chips matched!
		String machine = group.get("m").getAsString();
		String cpu = group.has("c") ? group.get("c").getAsString() : "unknown";
		String desc = group.has("d") ? group.get("d").getAsString() : machine;
		String mfr = group.has("v") ? group.get("v").getAsString() : "";

		return new RomMatch(machine, desc, mfr, cpu, romData.length, 0,
			"maincpu", "combined_i" + interleave + "_n" + numChips, "");
	}

	/**
	 * Read all initialized memory blocks into a contiguous byte array.
	 */
	private byte[] readAllMemory(Memory memory) {
		try {
			// Find the total span of initialized memory
			long minAddr = Long.MAX_VALUE;
			long maxAddr = Long.MIN_VALUE;
			long totalBytes = 0;

			for (MemoryBlock block : memory.getBlocks()) {
				if (!block.isInitialized()) continue;
				long start = block.getStart().getOffset();
				long end = start + block.getSize();
				if (start < minAddr) minAddr = start;
				if (end > maxAddr) maxAddr = end;
				totalBytes += block.getSize();
			}

			if (totalBytes == 0 || totalBytes > 64 * 1024 * 1024) {
				return null; // Too large or no data
			}

			// If there's only one block, read it directly
			MemoryBlock[] blocks = memory.getBlocks();
			int initBlocks = 0;
			MemoryBlock singleBlock = null;
			for (MemoryBlock b : blocks) {
				if (b.isInitialized()) {
					initBlocks++;
					singleBlock = b;
				}
			}

			byte[] data;
			if (initBlocks == 1) {
				data = new byte[(int) singleBlock.getSize()];
				memory.getBytes(singleBlock.getStart(), data);
			} else {
				// Multiple blocks — read each one
				// Use contiguous array from first block start
				data = new byte[(int) totalBytes];
				int pos = 0;
				for (MemoryBlock block : blocks) {
					if (!block.isInitialized()) continue;
					byte[] blockData = new byte[(int) block.getSize()];
					memory.getBytes(block.getStart(), blockData);
					System.arraycopy(blockData, 0, data, pos, blockData.length);
					pos += blockData.length;
				}
			}

			return data;

		} catch (Exception e) {
			Msg.warn(this, "Failed to read memory for ROM identification: " + e.getMessage());
			return null;
		}
	}

	/**
	 * Compute SHA1 hex string for a byte array.
	 */
	private static String sha1hex(byte[] data) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			byte[] digest = md.digest(data);
			StringBuilder sb = new StringBuilder();
			for (byte b : digest) {
				sb.append(String.format("%02x", b & 0xFF));
			}
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-1 not available", e);
		}
	}

	/**
	 * Get the database entry count (for diagnostics).
	 */
	public int getEntryCount() {
		ensureLoaded();
		return sha1Lookup != null ? sha1Lookup.size() : 0;
	}
}
