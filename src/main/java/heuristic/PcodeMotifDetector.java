/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

/**
 * Detects algorithmic motifs — small recurring P-code operation patterns
 * that are characteristic of specific algorithm families.
 *
 * Unlike the rule-based detectors in FunctionPatternDetector which work on
 * aggregate opcode statistics, this operates on local sequential patterns
 * (3-6 P-code ops), identifying algorithm fragments wherever they appear
 * in a function. Multiple motif instances strengthen classification.
 *
 * Motifs are architecture-independent since they operate on P-code, not
 * raw instructions. A hash mixing motif (SHIFT+ADD+XOR) matches whether
 * the source is x86, ARM, MIPS, or 68000.
 *
 * Motif categories:
 *   - Hash mixing: SHIFT/ROTATE + ADD + XOR (hash functions, CRC)
 *   - Feistel round: XOR + substitution table LOAD + XOR (DES, Blowfish)
 *   - ARX (Add-Rotate-XOR): INT_ADD + SHIFT + INT_XOR (ChaCha, Salsa, BLAKE)
 *   - SPN round: byte extract (AND+SHIFT) + table LOAD + XOR (AES, Serpent)
 *   - Galois feedback: SHIFT + conditional XOR with polynomial (CRC, LFSR)
 *   - Accumulate-reduce: LOAD + arithmetic + STORE to same (checksums, sums)
 *   - Butterfly: indexed LOAD pair + ADD/SUB + indexed STORE pair (FFT)
 *   - Shift-accumulate: SHIFT + AND/test + conditional ADD (software multiply)
 *   - Compare-swap: LOAD pair + compare + conditional STORE (sort inner loop)
 *   - LZ back-reference: LOAD from offset + STORE sequential (LZ decompression)
 */
public class PcodeMotifDetector {

	/** A detected motif instance */
	public static class MotifMatch {
		public final MotifType type;
		public final int pcodeIndex;  // where in the P-code array this was found

		public MotifMatch(MotifType type, int pcodeIndex) {
			this.type = type;
			this.pcodeIndex = pcodeIndex;
		}
	}

	/** Motif types with their algorithm family associations */
	public enum MotifType {
		HASH_MIX("hash", "Hash mixing (shift+add+xor)"),
		ARX("crypto", "Add-Rotate-XOR (ChaCha/Salsa/BLAKE)"),
		FEISTEL("crypto", "Feistel round (xor+table+xor)"),
		SPN_ROUND("crypto", "SPN round (byte extract+table+xor)"),
		GALOIS_FEEDBACK("crc", "Galois feedback (shift+conditional xor)"),
		ACCUMULATE_REDUCE("checksum", "Accumulate-reduce (load+op+store)"),
		BUTTERFLY("fft", "Butterfly (load pair+add/sub+store pair)"),
		SHIFT_ACCUMULATE("multiply", "Shift-accumulate (shift+test+add)"),
		COMPARE_SWAP("sort", "Compare-swap (load+compare+store)"),
		LZ_BACKREF("compression", "LZ back-reference (load offset+store seq)");

		public final String category;
		public final String description;

		MotifType(String category, String description) {
			this.category = category;
			this.description = description;
		}
	}

	/** Result of motif analysis on a function */
	public static class MotifProfile {
		public final Map<MotifType, Integer> counts = new EnumMap<>(MotifType.class);
		public final List<MotifMatch> matches = new ArrayList<>();
		public int totalMotifs = 0;

		public int count(MotifType type) {
			return counts.getOrDefault(type, 0);
		}

		/** Dominant motif type (most frequent), or null if no motifs found */
		public MotifType dominant() {
			MotifType best = null;
			int bestCount = 0;
			for (Map.Entry<MotifType, Integer> e : counts.entrySet()) {
				if (e.getValue() > bestCount) {
					bestCount = e.getValue();
					best = e.getKey();
				}
			}
			return best;
		}

		/** Fraction of total P-code ops covered by motif instances */
		public double density(int totalOps) {
			if (totalOps == 0) return 0.0;
			// Each motif covers ~3-5 ops
			return (totalMotifs * 4.0) / totalOps;
		}
	}

	/**
	 * Scan a P-code array for all motif instances.
	 * Returns a profile with counts per motif type and all match locations.
	 */
	public MotifProfile analyze(PcodeOp[] pcode) {
		MotifProfile profile = new MotifProfile();
		if (pcode == null || pcode.length < 3) return profile;

		for (int i = 0; i < pcode.length; i++) {
			// Try each motif detector at this position
			MotifType match = detectMotifAt(pcode, i);
			if (match != null) {
				profile.matches.add(new MotifMatch(match, i));
				profile.counts.merge(match, 1, Integer::sum);
				profile.totalMotifs++;
			}
		}
		return profile;
	}

	/**
	 * Check if a motif starts at position i in the P-code array.
	 * Returns the motif type if found, null otherwise.
	 * Only returns the first (highest priority) match at each position.
	 */
	private MotifType detectMotifAt(PcodeOp[] pcode, int i) {
		int remaining = pcode.length - i;

		// Each detector checks a small window starting at i
		if (remaining >= 3) {
			// Priority order: more specific patterns first

			if (isArkMotif(pcode, i)) return MotifType.ARX;
			if (isFeistelMotif(pcode, i)) return MotifType.FEISTEL;
			if (isSpnRound(pcode, i)) return MotifType.SPN_ROUND;
			if (isGaloisFeedback(pcode, i)) return MotifType.GALOIS_FEEDBACK;
			if (isHashMix(pcode, i)) return MotifType.HASH_MIX;
			if (isButterfly(pcode, i)) return MotifType.BUTTERFLY;
			if (isShiftAccumulate(pcode, i)) return MotifType.SHIFT_ACCUMULATE;
			if (isCompareSwap(pcode, i)) return MotifType.COMPARE_SWAP;
			if (isAccumulateReduce(pcode, i)) return MotifType.ACCUMULATE_REDUCE;
			if (isLzBackref(pcode, i)) return MotifType.LZ_BACKREF;
		}
		return null;
	}

	// ================================================================
	// Individual motif detectors
	// ================================================================

	/**
	 * Hash mixing: SHIFT (or MULT by small prime) + ADD + XOR within 4 ops.
	 * Covers: djb2, FNV, Jenkins, MurmurHash mixing steps.
	 * Pattern: any permutation of {shift/mult, add, xor} within a window.
	 */
	private boolean isHashMix(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 5, pcode.length);
		boolean hasShiftOrMult = false;
		boolean hasAdd = false;
		boolean hasXor = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_LEFT || op == PcodeOp.INT_RIGHT) {
				hasShiftOrMult = true;
			}
			if (op == PcodeOp.INT_MULT) {
				// Only count as hash-mix if multiplying by a small prime
				Varnode in1 = pcode[j].getInput(1);
				if (in1 != null && in1.isConstant()) {
					long v = in1.getOffset();
					if (v == 31 || v == 33 || v == 37 || v == 5 || v == 7 ||
						v == 0x01000193L || v == 16777619L) {
						hasShiftOrMult = true;
					}
				}
			}
			if (op == PcodeOp.INT_ADD) hasAdd = true;
			if (op == PcodeOp.INT_XOR) hasXor = true;
		}
		return hasShiftOrMult && hasAdd && hasXor;
	}

	/**
	 * ARX (Add-Rotate-XOR): INT_ADD + INT_LEFT/RIGHT by constant + INT_XOR.
	 * Must have a rotation (shift by specific constant like 7, 8, 12, 16).
	 * Covers: ChaCha20 quarter-round, Salsa20, BLAKE2, Skein/ThreeFish.
	 */
	private boolean isArkMotif(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 5, pcode.length);
		boolean hasAdd = false;
		boolean hasRotate = false;
		boolean hasXor = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_ADD) hasAdd = true;
			if (op == PcodeOp.INT_XOR) hasXor = true;
			if (op == PcodeOp.INT_LEFT || op == PcodeOp.INT_RIGHT) {
				Varnode amt = pcode[j].getInput(1);
				if (amt != null && amt.isConstant()) {
					long v = amt.getOffset();
					// ChaCha: 16,12,8,7. BLAKE2: 32,24,16,63. Salsa: 7,9,13,18.
					if (v == 7 || v == 8 || v == 9 || v == 12 || v == 13 ||
						v == 16 || v == 18 || v == 24 || v == 25 || v == 32 || v == 63) {
						hasRotate = true;
					}
				}
			}
		}
		// ARX requires all three and the rotate must be by a known constant
		return hasAdd && hasRotate && hasXor;
	}

	/**
	 * Feistel round: XOR + table LOAD + XOR.
	 * The table LOAD uses a value derived from an XOR as the index.
	 * Covers: DES, Blowfish, Twofish, CAST.
	 */
	private boolean isFeistelMotif(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 6, pcode.length);
		int xorCount = 0;
		boolean hasLoad = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_XOR) xorCount++;
			if (op == PcodeOp.LOAD) hasLoad = true;
		}
		// Feistel: at least 2 XORs (round function input/output) + table lookup
		return xorCount >= 2 && hasLoad;
	}

	/**
	 * SPN (Substitution-Permutation Network) round:
	 * byte extract (AND 0xFF or ZEXT) + table LOAD (S-box) + XOR (key mixing).
	 * Covers: AES SubBytes+MixColumns, Serpent S-box.
	 */
	private boolean isSpnRound(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 6, pcode.length);
		boolean hasByteExtract = false;
		boolean hasTableLoad = false;
		boolean hasXor = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_AND) {
				Varnode mask = pcode[j].getInput(1);
				if (mask != null && mask.isConstant() && mask.getOffset() == 0xFF) {
					hasByteExtract = true;
				}
			}
			if (op == PcodeOp.INT_ZEXT) hasByteExtract = true;
			if (op == PcodeOp.LOAD) hasTableLoad = true;
			if (op == PcodeOp.INT_XOR) hasXor = true;
		}
		return hasByteExtract && hasTableLoad && hasXor;
	}

	/**
	 * Galois feedback: SHIFT by 1 + conditional XOR with polynomial constant.
	 * In P-code: INT_RIGHT/INT_LEFT + INT_AND (bit test) + INT_XOR.
	 * The XOR operand is typically a known polynomial (CRC, LFSR).
	 * Covers: CRC bit-by-bit, LFSR, PRNG feedback.
	 */
	private boolean isGaloisFeedback(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 5, pcode.length);
		boolean hasShiftBy1 = false;
		boolean hasBitTest = false;
		boolean hasXor = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_LEFT || op == PcodeOp.INT_RIGHT) {
				Varnode amt = pcode[j].getInput(1);
				if (amt != null && amt.isConstant() && amt.getOffset() == 1) {
					hasShiftBy1 = true;
				}
			}
			if (op == PcodeOp.INT_AND) {
				Varnode mask = pcode[j].getInput(1);
				if (mask != null && mask.isConstant()) {
					long v = mask.getOffset();
					// Bit test: AND with 1, 0x80, 0x8000, 0x80000000, etc.
					if (v == 1 || v == 0x80 || v == 0x8000 || v == 0x80000000L) {
						hasBitTest = true;
					}
				}
			}
			if (op == PcodeOp.INT_XOR) {
				Varnode xorConst = pcode[j].getInput(1);
				if (xorConst != null && xorConst.isConstant() && xorConst.getOffset() > 0xFF) {
					hasXor = true;  // Large XOR constant = likely polynomial
				}
			}
		}
		return hasShiftBy1 && hasBitTest && hasXor;
	}

	/**
	 * Accumulate-reduce: LOAD + ADD/XOR + LOAD (tight accumulator loop).
	 * Pattern: consecutive LOAD+accumulate pairs without intervening STORE or
	 * branch ops, indicating a reduction loop (checksum, sum, XOR check).
	 * Requires the accumulating op to be XOR or ADD (not OR, too generic).
	 * Covers: IP checksum (add-with-carry), simple sums, byte-wise XOR check.
	 */
	private boolean isAccumulateReduce(PcodeOp[] pcode, int i) {
		if (i + 3 >= pcode.length) return false;
		int op0 = pcode[i].getOpcode();
		int op1 = pcode[i + 1].getOpcode();
		int op2 = pcode[i + 2].getOpcode();
		int op3 = pcode[i + 3].getOpcode();

		// LOAD + ADD/XOR + LOAD + ADD/XOR (two consecutive accumulations)
		if (op0 != PcodeOp.LOAD) return false;
		if (op1 != PcodeOp.INT_ADD && op1 != PcodeOp.INT_XOR) return false;
		if (op2 != PcodeOp.LOAD) return false;
		if (op3 != PcodeOp.INT_ADD && op3 != PcodeOp.INT_XOR) return false;
		// The accumulating ops should be the same type (both ADD or both XOR)
		return op1 == op3;
	}

	/**
	 * Butterfly: LOAD pair + ADD and SUB + STORE pair.
	 * Pattern: load a[i], load a[j], compute a[i]+a[j] and a[i]-a[j], store both.
	 * Covers: FFT butterfly, DCT, Walsh-Hadamard transform.
	 */
	private boolean isButterfly(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 8, pcode.length);
		int loads = 0, stores = 0;
		boolean hasAdd = false, hasSub = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.LOAD) loads++;
			if (op == PcodeOp.STORE) stores++;
			if (op == PcodeOp.INT_ADD) hasAdd = true;
			if (op == PcodeOp.INT_SUB) hasSub = true;
		}
		// Butterfly requires paired loads, both add and sub, paired stores
		return loads >= 2 && stores >= 2 && hasAdd && hasSub;
	}

	/**
	 * Shift-accumulate: SHIFT + AND/test bit + conditional ADD.
	 * Pattern: shift operand left, test bit of multiplier, add if set.
	 * Covers: software multiply (shift-and-add), Russian peasant multiply.
	 */
	private boolean isShiftAccumulate(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 5, pcode.length);
		boolean hasShift = false;
		boolean hasBitTest = false;
		boolean hasAdd = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_LEFT || op == PcodeOp.INT_RIGHT) hasShift = true;
			if (op == PcodeOp.INT_AND) {
				Varnode mask = pcode[j].getInput(1);
				if (mask != null && mask.isConstant()) {
					long v = mask.getOffset();
					// Power of 2 mask = bit test
					if (v > 0 && (v & (v - 1)) == 0) hasBitTest = true;
				}
			}
			if (op == PcodeOp.INT_ADD) hasAdd = true;
		}
		return hasShift && hasBitTest && hasAdd;
	}

	/**
	 * Compare-swap: LOAD + LOAD + compare + conditional STORE.
	 * The core operation of comparison-based sorting (bubble, insertion, selection).
	 * Covers: qsort partition, bubble sort inner loop, insertion sort shift.
	 */
	private boolean isCompareSwap(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 6, pcode.length);
		int loads = 0, stores = 0;
		boolean hasCompare = false;

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.LOAD) loads++;
			if (op == PcodeOp.STORE) stores++;
			if (op == PcodeOp.INT_SLESS || op == PcodeOp.INT_LESS ||
				op == PcodeOp.INT_SLESSEQUAL || op == PcodeOp.INT_LESSEQUAL) {
				hasCompare = true;
			}
		}
		// Need two loads (elements to compare), comparison, and at least one store (swap)
		return loads >= 2 && hasCompare && stores >= 1;
	}

	/**
	 * LZ back-reference: LOAD from computed offset + STORE to sequential output.
	 * Pattern: compute source = output - distance, load byte, store to output, increment.
	 * Covers: LZSS, LZ77, LZW copy phase, Deflate length-distance pairs.
	 */
	private boolean isLzBackref(PcodeOp[] pcode, int i) {
		int end = Math.min(i + 6, pcode.length);
		boolean hasSub = false;  // distance computation
		boolean hasLoad = false;
		boolean hasStore = false;
		boolean hasAdd = false;  // pointer increment

		for (int j = i; j < end; j++) {
			int op = pcode[j].getOpcode();
			if (op == PcodeOp.INT_SUB) hasSub = true;
			if (op == PcodeOp.LOAD) hasLoad = true;
			if (op == PcodeOp.STORE) hasStore = true;
			if (op == PcodeOp.INT_ADD) hasAdd = true;
		}
		return hasSub && hasLoad && hasStore && hasAdd;
	}

	// ================================================================
	// Classification from motif profile
	// ================================================================

	/**
	 * Classify a function based on its motif profile.
	 * Returns a FunctionType if motif evidence is strong enough, null otherwise.
	 *
	 * Classification requires:
	 *   - Multiple instances of the same motif type (repetition = algorithmic structure)
	 *   - Sufficient motif density relative to function size
	 *   - Context from hasLoop and constant analysis
	 */
	public FunctionPatternDetector.FunctionType classifyFromMotifs(
			MotifProfile profile, PcodeOp[] pcode, boolean hasLoop) {
		if (profile.totalMotifs < 2) return null;
		int totalOps = pcode.length;

		MotifType dominant = profile.dominant();
		if (dominant == null) return null;
		int domCount = profile.count(dominant);

		// Require at least 3 instances for crypto/hash (repetitive rounds)
		// or 2 for simpler patterns (sort, multiply)
		switch (dominant) {
			case ARX:
				if (domCount >= 4 && hasLoop) {
					double conf = Math.min(0.60 + domCount * 0.05, 0.92);
					return new FunctionPatternDetector.FunctionType("crypto",
						"arx_cipher_round",
						conf,
						String.format("ARX cipher (%d add-rotate-xor motifs)", domCount));
				}
				break;

			case FEISTEL:
				if (domCount >= 3 && hasLoop) {
					double conf = Math.min(0.55 + domCount * 0.06, 0.90);
					return new FunctionPatternDetector.FunctionType("crypto",
						"feistel_cipher",
						conf,
						String.format("Feistel cipher (%d xor-table-xor motifs)", domCount));
				}
				break;

			case SPN_ROUND:
				if (domCount >= 4) {
					double conf = Math.min(0.55 + domCount * 0.05, 0.90);
					// If we see 16+ SPN motifs, it's likely AES (16 S-box lookups per round)
					String label = domCount >= 12 ? "aes_like_cipher" : "spn_cipher";
					return new FunctionPatternDetector.FunctionType("crypto",
						label,
						conf,
						String.format("SPN cipher (%d byte-extract+table+xor motifs)", domCount));
				}
				break;

			case GALOIS_FEEDBACK:
				if (domCount >= 2 && hasLoop) {
					double conf = Math.min(0.60 + domCount * 0.08, 0.92);
					// Check for known CRC polynomials in constants
					boolean hasKnownPoly = hasKnownCrcPolynomial(pcode);
					if (hasKnownPoly) conf = Math.min(conf + 0.15, 0.95);
					String label = hasKnownPoly ? "crc_computation" : "galois_feedback";
					return new FunctionPatternDetector.FunctionType("crc",
						label,
						conf,
						String.format("Galois feedback (%d shift+test+xor motifs%s)",
							domCount, hasKnownPoly ? ", known polynomial" : ""));
				}
				break;

			case HASH_MIX:
				if (domCount >= 3 && hasLoop) {
					double conf = Math.min(0.55 + domCount * 0.06, 0.90);
					boolean hasHashPrime = hasKnownHashConstant(pcode);
					if (hasHashPrime) conf = Math.min(conf + 0.12, 0.93);
					return new FunctionPatternDetector.FunctionType("hash_function",
						"hash_computation",
						conf,
						String.format("Hash function (%d shift+add+xor motifs%s)",
							domCount, hasHashPrime ? ", known hash constant" : ""));
				}
				break;

			case BUTTERFLY:
				if (domCount >= 3 && hasLoop) {
					double conf = Math.min(0.55 + domCount * 0.07, 0.90);
					return new FunctionPatternDetector.FunctionType("fft",
						"fft_butterfly",
						conf,
						String.format("FFT/transform (%d butterfly motifs)", domCount));
				}
				break;

			case SHIFT_ACCUMULATE:
				if (domCount >= 2 && hasLoop && totalOps < 200) {
					double conf = Math.min(0.55 + domCount * 0.08, 0.88);
					return new FunctionPatternDetector.FunctionType("multiply",
						"software_multiply",
						conf,
						String.format("Software multiply (%d shift+test+add motifs)", domCount));
				}
				break;

			case COMPARE_SWAP:
				if (domCount >= 3 && hasLoop) {
					double conf = Math.min(0.50 + domCount * 0.06, 0.85);
					return new FunctionPatternDetector.FunctionType("sort",
						"sort_routine",
						conf,
						String.format("Sort routine (%d compare-swap motifs)", domCount));
				}
				break;

			case ACCUMULATE_REDUCE:
				if (domCount >= 4 && hasLoop) {
					double conf = Math.min(0.60 + domCount * 0.05, 0.88);
					return new FunctionPatternDetector.FunctionType("checksum",
						"checksum_accumulate",
						conf,
						String.format("Checksum/accumulator (%d load+op+store motifs)", domCount));
				}
				break;

			case LZ_BACKREF:
				if (domCount >= 2 && hasLoop) {
					double conf = Math.min(0.50 + domCount * 0.07, 0.88);
					return new FunctionPatternDetector.FunctionType("decompression",
						"lz_decompressor",
						conf,
						String.format("LZ decompression (%d back-reference motifs)", domCount));
				}
				break;
		}
		return null;
	}

	// ================================================================
	// Constant analysis helpers
	// ================================================================

	private boolean hasKnownCrcPolynomial(PcodeOp[] pcode) {
		Set<Long> knownPolys = Set.of(
			0xEDB88320L, 0x04C11DB7L,   // CRC-32
			0x82F63B78L, 0x1EDC6F41L,   // CRC-32C (Castagnoli)
			0xA001L, 0x8005L,            // CRC-16
			0x1021L, 0x8408L             // CRC-CCITT
		);
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_XOR) {
				for (int j = 0; j < op.getNumInputs(); j++) {
					Varnode in = op.getInput(j);
					if (in != null && in.isConstant() && knownPolys.contains(in.getOffset())) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private boolean hasKnownHashConstant(PcodeOp[] pcode) {
		Set<Long> knownHash = Set.of(
			31L, 33L, 37L, 5381L,                // djb2, djb2a, sdbm
			0x01000193L, 16777619L,               // FNV-1 prime (32-bit)
			2166136261L,                           // FNV-1 offset basis
			0x9E3779B9L,                           // golden ratio (hash mixing)
			0xCC9E2D51L, 0x1B873593L,             // MurmurHash3
			0x85EBCA6BL, 0xC2B2AE35L,             // MurmurHash3 fmix
			65599L                                 // SDBM
		);
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_MULT || op.getOpcode() == PcodeOp.INT_XOR ||
				op.getOpcode() == PcodeOp.INT_ADD) {
				for (int j = 0; j < op.getNumInputs(); j++) {
					Varnode in = op.getInput(j);
					if (in != null && in.isConstant() && knownHash.contains(in.getOffset())) {
						return true;
					}
				}
			}
		}
		return false;
	}
}
