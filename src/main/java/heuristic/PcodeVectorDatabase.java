/* Licensed under the Apache License, Version 2.0 */
package heuristic;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

import com.google.gson.*;

import java.io.*;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * P-code vector database for function classification via structural similarity.
 *
 * Instead of hand-crafted rules or low-dimensional feature vectors, this stores
 * normalized P-code n-gram signatures from known functions and matches unknown
 * functions by cosine similarity on sparse TF-IDF weighted vectors.
 *
 * Key design:
 *   1. P-code normalization: Each op becomes an architecture-independent token
 *      encoding opcode group, output size, and constant class (e.g., "AD4",
 *      "AN4m", "LD1", "SL4s"). This preserves structural patterns while
 *      stripping register-specific details.
 *
 *   2. N-gram embedding: Bigrams and trigrams of normalized tokens form a
 *      high-dimensional sparse feature vector (~100-300 non-zero dimensions
 *      out of ~10K vocabulary). Far richer than 25-dimensional summaries.
 *
 *   3. TF-IDF weighting: Common n-grams (COPY→COPY) are down-weighted;
 *      rare discriminative patterns (LOAD→XOR→SHIFT) are amplified.
 *
 *   4. ROM domain filtering: RomIdentifier results constrain which function
 *      categories are plausible, eliminating impossible matches before
 *      similarity computation.
 *
 *   5. Reference database: Pre-built from real annotated ROMs across ISAs.
 *      Each entry stores category, label, source CPU, and n-gram vector.
 *      Loaded from data/pcode_signatures.json.gz at runtime.
 */
public class PcodeVectorDatabase {

	// ================================================================
	// ROM domain classification
	// ================================================================

	/** High-level ROM domain derived from ROM identification */
	public enum RomDomain {
		GAME_CONSOLE,       // Sega Genesis, NES, SNES, GBA, Saturn, etc.
		COMPUTER_BOOT,      // AT&T 3B2, Mac, workstation boot ROMs
		RTOS_EMBEDDED,      // pSOS, VxWorks, embedded controllers
		TYPESETTER,         // AGFA, PostScript RIPs
		NETWORK_DEVICE,     // routers, network cards
		INDUSTRIAL,         // gas pumps, fire panels, PLCs
		ARCADE,             // arcade game boards
		AUDIO_DEVICE,       // sound cards, audio processors
		GENERIC             // unknown — allow all categories
	}

	/** Plausible function categories per ROM domain */
	private static final Map<RomDomain, Set<String>> DOMAIN_CATEGORIES = new HashMap<>();
	static {
		// Game consoles: graphics, sound, physics, input, compression
		DOMAIN_CATEGORIES.put(RomDomain.GAME_CONSOLE, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum", "decompression",
			"rle", "lzss", "huffman", "bcd", "jump_table",
			"interrupt_handler", "boot_init", "rng", "fixed_point",
			"collision", "velocity_physics", "gravity", "jump_physics",
			"sprite_render", "sprite_scale", "scroll", "palette_fade",
			"palette_cycle", "screen_fade", "tile_decode", "tilemap_load",
			"animation", "particle", "dma_transfer", "dma_queue",
			"vblank_wait", "controller_input", "debounce",
			"sound_driver", "adpcm", "audio_mixer", "fm_synth",
			"wavetable", "object_update", "object_spawn",
			"state_machine", "bytecode_interp",
			"sort", "binary_search", "table_lookup",
			"score_update", "high_score", "save_load",
			"camera_tracking", "parallax_scroll", "raycasting",
			"line_draw", "circle_draw", "polygon_fill",
			"ai_decision", "enemy_patrol", "boss_pattern",
			"pathfinding", "npc_dialog", "inventory",
			"health_damage", "continue_countdown",
			"demo_playback", "input_recording",
			"number_to_string", "hex_dump",
			"framebuffer_swap", "vram_clear", "interlace",
			"abs_value", "clamp", "byte_swap",
			"dot_product", "matrix_multiply", "trig_lookup",
			"sqrt", "atan2", "coordinate_transform",
			"bitmap_blit", "bitmap_alloc",
			"circular_buffer", "linked_list",
			"osd_overlay", "char_gen", "text_render",
			"menu_navigation", "random_level"
		)));

		// Computer boot ROMs: hardware init, self-test, drivers, OS bootstrap
		DOMAIN_CATEGORIES.put(RomDomain.COMPUTER_BOOT, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum", "crc",
			"bcd", "jump_table", "interrupt_handler", "boot_init",
			"printf", "sprintf", "number_to_string", "hex_dump",
			"memory_test", "self_test", "post_memory_test",
			"serial_io", "uart_init", "dma_transfer",
			"scsi_command", "disk_block_io", "flash_program",
			"flash_erase", "eeprom",
			"device_driver", "interrupt_control",
			"vector_table", "context_save", "exception_frame",
			"state_machine", "command_parser", "retry_loop",
			"busy_wait", "delay_loop", "watchdog",
			"sort", "binary_search", "table_lookup",
			"linked_list", "circular_buffer",
			"block_mapping", "page_table", "mpu_config",
			"cache_flush", "tlb_flush",
			"checksum_validate", "ip_checksum",
			"abs_value", "clamp", "byte_swap",
			"timer_setup", "rtc",
			"keyboard_scan", "dip_switch",
			"crt_init", "lcd_init", "text_render",
			"error_handler", "assert_panic", "log_print",
			"bootloader_jump", "relocation",
			"bus_arbitration", "jtag",
			"fat_filesystem", "file_operation",
			"heap_alloc", "memory_pool", "slab_alloc",
			"task_scheduler", "semaphore", "mutex",
			"coroutine", "event_signal",
			"atoi", "itoa", "string_search", "string_tokenize",
			"software_float", "float_add", "float_mul"
		)));

		// RTOS/embedded: task management, IPC, drivers
		DOMAIN_CATEGORIES.put(RomDomain.RTOS_EMBEDDED, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum", "crc",
			"jump_table", "interrupt_handler", "boot_init",
			"printf", "sprintf", "number_to_string", "hex_dump",
			"task_scheduler", "thread_scheduler", "semaphore", "mutex",
			"message_passing", "pipe_ipc", "event_signal",
			"priority_queue", "fifo_queue",
			"serial_io", "uart_init", "i2c", "spi",
			"device_driver", "interrupt_control",
			"timer_setup", "watchdog", "delay_loop",
			"dma_transfer", "dma_chain",
			"memory_test", "self_test",
			"state_machine", "command_parser", "retry_loop",
			"sort", "binary_search", "table_lookup",
			"linked_list", "circular_buffer",
			"heap_alloc", "memory_pool", "slab_alloc",
			"flash_program", "flash_erase", "eeprom",
			"context_save", "exception_frame",
			"error_handler", "assert_panic", "log_print",
			"fat_filesystem", "file_operation",
			"ip_checksum", "network_protocol",
			"abs_value", "clamp", "byte_swap",
			"pid_controller", "pwm", "sensor", "adc", "dac",
			"motor_control", "stepper",
			"rtc", "calendar",
			"power_sleep",
			"atoi", "itoa", "string_search", "string_tokenize",
			"syscall_dispatch", "signal_handler",
			"socket", "mount", "file_desc"
		)));

		// Typesetter/RIP: interpreter, math, graphics, fonts
		DOMAIN_CATEGORIES.put(RomDomain.TYPESETTER, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum",
			"printf", "sprintf", "number_to_string",
			"sort", "binary_search", "table_lookup",
			"heap_alloc", "memory_pool",
			"linked_list", "hash_table",
			"bytecode_interp", "stack_interp",
			"state_machine", "command_parser",
			"line_draw", "circle_draw", "polygon_fill",
			"bitmap_blit", "bitmap_alloc", "flood_fill",
			"alpha_blend", "gamma_correct", "color_space",
			"fixed_point", "sqrt", "atan2", "trig_lookup",
			"dot_product", "matrix_multiply",
			"coordinate_transform", "bezier",
			"newton_raphson", "polynomial",
			"linear_interp", "log_approx", "exp_approx",
			"software_float", "float_add", "float_mul",
			"font_decode", "char_gen", "text_render",
			"rle", "lzss", "huffman",
			"fat_filesystem", "file_operation", "disk_block_io",
			"scsi_command",
			"serial_io", "uart_init",
			"interrupt_handler", "boot_init",
			"device_driver", "dma_transfer",
			"error_handler", "assert_panic", "log_print",
			"task_scheduler", "semaphore",
			"regex", "string_search", "string_tokenize",
			"atoi", "itoa", "json_parser",
			"abs_value", "clamp", "byte_swap"
		)));

		// Network devices
		DOMAIN_CATEGORIES.put(RomDomain.NETWORK_DEVICE, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum", "crc",
			"ip_checksum", "network_protocol",
			"arp", "tcp_state", "udp_checksum",
			"dns", "dhcp", "http_parser", "smtp",
			"tftp", "ntp", "ppp", "telnet", "snmp",
			"xdr_encode", "xdr_decode",
			"serial_io", "uart_init",
			"interrupt_handler", "boot_init",
			"device_driver", "dma_transfer",
			"state_machine", "command_parser",
			"sort", "binary_search", "table_lookup",
			"linked_list", "circular_buffer", "fifo_queue",
			"heap_alloc", "memory_pool",
			"printf", "sprintf", "number_to_string", "hex_dump",
			"timer_setup", "watchdog",
			"error_handler", "log_print",
			"hash_function", "hash_table",
			"encrypt_decrypt", "aes", "des", "rc4", "hmac",
			"base64_encode", "base64_decode",
			"abs_value", "byte_swap",
			"socket", "mount"
		)));

		// Industrial controllers
		DOMAIN_CATEGORIES.put(RomDomain.INDUSTRIAL, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum", "crc",
			"bcd", "jump_table", "interrupt_handler", "boot_init",
			"printf", "sprintf", "number_to_string",
			"serial_io", "uart_init", "i2c", "spi",
			"modbus", "can_bus", "hdlc", "manchester",
			"device_driver", "dma_transfer",
			"state_machine", "command_parser",
			"pid_controller", "pwm", "sensor", "adc", "dac",
			"motor_control", "stepper",
			"timer_setup", "watchdog", "delay_loop",
			"eeprom", "flash_program",
			"rtc", "calendar",
			"lcd_init", "text_render", "thermal_printer",
			"keyboard_scan", "dip_switch",
			"error_handler", "assert_panic",
			"sort", "binary_search", "table_lookup",
			"linked_list", "circular_buffer",
			"heap_alloc",
			"task_scheduler", "semaphore",
			"power_sleep", "battery_monitor",
			"weight_tare", "fuel_injection", "barcode",
			"abs_value", "clamp",
			"fixed_point", "moving_average", "median_filter",
			"busy_wait", "retry_loop"
		)));

		// Arcade
		DOMAIN_CATEGORIES.put(RomDomain.ARCADE, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
			"strlen", "strcmp", "strcpy", "checksum",
			"decompression", "rle", "lzss",
			"bcd", "jump_table", "interrupt_handler", "boot_init",
			"rng", "fixed_point",
			"collision", "velocity_physics",
			"sprite_render", "sprite_scale", "scroll", "palette_fade",
			"palette_cycle", "screen_fade", "tile_decode", "tilemap_load",
			"animation", "particle", "dma_transfer", "dma_queue",
			"vblank_wait", "controller_input", "debounce",
			"sound_driver", "adpcm", "audio_mixer", "fm_synth",
			"object_update", "object_spawn",
			"state_machine",
			"sort", "table_lookup",
			"score_update", "high_score",
			"coin_handler", "dip_switch",
			"osd_overlay", "char_gen", "text_render",
			"number_to_string",
			"abs_value", "clamp", "byte_swap",
			"trig_lookup", "line_draw",
			"framebuffer_swap", "vram_clear",
			"bitmap_blit", "circular_buffer",
			"watchdog", "self_test",
			"memory_test", "encrypt_decrypt"
		)));

		// Audio devices
		DOMAIN_CATEGORIES.put(RomDomain.AUDIO_DEVICE, new HashSet<>(Arrays.asList(
			"multiply", "divide", "memcpy", "memset",
			"interrupt_handler", "boot_init",
			"dma_transfer",
			"sound_driver", "adpcm", "audio_mixer",
			"fm_synth", "wavetable", "adsr",
			"sample_rate_convert",
			"fir_filter", "iir_filter", "moving_average",
			"fft_butterfly", "convolution",
			"fixed_point", "abs_value", "clamp",
			"circular_buffer", "fifo_queue",
			"timer_setup",
			"midi_handler",
			"delta_encode", "delta_decode",
			"state_machine", "table_lookup"
		)));

		// Generic: allow everything (no filtering)
		// We don't add entries — absence means "allow all"
	}

	// ================================================================
	// P-code token normalization
	// ================================================================

	/** Opcode group names — compact 2-letter codes */
	private static final String[] OPCODE_GROUPS = new String[73];
	static {
		Arrays.fill(OPCODE_GROUPS, "OT"); // default: other
		OPCODE_GROUPS[PcodeOp.COPY]           = "CP";
		OPCODE_GROUPS[PcodeOp.LOAD]           = "LD";
		OPCODE_GROUPS[PcodeOp.STORE]          = "ST";
		OPCODE_GROUPS[PcodeOp.BRANCH]         = "BR";
		OPCODE_GROUPS[PcodeOp.CBRANCH]        = "CB";
		OPCODE_GROUPS[PcodeOp.BRANCHIND]      = "BI";
		OPCODE_GROUPS[PcodeOp.CALL]           = "CL";
		OPCODE_GROUPS[PcodeOp.CALLIND]        = "CI";
		OPCODE_GROUPS[PcodeOp.CALLOTHER]      = "CO";
		OPCODE_GROUPS[PcodeOp.RETURN]         = "RT";
		OPCODE_GROUPS[PcodeOp.INT_EQUAL]      = "EQ";
		OPCODE_GROUPS[PcodeOp.INT_NOTEQUAL]   = "NE";
		OPCODE_GROUPS[PcodeOp.INT_SLESS]      = "LT";
		OPCODE_GROUPS[PcodeOp.INT_SLESSEQUAL] = "LT";
		OPCODE_GROUPS[PcodeOp.INT_LESS]       = "LT";
		OPCODE_GROUPS[PcodeOp.INT_LESSEQUAL]  = "LT";
		OPCODE_GROUPS[PcodeOp.INT_ZEXT]       = "ZX";
		OPCODE_GROUPS[PcodeOp.INT_SEXT]       = "SX";
		OPCODE_GROUPS[PcodeOp.INT_ADD]        = "AD";
		OPCODE_GROUPS[PcodeOp.INT_SUB]        = "SU";
		OPCODE_GROUPS[PcodeOp.INT_CARRY]      = "FL";
		OPCODE_GROUPS[PcodeOp.INT_SCARRY]     = "FL";
		OPCODE_GROUPS[PcodeOp.INT_SBORROW]    = "FL";
		OPCODE_GROUPS[PcodeOp.INT_2COMP]      = "NG";
		OPCODE_GROUPS[PcodeOp.INT_NEGATE]     = "NG";
		OPCODE_GROUPS[PcodeOp.INT_XOR]        = "XR";
		OPCODE_GROUPS[PcodeOp.INT_AND]        = "AN";
		OPCODE_GROUPS[PcodeOp.INT_OR]         = "OR";
		OPCODE_GROUPS[PcodeOp.INT_LEFT]       = "SL";
		OPCODE_GROUPS[PcodeOp.INT_RIGHT]      = "SR";
		OPCODE_GROUPS[PcodeOp.INT_SRIGHT]     = "SR";
		OPCODE_GROUPS[PcodeOp.INT_MULT]       = "ML";
		OPCODE_GROUPS[PcodeOp.INT_DIV]        = "DV";
		OPCODE_GROUPS[PcodeOp.INT_SDIV]       = "DV";
		OPCODE_GROUPS[PcodeOp.INT_REM]        = "RM";
		OPCODE_GROUPS[PcodeOp.INT_SREM]       = "RM";
		OPCODE_GROUPS[PcodeOp.BOOL_NEGATE]    = "BN";
		OPCODE_GROUPS[PcodeOp.BOOL_XOR]       = "BX";
		OPCODE_GROUPS[PcodeOp.BOOL_AND]       = "BA";
		OPCODE_GROUPS[PcodeOp.BOOL_OR]        = "BO";
		OPCODE_GROUPS[PcodeOp.FLOAT_EQUAL]    = "FC";
		OPCODE_GROUPS[PcodeOp.FLOAT_NOTEQUAL] = "FC";
		OPCODE_GROUPS[PcodeOp.FLOAT_LESS]     = "FC";
		OPCODE_GROUPS[PcodeOp.FLOAT_LESSEQUAL]= "FC";
		OPCODE_GROUPS[PcodeOp.FLOAT_ADD]      = "FA";
		OPCODE_GROUPS[PcodeOp.FLOAT_SUB]      = "FS";
		OPCODE_GROUPS[PcodeOp.FLOAT_MULT]     = "FM";
		OPCODE_GROUPS[PcodeOp.FLOAT_DIV]      = "FD";
		OPCODE_GROUPS[PcodeOp.FLOAT_NEG]      = "FN";
		OPCODE_GROUPS[PcodeOp.FLOAT_ABS]      = "FB";
		OPCODE_GROUPS[PcodeOp.FLOAT_SQRT]     = "FQ";
		OPCODE_GROUPS[PcodeOp.FLOAT_INT2FLOAT]= "FI";
		OPCODE_GROUPS[PcodeOp.FLOAT_FLOAT2FLOAT]="FF";
		OPCODE_GROUPS[PcodeOp.FLOAT_TRUNC]    = "FT";
		OPCODE_GROUPS[PcodeOp.PIECE]          = "PP";
		OPCODE_GROUPS[PcodeOp.SUBPIECE]       = "SP";
	}

	/**
	 * Classify a constant value into a single-character class for token encoding.
	 *
	 * Classes:
	 *   z = zero
	 *   1 = literal 1
	 *   s = small (2-15)
	 *   b = byte-range (16-255)
	 *   m = mask (power of 2 minus 1: 0x1, 0x3, 0x7, 0xF, 0x1F, 0xFF, ...)
	 *   p = power of 2 (2, 4, 8, 16, ...)
	 *   w = word-range (256-65535)
	 *   a = ASCII printable (0x20-0x7E)
	 *   l = large (>65535)
	 */
	static char classifyConstant(long val) {
		if (val == 0) return 'z';
		if (val == 1) return '1';
		// Check mask before small/byte — 0xF is both small and mask
		if (val > 0 && ((val + 1) & val) == 0) return 'm'; // power of 2 minus 1
		if (val > 0 && (val & (val - 1)) == 0) return 'p'; // power of 2
		if (val >= 2 && val <= 15) return 's';
		if (val >= 16 && val <= 255) return 'b';
		if (val >= 0x20 && val <= 0x7E) return 'a'; // ASCII (overlaps with byte)
		if (val >= 256 && val <= 65535) return 'w';
		return 'l';
	}

	/**
	 * Normalize a P-code op to an architecture-independent token string.
	 *
	 * Format: OPGROUP + output_size + [constant_class]
	 * Examples: "AD4" (4-byte add), "AN4m" (AND with mask), "LD1" (byte load),
	 *           "SL4s" (shift left by small constant), "CB" (conditional branch)
	 */
	public static String normalizeOp(PcodeOp op) {
		int opcode = op.getOpcode();
		String group = (opcode >= 0 && opcode < OPCODE_GROUPS.length)
			? OPCODE_GROUPS[opcode] : "OT";

		// Skip flag-computation ops (ISA artifacts, not structural)
		if (group.equals("FL")) return null;

		// Skip condition-code noise: 1-byte comparisons with zero and
		// 1-byte copies of zero are SLEIGH artifacts for flag computation
		// (e.g., LT1z, EQ1z, CP1z patterns on 68000). These dominate
		// real P-code sequences and obscure structural patterns.
		Varnode out = op.getOutput();
		if (out != null && out.getSize() == 1) {
			if (opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_SLESS ||
				opcode == PcodeOp.INT_LESSEQUAL || opcode == PcodeOp.INT_SLESSEQUAL ||
				opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL) {
				// Check if comparing with zero constant
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					if (in != null && in.isConstant() && in.getOffset() == 0) {
						return null; // Skip flag-like comparison
					}
				}
			}
			if (opcode == PcodeOp.COPY) {
				Varnode in0 = op.getInput(0);
				if (in0 != null && in0.isConstant() && in0.getOffset() == 0) {
					return null; // Skip zero-constant copy (flag init)
				}
				// Also skip 1-byte copy of 1-byte value from comparison result
				if (in0 != null && in0.getSize() == 1 && !in0.isConstant() && !in0.isAddress()) {
					return null; // Skip flag register copy
				}
			}
			// Skip BOOL_NEGATE, BOOL_AND, BOOL_OR on 1-byte (flag manipulation)
			if (opcode == PcodeOp.BOOL_NEGATE || opcode == PcodeOp.BOOL_AND ||
				opcode == PcodeOp.BOOL_OR || opcode == PcodeOp.BOOL_XOR) {
				return null;
			}
		}

		// Output size (0 for control flow ops)
		int outSize = (out != null) ? out.getSize() : 0;

		// Find constant inputs and classify
		char constClass = 0;
		for (int i = 0; i < op.getNumInputs(); i++) {
			Varnode input = op.getInput(i);
			if (input != null && input.isConstant()) {
				long val = input.getOffset();
				// For branch/call ops, the constant is a target address, skip
				if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH ||
					opcode == PcodeOp.CALL || opcode == PcodeOp.BRANCHIND ||
					opcode == PcodeOp.CALLIND || opcode == PcodeOp.RETURN) {
					continue;
				}
				// For LOAD/STORE, input 0 is space ID — skip it, only consider addr
				if ((opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) && i == 0) {
					continue;
				}
				constClass = classifyConstant(val);
				break; // Use first non-target constant
			}
		}

		StringBuilder sb = new StringBuilder(5);
		sb.append(group);
		if (outSize > 0) sb.append(outSize);
		if (constClass != 0) sb.append(constClass);
		return sb.toString();
	}

	/**
	 * Normalize a complete P-code sequence to tokens, filtering nulls.
	 */
	public static String[] normalizeSequence(PcodeOp[] pcode) {
		List<String> tokens = new ArrayList<>(pcode.length);
		for (PcodeOp op : pcode) {
			String token = normalizeOp(op);
			if (token != null) tokens.add(token);
		}
		return tokens.toArray(new String[0]);
	}

	// ================================================================
	// N-gram extraction and vectorization
	// ================================================================

	/**
	 * Extract bigram and trigram counts from a token sequence.
	 * Returns a sparse map of n-gram string → raw count.
	 */
	public static Map<String, Integer> extractNgrams(String[] tokens) {
		Map<String, Integer> ngrams = new HashMap<>();
		if (tokens.length < 2) return ngrams;

		// Bigrams
		for (int i = 0; i < tokens.length - 1; i++) {
			String bigram = tokens[i] + ":" + tokens[i + 1];
			ngrams.merge(bigram, 1, Integer::sum);
		}

		// Trigrams
		if (tokens.length >= 3) {
			for (int i = 0; i < tokens.length - 2; i++) {
				String trigram = tokens[i] + ":" + tokens[i + 1] + ":" + tokens[i + 2];
				ngrams.merge(trigram, 1, Integer::sum);
			}
		}

		return ngrams;
	}

	/**
	 * Convert raw n-gram counts to a TF-normalized vector.
	 * TF = count / total_ngrams (within function).
	 * IDF is applied during comparison using the database's IDF table.
	 */
	public static Map<String, Double> computeTfVector(Map<String, Integer> ngrams) {
		int total = 0;
		for (int c : ngrams.values()) total += c;
		if (total == 0) return Collections.emptyMap();

		Map<String, Double> tf = new HashMap<>();
		double totalD = total;
		for (Map.Entry<String, Integer> e : ngrams.entrySet()) {
			tf.put(e.getKey(), e.getValue() / totalD);
		}
		return tf;
	}

	/**
	 * Compute cosine similarity between two sparse TF-IDF vectors,
	 * applying IDF weights during comparison.
	 */
	static double cosineSimilarity(Map<String, Double> a, Map<String, Double> b,
			Map<String, Double> idf) {
		if (a.isEmpty() || b.isEmpty()) return 0;

		// Use the smaller map for iteration
		Map<String, Double> smaller = a.size() <= b.size() ? a : b;
		Map<String, Double> larger = a.size() <= b.size() ? b : a;

		double dot = 0;
		double normA = 0;
		double normB = 0;

		// Dot product: only iterate over shared keys
		for (Map.Entry<String, Double> e : smaller.entrySet()) {
			Double otherVal = larger.get(e.getKey());
			if (otherVal != null) {
				double w = idf != null ? idf.getOrDefault(e.getKey(), 1.0) : 1.0;
				dot += e.getValue() * w * otherVal * w;
			}
		}

		// Norms (must compute over all keys, weighted by IDF)
		for (Map.Entry<String, Double> e : a.entrySet()) {
			double w = idf != null ? idf.getOrDefault(e.getKey(), 1.0) : 1.0;
			double val = e.getValue() * w;
			normA += val * val;
		}
		for (Map.Entry<String, Double> e : b.entrySet()) {
			double w = idf != null ? idf.getOrDefault(e.getKey(), 1.0) : 1.0;
			double val = e.getValue() * w;
			normB += val * val;
		}

		if (normA < 1e-10 || normB < 1e-10) return 0;
		return dot / (Math.sqrt(normA) * Math.sqrt(normB));
	}

	/** Cosine similarity without IDF weighting */
	static double cosineSimilarity(Map<String, Double> a, Map<String, Double> b) {
		return cosineSimilarity(a, b, null);
	}

	// ================================================================
	// Structural features (supplement to n-gram vector)
	// ================================================================

	/** Lightweight structural summary for secondary matching */
	public static class StructuralFeatures {
		public int totalOps;
		public int loopCount;
		public int maxNestDepth;
		public int callCount;
		public boolean isLeaf;         // no CALL/CALLIND ops
		public boolean hasIndirectCall;
		public boolean hasTrap;        // CALLOTHER (syscall/trap)
		public boolean hasFloatOps;
		public int returnCount;
		public int branchIndCount;     // indirect branch (jump table)

		/**
		 * Structural similarity: 0-1 score based on how similar
		 * two functions' structural profiles are.
		 */
		double similarity(StructuralFeatures other) {
			double score = 0;
			int checks = 0;

			// Size similarity (log scale — 10 ops vs 20 is closer than 10 vs 100)
			double sizeRatio = Math.min(totalOps, other.totalOps) /
				(double) Math.max(totalOps, other.totalOps);
			score += sizeRatio;
			checks++;

			// Loop presence and count
			if (loopCount == 0 && other.loopCount == 0) { score += 1.0; }
			else if (loopCount > 0 && other.loopCount > 0) {
				score += 1.0 - Math.min(1.0, Math.abs(loopCount - other.loopCount) / 3.0);
			}
			checks++;

			// Leaf similarity
			if (isLeaf == other.isLeaf) score += 1.0;
			checks++;

			// Call count similarity
			if (callCount == 0 && other.callCount == 0) { score += 1.0; }
			else if (callCount > 0 && other.callCount > 0) {
				double callRatio = Math.min(callCount, other.callCount) /
					(double) Math.max(callCount, other.callCount);
				score += callRatio;
			}
			checks++;

			// Trap/syscall
			if (hasTrap == other.hasTrap) score += 1.0;
			checks++;

			// Float ops
			if (hasFloatOps == other.hasFloatOps) score += 1.0;
			checks++;

			// Jump table
			if ((branchIndCount > 0) == (other.branchIndCount > 0)) score += 1.0;
			checks++;

			return score / checks;
		}
	}

	/** Extract structural features from P-code */
	public static StructuralFeatures extractStructural(PcodeOp[] pcode) {
		StructuralFeatures f = new StructuralFeatures();
		f.totalOps = pcode.length;

		Set<Long> branchBackTargets = new HashSet<>();
		Map<Long, Integer> addrToIndex = new HashMap<>();
		int idx = 0;

		for (PcodeOp op : pcode) {
			// Map sequence addresses for loop detection
			if (op.getSeqnum() != null) {
				addrToIndex.put(op.getSeqnum().getTarget().getOffset(), idx);
			}
			idx++;

			switch (op.getOpcode()) {
				case PcodeOp.CALL:
					f.callCount++;
					break;
				case PcodeOp.CALLIND:
					f.callCount++;
					f.hasIndirectCall = true;
					break;
				case PcodeOp.CALLOTHER:
					f.hasTrap = true;
					break;
				case PcodeOp.RETURN:
					f.returnCount++;
					break;
				case PcodeOp.BRANCHIND:
					f.branchIndCount++;
					break;
				case PcodeOp.FLOAT_ADD: case PcodeOp.FLOAT_SUB:
				case PcodeOp.FLOAT_MULT: case PcodeOp.FLOAT_DIV:
				case PcodeOp.FLOAT_SQRT:
					f.hasFloatOps = true;
					break;
			}

			// Loop detection: CBRANCH with backward target
			if (op.getOpcode() == PcodeOp.CBRANCH) {
				Varnode target = op.getInput(0);
				if (target != null && target.isAddress()) {
					long targetAddr = target.getOffset();
					if (op.getSeqnum() != null &&
						targetAddr <= op.getSeqnum().getTarget().getOffset()) {
						f.loopCount++;
					}
				}
			}
		}

		f.isLeaf = (f.callCount == 0);

		// Rough nesting detection: count how many loops contain other loops
		// (simplified — proper nesting needs CFG analysis)
		f.maxNestDepth = f.loopCount > 1 ? 2 : (f.loopCount > 0 ? 1 : 0);

		return f;
	}

	// ================================================================
	// Reference signature database
	// ================================================================

	/** A reference signature from a known function */
	static class PcodeSignature {
		String category;        // e.g., "memcpy", "checksum"
		String label;           // e.g., "software_multiply_32x32"
		String description;
		String sourceCpu;       // CPU it was extracted from (e.g., "m68000")
		String sourceMachine;   // MAME machine name (e.g., "genesis")
		Map<String, Double> tfVector;   // TF-normalized n-gram vector
		StructuralFeatures structural;

		PcodeSignature(String category, String label, String description,
				String sourceCpu, String sourceMachine,
				Map<String, Double> tfVector, StructuralFeatures structural) {
			this.category = category;
			this.label = label;
			this.description = description;
			this.sourceCpu = sourceCpu;
			this.sourceMachine = sourceMachine;
			this.tfVector = tfVector;
			this.structural = structural;
		}
	}

	/** Match result from database lookup */
	public static class VectorMatch {
		public final String category;
		public final String label;
		public final String description;
		public final double similarity;      // combined score
		public final double ngramSimilarity; // n-gram cosine similarity
		public final double structSimilarity; // structural similarity
		public final String sourceCpu;
		public final String sourceMachine;

		VectorMatch(String category, String label, String description,
				double similarity, double ngramSimilarity, double structSimilarity,
				String sourceCpu, String sourceMachine) {
			this.category = category;
			this.label = label;
			this.description = description;
			this.similarity = similarity;
			this.ngramSimilarity = ngramSimilarity;
			this.structSimilarity = structSimilarity;
			this.sourceCpu = sourceCpu;
			this.sourceMachine = sourceMachine;
		}

		@Override
		public String toString() {
			return String.format("%s (%.0f%% ngram, %.0f%% struct, %.0f%% combined) from %s/%s",
				label, ngramSimilarity * 100, structSimilarity * 100,
				similarity * 100, sourceCpu, sourceMachine);
		}
	}

	// ================================================================
	// Database instance
	// ================================================================

	private List<PcodeSignature> signatures = new ArrayList<>();
	private Map<String, Double> idfWeights = new HashMap<>();
	private boolean loaded = false;

	// Matching parameters
	private double ngramWeight = 0.85;      // weight of n-gram similarity in combined score
	private double structWeight = 0.15;     // weight of structural similarity
	private double minNgramSimilarity = 0.65;  // minimum n-gram sim to consider
	private double minCombinedSimilarity = 0.80; // minimum combined score to report

	public PcodeVectorDatabase() {
		// Lazy load
	}

	/**
	 * Load signatures from the extension's data directory.
	 * Falls back to built-in bootstrap signatures if file not found.
	 */
	public synchronized void ensureLoaded() {
		if (loaded) return;

		// Try loading from file
		boolean fileLoaded = loadFromFile();

		if (!fileLoaded) {
			// Use built-in bootstrap signatures
			loadBootstrapSignatures();
		}

		// Compute IDF weights from loaded signatures
		computeIdfWeights();

		Msg.info(this, String.format("P-code vector database: %d signatures, %d IDF terms",
			signatures.size(), idfWeights.size()));
		loaded = true;
	}

	/**
	 * Try to load signatures from data/pcode_signatures.json.gz
	 */
	private boolean loadFromFile() {
		String[] searchPaths = {
			"data/pcode_signatures.json.gz",
			"../data/pcode_signatures.json.gz",
		};

		InputStream is = null;
		for (String path : searchPaths) {
			is = getClass().getClassLoader().getResourceAsStream(path);
			if (is != null) break;
		}

		if (is == null) {
			try {
				String classDir = getClass().getProtectionDomain()
					.getCodeSource().getLocation().getPath();
				File parent = new File(classDir);
				while (parent != null && !new File(parent, "data/pcode_signatures.json.gz").exists()) {
					parent = parent.getParentFile();
				}
				if (parent != null) {
					File f = new File(parent, "data/pcode_signatures.json.gz");
					if (f.exists()) is = new FileInputStream(f);
				}
			} catch (Exception e) {
				// ignore
			}
		}

		if (is == null) return false;

		try {
			GZIPInputStream gis = new GZIPInputStream(is);
			byte[] data = gis.readAllBytes();
			gis.close();

			JsonObject db = JsonParser.parseString(new String(data, "UTF-8")).getAsJsonObject();
			JsonArray sigArray = db.getAsJsonArray("signatures");

			for (JsonElement el : sigArray) {
				JsonObject obj = el.getAsJsonObject();
				String category = obj.get("category").getAsString();
				String label = obj.get("label").getAsString();
				String desc = obj.has("description") ? obj.get("description").getAsString() : "";
				String cpu = obj.has("cpu") ? obj.get("cpu").getAsString() : "";
				String machine = obj.has("machine") ? obj.get("machine").getAsString() : "";

				// Parse TF vector
				Map<String, Double> tf = new HashMap<>();
				JsonObject tfObj = obj.getAsJsonObject("tf_vector");
				for (Map.Entry<String, JsonElement> e : tfObj.entrySet()) {
					tf.put(e.getKey(), e.getValue().getAsDouble());
				}

				// Parse structural features
				StructuralFeatures sf = new StructuralFeatures();
				if (obj.has("structural")) {
					JsonObject st = obj.getAsJsonObject("structural");
					sf.totalOps = st.has("total_ops") ? st.get("total_ops").getAsInt() : 0;
					sf.loopCount = st.has("loop_count") ? st.get("loop_count").getAsInt() : 0;
					sf.callCount = st.has("call_count") ? st.get("call_count").getAsInt() : 0;
					sf.isLeaf = st.has("is_leaf") && st.get("is_leaf").getAsBoolean();
					sf.hasTrap = st.has("has_trap") && st.get("has_trap").getAsBoolean();
					sf.hasFloatOps = st.has("has_float") && st.get("has_float").getAsBoolean();
					sf.branchIndCount = st.has("branch_ind") ? st.get("branch_ind").getAsInt() : 0;
				}

				signatures.add(new PcodeSignature(category, label, desc, cpu, machine, tf, sf));
			}

			Msg.info(this, "Loaded " + signatures.size() + " P-code signatures from file");
			return true;

		} catch (Exception e) {
			Msg.error(this, "Failed to load P-code signature database: " + e.getMessage());
			return false;
		}
	}

	/**
	 * Compute IDF weights from the loaded signature set.
	 * IDF = log(N / df) where N = total signatures, df = signatures containing this n-gram.
	 */
	private void computeIdfWeights() {
		if (signatures.isEmpty()) return;

		Map<String, Integer> docFreq = new HashMap<>();
		for (PcodeSignature sig : signatures) {
			for (String ngram : sig.tfVector.keySet()) {
				docFreq.merge(ngram, 1, Integer::sum);
			}
		}

		double N = signatures.size();
		for (Map.Entry<String, Integer> e : docFreq.entrySet()) {
			idfWeights.put(e.getKey(), Math.log(N / e.getValue()));
		}
	}

	// ================================================================
	// Main classification interface
	// ================================================================

	/**
	 * Classify a function by its P-code against the reference database.
	 *
	 * @param pcode    P-code ops from the function
	 * @param domain   ROM domain for filtering (null = GENERIC)
	 * @return         List of matches sorted by similarity (highest first),
	 *                 or empty if no good matches found
	 */
	public List<VectorMatch> classify(PcodeOp[] pcode, RomDomain domain) {
		ensureLoaded();
		if (signatures.isEmpty() || pcode.length < 20) {
			return Collections.emptyList();
		}

		// Normalize and vectorize the input function
		String[] tokens = normalizeSequence(pcode);
		if (tokens.length < 10) return Collections.emptyList();

		Map<String, Integer> ngrams = extractNgrams(tokens);
		Map<String, Double> tfVector = computeTfVector(ngrams);
		StructuralFeatures structural = extractStructural(pcode);

		// Get allowed categories for this domain
		Set<String> allowedCategories = null;
		if (domain != null && domain != RomDomain.GENERIC) {
			allowedCategories = DOMAIN_CATEGORIES.get(domain);
		}

		// Compare against all signatures
		List<VectorMatch> results = new ArrayList<>();
		Set<String> seenCategories = new HashSet<>(); // best match per category

		for (PcodeSignature sig : signatures) {
			// Domain filtering: skip categories not plausible for this ROM type
			if (allowedCategories != null && !allowedCategories.contains(sig.category)) {
				continue;
			}

			// N-gram cosine similarity (with IDF weighting)
			double ngramSim = cosineSimilarity(tfVector, sig.tfVector, idfWeights);
			if (ngramSim < minNgramSimilarity) continue;

			// Structural similarity
			double structSim = structural.similarity(sig.structural);

			// Combined score
			double combined = ngramWeight * ngramSim + structWeight * structSim;
			if (combined < minCombinedSimilarity) continue;

			// Keep best match per category
			if (!seenCategories.contains(sig.category) ||
				results.stream().filter(r -> r.category.equals(sig.category))
					.mapToDouble(r -> r.similarity).max().orElse(0) < combined) {

				// Remove previous match for this category if exists
				results.removeIf(r -> r.category.equals(sig.category));
				seenCategories.add(sig.category);

				results.add(new VectorMatch(
					sig.category, sig.label, sig.description,
					combined, ngramSim, structSim,
					sig.sourceCpu, sig.sourceMachine));
			}
		}

		results.sort((a, b) -> Double.compare(b.similarity, a.similarity));
		return results;
	}

	/**
	 * Determine ROM domain from ROM identification results.
	 */
	public static RomDomain classifyDomain(List<RomIdentifier.RomMatch> romMatches) {
		if (romMatches == null || romMatches.isEmpty()) return RomDomain.GENERIC;

		RomIdentifier.RomMatch best = romMatches.get(0);
		String machine = best.machine.toLowerCase();
		String region = best.region.toLowerCase();
		String mfr = best.manufacturer != null ? best.manufacturer.toLowerCase() : "";
		String cpu = best.cpu != null ? best.cpu.toLowerCase() : "";

		// Audio-specific regions
		if (region.contains("audio") || region.contains("sound") ||
			region.contains("ym") || region.contains("spc")) {
			return RomDomain.AUDIO_DEVICE;
		}

		// AT&T/WE32100 = minicomputer boot
		if (cpu.contains("we32100") || machine.contains("3b2") || machine.contains("3b5") ||
			machine.contains("3b15") || machine.contains("7300")) {
			return RomDomain.COMPUTER_BOOT;
		}

		// Manufacturer-based
		if (mfr.contains("sega") || mfr.contains("nintendo") || mfr.contains("snk") ||
			mfr.contains("konami") || mfr.contains("capcom") || mfr.contains("namco") ||
			mfr.contains("taito") || mfr.contains("atari") || mfr.contains("midway") ||
			mfr.contains("irem") || mfr.contains("toaplan") || mfr.contains("cave") ||
			mfr.contains("hudson") || mfr.contains("nec") || mfr.contains("bandai")) {
			// Could be console or arcade
			if (machine.contains("genesis") || machine.contains("megadriv") ||
				machine.contains("nes") || machine.contains("famicom") ||
				machine.contains("snes") || machine.contains("sufami") ||
				machine.contains("gba") || machine.contains("gb") ||
				machine.contains("saturn") || machine.contains("dreamcast") ||
				machine.contains("pce") || machine.contains("ngp")) {
				return RomDomain.GAME_CONSOLE;
			}
			return RomDomain.ARCADE;
		}

		// Console-specific machine names
		if (machine.contains("genesis") || machine.contains("megadriv") ||
			machine.contains("nes") || machine.contains("famicom") ||
			machine.contains("snes") || machine.contains("sufami") ||
			machine.contains("gba") || machine.contains("nds") ||
			machine.contains("saturn") || machine.contains("dreamcast") ||
			machine.contains("psx") || machine.contains("ps2") ||
			machine.contains("msx") || machine.contains("coleco") ||
			machine.contains("spectr") || machine.contains("c64") ||
			machine.contains("amiga") || machine.contains("atari2600") ||
			machine.contains("atari5200") || machine.contains("atari7800") ||
			machine.contains("jaguar") || machine.contains("lynx") ||
			machine.contains("neogeo") || machine.contains("pce") ||
			machine.contains("vectrex") || machine.contains("intv")) {
			return RomDomain.GAME_CONSOLE;
		}

		// Apollo workstations (DN/DSP series)
		if (machine.startsWith("dn") || machine.startsWith("dsp") ||
			mfr.contains("apollo")) {
			return RomDomain.COMPUTER_BOOT;
		}

		// Computer boot ROMs
		if (machine.contains("mac") || machine.contains("lisa") ||
			machine.contains("sun") ||
			machine.contains("hp9000") || machine.contains("mvme") ||
			machine.contains("vme") || machine.contains("sbc") ||
			machine.contains("ibmpc") || machine.contains("pc_") ||
			region.contains("bootstrap") || region.contains("bios") ||
			region.contains("monitor") || region.contains("firmware")) {
			return RomDomain.COMPUTER_BOOT;
		}

		// Typesetter/printing
		if (mfr.contains("agfa") || mfr.contains("compugraphic") ||
			mfr.contains("linotype") || mfr.contains("xerox") ||
			machine.contains("rip") || machine.contains("postscript")) {
			return RomDomain.TYPESETTER;
		}

		// Network
		if (machine.contains("router") || machine.contains("switch") ||
			machine.contains("bridge") || machine.contains("modem") ||
			machine.contains("ethernet") || machine.contains("lanc")) {
			return RomDomain.NETWORK_DEVICE;
		}

		// Industrial
		if (mfr.contains("gilbarco") || mfr.contains("veeder") ||
			machine.contains("pump") || machine.contains("plc") ||
			machine.contains("fire") || machine.contains("alarm") ||
			machine.contains("scale") || machine.contains("meter")) {
			return RomDomain.INDUSTRIAL;
		}

		// CPU-based fallback
		if (cpu.contains("z80") || cpu.contains("6502") || cpu.contains("65c816")) {
			// These CPUs are mostly used in games/consoles
			return RomDomain.GAME_CONSOLE;
		}
		if (cpu.contains("68000") || cpu.contains("68k") || cpu.contains("m68")) {
			// 68000 is used everywhere — can't determine domain from CPU alone
			return RomDomain.GENERIC;
		}

		return RomDomain.GENERIC;
	}

	/**
	 * Determine ROM domain from CPU name and platform description.
	 * Used when ROM identification doesn't match.
	 */
	public static RomDomain classifyDomainFromPlatform(String cpuName,
			PlatformDescription platform) {
		if (cpuName == null) return RomDomain.GENERIC;
		String cpu = cpuName.toLowerCase();

		if (cpu.contains("we32100")) return RomDomain.COMPUTER_BOOT;
		if (cpu.contains("6502") && !cpu.contains("65c816")) return RomDomain.GAME_CONSOLE;
		if (cpu.contains("65c816") || cpu.contains("65816")) return RomDomain.GAME_CONSOLE;
		if (cpu.contains("z80")) return RomDomain.GAME_CONSOLE;
		if (cpu.contains("sh1") || cpu.contains("sh2")) return RomDomain.GAME_CONSOLE;

		// Check platform for hints
		if (platform != null) {
			String platName = platform.getPlatformName() != null ? platform.getPlatformName().toLowerCase() : "";
			if (platName.contains("genesis") || platName.contains("nes") ||
				platName.contains("snes") || platName.contains("gba") ||
				platName.contains("msx") || platName.contains("saturn")) {
				return RomDomain.GAME_CONSOLE;
			}
			if (platName.contains("mvme") || platName.contains("vme") ||
				platName.contains("3b2") || platName.contains("mac")) {
				return RomDomain.COMPUTER_BOOT;
			}
		}

		return RomDomain.GENERIC;
	}

	// ================================================================
	// Bootstrap signatures (used when no database file is available)
	// ================================================================

	/**
	 * Load hand-crafted reference signatures based on known function archetypes.
	 * These represent idealized P-code n-gram profiles derived from studying
	 * real functions across multiple architectures.
	 */
	private void loadBootstrapSignatures() {
		// Each signature is created from a representative token sequence
		// that captures the essential P-code structure of the function type.

		// --- Memory operations ---
		addBootstrapSig("memcpy", "memory_copy", "Byte-by-byte memory copy loop",
			"generic", "generic",
			new String[]{"LD1","ST1","AD4","AD4","SU4","LT","CB",
						 "LD1","ST1","AD4","AD4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("memcpy", "memory_copy_word", "Word-aligned memory copy loop",
			"generic", "generic",
			new String[]{"LD4","ST4","AD4","AD4","SU4","LT","CB",
						 "LD4","ST4","AD4","AD4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("memset", "memory_fill", "Memory fill loop",
			"generic", "generic",
			new String[]{"ST1","AD4","SU4","LT","CB",
						 "ST1","AD4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("memset", "memory_fill_word", "Word-aligned memory fill loop",
			"generic", "generic",
			new String[]{"ST4","AD4","SU4","LT","CB",
						 "ST4","AD4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("memcmp", "memory_compare", "Memory comparison loop",
			"generic", "generic",
			new String[]{"LD1","LD1","SU1","NE","CB","AD4","AD4","SU4","LT","CB",
						 "LD1","LD1","SU1","NE","CB","AD4","AD4","SU4","LT","CB"},
			true, 0, 2, false, false);

		addBootstrapSig("memmove", "memory_move", "Overlapping memory move with direction check",
			"generic", "generic",
			new String[]{"LT","CB","LD1","ST1","AD4","AD4","SU4","LT","CB","BR",
						 "AD4","AD4","LD1","ST1","SU4","SU4","SU4","LT","CB"},
			true, 0, 2, false, false);

		// --- String operations ---
		addBootstrapSig("strlen", "string_length", "String length by scanning for zero terminator",
			"generic", "generic",
			new String[]{"LD1","EQ","CB","AD4","AD4","BR",
						 "LD1","EQ","CB","AD4","AD4","BR"},
			true, 0, 1, false, false);

		addBootstrapSig("strcmp", "string_compare", "String comparison loop",
			"generic", "generic",
			new String[]{"LD1","LD1","NE","CB","LD1","EQ","CB","AD4","AD4","BR",
						 "LD1","LD1","NE","CB","LD1","EQ","CB","AD4","AD4","BR"},
			true, 0, 1, false, false);

		addBootstrapSig("strcpy", "string_copy", "String copy loop (until null terminator)",
			"generic", "generic",
			new String[]{"LD1","ST1","EQ","CB","AD4","AD4","BR",
						 "LD1","ST1","EQ","CB","AD4","AD4","BR"},
			true, 0, 1, false, false);

		// --- Arithmetic ---
		addBootstrapSig("multiply", "software_multiply", "Shift-and-add multiplication loop",
			"generic", "generic",
			new String[]{"AN4","CB","AD4","SL4","SR4","SU4","LT","CB",
						 "AN4","CB","AD4","SL4","SR4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("multiply", "software_multiply_32x32", "32-bit multiply via shift-add",
			"m68000", "genesis",
			new String[]{"AN4m","CB","AD4","SL4","SL4","SR4","SU4s","NE","CB",
						 "AN4m","CB","AD4","SL4","SL4","SR4","SU4s","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("divide", "software_divide", "Shift-and-subtract division loop",
			"generic", "generic",
			new String[]{"SL4","SL4","LT","CB","SU4","SL4","OR4","BR","SL4","SU4s","NE","CB",
						 "SL4","SL4","LT","CB","SU4","SL4","OR4","BR","SL4","SU4s","NE","CB"},
			true, 0, 1, false, false);

		// --- Checksum/hash ---
		addBootstrapSig("checksum", "checksum_accumulate", "Byte-by-byte accumulator checksum",
			"generic", "generic",
			new String[]{"LD1","ZX","AD4","AD4","SU4","LT","CB",
						 "LD1","ZX","AD4","AD4","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("checksum", "checksum_word", "Word-by-word accumulator checksum",
			"generic", "generic",
			new String[]{"LD2","ZX","AD4","AD4s","SU4","LT","CB",
						 "LD2","ZX","AD4","AD4s","SU4","LT","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("crc", "crc_polynomial", "CRC computation with polynomial XOR",
			"generic", "generic",
			new String[]{"LD1","XR4","AN4m","CB","XR4l","SR4s","SU4s","NE","CB",
						 "LD1","XR4","AN4m","CB","XR4l","SR4s","SU4s","NE","CB"},
			true, 0, 2, false, false);

		addBootstrapSig("crc", "crc_table_lookup", "Table-driven CRC with XOR",
			"generic", "generic",
			new String[]{"LD1","XR4","AN4m","SL4s","AD4","LD4","XR4","SR4s","AD4s","SU4","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("ip_checksum", "ip_checksum_ones_complement", "TCP/IP ones-complement checksum",
			"generic", "generic",
			new String[]{"LD2","ZX","AD4","AD4s","SU4","LT","CB","SR4","AN4w","AD4"},
			true, 0, 1, false, false);

		// --- Decompression ---
		addBootstrapSig("decompression", "decompress_rle", "RLE decompression: read count + byte, fill/copy",
			"generic", "generic",
			new String[]{"LD1","AN4m","LT","CB","LD1","ST1","AD4","SU4s","NE","CB","BR",
						 "LD1","ST1","AD4","AD4","SU4s","NE","CB"},
			true, 2, 2, false, false);

		addBootstrapSig("decompression", "decompress_lzss", "LZSS decompression with ring buffer",
			"generic", "generic",
			new String[]{"LD1","SR4s","AN4m","CB",
						 "LD1","LD1","OR4","AN4m","AD4","LD1","ST1","AD4","AN4m",
						 "SU4s","NE","CB","SL4s","SU4s","NE","CB"},
			true, 0, 3, false, false);

		addBootstrapSig("decompression", "decompress_huffman", "Huffman bitstream decoder with tree walk",
			"generic", "generic",
			new String[]{"LD1","SL4s","AN4m","CB","LD4","AD4","BR","LD4","AD4",
						 "AN4w","NE","CB"},
			true, 0, 2, false, false);

		// --- BCD ---
		addBootstrapSig("bcd", "bcd_to_binary", "BCD to binary conversion with nibble extraction",
			"generic", "generic",
			new String[]{"AN4m","SR4s","ML4","AN4m","AD4","SR4s","AN4m","ML4","AN4m","AD4"},
			false, 0, 0, false, false);

		addBootstrapSig("bcd", "bcd_add", "BCD addition with decimal adjust",
			"generic", "generic",
			new String[]{"AD4","AN4m","LT","CB","AD4b","AN4","SR4s","AN4m","LT","CB","AD4b"},
			false, 0, 0, false, false);

		// --- Control flow ---
		addBootstrapSig("jump_table", "jump_table_dispatch", "Indexed jump table dispatch",
			"generic", "generic",
			new String[]{"LT","CB","SL4s","AD4","LD4","BI"},
			false, 0, 0, false, false);

		addBootstrapSig("jump_table", "switch_dispatch", "Switch-case dispatch with bounds check",
			"generic", "generic",
			new String[]{"SU4s","LT","CB","SL4s","AD4","LD4","CL"},
			false, 0, 0, false, false);

		addBootstrapSig("interrupt_handler", "interrupt_handler", "Interrupt handler: save/restore + CALLOTHER (RTE)",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","ST4","CL","LD4","LD4","LD4","LD4","CO"},
			false, 1, 0, true, false);

		addBootstrapSig("boot_init", "hardware_init", "Hardware initialization: store sequence to IO addresses",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","ST4","ST4","ST4","ST4","ST4","CL","CL","CL"},
			false, 3, 0, false, false);

		// --- Sort ---
		addBootstrapSig("sort", "bubble_sort", "Bubble sort with swap",
			"generic", "generic",
			new String[]{"LD4","LD4","LT","CB","ST4","ST4","AD4s","SU4s","NE","CB",
						 "SU4s","NE","CB"},
			true, 0, 2, false, false);

		addBootstrapSig("sort", "quicksort", "Quicksort partition with recursive calls",
			"generic", "generic",
			new String[]{"LD4","LT","CB","AD4s","BR","LD4","LT","CB","SU4s","BR",
						 "LD4","ST4","LD4","ST4","CL","CL"},
			true, 2, 2, false, false);

		// --- Fixed-point math ---
		addBootstrapSig("fixed_point", "fixed_point_multiply", "16.16 fixed-point multiply",
			"generic", "generic",
			new String[]{"ML4","SR4","AN4w","ML4","SL4","OR4","ML4","SR4"},
			false, 0, 0, false, false);

		addBootstrapSig("sqrt", "sqrt_integer", "Integer square root via iterative method",
			"generic", "generic",
			new String[]{"SL4","AD4","SR4s","DV4","AD4","SR4s","SU4","LT","CB",
						 "SL4","AD4","SR4s","DV4","AD4","SR4s","SU4","LT","CB"},
			true, 0, 1, false, false);

		// --- Printf/sprintf ---
		addBootstrapSig("printf", "printf_format", "Printf-style format string parser",
			"generic", "generic",
			new String[]{"LD1","EQ","CB","EQ","CB","EQ","CB","EQ","CB","EQ","CB",
						 "CL","AD4","BR","CL","AD4","BR","CL","AD4","BR"},
			true, 4, 2, false, false);

		addBootstrapSig("sprintf", "sprintf_format", "Sprintf format into buffer",
			"generic", "generic",
			new String[]{"LD1","EQ","CB","EQ","CB","EQ","CB",
						 "CL","ST1","AD4","BR","CL","ST1","AD4","BR"},
			true, 3, 2, false, false);

		addBootstrapSig("number_to_string", "itoa_decimal", "Integer to decimal string conversion",
			"generic", "generic",
			new String[]{"DV4","RM4","AD4b","ST1","SU4","AD4","NE","CB",
						 "DV4","RM4","AD4b","ST1","SU4","AD4","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("hex_dump", "hex_dump", "Hex dump: byte to hex characters",
			"generic", "generic",
			new String[]{"LD1","SR4s","AN4m","AD4","LD1","ST1","AN4m","AD4","LD1","ST1",
						 "AD4","SU4","NE","CB"},
			true, 0, 1, false, false);

		// --- Serial/UART ---
		addBootstrapSig("serial_io", "serial_putchar", "Serial port character output with ready-wait",
			"generic", "generic",
			new String[]{"LD1","AN4m","EQ","CB","BR","ST1"},
			true, 0, 1, false, false);

		addBootstrapSig("serial_io", "serial_getchar", "Serial port character input with ready-wait",
			"generic", "generic",
			new String[]{"LD1","AN4m","EQ","CB","BR","LD1","AN4m"},
			true, 0, 1, false, false);

		// --- Memory test ---
		addBootstrapSig("memory_test", "memory_test_pattern", "Memory test: write pattern, read back, compare",
			"generic", "generic",
			new String[]{"ST4","AD4s","LT","CB",
						 "LD4","NE","CB","AD4s","LT","CB"},
			true, 0, 2, false, false);

		addBootstrapSig("self_test", "post_diagnostic", "POST diagnostic with pass/fail reporting",
			"generic", "generic",
			new String[]{"CL","EQ","CB","CL","BR","CL","CL","EQ","CB","CL","BR","CL"},
			false, 6, 0, false, false);

		// --- Busy wait / delay ---
		addBootstrapSig("busy_wait", "busy_wait_register", "Busy-wait loop polling hardware register",
			"generic", "generic",
			new String[]{"LD4","AN4m","EQ","CB","LD4","AN4m","EQ","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("delay_loop", "delay_countdown", "Software delay countdown loop",
			"generic", "generic",
			new String[]{"SU4s","NE","CB","SU4s","NE","CB"},
			true, 0, 1, false, false);

		// --- DMA ---
		addBootstrapSig("dma_transfer", "dma_setup_transfer", "DMA controller setup: source, dest, count, control",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","ST4","LD4","AN4m","EQ","CB"},
			false, 0, 1, false, false);

		// --- Sound ---
		addBootstrapSig("sound_driver", "psg_write", "PSG/FM sound register write sequence",
			"generic", "generic",
			new String[]{"ST1","ST1","ST1","ST1","LD1","AN4m","NE","CB",
						 "ST1","ST1","ST1","ST1"},
			true, 0, 1, false, false);

		addBootstrapSig("adpcm", "adpcm_decode_step", "ADPCM decode: delta, clamp, step table lookup",
			"generic", "generic",
			new String[]{"LD1","AN4m","SR4s","AN4m","SL4s","AD4","AN4m","CB","AD4",
						 "LD2","SL4s","SR4s","AD4","LD2","ST2"},
			true, 0, 1, false, false);

		// --- Sprite/tile ---
		addBootstrapSig("sprite_render", "sprite_draw", "Sprite draw: read tile, map pixel, write to VRAM",
			"m68000", "genesis",
			new String[]{"LD4","AN4m","SL4s","AD4","LD1","AN4m","SL4s","OR4",
						 "ST1","AD4","SU4s","NE","CB","AD4","SU4s","NE","CB"},
			true, 0, 2, false, false);

		addBootstrapSig("tile_decode", "tile_decode_planar", "Planar tile format decode",
			"m68000", "genesis",
			new String[]{"LD1","SL4s","OR4","LD1","SL4s","OR4","LD1","SL4s","OR4",
						 "LD1","OR4","ST4","AD4s","SU4s","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("scroll", "scroll_update", "Background scroll position update",
			"generic", "generic",
			new String[]{"LD4","AD4","AN4w","ST4","LD4","AD4","AN4w","ST4",
						 "LD4","SR4s","ST4","LD4","SR4s","ST4"},
			false, 0, 0, false, false);

		// --- Palette ---
		addBootstrapSig("palette_fade", "palette_fade_step", "Palette fade: interpolate each component",
			"generic", "generic",
			new String[]{"LD2","AN4m","SR4s","LD2","AN4m","SR4s","SU4","SR4s","AD4",
						 "AN4m","SL4s","OR4","ST2","AD4s","SU4s","NE","CB"},
			true, 0, 1, false, false);

		// --- Object system ---
		addBootstrapSig("object_update", "object_update_loop", "Object pool iteration with type dispatch",
			"generic", "generic",
			new String[]{"LD4","EQ","CB","LD4","SL4s","AD4","LD4","CI",
						 "AD4s","SU4s","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("state_machine", "state_dispatch", "State machine: load state, dispatch via table/switch",
			"generic", "generic",
			new String[]{"LD4","LT","CB","SL4s","AD4","LD4","CI","ST4"},
			false, 0, 0, false, false);

		// --- Heap/allocator ---
		addBootstrapSig("heap_alloc", "heap_malloc", "Heap allocator: traverse free list, split block",
			"generic", "generic",
			new String[]{"LD4","EQ","CB","LD4","LT","CB","LD4","LD4","SU4","LT","CB",
						 "AD4","ST4","ST4","LD4"},
			true, 2, 1, false, false);

		// --- Task scheduling ---
		addBootstrapSig("task_scheduler", "task_switch", "Task context switch: save/restore registers, update TCB",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","ST4","ST4","ST4","LD4","ST4",
						 "LD4","LD4","LD4","LD4","LD4","LD4","CO"},
			false, 0, 0, true, false);

		addBootstrapSig("semaphore", "semaphore_pend", "Semaphore P operation: test-and-decrement with block",
			"generic", "generic",
			new String[]{"LD4","LT","CB","SU4s","ST4","BR","CL","ST4"},
			false, 1, 0, false, false);

		// --- Encryption ---
		addBootstrapSig("encrypt_decrypt", "xor_cipher", "XOR cipher: key byte XOR each data byte",
			"generic", "generic",
			new String[]{"LD1","LD1","XR1","ST1","AD4","AD4","AN4m","SU4","NE","CB"},
			true, 0, 1, false, false);

		addBootstrapSig("aes", "aes_round", "AES round: SubBytes + ShiftRows + MixColumns + AddRoundKey",
			"generic", "generic",
			new String[]{"LD1","AN4m","LD4","XR4","SR4s","AN4m","LD4","XR4",
						 "SR4s","AN4m","LD4","XR4","SR4s","AN4m","LD4","XR4"},
			true, 0, 1, false, false);

		// --- Collision detection ---
		addBootstrapSig("collision", "aabb_collision", "AABB collision: compare x/y extents",
			"generic", "generic",
			new String[]{"LD4","LD4","SU4","LT","CB","LD4","LD4","SU4","LT","CB",
						 "LD4","LD4","SU4","LT","CB","LD4","LD4","SU4","LT","CB"},
			false, 0, 0, false, false);

		// --- Physics ---
		addBootstrapSig("velocity_physics", "velocity_integrate", "Velocity integration: pos += vel, vel += accel",
			"generic", "generic",
			new String[]{"LD4","LD4","AD4","ST4","LD4","LD4","AD4","ST4",
						 "LD4","LT","CB","NG4","ST4"},
			false, 0, 0, false, false);

		addBootstrapSig("gravity", "gravity_apply", "Apply gravity acceleration to Y velocity",
			"generic", "generic",
			new String[]{"LD4","AD4","ST4","LD4","AD4","ST4","LD4","LT","CB"},
			false, 0, 0, false, false);

		// --- RNG ---
		addBootstrapSig("rng", "prng_lcg", "Linear congruential PRNG: seed = seed * A + B",
			"generic", "generic",
			new String[]{"LD4","ML4l","AD4l","ST4","SR4s","AN4m"},
			false, 0, 0, false, false);

		addBootstrapSig("rng", "prng_lfsr", "LFSR-based PRNG: shift, XOR feedback",
			"generic", "generic",
			new String[]{"LD4","SL4s","XR4","AN4m","CB","XR4l","ST4"},
			false, 0, 0, false, false);

		// --- Floating point emulation ---
		addBootstrapSig("software_float", "float_add_soft", "Software floating-point addition",
			"generic", "generic",
			new String[]{"SR4s","AN4w","SU4","LT","CB","SL4","SR4","SU4","SR4s",
						 "AN4m","AD4","SR4s","AN4m","SL4","OR4"},
			true, 0, 1, false, true);

		addBootstrapSig("software_float", "float_mul_soft", "Software floating-point multiplication",
			"generic", "generic",
			new String[]{"AN4w","AD4","SU4w","ML4","SR4s","AN4m","SL4","OR4",
						 "AN4m","AD4","AN4l","SL4","OR4"},
			false, 0, 0, false, true);

		// --- Command parser ---
		addBootstrapSig("command_parser", "cli_parser", "Command-line parser: compare strings, dispatch",
			"generic", "generic",
			new String[]{"LD1","LD1","NE","CB","AD4","AD4","LD1","NE","CB",
						 "CL","EQ","CB","AD4","LD1","LD1","NE","CB","CL","EQ","CB"},
			true, 3, 2, false, false);

		// --- File/disk operations ---
		addBootstrapSig("fat_filesystem", "fat_cluster_chain", "FAT filesystem cluster chain traversal",
			"generic", "generic",
			new String[]{"SL4s","AD4","LD2","ZX","LT","CB","SL4","AD4",
						 "CL","AD4","SU4","NE","CB"},
			true, 1, 1, false, false);

		addBootstrapSig("disk_block_io", "disk_read_sector", "Disk sector read: send command, transfer data",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","LD4","AN4m","EQ","CB",
						 "LD4","ST4","AD4","SU4","NE","CB"},
			true, 0, 2, false, false);

		// --- Linked list ---
		addBootstrapSig("linked_list", "linked_list_traverse", "Linked list traversal: follow next pointer",
			"generic", "generic",
			new String[]{"LD4","EQ","CB","LD4","CL","LD4","BR",
						 "LD4","EQ","CB","LD4","CL","LD4","BR"},
			true, 1, 1, false, false);

		// --- Binary search ---
		addBootstrapSig("binary_search", "binary_search", "Binary search: midpoint, compare, narrow range",
			"generic", "generic",
			new String[]{"AD4","SR4s","SL4s","AD4","LD4","LT","CB","AD4s","BR",
						 "LT","CB","SU4s","LT","CB"},
			true, 0, 1, false, false);

		// --- Hash table ---
		addBootstrapSig("hash_table", "hash_lookup", "Hash table lookup: hash key, probe chain",
			"generic", "generic",
			new String[]{"LD1","ML4s","AD4","SU4s","NE","CB","AN4m","SL4s","AD4",
						 "LD4","EQ","CB","LD1","LD1","NE","CB"},
			true, 0, 2, false, false);

		// --- Controller input ---
		addBootstrapSig("controller_input", "joypad_read", "Joypad read: latch, shift bits in",
			"m68000", "genesis",
			new String[]{"ST1","LD1","AN4m","SL4s","OR4","ST1","LD1","AN4m","SL4s","OR4",
						 "SU4s","NE","CB","ST4"},
			true, 0, 1, false, false);

		// --- VBlank wait ---
		addBootstrapSig("vblank_wait", "vblank_poll", "VBlank wait: poll status register bit",
			"generic", "generic",
			new String[]{"LD1","AN4m","EQ","CB","LD1","AN4m","EQ","CB"},
			true, 0, 1, false, false);

		// --- Matrix multiply ---
		addBootstrapSig("matrix_multiply", "matrix_mul_3x3", "3x3 matrix multiply with dot products",
			"generic", "generic",
			new String[]{"LD4","ML4","LD4","ML4","AD4","LD4","ML4","AD4","ST4",
						 "LD4","ML4","LD4","ML4","AD4","LD4","ML4","AD4","ST4",
						 "AD4s","SU4s","NE","CB"},
			true, 0, 2, false, false);

		// --- Trig lookup ---
		addBootstrapSig("trig_lookup", "sin_table_lookup", "Sine table lookup with quadrant mapping",
			"generic", "generic",
			new String[]{"AN4m","LT","CB","SU4w","NG4","BR","AN4m","SL4s","AD4","LD2","SX"},
			false, 0, 0, false, false);

		// --- Line drawing ---
		addBootstrapSig("line_draw", "bresenham_line", "Bresenham line drawing algorithm",
			"generic", "generic",
			new String[]{"SU4","SU4","SL4s","SU4","LT","CB","AD4","SU4","BR","AD4",
						 "ST1","AD4","SU4s","NE","CB"},
			true, 0, 1, false, false);

		// --- Error handler ---
		addBootstrapSig("error_handler", "error_halt", "Error handler: print message, halt/reset",
			"generic", "generic",
			new String[]{"CL","CL","CL","BR","CL","CL","CL","BR"},
			false, 6, 0, false, false);

		// --- SCSI ---
		addBootstrapSig("scsi_command", "scsi_send_command", "SCSI command phase: select, send CDB, transfer",
			"generic", "generic",
			new String[]{"ST1","LD1","AN4m","NE","CB","ST1","LD1","AN4m","NE","CB",
						 "LD1","ST1","AD4","SU4","NE","CB"},
			true, 0, 3, false, false);

		// --- Watchdog ---
		addBootstrapSig("watchdog", "watchdog_feed", "Watchdog timer feed/kick",
			"generic", "generic",
			new String[]{"ST4","ST4"},
			false, 0, 0, false, false);

		// --- Context save/restore ---
		addBootstrapSig("context_save", "context_save_restore", "CPU context save: push all registers to stack/TCB",
			"generic", "generic",
			new String[]{"ST4","ST4","ST4","ST4","ST4","ST4","ST4","ST4",
						 "ST4","ST4","ST4","ST4","ST4","ST4","ST4","ST4"},
			false, 0, 0, false, false);
	}

	/**
	 * Helper to create a bootstrap signature from a synthetic token sequence.
	 */
	private void addBootstrapSig(String category, String label, String description,
			String cpu, String machine, String[] tokens,
			boolean hasLoop, int callCount, int loopCount,
			boolean hasTrap, boolean hasFloat) {

		Map<String, Integer> ngrams = extractNgrams(tokens);
		Map<String, Double> tf = computeTfVector(ngrams);

		StructuralFeatures sf = new StructuralFeatures();
		sf.totalOps = tokens.length;
		sf.loopCount = loopCount;
		sf.callCount = callCount;
		sf.isLeaf = (callCount == 0);
		sf.hasTrap = hasTrap;
		sf.hasFloatOps = hasFloat;
		sf.maxNestDepth = loopCount > 1 ? 2 : (loopCount > 0 ? 1 : 0);

		signatures.add(new PcodeSignature(category, label, description, cpu, machine, tf, sf));
	}

	// ================================================================
	// Diagnostics
	// ================================================================

	/** Get number of loaded signatures */
	public int getSignatureCount() {
		ensureLoaded();
		return signatures.size();
	}

	/** Get number of IDF terms */
	public int getIdfTermCount() {
		ensureLoaded();
		return idfWeights.size();
	}

	/**
	 * Dump the normalized token sequence for a function (for debugging/export).
	 */
	public static String dumpTokens(PcodeOp[] pcode) {
		String[] tokens = normalizeSequence(pcode);
		return String.join(" ", tokens);
	}

	/**
	 * Dump the n-gram vector for a function (for debugging/export).
	 */
	public static String dumpNgrams(PcodeOp[] pcode) {
		String[] tokens = normalizeSequence(pcode);
		Map<String, Integer> ngrams = extractNgrams(tokens);

		// Sort by count descending
		List<Map.Entry<String, Integer>> sorted = new ArrayList<>(ngrams.entrySet());
		sorted.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, Integer> e : sorted) {
			sb.append(String.format("  %3d  %s\n", e.getValue(), e.getKey()));
		}
		return sb.toString();
	}
}
