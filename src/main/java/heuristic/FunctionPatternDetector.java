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
	private PcodeVectorDatabase vectorDb;
	private PcodeVectorDatabase.RomDomain romDomain = PcodeVectorDatabase.RomDomain.GENERIC;

	public FunctionPatternDetector(Program program, PlatformDescription platform) {
		this.program = program;
		this.platform = platform;
	}

	/**
	 * Set the P-code vector database for structural similarity matching.
	 * Must be called before classify() for vector-based classification.
	 */
	public void setVectorDatabase(PcodeVectorDatabase db) {
		this.vectorDb = db;
	}

	/**
	 * Set the ROM domain for filtering plausible function categories.
	 * Derived from ROM identification or platform description.
	 */
	public void setRomDomain(PcodeVectorDatabase.RomDomain domain) {
		this.romDomain = domain != null ? domain : PcodeVectorDatabase.RomDomain.GENERIC;
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

		// Phase 0: P-code vector database matching (primary classifier)
		// Uses normalized P-code n-gram similarity against a reference database
		// of known functions, filtered by ROM domain.
		if (vectorDb != null) {
			List<PcodeVectorDatabase.VectorMatch> vectorMatches =
				vectorDb.classify(pcode, romDomain);
			for (PcodeVectorDatabase.VectorMatch vm : vectorMatches) {
				// Convert to FunctionType, scaling confidence from similarity
				double conf = vm.similarity;
				String desc = vm.description +
					String.format(" (%.0f%% ngram, %.0f%% struct match from %s)",
						vm.ngramSimilarity * 100, vm.structSimilarity * 100, vm.sourceCpu);
				results.add(new FunctionType(vm.category, vm.label, conf, desc));
			}
		}

		// If vector database is active, it is the primary classifier.
		// Skip rule-based detectors which produce too many false positives
		// on unfamiliar ISAs. Only fall through to rules if vector DB
		// found nothing AND we have no ROM domain constraint.
		if (vectorDb != null) {
			if (!results.isEmpty()) {
				// Domain filtering for vector DB results
				if (romDomain != null && romDomain != PcodeVectorDatabase.RomDomain.GENERIC) {
					Set<String> allowed = getDomainCategories(romDomain);
					if (allowed != null) {
						results.removeIf(r -> !allowed.contains(r.category));
					}
				}
				if (!results.isEmpty()) {
					results.sort((a, b) -> Double.compare(b.confidence, a.confidence));
					return results;
				}
			}
			// Vector DB found nothing — if domain is known, don't fall through
			// to noisy rule-based detectors either
			if (romDomain != null && romDomain != PcodeVectorDatabase.RomDomain.GENERIC) {
				return Collections.emptyList();
			}
		}

		// Phase 1: Rule-based detectors (legacy fallback for unknown ROMs only)
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
		tryDetect(results, detectI2cProtocol(pcode, profile));
		tryDetect(results, detectSpiProtocol(pcode, profile));
		tryDetect(results, detectMidiHandler(pcode, profile));
		tryDetect(results, detectModbusProtocol(pcode, profile));
		tryDetect(results, detectHuffmanDecode(pcode, profile));
		tryDetect(results, detectBase64Encode(pcode, profile));
		tryDetect(results, detectBase64Decode(pcode, profile));
		tryDetect(results, detectUtf8Encode(pcode, profile));
		tryDetect(results, detectUtf8Decode(pcode, profile));
		tryDetect(results, detectPopcount(pcode, profile));
		tryDetect(results, detectBitmapBlit(pcode, profile));
		tryDetect(results, detectFloodFill(pcode, profile));
		tryDetect(results, detectCircleDraw(pcode, profile));
		tryDetect(results, detectPolygonFill(pcode, profile));
		tryDetect(results, detectRtcManagement(pcode, profile));
		tryDetect(results, detectCalendarDate(pcode, profile));
		tryDetect(results, detectCrtInit(pcode, profile));
		tryDetect(results, detectAssertPanic(pcode, profile));
		tryDetect(results, detectLogPrint(pcode, profile));
		tryDetect(results, detectPidController(pcode, profile));
		tryDetect(results, detectPwmGeneration(pcode, profile));
		tryDetect(results, detectFifoQueue(pcode, profile));
		tryDetect(results, detectPriorityQueue(pcode, profile));
		tryDetect(results, detectHashTableOp(pcode, profile));
		tryDetect(results, detectBinarySearch(pcode, profile));
		tryDetect(results, detectHammingEcc(pcode, profile));
		tryDetect(results, detectGaloisFieldMul(pcode, profile));
		tryDetect(results, detectDmaChaining(pcode, profile));
		tryDetect(results, detectTimerSetup(pcode, profile));
		tryDetect(results, detectFatFilesystem(pcode, profile));
		tryDetect(results, detectDiskBlockIo(pcode, profile));
		tryDetect(results, detectMatrixMultiply(pcode, profile));
		tryDetect(results, detectFftButterfly(pcode, profile));
		tryDetect(results, detectFloatEmulAdd(pcode, profile));
		tryDetect(results, detectFloatEmulMul(pcode, profile));
		tryDetect(results, detectVectorTableSetup(pcode, profile));
		tryDetect(results, detectRelocation(pcode, profile));
		tryDetect(results, detectScsiPhaseHandler(pcode, profile));
		tryDetect(results, detectCdromCommand(pcode, profile));
		tryDetect(results, detectArpHandler(pcode, profile));
		tryDetect(results, detectTcpStateMachine(pcode, profile));
		tryDetect(results, detectVt100Parser(pcode, profile));
		tryDetect(results, detectMutexSpinlock(pcode, profile));
		tryDetect(results, detectCoroutineSwitch(pcode, profile));
		tryDetect(results, detectAudioMixer(pcode, profile));
		tryDetect(results, detectAdsrEnvelope(pcode, profile));
		tryDetect(results, detectWavetableSynth(pcode, profile));
		tryDetect(results, detectFmSynthOperator(pcode, profile));
		tryDetect(results, detectSampleRateConvert(pcode, profile));
		tryDetect(results, detectRleEncode(pcode, profile));
		tryDetect(results, detectDeltaEncode(pcode, profile));
		tryDetect(results, detectDeltaDecode(pcode, profile));
		tryDetect(results, detectSensorCalibration(pcode, profile));
		tryDetect(results, detectPowerSleep(pcode, profile));
		tryDetect(results, detectSlabAllocator(pcode, profile));
		tryDetect(results, detectBitReverse(pcode, profile));
		tryDetect(results, detectXdrEncode(pcode, profile));
		tryDetect(results, detectXdrDecode(pcode, profile));
		tryDetect(results, detectPageTableWalk(pcode, profile));
		tryDetect(results, detectCacheFlush(pcode, profile));
		tryDetect(results, detectEventSignal(pcode, profile));
		tryDetect(results, detectPathfinding(pcode, profile));
		tryDetect(results, detectSaveLoadState(pcode, profile));
		tryDetect(results, detectHighScoreTable(pcode, profile));
		tryDetect(results, detectDemoPlayback(pcode, profile));
		tryDetect(results, detectLcdInit(pcode, profile));
		tryDetect(results, detectMotorControl(pcode, profile));
		tryDetect(results, detectKeyboardScan(pcode, profile));
		tryDetect(results, detectHmacCompute(pcode, profile));
		tryDetect(results, detectElfSectionParser(pcode, profile));
		tryDetect(results, detectPs2Protocol(pcode, profile));
		tryDetect(results, detectGarbageCollectMark(pcode, profile));
		tryDetect(results, detectFramebufferSwap(pcode, profile));
		tryDetect(results, detectVramClear(pcode, profile));
		tryDetect(results, detectEepromAccess(pcode, profile));
		tryDetect(results, detectAdcRead(pcode, profile));
		tryDetect(results, detectDacOutput(pcode, profile));
		tryDetect(results, detectDipSwitchRead(pcode, profile));
		tryDetect(results, detectCoinHandler(pcode, profile));
		tryDetect(results, detectOsdOverlay(pcode, profile));
		tryDetect(results, detectCharGenLookup(pcode, profile));
		tryDetect(results, detectNandFlashRead(pcode, profile));
		tryDetect(results, detectNewtonRaphson(pcode, profile));
		tryDetect(results, detectEuclideanDistance(pcode, profile));
		tryDetect(results, detectAtan2Approx(pcode, profile));
		tryDetect(results, detectSigmoidLookup(pcode, profile));
		tryDetect(results, detectCanBusFrame(pcode, profile));
		tryDetect(results, detectOneWireProtocol(pcode, profile));
		tryDetect(results, detectManchesterCodec(pcode, profile));
		tryDetect(results, detectHdlcFraming(pcode, profile));
		tryDetect(results, detectIdleWfi(pcode, profile));
		tryDetect(results, detectIrqPriorityDispatch(pcode, profile));
		tryDetect(results, detectExceptionFrameBuild(pcode, profile));
		tryDetect(results, detectPostMemoryTest(pcode, profile));
		tryDetect(results, detectAiDecisionTree(pcode, profile));
		tryDetect(results, detectContinueCountdown(pcode, profile));
		tryDetect(results, detectInterlaceToggle(pcode, profile));
		tryDetect(results, detectWearLeveling(pcode, profile));
		tryDetect(results, detectBadBlockScan(pcode, profile));
		tryDetect(results, detectRandomLevelGen(pcode, profile));
		tryDetect(results, detectInputRecording(pcode, profile));
		tryDetect(results, detectThermalPrinter(pcode, profile));
		tryDetect(results, detectWeightTare(pcode, profile));
		tryDetect(results, detectFuelInjection(pcode, profile));
		tryDetect(results, detectBarcodeDecode(pcode, profile));
		tryDetect(results, detectJtagBoundaryScan(pcode, profile));
		tryDetect(results, detectBusArbitrationTest(pcode, profile));
		tryDetect(results, detectMpuRegionConfig(pcode, profile));
		tryDetect(results, detectDnsResolver(pcode, profile));
		tryDetect(results, detectDhcpClient(pcode, profile));
		tryDetect(results, detectHttpParser(pcode, profile));
		tryDetect(results, detectSmtpHandler(pcode, profile));
		tryDetect(results, detectTftpClient(pcode, profile));
		tryDetect(results, detectNtpSync(pcode, profile));
		tryDetect(results, detectPppFraming(pcode, profile));
		tryDetect(results, detectTelnetProtocol(pcode, profile));
		tryDetect(results, detectSnmpAgent(pcode, profile));
		tryDetect(results, detectUdpChecksum(pcode, profile));
		tryDetect(results, detectAesRound(pcode, profile));
		tryDetect(results, detectDesRound(pcode, profile));
		tryDetect(results, detectSha256Round(pcode, profile));
		tryDetect(results, detectMd5Round(pcode, profile));
		tryDetect(results, detectRc4Cipher(pcode, profile));
		tryDetect(results, detectChaCha20(pcode, profile));
		tryDetect(results, detectFirFilter(pcode, profile));
		tryDetect(results, detectIirFilter(pcode, profile));
		tryDetect(results, detectMovingAverage(pcode, profile));
		tryDetect(results, detectMedianFilter(pcode, profile));
		tryDetect(results, detectZeroCrossing(pcode, profile));
		tryDetect(results, detectConvolution(pcode, profile));
		tryDetect(results, detectStepperMotor(pcode, profile));
		tryDetect(results, detectBootloaderJump(pcode, profile));
		tryDetect(results, detectFlashErase(pcode, profile));
		tryDetect(results, detectBatteryMonitor(pcode, profile));
		tryDetect(results, detectTempCompensation(pcode, profile));
		tryDetect(results, detectSpriteScaling(pcode, profile));
		tryDetect(results, detectAlphaBlending(pcode, profile));
		tryDetect(results, detectGammaCorrection(pcode, profile));
		tryDetect(results, detectColorSpaceConvert(pcode, profile));
		tryDetect(results, detectParallaxScroll(pcode, profile));
		tryDetect(results, detectRaycasting(pcode, profile));
		tryDetect(results, detectJsonParser(pcode, profile));
		tryDetect(results, detectCsvParser(pcode, profile));
		tryDetect(results, detectCoffParser(pcode, profile));
		tryDetect(results, detectBmpLoader(pcode, profile));
		tryDetect(results, detectWavLoader(pcode, profile));
		tryDetect(results, detectSyscallDispatch(pcode, profile));
		tryDetect(results, detectThreadScheduler(pcode, profile));
		tryDetect(results, detectSignalHandler(pcode, profile));
		tryDetect(results, detectPipeIpc(pcode, profile));
		tryDetect(results, detectMemoryPool(pcode, profile));
		tryDetect(results, detectTlbFlush(pcode, profile));
		tryDetect(results, detectFileDescTable(pcode, profile));
		tryDetect(results, detectMountHandler(pcode, profile));
		tryDetect(results, detectSocketBind(pcode, profile));
		tryDetect(results, detectBigIntAdd(pcode, profile));
		tryDetect(results, detectBigIntMul(pcode, profile));
		tryDetect(results, detectPolynomialEval(pcode, profile));
		tryDetect(results, detectLinearInterp(pcode, profile));
		tryDetect(results, detectLogApprox(pcode, profile));
		tryDetect(results, detectExpApprox(pcode, profile));
		tryDetect(results, detectReciprocalApprox(pcode, profile));
		tryDetect(results, detectDivByConstant(pcode, profile));
		tryDetect(results, detectGcdCompute(pcode, profile));
		tryDetect(results, detectRegexMatch(pcode, profile));
		tryDetect(results, detectStringHash(pcode, profile));
		tryDetect(results, detectStringTokenize(pcode, profile));
		tryDetect(results, detectAtoi(pcode, profile));
		tryDetect(results, detectItoa(pcode, profile));
		tryDetect(results, detectStringSearch(pcode, profile));
		tryDetect(results, detectCaseConvert(pcode, profile));
		tryDetect(results, detectWhitespaceStrip(pcode, profile));
		tryDetect(results, detectCollisionResponse(pcode, profile));
		tryDetect(results, detectGravitySim(pcode, profile));
		tryDetect(results, detectJumpPhysics(pcode, profile));
		tryDetect(results, detectHealthDamage(pcode, profile));
		tryDetect(results, detectInventoryManage(pcode, profile));
		tryDetect(results, detectNpcDialog(pcode, profile));
		tryDetect(results, detectEnemyPatrol(pcode, profile));
		tryDetect(results, detectBossPattern(pcode, profile));
		tryDetect(results, detectArithmeticCoding(pcode, profile));
		tryDetect(results, detectLzwCodec(pcode, profile));
		tryDetect(results, detectBwtTransform(pcode, profile));
		tryDetect(results, detectDeflate(pcode, profile));
		tryDetect(results, detectUartInit(pcode, profile));

		// Phase 2: Feature-vector similarity (broader coverage via P-code
		// operation distribution fingerprinting — catches patterns that
		// don't match any specific rule but resemble known function types)
		if (results.isEmpty()) {
			FunctionType vectorMatch = classifyByFeatureVector(pcode, profile);
			if (vectorMatch != null) results.add(vectorMatch);
		}

		// Domain filtering: remove results whose category is implausible
		// for the identified ROM type (e.g., no sprite renderers in boot ROMs)
		if (romDomain != null && romDomain != PcodeVectorDatabase.RomDomain.GENERIC) {
			Set<String> allowed = getDomainCategories(romDomain);
			if (allowed != null) {
				results.removeIf(r -> !allowed.contains(r.category));
			}
		}

		results.sort((a, b) -> Double.compare(b.confidence, a.confidence));
		return results;
	}

	/**
	 * Get the set of plausible function categories for a ROM domain.
	 * Returns null if all categories are allowed.
	 */
	private static Set<String> getDomainCategories(PcodeVectorDatabase.RomDomain domain) {
		// Delegate to the vector database's domain map, but we need a static
		// accessor. Build a local map covering the rule-based detector categories.
		// This map should stay in sync with PcodeVectorDatabase.DOMAIN_CATEGORIES.
		switch (domain) {
			case COMPUTER_BOOT:
				return new HashSet<>(Arrays.asList(
					"multiply", "divide", "memcpy", "memset", "memcmp", "memmove",
					"strlen", "strcmp", "strcpy", "checksum", "crc",
					"bcd", "jump_table", "interrupt_handler", "boot_init",
					"printf", "sprintf", "number_to_string", "hex_dump",
					"memory_test", "self_test", "post_memory_test",
					"serial_io", "uart_init", "dma_transfer",
					"scsi_command", "disk_block_io", "flash_program", "flash_erase",
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
					"software_float", "float_add", "float_mul",
					"rng", "fixed_point", "sqrt"
				));
			case GAME_CONSOLE:
			case ARCADE:
				return null; // Allow all for games — they have everything
			default:
				return null; // GENERIC: allow all
		}
	}

	private void tryDetect(List<FunctionType> results, FunctionType result) {
		if (result != null && result.confidence >= 0.80) {
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

			Msg.info(this, String.format("  Classified %s @%s as %s: %s (%.0f%%)",
				func.getName(), func.getEntryPoint(), best.category, best.label,
				best.confidence * 100));
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

		// Must have both left and right shifts (shift dividend, build quotient)
		if (p.lefts < 1 || p.rights < 1) return null;

		double conf = 0.45;
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.10; // Comparison with divisor
		if (p.loopCount == 1) conf += 0.05; // Single loop (shift-subtract)
		if (p.divs == 0) conf += 0.05;  // No hardware divide
		if (shiftSubRatio > 0.25) conf += 0.10; // Very shift-heavy
		if (p.totalOps < 60) conf += 0.05; // Compact function

		if (conf < 0.60) return null;

		return new FunctionType("divide", "software_divide",
			Math.min(conf, 0.90),
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
		// Decompressors are substantial leaf functions
		if (p.totalOps < 80) return null;

		// Decompressors are self-contained — they don't call many other functions.
		// A function that calls 4+ subroutines is not a decompressor.
		if (p.calls >= 4) return null;

		// Require substantial shift+mask usage — this is the core discriminator.
		// Shifts and ANDs must be a significant fraction of total ops, not incidental.
		if (p.shifts < 4 || p.ands < 4) return null;
		if (p.loads < 5 || p.stores < 3) return null;
		if (p.cbranches < 4) return null;

		double shiftMaskRatio = (double)(p.shifts + p.ands) / p.totalOps;
		if (shiftMaskRatio < 0.10) return null;

		// Decompressors need NESTED loops or multiple loops — a single loop
		// is too common in generic code.
		if (p.loopCount < 2 && !p.hasNestedLoop) return null;

		// Check for ring buffer mask patterns.
		// LZSS requires 0xFFF (4K) or 0x3FF (1K). These are NOT common in
		// generic code and serve as strong positive signals.
		// 0xFF is too common (byte masking) — it's not a ring buffer indicator.
		boolean hasRingBufferMask = false;
		boolean hasBitExtraction = false;
		int distinctBitMasks = 0;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_AND) {
				Varnode mask = op.getInput(1);
				if (mask != null && mask.isConstant()) {
					long val = mask.getOffset();
					// Ring buffer: 0xFFF (4K), 0x3FF (1K), 0x1FF (512)
					// 0xFF is excluded — it's generic byte masking
					if (val == 0xFFF || val == 0x3FF || val == 0x1FF) {
						hasRingBufferMask = true;
					}
					// Bit extraction masks (1, 3, 7, 0xF, 0x1F, 0x3F, 0x7F)
					if (val >= 1 && val <= 0x7F && ((val + 1) & val) == 0) {
						hasBitExtraction = true;
						distinctBitMasks++;
					}
				}
			}
		}

		// Without a ring buffer mask, need very strong shift/mask signal
		// to distinguish from generic byte-manipulation code
		if (!hasRingBufferMask && shiftMaskRatio < 0.15) return null;
		if (!hasRingBufferMask && !hasBitExtraction) return null;

		// Decompressors are mostly self-contained byte shufflers.
		// Penalize if the function has many calls (utility/glue code, not algorithm)
		// or many ASCII constant comparisons (string processing, not compression).
		if (p.constAsciiCompares >= 3) return null; // string handler, not decompressor

		double conf = 0.45;
		if (hasRingBufferMask) conf += 0.25; // definitive LZSS signal
		if (hasBitExtraction && distinctBitMasks >= 2) conf += 0.10;
		if (shiftMaskRatio > 0.15) conf += 0.05;
		if (p.hasNestedLoop) conf += 0.05;
		if (p.totalOps > 150) conf += 0.05;
		if (p.calls == 0) conf += 0.05; // pure leaf function = stronger signal
		if (p.calls >= 2) conf -= 0.10; // calls weaken the case

		if (conf < 0.60) return null;

		String variant = hasRingBufferMask ? "lzss" : "rle_or_bitstream";
		return new FunctionType("decompression", "decompress_" + variant,
			Math.min(conf, 0.90),
			"Decompression routine (shift/mask ratio " +
			String.format("%.0f%%", shiftMaskRatio * 100) +
			(hasRingBufferMask ? ", ring buffer mask" : "") + ")");
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
		// Real ISRs: save regs, do minimal work, restore regs, RTE/RETI.
		// They rarely call subroutines — functions that call 3+ other functions
		// are almost certainly not interrupt handlers.
		if (p.calls >= 3) return null;
		if (p.stores < 4) return null;

		// Must have CALLOTHER (which maps to TRAP/RTE/RETI on many ISAs)
		// or be very small (some ISRs are just a register write + return).
		boolean hasSpecialReturn = p.hasTrapOp || p.callOtherCount > 0;
		boolean isSmall = p.totalOps < 40;

		// Count initial stores that look like register saves.
		// On most ISAs, ISR prologues save more registers than normal functions.
		// But we need to distinguish ISR saves from normal function prologues.
		// Real ISRs save registers to a *different* location (ISR stack) or
		// save *all* registers (not just callee-saved ones).
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

		// Require strong evidence: special return instruction OR (no calls AND
		// save/restore symmetry AND small function)
		double conf = 0.3;
		if (hasSpecialReturn) conf += 0.25; // strong signal: RTE/RETI
		if (p.calls == 0) conf += 0.10;
		if (initialStores >= 6 && trailingLoads >= 4) conf += 0.10; // heavy save/restore
		if (isSmall && p.calls == 0) conf += 0.10; // short leaf = strong ISR signal
		if (p.hasLoop) conf -= 0.15; // ISRs rarely loop
		if (p.calls >= 1) conf -= 0.10; // each call weakens the case
		if (p.totalOps > 200) conf -= 0.10; // ISRs are usually short

		if (conf < 0.60) return null;

		return new FunctionType("interrupt_handler", "interrupt_handler",
			Math.min(conf, 0.90),
			"Interrupt/exception handler (register save/restore + special return)");
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
		if (p.loads < 2 || p.stores < 2) return null;
		// Must have actual ring buffer wrap: AND with power-of-2 mask ≥ 0xF
		// (not just byte masking with 0xFF which is ubiquitous)
		if (p.powerOf2Masks < 2 && p.rems < 1) return null;
		// Ring buffers are leaf or near-leaf operations
		if (p.calls >= 3) return null;

		// Check for actual ring-buffer-sized masks (not just 0xFF/0x1)
		int ringMasks = 0;
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.INT_AND) {
				Varnode mask = op.getInput(1);
				if (mask != null && mask.isConstant()) {
					long val = mask.getOffset();
					// Ring buffer sizes: 0xF (16), 0x1F (32), 0x3F (64), 0xFF (256), 0x1FF, 0x3FF, 0xFFF
					if (val >= 0xF && val <= 0xFFFF && ((val + 1) & val) == 0) {
						ringMasks++;
					}
				}
			}
		}
		if (ringMasks < 1 && p.rems < 1) return null;

		// Must have index update (ADD) and bounds/empty check
		if (p.adds < 1 || p.compares < 1) return null;

		double conf = 0.50;
		if (ringMasks >= 2) conf += 0.15;
		if (p.rems >= 1) conf += 0.10;
		if (p.constZeroCompares > 0) conf += 0.05; // empty/full check
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.60) return null;

		return new FunctionType("circular_buffer", "circular_buffer_op",
			Math.min(conf, 0.85),
			"Circular/ring buffer operation (modular index wrap)");
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
		if (p.totalOps < 40) return null;
		if (p.loads < 5 || p.stores < 5) return null;

		// Packet build/parse is distinguished by byte-order conversion:
		// BOTH left and right shifts are required (byte swapping / field extraction+packing).
		// Also needs AND masks for field isolation.
		if (p.lefts < 1 || p.rights < 1) return null;
		if (p.ands < 2) return null;

		// Must have specific network-relevant constants:
		// port numbers, protocol numbers, header sizes, byte-order shifts (8, 16, 24)
		boolean hasNetworkShifts = p.constants.contains(8L) && p.constants.contains(16L);
		boolean hasProtocolConst = false;
		for (long c : p.constants) {
			// Common: 0xFF (byte mask), 0xFFFF (word mask), known port numbers, IP header size
			if (c == 0xFF00L || c == 0xFF0000L || c == 0xFF000000L) hasProtocolConst = true;
		}
		if (!hasNetworkShifts && !hasProtocolConst) return null;

		double conf = 0.50;
		if (hasNetworkShifts) conf += 0.15;
		if (p.ors >= 2) conf += 0.05; // field packing
		if (p.adds >= 2 && p.compares >= 2) conf += 0.05;

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
		if (p.totalOps < 30) return null;
		// Bitmap allocators are leaf functions — no external calls
		if (p.calls >= 2) return null;
		// Must have substantial shift+logic operations, not incidental
		if (p.shifts < 3) return null;
		if (p.ands < 3) return null;

		// Bitmap ops: shift to bit position, AND to test, OR to set bits
		double shiftFrac = p.shifts / (double) p.totalOps;
		double logicFrac = p.logic / (double) p.totalOps;
		// Both shift and logic must be substantial fractions
		if (shiftFrac < 0.08 || logicFrac < 0.08) return null;

		// Must have OR (to set bits) — bitmap allocators both test AND set
		if (p.ors < 1) return null;
		// Need bidirectional shifts (left to create mask, right to extract position)
		if (p.lefts < 1 || p.rights < 1) return null;

		double conf = 0.50;
		if (p.powerOf2Masks >= 2) conf += 0.10;
		if (p.compares >= 2) conf += 0.05;
		if (shiftFrac > 0.12) conf += 0.05;
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.60) return null;

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

		// Device dispatch: load from table, indirect call or branch.
		// Must have BOTH indirect dispatch AND index scaling.
		boolean hasIndirectDispatch = p.callInds > 0 || p.branchInds > 0;
		if (!hasIndirectDispatch) return null;
		// Index scaling: shift left or multiply to compute table offset
		boolean hasIndexScale = p.lefts > 0 || p.mults > 0;
		if (!hasIndexScale) return null;
		// Should have bounds checking
		if (p.compares < 1) return null;

		double conf = 0.50;
		if (p.callInds > 0) conf += 0.10; // indirect call (not just branch)
		if (p.cbranch_eq_runs >= 2) conf += 0.10; // compare-and-branch dispatch
		if (p.loads >= 4) conf += 0.05;
		if (p.totalOps < 80) conf += 0.05; // dispatch tables are usually compact

		if (conf < 0.60) return null;

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

	// ---- Round 6 detectors ----

	private FunctionType detectI2cProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// I2C bit-bangs SDA/SCL: many stores to IO, shift for bit assembly
		if (p.ioRegionAccesses >= 6) conf += 0.25;
		if (p.shifts >= 3) conf += 0.15;
		if (p.hasLoop && p.loopCount >= 1) conf += 0.15; // 8-bit shift loop
		if (p.constSmallInts >= 2) conf += 0.10; // bit positions 0-7
		if (p.ands >= 2) conf += 0.10; // masking SDA/SCL bits
		// Needs delay between toggles
		if (p.loads >= 4 && p.stores >= 6) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("i2c_protocol", "i2c_bit_bang",
			Math.min(conf, 0.75), "I2C bus protocol handler (bit-bang)");
	}

	private FunctionType detectSpiProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// SPI: 8-bit shift loop, MOSI out, MISO in, clock toggle
		if (p.ioRegionAccesses >= 4) conf += 0.20;
		if (p.shifts >= 2) conf += 0.15;
		if (p.hasLoop) conf += 0.15;
		if (p.loadStoreAlternations >= 3) conf += 0.15; // read MISO, write MOSI
		if (p.ands >= 1) conf += 0.10; // bit masking
		if (p.ors >= 1) conf += 0.10; // bit assembly
		if (conf < 0.55) return null;
		return new FunctionType("spi_protocol", "spi_transfer",
			Math.min(conf, 0.75), "SPI bus transfer routine");
	}

	private FunctionType detectMidiHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// MIDI: status byte >= 0x80, data bytes < 0x80
		boolean has0x80 = p.constants.contains(0x80L);
		boolean has0xF0 = p.constants.contains(0xF0L);
		boolean has0x90 = p.constants.contains(0x90L); // Note On
		if (has0x80) conf += 0.20;
		if (has0xF0) conf += 0.15; // SysEx or status mask
		if (has0x90) conf += 0.15;
		if (p.ands >= 2) conf += 0.10; // status/data masking
		if (p.cbranch_eq_runs >= 3) conf += 0.15; // dispatch by message type
		if (p.ioRegionAccesses >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("midi_handler", "midi_message_dispatch",
			Math.min(conf, 0.80), "MIDI protocol message handler");
	}

	private FunctionType detectModbusProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// Modbus: CRC16 with 0xA001, function code dispatch, slave ID check
		boolean hasA001 = p.constants.contains(0xA001L);
		if (hasA001) conf += 0.30; // Modbus CRC polynomial
		if (p.cbranch_eq_runs >= 4) conf += 0.20; // function code dispatch
		if (p.xors >= 2) conf += 0.10; // CRC XOR
		if (p.shifts >= 2) conf += 0.10; // CRC shift
		if (p.ioRegionAccesses >= 1) conf += 0.10; // serial port
		if (p.calls >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("modbus_protocol", "modbus_rtu_handler",
			Math.min(conf, 0.80), "Modbus RTU protocol handler");
	}

	private FunctionType detectHuffmanDecode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Huffman: bit-by-bit reading, tree traversal, output symbol
		if (p.hasNestedLoop) conf += 0.20; // outer symbol loop, inner bit loop
		if (p.shifts >= 3) conf += 0.15; // bit extraction
		if (p.ands >= 2) conf += 0.10; // bit masking
		if (p.cbranches >= 4) conf += 0.15; // tree left/right decisions
		if (p.loads >= 5) conf += 0.10; // table reads
		if (p.stores >= 2) conf += 0.10; // output buffer writes
		if (p.hasLoop && p.loopCount >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("huffman_decode", "huffman_bitstream_decoder",
			Math.min(conf, 0.80), "Huffman bitstream decoder");
	}

	private FunctionType detectBase64Encode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Base64: 3-byte input -> 4-char output, 6-bit chunks, lookup table
		boolean has63 = p.constants.contains(63L) || p.constants.contains(0x3FL);
		boolean has6 = p.constants.contains(6L);
		if (has63) conf += 0.25; // mask for 6-bit value
		if (has6) conf += 0.10; // shift by 6
		if (p.shifts >= 3) conf += 0.15; // shift to extract 6-bit chunks
		if (p.ands >= 2) conf += 0.15; // mask operations
		if (p.hasLoop) conf += 0.10;
		if (p.loads >= 3 && p.stores >= 3) conf += 0.10; // read input, write output
		if (conf < 0.55) return null;
		return new FunctionType("base64_encode", "base64_encoder",
			Math.min(conf, 0.80), "Base64 encoding routine");
	}

	private FunctionType detectBase64Decode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Base64 decode: 4-char input -> 3-byte output, reverse table
		boolean has63 = p.constants.contains(63L) || p.constants.contains(0x3FL);
		if (has63) conf += 0.20;
		if (p.shifts >= 3) conf += 0.15;
		if (p.ors >= 2) conf += 0.15; // bit assembly from 6-bit pieces
		if (p.ands >= 2) conf += 0.10;
		if (p.hasLoop) conf += 0.10;
		// Distinguisher from encode: more ORs (assembly) than AND (extraction)
		if (p.ors > p.ands) conf += 0.10;
		if (p.constAsciiCompares >= 2) conf += 0.10; // 'A', 'a', '0', '+', '/'
		if (conf < 0.55) return null;
		return new FunctionType("base64_decode", "base64_decoder",
			Math.min(conf, 0.80), "Base64 decoding routine");
	}

	private FunctionType detectUtf8Encode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// UTF-8 encode: range checks, continuation byte 0x80, lead byte patterns
		boolean has0x80 = p.constants.contains(0x80L);
		boolean has0xC0 = p.constants.contains(0xC0L);
		boolean has0x800 = p.constants.contains(0x800L);
		boolean has0x10000 = p.constants.contains(0x10000L);
		if (has0x80) conf += 0.15;
		if (has0xC0) conf += 0.15;
		if (has0x800 || has0x10000) conf += 0.20; // multi-byte thresholds
		if (p.cbranches >= 3) conf += 0.15; // range checks
		if (p.ors >= 2) conf += 0.10; // combine lead/continuation bits
		if (p.shifts >= 2) conf += 0.10; // extract bit fields
		if (conf < 0.55) return null;
		return new FunctionType("utf8_encode", "utf8_encoder",
			Math.min(conf, 0.80), "UTF-8 encoding routine");
	}

	private FunctionType detectUtf8Decode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		boolean has0x80 = p.constants.contains(0x80L);
		boolean has0xC0 = p.constants.contains(0xC0L);
		boolean has0xE0 = p.constants.contains(0xE0L);
		boolean has0xF0 = p.constants.contains(0xF0L);
		if (has0x80 && has0xC0) conf += 0.20;
		if (has0xE0) conf += 0.15;
		if (has0xF0) conf += 0.15;
		if (p.ands >= 3) conf += 0.15; // mask lead byte
		if (p.cbranches >= 3) conf += 0.10; // sequence length dispatch
		if (p.shifts >= 2) conf += 0.10; // reassemble codepoint
		if (conf < 0.55) return null;
		return new FunctionType("utf8_decode", "utf8_decoder",
			Math.min(conf, 0.80), "UTF-8 decoding routine");
	}

	private FunctionType detectPopcount(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Popcount/Hamming weight: Kernighan's (x &= x-1) or SWAR
		boolean has55555555 = p.constants.contains(0x55555555L);
		boolean has33333333 = p.constants.contains(0x33333333L);
		boolean has0F0F0F0F = p.constants.contains(0x0F0F0F0FL);
		if (has55555555 && has33333333) conf += 0.40; // SWAR technique
		if (has0F0F0F0F) conf += 0.15;
		// Kernighan's: loop with x &= (x-1)
		if (p.hasLoop && p.ands >= 2 && p.subs >= 1) conf += 0.25;
		if (p.adds >= 1) conf += 0.10; // count++
		if (p.shifts >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("popcount", "population_count",
			Math.min(conf, 0.85), "Population count (Hamming weight)");
	}

	private FunctionType detectBitmapBlit(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// Bitmap blit: nested loop (rows x cols), read src, write dst, stride add
		if (p.hasNestedLoop) conf += 0.25;
		if (p.loadStoreAlternations >= 4) conf += 0.20; // copy pixels
		if (p.adds >= 4) conf += 0.10; // pointer advancement + stride
		if (p.loads >= 6 && p.stores >= 4) conf += 0.10;
		// Masking/ROP ops
		if (p.ands >= 1 || p.ors >= 1 || p.xors >= 1) conf += 0.10;
		if (p.mults >= 1) conf += 0.10; // stride * y calculation
		if (conf < 0.55) return null;
		return new FunctionType("bitmap_blit", "block_image_transfer",
			Math.min(conf, 0.80), "Bitmap block transfer (blit)");
	}

	private FunctionType detectFloodFill(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Flood fill: stack/queue, pixel read, color compare, 4-way neighbor
		if (p.hasLoop) conf += 0.15;
		if (p.loads >= 5) conf += 0.10; // many pixel reads
		if (p.stores >= 3) conf += 0.10; // pixel writes + stack push
		if (p.equals >= 3) conf += 0.15; // color comparison per neighbor
		if (p.cbranches >= 4) conf += 0.15; // boundary checks per direction
		if (p.adds >= 4 && p.subs >= 1) conf += 0.15; // x+1,x-1,y+stride,y-stride
		if (p.calls >= 1 || p.hasNestedLoop) conf += 0.10; // recursive or iterative
		if (conf < 0.55) return null;
		return new FunctionType("flood_fill", "flood_fill_algorithm",
			Math.min(conf, 0.80), "Flood fill algorithm");
	}

	private FunctionType detectCircleDraw(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Bresenham circle: decision variable, 8-way symmetry, increment
		if (p.hasLoop) conf += 0.15;
		if (p.mults >= 2) conf += 0.15; // x*x, y*y or 2*x
		if (p.subs >= 2) conf += 0.10;
		if (p.adds >= 3) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.10; // decision variable check
		if (p.stores >= 4) conf += 0.15; // plot 4-8 symmetric points
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("circle_draw", "bresenham_circle",
			Math.min(conf, 0.75), "Circle/arc rasterizer (Bresenham)");
	}

	private FunctionType detectPolygonFill(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 50) return null;
		double conf = 0;
		// Scanline polygon fill: edge table, per-line intersections, span fill
		if (p.hasNestedLoop) conf += 0.20;
		if (p.mults >= 2) conf += 0.10; // slope calculation
		if (p.divs >= 1) conf += 0.15; // slope = dy/dx
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.10;
		if (p.consecutiveStores >= 3) conf += 0.15; // horizontal span fill
		if (p.adds >= 4) conf += 0.10; // DDA stepping
		if (p.loads >= 5) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("polygon_fill", "scanline_polygon_fill",
			Math.min(conf, 0.80), "Polygon scanline fill rasterizer");
	}

	private FunctionType detectRtcManagement(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// RTC: read/write seconds/minutes/hours, BCD conversion, IO accesses
		if (p.ioRegionAccesses >= 3) conf += 0.25;
		boolean has60 = p.constants.contains(60L); // seconds/minutes
		boolean has24 = p.constants.contains(24L); // hours
		boolean has12 = p.constants.contains(12L); // 12-hour mode
		if (has60) conf += 0.20;
		if (has24 || has12) conf += 0.15;
		if (p.rems >= 1 || p.divs >= 1) conf += 0.10; // modular arithmetic
		if (p.loads >= 3 && p.stores >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("rtc_management", "realtime_clock_handler",
			Math.min(conf, 0.80), "Real-time clock read/write/management");
	}

	private FunctionType detectCalendarDate(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Calendar: days-per-month table, leap year check, carry propagation
		boolean has365 = p.constants.contains(365L);
		boolean has366 = p.constants.contains(366L);
		boolean has400 = p.constants.contains(400L);
		boolean has28 = p.constants.contains(28L);
		boolean has31 = p.constants.contains(31L);
		if (has365 || has366) conf += 0.20;
		if (has400) conf += 0.20; // leap year: divisible by 400
		if (has28 && has31) conf += 0.15; // Feb/month lengths
		if (p.rems >= 1 || p.divs >= 1) conf += 0.10;
		if (p.cbranches >= 3) conf += 0.10; // boundary checks
		if (p.loads >= 2) conf += 0.10; // table lookups
		if (conf < 0.55) return null;
		return new FunctionType("calendar_date", "date_arithmetic",
			Math.min(conf, 0.80), "Calendar/date arithmetic routine");
	}

	private FunctionType detectCrtInit(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// CRT init: copy .data (ROM→RAM), zero .bss, set vectors, jump to main
		if (p.consecutiveStores >= 4) conf += 0.20; // zero BSS or copy data
		if (p.loadStoreAlternations >= 4) conf += 0.15; // ROM to RAM copy
		if (p.hasLoop && p.loopCount >= 2) conf += 0.15; // copy loop + zero loop
		if (p.calls >= 1) conf += 0.10; // call to main
		if (p.xorSelfOps >= 1) conf += 0.10; // clear register (zero source)
		if (p.constZeroCompares >= 1) conf += 0.10; // loop termination
		if (conf < 0.55) return null;
		return new FunctionType("crt_init", "c_runtime_init",
			Math.min(conf, 0.80), "C runtime initialization (_start/crt0)");
	}

	private FunctionType detectAssertPanic(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Assert/panic: condition check, call to output, then halt loop or trap
		if (p.hasTrapOp) conf += 0.25; // TRAP instruction
		if (p.callOtherCount >= 1) conf += 0.15;
		if (p.calls >= 1) conf += 0.10; // call to print/output
		// Check for infinite loop at end (halt)
		boolean hasEndLoop = false;
		for (int i = pcode.length - 3; i < pcode.length; i++) {
			if (i >= 0 && pcode[i].getOpcode() == PcodeOp.BRANCH) hasEndLoop = true;
		}
		if (hasEndLoop) conf += 0.20;
		if (p.constAsciiCompares >= 1) conf += 0.10; // string data reference
		if (p.cbranches <= 2) conf += 0.10; // simple condition + halt
		if (conf < 0.55) return null;
		return new FunctionType("assert_panic", "assertion_handler",
			Math.min(conf, 0.80), "Assertion/panic handler");
	}

	private FunctionType detectLogPrint(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Log with severity: level compare, conditional output, format string
		if (p.cbranch_eq_runs >= 2) conf += 0.15; // level dispatch
		if (p.calls >= 2) conf += 0.15; // call to format + output
		if (p.constAsciiCompares >= 1) conf += 0.15;
		if (p.loads >= 3) conf += 0.10;
		if (p.constSmallInts >= 2) conf += 0.10; // severity level constants
		// Check for level comparison at start (severity gate)
		if (pcode.length > 3) {
			int op0 = pcode[0].getOpcode();
			int op1 = pcode[1].getOpcode();
			if ((op0 == PcodeOp.INT_LESS || op0 == PcodeOp.INT_SLESS) &&
				op1 == PcodeOp.CBRANCH) conf += 0.15;
		}
		if (conf < 0.55) return null;
		return new FunctionType("log_print", "severity_logger",
			Math.min(conf, 0.80), "Log/print with severity level");
	}

	private FunctionType detectPidController(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// PID: error = setpoint - measured, integral += error, derivative = error - prev
		if (p.subs >= 2) conf += 0.15; // error calculation, derivative
		if (p.adds >= 2) conf += 0.10; // integral accumulation
		if (p.mults >= 2) conf += 0.20; // Kp*error, Ki*integral, Kd*derivative
		if (p.loads >= 4 && p.stores >= 3) conf += 0.15; // state variables
		if (p.hasLoop) conf += 0.05; // may run in loop or be called periodically
		// Three multiply operations is very characteristic
		if (p.mults >= 3) conf += 0.15;
		if (conf < 0.55) return null;
		return new FunctionType("pid_controller", "pid_control_loop",
			Math.min(conf, 0.80), "PID controller (proportional-integral-derivative)");
	}

	private FunctionType detectPwmGeneration(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// PWM: compare counter with duty cycle, toggle output
		if (p.ioRegionAccesses >= 2) conf += 0.20; // timer/output registers
		if (p.compares >= 2) conf += 0.15; // compare with period and duty
		if (p.stores >= 2) conf += 0.10;
		if (p.loads >= 2) conf += 0.10;
		if (p.cbranches >= 1) conf += 0.10;
		// Constants that look like timer periods or duty cycles
		if (p.distinctConstants >= 3) conf += 0.10;
		if (p.ands >= 1 || p.ors >= 1) conf += 0.10; // bit set/clear for output
		if (conf < 0.55) return null;
		return new FunctionType("pwm_generation", "pwm_output_setup",
			Math.min(conf, 0.75), "PWM signal generation/configuration");
	}

	private FunctionType detectFifoQueue(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// FIFO: head/tail pointers, modular increment, store/load element
		if (p.loads >= 3 && p.stores >= 2) conf += 0.15;
		if (p.adds >= 1) conf += 0.10; // increment pointer
		if (p.rems >= 1 || p.powerOf2Masks >= 1) conf += 0.25; // wrap-around
		if (p.equals >= 1) conf += 0.10; // full/empty check (head == tail)
		if (p.cbranches >= 1) conf += 0.10;
		// Distinguish from circular buffer: FIFO has separate push/pop
		if (p.totalOps < 60) conf += 0.10; // FIFO ops are typically small
		if (conf < 0.55) return null;
		return new FunctionType("fifo_queue", "fifo_enqueue_dequeue",
			Math.min(conf, 0.75), "FIFO queue operation (push/pop)");
	}

	private FunctionType detectPriorityQueue(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Priority queue/heap: parent = i/2, children = 2i, 2i+1, sift up/down
		boolean has2 = p.constants.contains(2L);
		if (has2 && (p.divs >= 1 || p.rights >= 1)) conf += 0.20; // parent = i/2
		if (has2 && (p.mults >= 1 || p.lefts >= 1)) conf += 0.20; // child = 2*i
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.15; // compare priorities
		if (p.hasLoop) conf += 0.10; // sift loop
		if (p.loadStoreAlternations >= 2) conf += 0.10; // swap elements
		if (p.adds >= 1) conf += 0.10; // child = 2*i + 1
		if (conf < 0.55) return null;
		return new FunctionType("priority_queue", "heap_sift_operation",
			Math.min(conf, 0.80), "Priority queue (binary heap sift)");
	}

	private FunctionType detectHashTableOp(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Hash table: compute hash, modulo bucket count, chain traversal
		if (p.rems >= 1 || p.powerOf2Masks >= 1) conf += 0.20; // bucket index
		if (p.xors >= 1 || p.mults >= 1) conf += 0.15; // hash computation
		if (p.hasLoop) conf += 0.15; // chain traversal
		if (p.equals >= 2) conf += 0.10; // key comparison
		if (p.loads >= 4) conf += 0.10; // read key, value, next pointer
		if (p.cbranches >= 2) conf += 0.10; // found vs. chain next
		if (conf < 0.55) return null;
		return new FunctionType("hash_table", "hash_table_lookup",
			Math.min(conf, 0.80), "Hash table lookup/insert");
	}

	private FunctionType detectBinarySearch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Binary search: mid = (lo+hi)/2, compare, adjust lo or hi
		if (p.adds >= 1) conf += 0.10; // lo + hi
		if (p.rights >= 1 || p.divs >= 1) conf += 0.20; // /2 for midpoint
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.15; // compare with target
		if (p.hasLoop) conf += 0.15; // search loop
		if (p.cbranches >= 2) conf += 0.15; // less/greater/equal branches
		if (p.loads >= 2) conf += 0.10; // read array[mid]
		if (conf < 0.55) return null;
		return new FunctionType("binary_search", "binary_search_algorithm",
			Math.min(conf, 0.80), "Binary search algorithm");
	}

	private FunctionType detectHammingEcc(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Hamming ECC: parity bits at power-of-2 positions, XOR tree
		if (p.xors >= 3) conf += 0.20; // parity XOR accumulation
		if (p.ands >= 3) conf += 0.15; // bit position masking
		if (p.hasLoop) conf += 0.10;
		if (p.shifts >= 2) conf += 0.10;
		// Power-of-2 constants: 1, 2, 4, 8
		int pow2Count = 0;
		for (long c : new long[]{1, 2, 4, 8, 16}) {
			if (p.constants.contains(c)) pow2Count++;
		}
		if (pow2Count >= 3) conf += 0.20;
		if (conf < 0.55) return null;
		return new FunctionType("hamming_ecc", "hamming_error_correction",
			Math.min(conf, 0.80), "Hamming error correction code");
	}

	private FunctionType detectGaloisFieldMul(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// GF(2^8): XOR for add, shift+conditional-XOR for multiply, polynomial reduction
		boolean has0x11D = p.constants.contains(0x11DL); // AES polynomial
		boolean has0x11B = p.constants.contains(0x11BL); // common GF polynomial
		boolean has0x1D = p.constants.contains(0x1DL);
		if (has0x11D || has0x11B || has0x1D) conf += 0.30;
		if (p.xors >= 2) conf += 0.15;
		if (p.shifts >= 2) conf += 0.15; // shift for multiply-by-2
		if (p.hasLoop) conf += 0.10; // 8-bit loop
		if (p.ands >= 1) conf += 0.10; // bit test for conditional XOR
		if (p.cbranches >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("galois_field", "gf_multiply",
			Math.min(conf, 0.80), "Galois field multiplication (GF(2^8))");
	}

	private FunctionType detectDmaChaining(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// DMA chaining: build descriptor list, write src/dst/count/next/ctrl
		if (p.consecutiveStores >= 4) conf += 0.25; // descriptor fields
		if (p.hasLoop) conf += 0.15; // iterate descriptor list
		if (p.ioRegionAccesses >= 2) conf += 0.15; // DMA engine registers
		if (p.adds >= 2) conf += 0.10; // next descriptor pointer
		if (p.loads >= 3) conf += 0.10; // read source params
		if (p.ors >= 1 || p.ands >= 1) conf += 0.10; // control bits
		if (conf < 0.55) return null;
		return new FunctionType("dma_chaining", "dma_descriptor_chain",
			Math.min(conf, 0.80), "DMA descriptor chain setup");
	}

	private FunctionType detectTimerSetup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Timer: write prescaler, count, control, enable
		if (p.ioRegionAccesses >= 3) conf += 0.30;
		if (p.consecutiveStores >= 3) conf += 0.20; // write multiple timer regs
		if (p.stores >= 3) conf += 0.10;
		if (p.ors >= 1 || p.ands >= 1) conf += 0.10; // enable/disable bits
		if (p.totalOps < 50) conf += 0.10; // timer setup is typically short
		if (conf < 0.55) return null;
		return new FunctionType("timer_setup", "timer_configuration",
			Math.min(conf, 0.75), "Hardware timer setup/configuration");
	}

	private FunctionType detectFatFilesystem(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// FAT: cluster chain traversal, sector calculation, directory entry parsing
		boolean has512 = p.constants.contains(512L); // sector size
		boolean has32 = p.constants.contains(32L); // dir entry size
		boolean has0x0FFF = p.constants.contains(0x0FFFL); // FAT12 end
		boolean has0xFFFF = p.constants.contains(0xFFFFL); // FAT16 end
		boolean has0x0FFFFFF8 = p.constants.contains(0x0FFFFFF8L); // FAT32 end
		if (has512) conf += 0.20;
		if (has32) conf += 0.10;
		if (has0x0FFF || has0xFFFF || has0x0FFFFFF8) conf += 0.25;
		if (p.hasLoop) conf += 0.10;
		if (p.mults >= 1 || p.shifts >= 1) conf += 0.10; // sector/cluster calc
		if (p.calls >= 2) conf += 0.10; // read sector, follow chain
		if (conf < 0.55) return null;
		return new FunctionType("fat_filesystem", "fat_cluster_operation",
			Math.min(conf, 0.80), "FAT filesystem cluster/directory operation");
	}

	private FunctionType detectDiskBlockIo(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Disk block read/write: LBA/CHS conversion, DMA setup, status poll
		boolean has512 = p.constants.contains(512L);
		boolean has63 = p.constants.contains(63L); // sectors per track
		boolean has255 = p.constants.contains(255L); // heads
		if (has512) conf += 0.15;
		if (has63 || has255) conf += 0.15; // CHS geometry
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.divs >= 1 || p.rems >= 1) conf += 0.10; // CHS calculation
		if (p.hasLoop) conf += 0.10; // status poll loop
		if (p.calls >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("disk_block_io", "disk_sector_read_write",
			Math.min(conf, 0.80), "Disk block/sector I/O operation");
	}

	private FunctionType detectMatrixMultiply(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// Matrix multiply: triple nested loop, multiply-accumulate
		if (p.hasNestedLoop) conf += 0.25;
		if (p.loopCount >= 3) conf += 0.20; // triple loop
		if (p.mults >= 3) conf += 0.15; // multiply per inner iteration
		if (p.adds >= 3) conf += 0.10; // accumulate sums
		if (p.loads >= 6) conf += 0.10; // read matrix elements
		if (p.stores >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("matrix_multiply", "matrix_mul",
			Math.min(conf, 0.80), "Matrix multiplication");
	}

	private FunctionType detectFftButterfly(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// FFT butterfly: complex multiply (4 muls + 2 add/sub), twiddle factor
		if (p.mults >= 4) conf += 0.20; // complex multiplication
		if (p.adds >= 2 && p.subs >= 2) conf += 0.20; // butterfly add/subtract
		if (p.hasNestedLoop) conf += 0.15; // stage loop + butterfly loop
		if (p.loads >= 6) conf += 0.10; // read real/imag pairs
		if (p.stores >= 4) conf += 0.10; // write results
		if (p.shifts >= 1) conf += 0.10; // bit-reversal or scaling
		if (conf < 0.55) return null;
		return new FunctionType("fft_butterfly", "fft_radix2_butterfly",
			Math.min(conf, 0.80), "FFT butterfly operation (radix-2)");
	}

	private FunctionType detectFloatEmulAdd(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Software float add: extract sign/exp/mantissa, align, add, normalize
		boolean has0x7F800000 = p.constants.contains(0x7F800000L); // float exponent mask
		boolean has0x007FFFFF = p.constants.contains(0x007FFFFFL); // float mantissa mask
		boolean has0x80000000 = p.constants.contains(0x80000000L); // sign bit
		boolean has23 = p.constants.contains(23L); // mantissa shift
		if (has0x7F800000 || has0x007FFFFF) conf += 0.25;
		if (has0x80000000) conf += 0.10;
		if (has23) conf += 0.15; // shift by mantissa width
		if (p.shifts >= 3) conf += 0.10;
		if (p.ands >= 2) conf += 0.10; // field extraction
		if (p.adds >= 1 && p.subs >= 1) conf += 0.10; // align + add
		if (conf < 0.55) return null;
		return new FunctionType("float_emulation", "softfloat_add",
			Math.min(conf, 0.80), "Software floating-point addition");
	}

	private FunctionType detectFloatEmulMul(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		boolean has0x7F800000 = p.constants.contains(0x7F800000L);
		boolean has0x007FFFFF = p.constants.contains(0x007FFFFFL);
		boolean has23 = p.constants.contains(23L);
		boolean has127 = p.constants.contains(127L); // exponent bias
		if (has0x7F800000 || has0x007FFFFF) conf += 0.20;
		if (has23) conf += 0.10;
		if (has127) conf += 0.15; // bias subtraction
		if (p.mults >= 1) conf += 0.15; // mantissa multiply
		if (p.adds >= 1) conf += 0.10; // exponent add
		if (p.shifts >= 2) conf += 0.10; // normalize
		if (p.ands >= 2) conf += 0.10; // extract fields
		if (conf < 0.55) return null;
		return new FunctionType("float_emulation", "softfloat_mul",
			Math.min(conf, 0.80), "Software floating-point multiplication");
	}

	private FunctionType detectVectorTableSetup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Vector table: consecutive stores of function addresses to vector area
		if (p.consecutiveStores >= 5) conf += 0.30; // many vector writes
		if (p.stores >= 8) conf += 0.15;
		if (p.distinctConstants >= 5) conf += 0.15; // different handler addresses
		if (p.loads >= 2) conf += 0.05;
		// Should have minimal arithmetic
		if (p.arithmetic < p.totalOps / 5) conf += 0.10;
		if (!p.hasLoop || p.loopCount <= 1) conf += 0.10; // often unrolled
		if (conf < 0.55) return null;
		return new FunctionType("vector_table_setup", "exception_vector_init",
			Math.min(conf, 0.80), "Exception/interrupt vector table setup");
	}

	private FunctionType detectRelocation(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Relocation: load address, add base offset, store back
		if (p.hasLoop) conf += 0.15;
		if (p.loads >= 3) conf += 0.10;
		if (p.adds >= 2) conf += 0.15; // add base to each entry
		if (p.stores >= 3) conf += 0.10;
		if (p.loadStoreAlternations >= 3) conf += 0.15; // read-modify-write pattern
		// Minimal branching inside loop
		if (p.cbranches <= 3) conf += 0.10;
		if (p.distinctConstants >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("relocation", "address_relocation",
			Math.min(conf, 0.75), "Address relocation/fixup routine");
	}

	// ---- Round 7 detectors ----

	private FunctionType detectScsiPhaseHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// SCSI phase: read phase register, mask 0x07, dispatch on phase value
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		boolean has7 = p.constants.contains(7L) || p.constants.contains(0x07L);
		if (has7) conf += 0.15; // phase mask
		if (p.cbranch_eq_runs >= 4) conf += 0.20; // 8-way phase dispatch
		if (p.ands >= 2) conf += 0.10;
		if (p.calls >= 2) conf += 0.10; // call phase-specific handlers
		if (p.loads >= 4) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("scsi_phase", "scsi_phase_handler",
			Math.min(conf, 0.80), "SCSI bus phase state machine");
	}

	private FunctionType detectCdromCommand(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// CD-ROM command dispatch: opcode byte, switch to handlers
		if (p.cbranch_eq_runs >= 5) conf += 0.25; // many command opcodes
		if (p.calls >= 3) conf += 0.15; // call per-command handlers
		if (p.loads >= 3) conf += 0.10;
		if (p.ands >= 1) conf += 0.05;
		// CD-ROM constants: sector size 2048 or 2352
		boolean has2048 = p.constants.contains(2048L);
		boolean has2352 = p.constants.contains(2352L);
		if (has2048 || has2352) conf += 0.20;
		if (p.ioRegionAccesses >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("cdrom_command", "cdrom_command_dispatch",
			Math.min(conf, 0.80), "CD-ROM/ATAPI command dispatcher");
	}

	private FunctionType detectArpHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// ARP: ethertype 0x0806, opcode 1 (request) or 2 (reply), IP/MAC addresses
		boolean has0x0806 = p.constants.contains(0x0806L);
		if (has0x0806) conf += 0.30; // ARP ethertype
		if (p.equals >= 3) conf += 0.15; // compare IPs, opcode
		if (p.loads >= 6) conf += 0.10; // load sender/target IP+MAC
		if (p.stores >= 4) conf += 0.10; // store to ARP cache
		if (p.cbranches >= 2) conf += 0.10;
		if (p.calls >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("arp_handler", "arp_protocol",
			Math.min(conf, 0.80), "ARP protocol handler");
	}

	private FunctionType detectTcpStateMachine(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 50) return null;
		double conf = 0;
		// TCP: many state+flag combinations, complex dispatch
		if (p.cbranch_eq_runs >= 6) conf += 0.25; // state dispatch
		if (p.ands >= 3) conf += 0.10; // flag extraction (SYN, ACK, FIN, RST)
		if (p.calls >= 4) conf += 0.15; // state handlers
		if (p.loads >= 8) conf += 0.10;
		if (p.stores >= 4) conf += 0.10; // update connection state
		// TCP flag constants
		boolean has0x02 = p.constants.contains(0x02L); // SYN
		boolean has0x10 = p.constants.contains(0x10L); // ACK
		boolean has0x01 = p.constants.contains(0x01L); // FIN
		if (has0x02 && has0x10) conf += 0.15;
		if (has0x01) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("tcp_state", "tcp_state_machine",
			Math.min(conf, 0.80), "TCP connection state machine");
	}

	private FunctionType detectVt100Parser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// VT100: ESC (0x1B) check, CSI sequence, parameter parsing
		boolean has0x1B = p.constants.contains(0x1BL); // ESC
		boolean has0x5B = p.constants.contains(0x5BL); // '['
		if (has0x1B) conf += 0.25;
		if (has0x5B) conf += 0.15;
		if (p.constAsciiCompares >= 3) conf += 0.15; // compare with letters
		if (p.cbranch_eq_runs >= 4) conf += 0.10; // dispatch on command char
		if (p.hasLoop) conf += 0.10; // parameter digit parsing
		if (p.stores >= 3) conf += 0.10; // update cursor/color state
		if (conf < 0.55) return null;
		return new FunctionType("vt100_parser", "terminal_escape_parser",
			Math.min(conf, 0.80), "VT100/ANSI escape sequence parser");
	}

	private FunctionType detectMutexSpinlock(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Spinlock: load lock, compare 0, branch-if-locked, store owner
		if (p.hasLoop) conf += 0.20; // spin loop
		if (p.loads >= 2) conf += 0.10;
		if (p.constZeroCompares >= 1) conf += 0.15; // check if unlocked
		if (p.cbranches >= 1) conf += 0.10;
		if (p.stores >= 1) conf += 0.10;
		// Should be very small
		if (p.totalOps < 30) conf += 0.15;
		if (p.calls == 0) conf += 0.10; // no calls, just spin
		if (conf < 0.55) return null;
		return new FunctionType("mutex_spinlock", "spinlock_acquire",
			Math.min(conf, 0.75), "Mutex/spinlock acquire");
	}

	private FunctionType detectCoroutineSwitch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Coroutine: save all regs (many stores), load all regs (many loads), swap SP
		if (p.consecutiveStores >= 4) conf += 0.20; // save register set
		if (p.consecutiveLoads >= 4) conf += 0.20; // restore register set
		if (p.loads >= 6 && p.stores >= 6) conf += 0.15;
		// Minimal computation between save and restore
		if (p.arithmetic < p.totalOps / 5) conf += 0.10;
		if (p.adds >= 1) conf += 0.05; // pointer adjustments
		if (p.branchInds >= 1 || p.returns >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("coroutine_switch", "fiber_context_swap",
			Math.min(conf, 0.80), "Coroutine/fiber context switch");
	}

	private FunctionType detectAudioMixer(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Mixer: loop over channels, load sample, multiply volume, accumulate
		if (p.hasLoop) conf += 0.15;
		if (p.mults >= 2) conf += 0.20; // volume scaling per channel
		if (p.adds >= 3) conf += 0.15; // accumulate channels
		if (p.loads >= 4) conf += 0.10; // read samples + volumes
		if (p.stores >= 1) conf += 0.05;
		// Clipping: compare with max, conditional select
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10;
		if (p.hasNestedLoop) conf += 0.10; // channel × sample loops
		if (conf < 0.55) return null;
		return new FunctionType("audio_mixer", "multichannel_mixer",
			Math.min(conf, 0.80), "Audio mixer (multi-channel blend)");
	}

	private FunctionType detectAdsrEnvelope(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// ADSR: 4-phase state machine (attack/decay/sustain/release)
		if (p.cbranch_eq_runs >= 3) conf += 0.20; // phase dispatch
		if (p.adds >= 1 || p.subs >= 1) conf += 0.10; // ramp up/down
		if (p.mults >= 1) conf += 0.10; // scale by rate
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // compare with level
		if (p.stores >= 2) conf += 0.10; // update level + phase
		if (p.loads >= 3) conf += 0.10; // read rate/level/phase
		if (p.constSmallInts >= 3) conf += 0.10; // phase constants 0-3
		if (conf < 0.55) return null;
		return new FunctionType("adsr_envelope", "sound_envelope",
			Math.min(conf, 0.80), "ADSR sound envelope generator");
	}

	private FunctionType detectWavetableSynth(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Wavetable: phase accumulator, table index from upper bits, interpolate
		if (p.hasLoop) conf += 0.15;
		if (p.adds >= 2) conf += 0.10; // phase accumulator += frequency
		if (p.rights >= 1) conf += 0.15; // extract table index from phase
		if (p.ands >= 1) conf += 0.10; // mask for table index
		if (p.loads >= 3) conf += 0.10; // read wavetable samples
		if (p.mults >= 1) conf += 0.10; // interpolation or volume
		if (p.stores >= 2) conf += 0.10; // write output sample + update phase
		if (conf < 0.55) return null;
		return new FunctionType("wavetable_synth", "wavetable_oscillator",
			Math.min(conf, 0.80), "Wavetable synthesis oscillator");
	}

	private FunctionType detectFmSynthOperator(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// FM synth: phase + modulator, sine lookup, multiply by envelope
		if (p.adds >= 2) conf += 0.10; // phase + modulation
		if (p.mults >= 2) conf += 0.20; // modulation depth, envelope
		if (p.loads >= 3) conf += 0.10; // sine table, envelope, modulator
		if (p.shifts >= 1) conf += 0.10; // fixed-point scaling
		if (p.ands >= 1) conf += 0.10; // phase wrap mask
		if (p.stores >= 2) conf += 0.10; // output + phase update
		if (p.hasLoop) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("fm_synth", "fm_synthesis_operator",
			Math.min(conf, 0.80), "FM synthesis operator");
	}

	private FunctionType detectSampleRateConvert(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// SRC: fractional position, interpolate between samples, step by ratio
		if (p.hasLoop) conf += 0.15;
		if (p.mults >= 2) conf += 0.15; // interpolation weights
		if (p.adds >= 2) conf += 0.10;
		if (p.subs >= 1) conf += 0.10; // weight = 1 - fraction
		if (p.shifts >= 2) conf += 0.10; // fixed-point fraction
		if (p.loads >= 3) conf += 0.10; // read adjacent samples
		if (p.stores >= 1) conf += 0.10;
		if (p.ands >= 1) conf += 0.05; // fraction mask
		if (conf < 0.55) return null;
		return new FunctionType("sample_rate_convert", "src_interpolator",
			Math.min(conf, 0.80), "Sample rate converter (interpolation)");
	}

	private FunctionType detectRleEncode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// RLE encode: compare current with previous, count runs, output pairs
		if (p.hasLoop) conf += 0.15;
		if (p.equals >= 2) conf += 0.20; // compare current == previous
		if (p.adds >= 1) conf += 0.10; // increment run count
		if (p.cbranches >= 2) conf += 0.10;
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 2) conf += 0.10; // output value + count
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // max run length check
		if (conf < 0.55) return null;
		return new FunctionType("rle_encode", "rle_compressor",
			Math.min(conf, 0.80), "Run-length encoder (compressor)");
	}

	private FunctionType detectDeltaEncode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Delta encode: current - previous, store delta, update previous
		if (p.hasLoop) conf += 0.15;
		if (p.subs >= 1) conf += 0.20; // delta = current - previous
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 2) conf += 0.15; // store delta + update previous
		if (p.loadStoreAlternations >= 2) conf += 0.10;
		// Typically small and simple
		if (p.totalOps < 50) conf += 0.10;
		if (p.mults == 0 && p.divs == 0) conf += 0.10; // no multiply/divide
		if (conf < 0.55) return null;
		return new FunctionType("delta_encode", "differential_encoder",
			Math.min(conf, 0.75), "Delta/differential encoder");
	}

	private FunctionType detectDeltaDecode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Delta decode: accumulator += delta
		if (p.hasLoop) conf += 0.15;
		if (p.adds >= 1) conf += 0.20; // accumulator += delta
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 2) conf += 0.15;
		if (p.loadStoreAlternations >= 2) conf += 0.10;
		if (p.totalOps < 50) conf += 0.10;
		if (p.mults == 0 && p.divs == 0) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("delta_decode", "differential_decoder",
			Math.min(conf, 0.75), "Delta/differential decoder");
	}

	private FunctionType detectSensorCalibration(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Calibration: read raw, subtract offset, multiply scale, clamp
		if (p.ioRegionAccesses >= 1) conf += 0.15; // ADC register read
		if (p.subs >= 1) conf += 0.15; // subtract offset
		if (p.mults >= 1) conf += 0.20; // multiply by scale factor
		if (p.loads >= 3) conf += 0.10; // raw value, offset, scale
		if (p.stores >= 1) conf += 0.10;
		// Clamping
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10;
		if (p.cbranches >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("sensor_calibration", "adc_calibrate",
			Math.min(conf, 0.75), "Sensor/ADC calibration (offset + scale)");
	}

	private FunctionType detectPowerSleep(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Power sleep: save context, write sleep register, halt
		if (p.ioRegionAccesses >= 2) conf += 0.20; // power control registers
		if (p.consecutiveStores >= 3) conf += 0.15; // save state
		if (p.ors >= 1 || p.ands >= 1) conf += 0.10; // set sleep bits
		if (p.stores >= 3) conf += 0.10;
		// Check for halt-like instruction at end
		boolean hasEndBranch = false;
		for (int i = Math.max(0, pcode.length - 3); i < pcode.length; i++) {
			if (pcode[i].getOpcode() == PcodeOp.BRANCH) hasEndBranch = true;
		}
		if (hasEndBranch) conf += 0.15;
		if (p.callOtherCount >= 1) conf += 0.10; // STOP/HALT instruction
		if (conf < 0.55) return null;
		return new FunctionType("power_sleep", "sleep_mode_enter",
			Math.min(conf, 0.75), "Power management / sleep mode entry");
	}

	private FunctionType detectSlabAllocator(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Slab: load freelist head, check null, update next, return object
		if (p.loads >= 3) conf += 0.15; // load freelist, next ptr, object
		if (p.stores >= 2) conf += 0.10; // update freelist head
		if (p.constZeroCompares >= 1) conf += 0.15; // check NULL (empty)
		if (p.cbranches >= 1) conf += 0.10;
		if (p.returns >= 1) conf += 0.05;
		// Small, fast-path oriented
		if (p.totalOps < 50) conf += 0.10;
		if (p.adds >= 1) conf += 0.10; // pointer arithmetic
		if (p.calls <= 1) conf += 0.10; // maybe one call to grow
		if (conf < 0.55) return null;
		return new FunctionType("slab_allocator", "slab_alloc",
			Math.min(conf, 0.75), "Slab/pool memory allocator");
	}

	private FunctionType detectBitReverse(PcodeOp[] pcode, OpcodeProfile p) {
		// Bit reverse: extract LSB, shift into MSB, iterate N times.
		// Must be a small, tight loop with shifts in BOTH directions (left + right),
		// AND for bit extraction, OR for bit insertion.
		// Must be a leaf function — bit reverse doesn't call subroutines.
		if (p.totalOps < 15 || p.totalOps > 80) return null;
		if (p.calls >= 1) return null;
		if (!p.hasLoop) return null;
		// Need both left and right shifts (extracting from one end, inserting at other)
		if (p.lefts < 1 || p.rights < 1) return null;
		if (p.ands < 1 || p.ors < 1) return null;
		// Shifts must be the dominant operation (not incidental)
		double shiftFrac = (double) p.shifts / p.totalOps;
		if (shiftFrac < 0.10) return null;
		// Should have constant 1 (single bit mask) and constant 8, 16, or 32 (iteration count)
		boolean hasBit1 = p.constants.contains(1L);
		boolean hasIterCount = p.constants.contains(8L) || p.constants.contains(16L) || p.constants.contains(32L);
		if (!hasBit1) return null;

		double conf = 0.55;
		if (hasIterCount) conf += 0.15;
		if (shiftFrac > 0.15) conf += 0.10;
		if (conf < 0.60) return null;
		return new FunctionType("bit_reverse", "bitreverse_permutation",
			Math.min(conf, 0.80), "Bit reversal permutation");
	}

	private FunctionType detectXdrEncode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// XDR encode: shift right by 24/16/8/0, mask 0xFF, store sequentially
		boolean has24 = p.constants.contains(24L);
		boolean has16 = p.constants.contains(16L);
		boolean has8 = p.constants.contains(8L);
		boolean has0xFF = p.constants.contains(0xFFL);
		if (has24 && has16 && has8) conf += 0.30; // classic byte extraction shifts
		if (has0xFF) conf += 0.15;
		if (p.rights >= 2) conf += 0.10;
		if (p.ands >= 2) conf += 0.10;
		if (p.stores >= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("xdr_encode", "network_byte_encode",
			Math.min(conf, 0.80), "XDR/network byte order encoder");
	}

	private FunctionType detectXdrDecode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// XDR decode: load 4 bytes, shift left by 24/16/8/0, OR together
		boolean has24 = p.constants.contains(24L);
		boolean has16 = p.constants.contains(16L);
		boolean has8 = p.constants.contains(8L);
		if (has24 && has16 && has8) conf += 0.30;
		if (p.lefts >= 2) conf += 0.15; // shift left for assembly
		if (p.ors >= 2) conf += 0.15; // OR bytes together
		if (p.loads >= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("xdr_decode", "network_byte_decode",
			Math.min(conf, 0.80), "XDR/network byte order decoder");
	}

	private FunctionType detectPageTableWalk(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Page table walk: shift address for index, load PTE, check valid bit, mask PFN
		if (p.rights >= 2) conf += 0.20; // extract page directory/table index
		if (p.ands >= 2) conf += 0.15; // mask index, check flags
		if (p.loads >= 3) conf += 0.15; // read PDE, PTE, physical addr
		if (p.cbranches >= 1) conf += 0.10; // valid bit check
		if (p.ors >= 1) conf += 0.10; // combine PFN + offset
		if (p.shifts >= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("page_table_walk", "mmu_pagetable_lookup",
			Math.min(conf, 0.80), "MMU page table walk");
	}

	private FunctionType detectCacheFlush(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Cache flush: loop by cache line size, write to cache control
		if (p.hasLoop) conf += 0.15;
		if (p.callOtherCount >= 1) conf += 0.20; // CPUSH/CINV instructions
		if (p.adds >= 1) conf += 0.10; // address += line_size
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // addr < end
		// Common cache line sizes
		boolean has16 = p.constants.contains(16L);
		boolean has32 = p.constants.contains(32L);
		boolean has64 = p.constants.contains(64L);
		if (has16 || has32 || has64) conf += 0.15;
		if (p.ioRegionAccesses >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("cache_flush", "cache_invalidate",
			Math.min(conf, 0.75), "Cache flush/invalidate routine");
	}

	private FunctionType detectEventSignal(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Event signal: load waiters list, traverse, set run flag
		if (p.loads >= 3) conf += 0.10;
		if (p.stores >= 2) conf += 0.10;
		if (p.hasLoop) conf += 0.15; // traverse waiter list
		if (p.constZeroCompares >= 1) conf += 0.10; // null check (end of list)
		if (p.ors >= 1) conf += 0.10; // set flag bit
		if (p.cbranches >= 1) conf += 0.10;
		if (p.calls >= 1) conf += 0.10; // call scheduler
		if (p.adds >= 1) conf += 0.10; // advance pointer
		if (conf < 0.55) return null;
		return new FunctionType("event_signal", "event_notification",
			Math.min(conf, 0.75), "Event/signal notification");
	}

	private FunctionType detectPathfinding(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 50) return null;
		double conf = 0;
		// A*/BFS/Dijkstra: open set, cost compare, neighbor expansion
		if (p.hasNestedLoop || p.hasLoop) conf += 0.15;
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.15; // cost comparisons
		if (p.adds >= 4) conf += 0.15; // neighbor offset (x+1,x-1,y+1,y-1)
		if (p.loads >= 6) conf += 0.10; // read cost/visited/neighbor arrays
		if (p.stores >= 4) conf += 0.10; // update cost/parent arrays
		if (p.cbranches >= 4) conf += 0.10; // bounds + visited checks
		if (p.calls >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("pathfinding", "pathfind_algorithm",
			Math.min(conf, 0.80), "Pathfinding algorithm (A*/BFS/Dijkstra)");
	}

	private FunctionType detectSaveLoadState(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Serialize: bulk copy of structured data, checksum at end
		if (p.loadStoreAlternations >= 6) conf += 0.25; // copy many fields
		if (p.loads >= 8 && p.stores >= 6) conf += 0.15;
		if (p.hasLoop) conf += 0.10; // array copy
		if (p.adds >= 2) conf += 0.10; // pointer advancement
		if (p.calls >= 1) conf += 0.10; // call to checksum/write
		// Minimal logic
		if (p.cbranches <= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("save_load_state", "state_serializer",
			Math.min(conf, 0.80), "Save/load state serialization");
	}

	private FunctionType detectHighScoreTable(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// High score: compare with table entries, shift entries down, insert
		if (p.hasLoop) conf += 0.15;
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.15; // score comparison
		if (p.loadStoreAlternations >= 3) conf += 0.15; // shift entries
		if (p.loads >= 4) conf += 0.10;
		if (p.stores >= 3) conf += 0.10;
		if (p.subs >= 1) conf += 0.10; // count down
		if (p.cbranches >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("high_score_table", "score_table_insert",
			Math.min(conf, 0.75), "High score table insertion");
	}

	private FunctionType detectDemoPlayback(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Demo/attract: read input from recording buffer, advance frame counter
		if (p.hasLoop) conf += 0.15;
		if (p.loads >= 3) conf += 0.10; // read recorded input + frame counter
		if (p.stores >= 2) conf += 0.10; // write to input registers
		if (p.adds >= 1) conf += 0.10; // increment frame/index
		if (p.equals >= 1) conf += 0.10; // check end marker
		if (p.cbranches >= 2) conf += 0.10; // end check + frame sync
		if (p.calls >= 1) conf += 0.10; // call game update
		if (p.constZeroCompares >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("demo_playback", "attract_mode_replay",
			Math.min(conf, 0.75), "Demo/attract mode input playback");
	}

	private FunctionType detectLcdInit(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// LCD init: many sequential IO writes, delay between commands
		if (p.ioRegionAccesses >= 5) conf += 0.30;
		if (p.consecutiveStores >= 4) conf += 0.20;
		if (p.stores >= 6) conf += 0.10;
		if (p.calls >= 1) conf += 0.10; // delay routine
		if (p.loads <= p.stores / 2) conf += 0.10; // write-heavy
		if (conf < 0.55) return null;
		return new FunctionType("lcd_init", "display_controller_init",
			Math.min(conf, 0.75), "LCD/display controller initialization");
	}

	private FunctionType detectMotorControl(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Stepper/motor: phase sequence, IO writes, step delay
		if (p.ioRegionAccesses >= 2) conf += 0.20;
		if (p.hasLoop) conf += 0.10;
		if (p.stores >= 3) conf += 0.10;
		if (p.constSmallInts >= 3) conf += 0.10; // phase patterns (0-3 or bitmask)
		if (p.ands >= 1) conf += 0.10; // phase masking
		if (p.adds >= 1) conf += 0.10; // step counter
		if (p.calls >= 1) conf += 0.10; // delay between steps
		if (p.cbranches >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("motor_control", "stepper_driver",
			Math.min(conf, 0.75), "Motor/stepper driver control");
	}

	private FunctionType detectKeyboardScan(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Keyboard matrix: drive rows, read columns, build keycode
		if (p.ioRegionAccesses >= 2) conf += 0.20;
		if (p.hasLoop) conf += 0.15; // scan rows
		if (p.shifts >= 1) conf += 0.10; // row select shift
		if (p.ands >= 1) conf += 0.10; // column read mask
		if (p.loads >= 3 && p.stores >= 2) conf += 0.10;
		if (p.adds >= 1) conf += 0.10; // row counter
		if (p.cbranches >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("keyboard_scan", "matrix_key_scanner",
			Math.min(conf, 0.75), "Keyboard matrix scanner");
	}

	private FunctionType detectHmacCompute(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// HMAC: XOR key with ipad/opad, hash(key^ipad || message), hash(key^opad || inner)
		boolean has0x36 = p.constants.contains(0x36L); // ipad
		boolean has0x5C = p.constants.contains(0x5CL); // opad
		if (has0x36 && has0x5C) conf += 0.40; // very distinctive HMAC constants
		if (p.xors >= 2) conf += 0.10;
		if (p.calls >= 2) conf += 0.15; // two hash calls
		if (p.hasLoop) conf += 0.10; // XOR key loop
		if (p.loads >= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("hmac_compute", "hmac_authentication",
			Math.min(conf, 0.85), "HMAC message authentication code");
	}

	private FunctionType detectElfSectionParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// ELF: magic 0x7F454C46, section header iteration, load fields
		boolean has0x7F454C46 = p.constants.contains(0x7F454C46L); // "\x7FELF"
		if (has0x7F454C46) conf += 0.35;
		if (p.hasLoop) conf += 0.10; // iterate sections
		if (p.loads >= 6) conf += 0.10; // read header fields
		if (p.adds >= 2) conf += 0.10; // offset calculations
		if (p.cbranches >= 2) conf += 0.10;
		if (p.calls >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("elf_parser", "elf_section_loader",
			Math.min(conf, 0.80), "ELF/COFF section header parser");
	}

	private FunctionType detectPs2Protocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// PS/2: clock/data bit-bang, 11-bit frame (start, 8 data, parity, stop)
		boolean has11 = p.constants.contains(11L);
		if (has11) conf += 0.15; // 11-bit frame
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.shifts >= 2) conf += 0.15; // bit assembly
		if (p.ands >= 1) conf += 0.10;
		if (p.hasLoop) conf += 0.10; // 8-bit receive loop
		if (p.xors >= 1) conf += 0.10; // parity computation
		if (conf < 0.55) return null;
		return new FunctionType("ps2_protocol", "ps2_keyboard_mouse",
			Math.min(conf, 0.75), "PS/2 keyboard/mouse protocol handler");
	}

	private FunctionType detectGarbageCollectMark(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// GC mark: traverse object graph, set mark bits, recurse/queue
		if (p.hasLoop) conf += 0.15;
		if (p.loads >= 5) conf += 0.10; // read object pointers + fields
		if (p.ands >= 2) conf += 0.10; // check/set mark bit
		if (p.ors >= 1) conf += 0.10; // set mark bit
		if (p.constZeroCompares >= 2) conf += 0.10; // null ptr checks
		if (p.cbranches >= 3) conf += 0.10;
		if (p.calls >= 1) conf += 0.10; // recursive mark or push to worklist
		if (p.stores >= 2) conf += 0.10; // write mark bits + worklist
		if (conf < 0.55) return null;
		return new FunctionType("gc_mark", "garbage_collector_mark",
			Math.min(conf, 0.80), "Garbage collector mark phase");
	}

	private FunctionType detectFramebufferSwap(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Double buffering: swap front/back pointers, update display register
		if (p.loads >= 2) conf += 0.15; // read front + back pointers
		if (p.stores >= 2) conf += 0.15; // swap pointers
		if (p.ioRegionAccesses >= 1) conf += 0.20; // write display base register
		if (p.xors >= 1 || p.adds >= 1) conf += 0.10; // toggle buffer index
		if (p.totalOps < 30) conf += 0.10; // typically very short
		if (p.cbranches <= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("framebuffer_swap", "double_buffer_flip",
			Math.min(conf, 0.75), "Framebuffer double-buffer swap");
	}

	private FunctionType detectVramClear(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// VRAM clear: tight store loop to graphics memory, often via IO register
		if (p.hasLoop) conf += 0.15;
		if (p.stores >= 2) conf += 0.10;
		if (p.ioRegionAccesses >= 2) conf += 0.20;
		if (p.consecutiveStores >= 2) conf += 0.10;
		// Write-heavy, minimal reads
		if (p.stores > p.loads * 2) conf += 0.15;
		if (p.xorSelfOps >= 1) conf += 0.10; // clear register = zero source
		if (p.adds >= 1) conf += 0.05; // counter/address increment
		if (conf < 0.55) return null;
		return new FunctionType("vram_clear", "vram_fill_loop",
			Math.min(conf, 0.75), "VRAM clear/fill loop");
	}

	// ---- Round 8 detectors ----

	private FunctionType detectEepromAccess(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// EEPROM: bit-bang or I2C, address+data writes, polling for ready
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.hasLoop) conf += 0.15; // poll ready or bit-bang
		if (p.shifts >= 1) conf += 0.10; // address/data shifting
		if (p.ands >= 1) conf += 0.10; // status bit mask
		if (p.stores >= 3) conf += 0.10;
		if (p.loads >= 3) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("eeprom_access", "eeprom_read_write",
			Math.min(conf, 0.75), "EEPROM/NVRAM read/write routine");
	}

	private FunctionType detectAdcRead(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// ADC: write start-conversion, poll ready bit, read result
		if (p.ioRegionAccesses >= 2) conf += 0.25;
		if (p.hasLoop) conf += 0.15; // poll conversion complete
		if (p.ands >= 1) conf += 0.10; // mask ready bit or result bits
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 1) conf += 0.10;
		if (p.totalOps < 40) conf += 0.10; // ADC reads are short
		if (conf < 0.55) return null;
		return new FunctionType("adc_read", "adc_conversion",
			Math.min(conf, 0.75), "ADC conversion read");
	}

	private FunctionType detectDacOutput(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;
		double conf = 0;
		// DAC: scale value, write to DAC register
		if (p.ioRegionAccesses >= 1) conf += 0.25;
		if (p.stores >= 1) conf += 0.10;
		if (p.shifts >= 1 || p.mults >= 1) conf += 0.15; // scale
		if (p.ands >= 1) conf += 0.10; // mask to DAC resolution
		if (p.totalOps < 25) conf += 0.15; // typically very short
		if (p.cbranches <= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("dac_output", "dac_write",
			Math.min(conf, 0.70), "DAC output write");
	}

	private FunctionType detectDipSwitchRead(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;
		double conf = 0;
		// DIP switch: single IO read, extract individual bits
		if (p.ioRegionAccesses >= 1) conf += 0.20;
		if (p.ands >= 2) conf += 0.20; // multiple bit extractions
		if (p.loads >= 1) conf += 0.10;
		if (p.shifts >= 1) conf += 0.10; // shift bits to position
		if (p.stores >= 2) conf += 0.10; // store individual flags
		if (p.totalOps < 30) conf += 0.10;
		if (p.calls == 0) conf += 0.10; // no calls, just bit extraction
		if (conf < 0.55) return null;
		return new FunctionType("dip_switch_read", "config_port_read",
			Math.min(conf, 0.75), "DIP switch / config port reader");
	}

	private FunctionType detectCoinHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Coin: edge detect on input, increment credit counter, BCD or saturation
		if (p.ioRegionAccesses >= 1) conf += 0.15;
		if (p.adds >= 1) conf += 0.10; // increment counter
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // max check
		if (p.cbranches >= 2) conf += 0.10;
		if (p.xors >= 1) conf += 0.10; // edge detection (XOR with previous)
		if (p.ands >= 1) conf += 0.10; // isolate coin bit
		if (p.loads >= 2 && p.stores >= 2) conf += 0.10;
		// BCD characteristic
		boolean has0x99 = p.constants.contains(0x99L);
		boolean has0x09 = p.constants.contains(0x09L) || p.constants.contains(9L);
		if (has0x99 || has0x09) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("coin_handler", "credit_coin_insert",
			Math.min(conf, 0.75), "Coin/credit insertion handler");
	}

	private FunctionType detectOsdOverlay(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// OSD: read background, conditionally write overlay pixel
		if (p.hasNestedLoop) conf += 0.20; // row x col
		if (p.loads >= 4) conf += 0.10; // read overlay + background
		if (p.stores >= 2) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.10; // conditional pixel write
		if (p.constZeroCompares >= 1) conf += 0.10; // skip transparent
		if (p.adds >= 2) conf += 0.10; // pointer advancement
		if (p.ands >= 1) conf += 0.05; // transparency mask
		if (conf < 0.55) return null;
		return new FunctionType("osd_overlay", "onscreen_display_blit",
			Math.min(conf, 0.80), "OSD/overlay renderer");
	}

	private FunctionType detectCharGenLookup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Char gen: char code * glyph_height, add ROM base, load scanlines
		if (p.mults >= 1 || p.lefts >= 1) conf += 0.20; // char * height
		if (p.adds >= 1) conf += 0.10; // add base address
		if (p.loads >= 2) conf += 0.15; // load glyph data
		if (p.hasLoop) conf += 0.10; // scanline loop
		if (p.shifts >= 1) conf += 0.10; // extract bits from glyph
		if (p.stores >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("chargen_lookup", "character_generator",
			Math.min(conf, 0.75), "Character generator ROM lookup");
	}

	private FunctionType detectNandFlashRead(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// NAND: write command+address to controller, poll ready, bulk read
		if (p.ioRegionAccesses >= 4) conf += 0.25;
		if (p.consecutiveStores >= 3) conf += 0.15; // command + address bytes
		if (p.hasLoop) conf += 0.15; // data read loop or busy poll
		if (p.loads >= 4) conf += 0.10;
		if (p.stores >= 4) conf += 0.10;
		// NAND command constants: 0x00 (read), 0x30 (confirm), 0xFF (reset)
		boolean has0x30 = p.constants.contains(0x30L);
		boolean has0xFF = p.constants.contains(0xFFL);
		if (has0x30 || has0xFF) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("nand_flash", "nand_page_read",
			Math.min(conf, 0.80), "NAND flash page read");
	}

	private FunctionType detectNewtonRaphson(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Newton-Raphson: x_new = (x + N/x) / 2, iterate until convergence
		if (p.hasLoop) conf += 0.15;
		if (p.divs >= 1) conf += 0.20; // N/x
		if (p.adds >= 1) conf += 0.10; // x + N/x
		if (p.rights >= 1) conf += 0.15; // divide by 2
		if (p.subs >= 1) conf += 0.10; // convergence check: |x_new - x_old|
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // threshold compare
		if (p.loads >= 2 && p.stores >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("newton_raphson", "iterative_root",
			Math.min(conf, 0.80), "Newton-Raphson iterative solver");
	}

	private FunctionType detectEuclideanDistance(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Distance: dx*dx + dy*dy, optional sqrt
		if (p.subs >= 2) conf += 0.20; // dx = x1-x2, dy = y1-y2
		if (p.mults >= 2) conf += 0.25; // dx*dx, dy*dy
		if (p.adds >= 1) conf += 0.10; // sum of squares
		if (p.calls >= 1) conf += 0.10; // call sqrt
		if (p.loads >= 4) conf += 0.10; // load x1,y1,x2,y2
		if (conf < 0.55) return null;
		return new FunctionType("euclidean_distance", "distance_calc",
			Math.min(conf, 0.80), "Euclidean distance calculation");
	}

	private FunctionType detectAtan2Approx(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// atan2: quadrant detection, ratio, polynomial or table lookup
		if (p.divs >= 1) conf += 0.15; // dy/dx ratio
		if (p.cbranches >= 3) conf += 0.15; // quadrant selection (sign checks)
		if (p.mults >= 2) conf += 0.15; // polynomial terms
		if (p.adds >= 2) conf += 0.10;
		if (p.subs >= 1) conf += 0.10; // negate for quadrant
		if (p.sLesses >= 1) conf += 0.10; // sign check
		if (p.loads >= 2) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("atan2_approx", "angle_from_deltas",
			Math.min(conf, 0.80), "atan2 angle approximation");
	}

	private FunctionType detectSigmoidLookup(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Sigmoid: clamp input, index table, interpolate
		if (p.loads >= 2) conf += 0.10;
		if (p.rights >= 1) conf += 0.15; // integer part for index
		if (p.ands >= 1) conf += 0.10; // fractional part mask
		if (p.mults >= 1) conf += 0.15; // interpolation
		if (p.adds >= 1) conf += 0.10;
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // clamp bounds
		if (p.cbranches >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("sigmoid_lookup", "activation_function",
			Math.min(conf, 0.75), "Sigmoid/activation function lookup");
	}

	private FunctionType detectCanBusFrame(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// CAN: pack frame (ID+DLC+data), write to controller, check arbitration
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.consecutiveStores >= 3) conf += 0.15; // write frame fields
		if (p.shifts >= 1) conf += 0.10; // pack ID bits
		if (p.ands >= 1) conf += 0.10;
		if (p.hasLoop) conf += 0.10; // poll transmit complete
		if (p.cbranches >= 2) conf += 0.10; // arbitration check
		if (conf < 0.55) return null;
		return new FunctionType("can_bus", "can_frame_send",
			Math.min(conf, 0.75), "CAN bus frame transmit");
	}

	private FunctionType detectOneWireProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// 1-Wire: precise timing, single IO pin toggle, CRC-8
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.hasLoop) conf += 0.10;
		if (p.shifts >= 2) conf += 0.15; // bit assembly
		if (p.ands >= 1) conf += 0.10;
		if (p.xors >= 1) conf += 0.10; // CRC-8
		if (p.calls >= 1) conf += 0.05; // delay routine
		if (p.stores >= 3) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("onewire_protocol", "onewire_bit_bang",
			Math.min(conf, 0.75), "1-Wire (Dallas) protocol handler");
	}

	private FunctionType detectManchesterCodec(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Manchester: each bit produces 2 transitions, XOR with clock
		if (p.hasLoop) conf += 0.15;
		if (p.xors >= 2) conf += 0.20; // bit XOR for encoding
		if (p.shifts >= 2) conf += 0.15; // shift in/out bits
		if (p.ands >= 1) conf += 0.10;
		if (p.ors >= 1) conf += 0.10; // assemble decoded bits
		if (p.stores >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("manchester_codec", "manchester_encode_decode",
			Math.min(conf, 0.75), "Manchester encoding/decoding");
	}

	private FunctionType detectHdlcFraming(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// HDLC: flag bytes 0x7E, escape 0x7D, CRC-CCITT
		boolean has0x7E = p.constants.contains(0x7EL); // HDLC flag
		boolean has0x7D = p.constants.contains(0x7DL); // HDLC escape
		if (has0x7E) conf += 0.25;
		if (has0x7D) conf += 0.20;
		if (p.xors >= 1) conf += 0.10; // CRC or escape XOR
		if (p.hasLoop) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.10; // flag/escape checks
		if (p.loads >= 2 && p.stores >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("hdlc_framing", "hdlc_frame_handler",
			Math.min(conf, 0.80), "HDLC frame framing/deframing");
	}

	private FunctionType detectIdleWfi(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 5) return null;
		double conf = 0;
		// Idle/WFI: very short, possibly a single halt instruction + branch back
		if (p.callOtherCount >= 1) conf += 0.25; // STOP/HALT/WFI instruction
		if (p.totalOps <= 10) conf += 0.20; // extremely short
		if (p.hasLoop) conf += 0.10;
		if (p.calls == 0) conf += 0.10; // no calls
		if (p.arithmetic == 0) conf += 0.10; // no computation
		if (p.stores <= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("idle_wfi", "idle_loop",
			Math.min(conf, 0.70), "Idle loop / wait-for-interrupt");
	}

	private FunctionType detectIrqPriorityDispatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// IRQ dispatch: read IRQ status, find highest priority, index vector table
		if (p.ioRegionAccesses >= 1) conf += 0.15;
		if (p.shifts >= 1) conf += 0.10; // extract vector number
		if (p.ands >= 1) conf += 0.10; // mask IRQ bits
		if (p.mults >= 1 || p.lefts >= 1) conf += 0.10; // vector * 4
		if (p.loads >= 2) conf += 0.10;
		if (p.branchInds >= 1 || p.callInds >= 1) conf += 0.20; // indirect jump/call to handler
		if (p.adds >= 1) conf += 0.05; // base + offset
		if (conf < 0.55) return null;
		return new FunctionType("irq_dispatch", "interrupt_priority_dispatch",
			Math.min(conf, 0.80), "Interrupt priority dispatch");
	}

	private FunctionType detectExceptionFrameBuild(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Exception frame: save multiple registers to stack
		if (p.consecutiveStores >= 5) conf += 0.30; // save register set
		if (p.stores >= 6) conf += 0.15;
		if (p.loads <= 2) conf += 0.10; // mostly stores
		if (p.arithmetic < p.totalOps / 4) conf += 0.10; // minimal math
		if (p.subs >= 1 || p.adds >= 1) conf += 0.05; // SP adjustment
		if (p.calls >= 1) conf += 0.10; // call actual handler
		if (conf < 0.55) return null;
		return new FunctionType("exception_frame", "exception_frame_builder",
			Math.min(conf, 0.80), "Exception/trap frame builder");
	}

	private FunctionType detectPostMemoryTest(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// POST: write pattern, read back, compare, error if mismatch
		if (p.hasNestedLoop || (p.hasLoop && p.loopCount >= 2)) conf += 0.20;
		if (p.loadStoreAlternations >= 3) conf += 0.15; // write-then-read
		if (p.equals >= 2) conf += 0.15; // verify pattern match
		if (p.cbranches >= 2) conf += 0.10;
		// Test pattern constants: 0xAAAA, 0x5555, 0xFFFF
		boolean hasAA = p.constants.contains(0xAAAAL) || p.constants.contains(0xAAAAAAAAL);
		boolean has55 = p.constants.contains(0x5555L) || p.constants.contains(0x55555555L);
		if (hasAA || has55) conf += 0.20;
		if (conf < 0.55) return null;
		return new FunctionType("post_memory", "post_ram_test",
			Math.min(conf, 0.80), "POST memory pattern test");
	}

	private FunctionType detectAiDecisionTree(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// AI: many comparisons against thresholds, cascading branches
		if (p.cbranch_eq_runs >= 4) conf += 0.15;
		if (p.sLesses >= 3 || p.lesses >= 3) conf += 0.20; // threshold checks
		if (p.loads >= 5) conf += 0.10; // read game state variables
		if (p.cbranches >= 5) conf += 0.15; // many decision points
		if (p.calls >= 2) conf += 0.10; // call behavior handlers
		if (p.subs >= 2) conf += 0.10; // distance/difference calculations
		if (conf < 0.55) return null;
		return new FunctionType("ai_decision", "ai_behavior_selector",
			Math.min(conf, 0.80), "AI decision tree / behavior selector");
	}

	private FunctionType detectContinueCountdown(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Continue countdown: decrement timer, check zero, trigger game over
		if (p.subs >= 1) conf += 0.15; // decrement
		if (p.constZeroCompares >= 1) conf += 0.20; // check if timer expired
		if (p.cbranches >= 1) conf += 0.10;
		if (p.loads >= 1 && p.stores >= 1) conf += 0.10;
		if (p.calls >= 1) conf += 0.10; // call game-over or display update
		if (p.totalOps < 30) conf += 0.10; // typically small
		// Often has a constant like 9 or 10 (seconds)
		boolean has10 = p.constants.contains(10L);
		boolean has9 = p.constants.contains(9L);
		if (has10 || has9) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("continue_countdown", "gameover_timer",
			Math.min(conf, 0.70), "Continue countdown / game-over timer");
	}

	private FunctionType detectInterlaceToggle(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;
		double conf = 0;
		// Interlace: toggle field bit, update display base address
		if (p.xors >= 1) conf += 0.20; // toggle field flag
		if (p.ioRegionAccesses >= 1) conf += 0.20;
		if (p.stores >= 1) conf += 0.10;
		if (p.ands >= 1) conf += 0.10; // mask field bit
		if (p.adds >= 1) conf += 0.10; // offset for odd/even field
		if (p.totalOps < 20) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("interlace_toggle", "field_toggle",
			Math.min(conf, 0.70), "Interlace field toggle");
	}

	private FunctionType detectWearLeveling(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Wear leveling: scan erase counts, find minimum, remap
		if (p.hasLoop) conf += 0.15;
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.15; // find minimum count
		if (p.loads >= 4) conf += 0.10; // read erase count array
		if (p.stores >= 2) conf += 0.10; // update mapping
		if (p.adds >= 1) conf += 0.10; // increment erase count
		if (p.cbranches >= 2) conf += 0.10;
		if (p.calls >= 1) conf += 0.10; // call erase or write
		if (conf < 0.55) return null;
		return new FunctionType("wear_leveling", "flash_wear_level",
			Math.min(conf, 0.80), "Flash wear leveling / block rotation");
	}

	private FunctionType detectBadBlockScan(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Bad block: iterate blocks, read marker byte, check 0xFF, update table
		if (p.hasLoop) conf += 0.15;
		if (p.loads >= 3) conf += 0.10;
		boolean has0xFF = p.constants.contains(0xFFL);
		if (has0xFF) conf += 0.15; // good block marker
		if (p.equals >= 1 || p.notEquals >= 1) conf += 0.10;
		if (p.cbranches >= 2) conf += 0.10;
		if (p.ors >= 1 || p.ands >= 1) conf += 0.10; // set bit in bitmap
		if (p.stores >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("bad_block_scan", "nand_bad_block_table",
			Math.min(conf, 0.75), "NAND bad block table scan");
	}

	private FunctionType detectRandomLevelGen(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Random level: RNG call, modulo for grid bounds, store to level array
		if (p.hasLoop || p.hasNestedLoop) conf += 0.15;
		if (p.calls >= 2) conf += 0.10; // RNG + placement
		if (p.rems >= 1 || p.powerOf2Masks >= 1) conf += 0.15; // constrain to bounds
		if (p.stores >= 4) conf += 0.10; // write to level array
		if (p.loads >= 3) conf += 0.10;
		if (p.adds >= 2) conf += 0.10; // array indexing
		if (p.cbranches >= 2) conf += 0.10; // bounds/collision checks
		if (conf < 0.55) return null;
		return new FunctionType("random_level_gen", "procedural_level",
			Math.min(conf, 0.75), "Random/procedural level generator");
	}

	private FunctionType detectInputRecording(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Input recording: read controller, store to ring buffer, advance index
		if (p.ioRegionAccesses >= 1) conf += 0.15;
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 2) conf += 0.10;
		if (p.adds >= 1) conf += 0.10; // advance buffer index
		if (p.rems >= 1 || p.powerOf2Masks >= 1) conf += 0.20; // ring buffer wrap
		if (p.hasLoop) conf += 0.10;
		if (p.totalOps < 40) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("input_recording", "input_record_buffer",
			Math.min(conf, 0.75), "Input recording to ring buffer");
	}

	private FunctionType detectThermalPrinter(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Thermal printer: command bytes interleaved with text data
		if (p.ioRegionAccesses >= 2) conf += 0.20;
		if (p.hasLoop) conf += 0.10;
		if (p.constAsciiCompares >= 1) conf += 0.10;
		boolean has0x1B = p.constants.contains(0x1BL); // ESC command prefix
		boolean has0x0A = p.constants.contains(0x0AL); // LF
		if (has0x1B) conf += 0.15;
		if (has0x0A) conf += 0.10;
		if (p.loads >= 3) conf += 0.10;
		if (p.stores >= 2) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("thermal_printer", "printer_command",
			Math.min(conf, 0.75), "Thermal/receipt printer command handler");
	}

	private FunctionType detectWeightTare(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Tare: average N ADC readings, store as offset
		if (p.hasLoop) conf += 0.15;
		if (p.adds >= 2) conf += 0.15; // accumulate readings
		if (p.divs >= 1 || p.rights >= 1) conf += 0.20; // divide for average
		if (p.ioRegionAccesses >= 1) conf += 0.10; // ADC read
		if (p.loads >= 2) conf += 0.10;
		if (p.stores >= 1) conf += 0.10; // store tare offset
		if (conf < 0.55) return null;
		return new FunctionType("weight_tare", "scale_zero_calibrate",
			Math.min(conf, 0.75), "Weight scale tare / zero calibration");
	}

	private FunctionType detectFuelInjection(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Fuel injection: read sensors, multiply/scale, clamp to pulse range
		if (p.ioRegionAccesses >= 2) conf += 0.15;
		if (p.mults >= 2) conf += 0.15; // scaling
		if (p.divs >= 1) conf += 0.10;
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // clamp
		if (p.loads >= 3) conf += 0.10; // sensor + calibration values
		if (p.stores >= 2) conf += 0.10; // output to PWM/timer
		if (p.cbranches >= 2) conf += 0.10; // min/max bounds
		if (conf < 0.55) return null;
		return new FunctionType("fuel_injection", "injection_timing",
			Math.min(conf, 0.75), "Fuel injection timing computation");
	}

	private FunctionType detectBarcodeDecode(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		double conf = 0;
		// Barcode: read bitstream, group into characters, table lookup, checksum
		if (p.hasLoop) conf += 0.10;
		if (p.loads >= 4) conf += 0.10;
		if (p.shifts >= 2) conf += 0.10;
		if (p.ands >= 2) conf += 0.10;
		if (p.adds >= 2) conf += 0.10; // accumulate checksum
		if (p.rems >= 1) conf += 0.10; // modulo for check digit
		if (p.cbranches >= 3) conf += 0.10; // validate characters
		// Barcode digit count constants
		boolean has12 = p.constants.contains(12L);
		boolean has13 = p.constants.contains(13L);
		if (has12 || has13) conf += 0.10; // EAN-12 or EAN-13
		if (conf < 0.55) return null;
		return new FunctionType("barcode_decode", "barcode_scanner",
			Math.min(conf, 0.75), "Barcode scanner decode");
	}

	private FunctionType detectJtagBoundaryScan(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// JTAG: TDI/TDO/TMS/TCK bit-bang, shift register loop
		if (p.ioRegionAccesses >= 3) conf += 0.20;
		if (p.hasLoop) conf += 0.15;
		if (p.shifts >= 2) conf += 0.15; // shift in/out
		if (p.ands >= 2) conf += 0.10;
		if (p.ors >= 1) conf += 0.10; // assemble TDO
		if (p.stores >= 3) conf += 0.10; // toggle TCK, write TDI/TMS
		if (conf < 0.55) return null;
		return new FunctionType("jtag_boundary", "jtag_scan_chain",
			Math.min(conf, 0.75), "JTAG boundary scan chain");
	}

	private FunctionType detectBusArbitrationTest(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Bus test: attempt access to unmapped address, catch timeout
		if (p.loads >= 1) conf += 0.10;
		if (p.stores >= 2) conf += 0.10; // set exception handler + probe
		if (p.cbranches >= 1) conf += 0.10;
		if (p.hasTrapOp || p.callOtherCount >= 1) conf += 0.15;
		if (p.constZeroCompares >= 1) conf += 0.10;
		if (p.ands >= 1) conf += 0.10; // flag check
		if (p.totalOps < 35) conf += 0.10;
		if (p.ioRegionAccesses >= 1) conf += 0.10;
		if (conf < 0.55) return null;
		return new FunctionType("bus_test", "bus_probe_timeout",
			Math.min(conf, 0.75), "Bus probe / timeout detection test");
	}

	private FunctionType detectMpuRegionConfig(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// MPU region: write base, size, permissions to MPU registers
		if (p.ioRegionAccesses >= 3) conf += 0.25;
		if (p.consecutiveStores >= 3) conf += 0.20; // base + size + perms
		if (p.ors >= 1 || p.ands >= 1) conf += 0.10; // permission bit assembly
		if (p.stores >= 3) conf += 0.10;
		if (p.totalOps < 30) conf += 0.10;
		if (p.loads <= 2) conf += 0.10; // mostly writes
		if (conf < 0.55) return null;
		return new FunctionType("mpu_config", "mpu_region_setup",
			Math.min(conf, 0.75), "MPU/MMU region configuration");
	}

	// New detectors: Network, Crypto, DSP, Embedded, Graphics, Parsers, OS, Math, String, Game, Compression

	/**
	 * DNS resolver: parses DNS packets. Expects port 53 (0x35), label-length
	 * prefixed domain names, query/response flags via shifts and masks.
	 */
	private FunctionType detectDnsResolver(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.loads < 5) return null;
		if (p.compares < 3) return null;

		boolean hasPort53 = p.constants.contains(53L) || p.constants.contains(0x35L);
		boolean hasDnsFlags = p.constants.contains(0x8000L) || p.constants.contains(0x0F00L);
		boolean hasLabelParse = p.hasLoop && p.loads >= 8 && p.adds >= 2;

		if (!hasPort53 && !hasDnsFlags) return null;

		double conf = 0.40;
		if (hasPort53) conf += 0.15;
		if (hasDnsFlags) conf += 0.10;
		if (hasLabelParse) conf += 0.15;
		if (p.constAsciiCompares > 0) conf += 0.05; // dot separators
		if (p.ands >= 2) conf += 0.05; // flag extraction
		if (p.shifts >= 1) conf += 0.05; // QR/opcode field shifts

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "dns_resolver",
			Math.min(conf, 0.75),
			"DNS packet parsing or resolution (port 53 protocol)");
	}

	/**
	 * DHCP client: constructs or parses DHCP packets with magic cookie
	 * 0x63825363, option TLV encoding, and broadcast behavior.
	 */
	private FunctionType detectDhcpClient(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		if (p.stores < 5) return null;

		boolean hasMagicCookie = p.constants.contains(0x63825363L);
		boolean hasPort67 = p.constants.contains(67L) || p.constants.contains(68L);
		boolean hasBroadcast = p.constants.contains(0xFFFFFFFFL);

		if (!hasMagicCookie && !hasPort67) return null;

		double conf = 0.40;
		if (hasMagicCookie) conf += 0.25;
		if (hasPort67) conf += 0.10;
		if (hasBroadcast) conf += 0.05;
		if (p.consecutiveStores >= 4) conf += 0.10; // filling packet fields
		if (p.hasLoop) conf += 0.05; // option iteration
		if (p.loads >= 3) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "dhcp_client",
			Math.min(conf, 0.75),
			"DHCP client packet build/parse (magic cookie 0x63825363)");
	}

	/**
	 * HTTP parser: heavy ASCII character comparisons for header fields,
	 * CR/LF detection, method/status code parsing.
	 */
	private FunctionType detectHttpParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		if (p.compares < 5) return null;
		if (p.cbranches < 4) return null;

		boolean hasCR = p.constants.contains(0x0DL);
		boolean hasLF = p.constants.contains(0x0AL);
		boolean hasSpace = p.constants.contains(0x20L);
		boolean hasColon = p.constants.contains(0x3AL);
		boolean hasHttpConst = p.constants.contains(0x48L) || // 'H'
			p.constants.contains(200L) || p.constants.contains(404L);

		int httpChars = (hasCR ? 1 : 0) + (hasLF ? 1 : 0) +
			(hasSpace ? 1 : 0) + (hasColon ? 1 : 0);
		if (httpChars < 2 && !hasHttpConst) return null;

		double conf = 0.35;
		if (httpChars >= 3) conf += 0.20;
		if (hasHttpConst) conf += 0.10;
		if (p.constAsciiCompares >= 4) conf += 0.15;
		if (p.hasLoop) conf += 0.05;
		if (p.loads >= 6) conf += 0.05;
		if (p.loadStoreAlternations >= 3) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "http_parser",
			Math.min(conf, 0.75),
			"HTTP protocol header parsing (CR/LF delimited fields)");
	}

	/**
	 * SMTP handler: command/response state machine with ASCII char compares,
	 * numeric reply codes (2xx/3xx/4xx/5xx), line-oriented processing.
	 */
	private FunctionType detectSmtpHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		if (p.compares < 4) return null;
		if (p.cbranches < 3) return null;

		boolean hasCRLF = p.constants.contains(0x0DL) && p.constants.contains(0x0AL);
		boolean hasReplyCode = p.constants.contains(250L) || p.constants.contains(220L) ||
			p.constants.contains(354L) || p.constants.contains(550L);
		boolean hasPort25 = p.constants.contains(25L);

		if (!hasCRLF && !hasReplyCode && !hasPort25) return null;

		double conf = 0.35;
		if (hasCRLF) conf += 0.10;
		if (hasReplyCode) conf += 0.20;
		if (hasPort25) conf += 0.10;
		if (p.constAsciiCompares >= 3) conf += 0.10;
		if (p.cbranch_eq_runs >= 2) conf += 0.10; // state machine transitions
		if (p.calls >= 2) conf += 0.05; // send/recv calls

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "smtp_handler",
			Math.min(conf, 0.75),
			"SMTP protocol handler (command/reply state machine)");
	}

	/**
	 * TFTP client: simple block-based transfer protocol. Few states,
	 * block numbers, opcode constants (1-5), 512-byte blocks.
	 */
	private FunctionType detectTftpClient(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.loads < 3 || p.stores < 2) return null;

		boolean hasBlockSize = p.constants.contains(512L) || p.constants.contains(0x200L);
		boolean hasPort69 = p.constants.contains(69L);
		boolean hasOpcodes = p.constants.contains(1L) && p.constants.contains(4L); // RRQ + ACK

		if (!hasBlockSize && !hasPort69) return null;

		double conf = 0.40;
		if (hasBlockSize) conf += 0.15;
		if (hasPort69) conf += 0.15;
		if (hasOpcodes) conf += 0.05;
		if (p.compares >= 2) conf += 0.05;
		if (p.hasLoop) conf += 0.10; // block retry/receive loop
		if (p.calls >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "tftp_client",
			Math.min(conf, 0.75),
			"TFTP client (block-based file transfer)");
	}

	/**
	 * NTP time synchronization: 48-byte packet, timestamp fractions with
	 * shift operations, epoch constants.
	 */
	private FunctionType detectNtpSync(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.shifts < 2) return null;

		boolean hasNtpPort = p.constants.contains(123L);
		boolean hasPktSize = p.constants.contains(48L);
		boolean hasEpochDelta = p.constants.contains(2208988800L); // NTP epoch offset
		boolean hasVersion = p.constants.contains(0x1BL) || p.constants.contains(0x23L);

		if (!hasNtpPort && !hasPktSize && !hasEpochDelta) return null;

		double conf = 0.35;
		if (hasNtpPort) conf += 0.15;
		if (hasPktSize) conf += 0.10;
		if (hasEpochDelta) conf += 0.25;
		if (hasVersion) conf += 0.10;
		if (p.lefts >= 1 && p.rights >= 1) conf += 0.10; // timestamp fraction math
		if (p.subs >= 1) conf += 0.05; // time difference

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "ntp_sync",
			Math.min(conf, 0.75),
			"NTP time synchronization (48-byte packet, timestamp math)");
	}

	/**
	 * PPP/HDLC framing: byte stuffing with flag (0x7E) and escape (0x7D)
	 * characters, FCS/CRC computation.
	 */
	private FunctionType detectPppFraming(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (!p.hasLoop) return null;
		if (p.loads < 3) return null;

		boolean hasFlag = p.constants.contains(0x7EL);
		boolean hasEscape = p.constants.contains(0x7DL);
		boolean hasXorMask = p.constants.contains(0x20L); // byte unstuffing XOR

		if (!hasFlag) return null;

		double conf = 0.40;
		if (hasFlag) conf += 0.10;
		if (hasEscape) conf += 0.15;
		if (hasXorMask && p.xors >= 1) conf += 0.15;
		if (p.cbranches >= 2) conf += 0.05; // flag/escape detection branches
		if (p.compares >= 3) conf += 0.05;
		if (p.stores >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "ppp_framing",
			Math.min(conf, 0.75),
			"PPP/HDLC byte stuffing and framing (0x7E/0x7D)");
	}

	/**
	 * Telnet protocol: IAC byte (0xFF) detection, option negotiation
	 * commands (WILL/WONT/DO/DONT), subnegotiation.
	 */
	private FunctionType detectTelnetProtocol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.compares < 3) return null;
		if (p.cbranches < 3) return null;

		boolean hasIAC = p.constants.contains(0xFFL);
		boolean hasWill = p.constants.contains(0xFBL);
		boolean hasWont = p.constants.contains(0xFCL);
		boolean hasDo = p.constants.contains(0xFDL);
		boolean hasDont = p.constants.contains(0xFEL);
		boolean hasPort23 = p.constants.contains(23L);

		int optionCmds = (hasWill ? 1 : 0) + (hasWont ? 1 : 0) +
			(hasDo ? 1 : 0) + (hasDont ? 1 : 0);
		if (!hasIAC && optionCmds < 2 && !hasPort23) return null;

		double conf = 0.35;
		if (hasIAC) conf += 0.15;
		if (optionCmds >= 2) conf += 0.20;
		if (hasPort23) conf += 0.10;
		if (p.hasLoop) conf += 0.05;
		if (p.loads >= 4) conf += 0.05;
		if (p.cbranch_eq_runs >= 2) conf += 0.05; // command dispatch

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "telnet_protocol",
			Math.min(conf, 0.75),
			"Telnet protocol handler (IAC option negotiation)");
	}

	/**
	 * SNMP agent: ASN.1 BER tag-length-value encoding, OID tree
	 * traversal with nested loops, community string comparison.
	 */
	private FunctionType detectSnmpAgent(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		if (p.loads < 5) return null;
		if (p.compares < 4) return null;

		// ASN.1 BER type tags
		boolean hasSequence = p.constants.contains(0x30L);
		boolean hasInteger = p.constants.contains(0x02L);
		boolean hasOctetStr = p.constants.contains(0x04L);
		boolean hasOID = p.constants.contains(0x06L);
		boolean hasPort161 = p.constants.contains(161L) || p.constants.contains(162L);

		int berTags = (hasSequence ? 1 : 0) + (hasInteger ? 1 : 0) +
			(hasOctetStr ? 1 : 0) + (hasOID ? 1 : 0);
		if (berTags < 2 && !hasPort161) return null;

		double conf = 0.35;
		if (berTags >= 3) conf += 0.20;
		else if (berTags >= 2) conf += 0.10;
		if (hasPort161) conf += 0.15;
		if (p.hasLoop) conf += 0.05; // OID walk
		if (p.cbranch_eq_runs >= 3) conf += 0.10; // tag dispatch
		if (p.ands >= 1) conf += 0.05; // length decoding

		if (conf < 0.55) return null;

		return new FunctionType("network_protocol", "snmp_agent",
			Math.min(conf, 0.75),
			"SNMP agent (ASN.1 BER encoding, OID tree traversal)");
	}

	/**
	 * UDP checksum: 16-bit one's complement sum over pseudo-header and data.
	 * Characterized by add-with-carry in a loop, final complement.
	 */
	private FunctionType detectUdpChecksum(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 200) return null;
		if (p.adds < 3) return null;

		// One's complement: add, carry detect (shift right 16), fold
		boolean hasFold = p.constants.contains(0xFFFFL) || p.hasShiftByConst16;
		boolean hasComplement = p.negates > 0 || p.xors >= 1;

		if (!hasFold) return null;

		double conf = 0.40;
		if (hasFold) conf += 0.15;
		if (hasComplement) conf += 0.15; // final NOT
		if (p.rights >= 1) conf += 0.10; // carry fold shift
		if (p.loads >= 3) conf += 0.05; // reading packet data
		if (p.calls == 0) conf += 0.05; // pure computation
		if (p.ands >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("checksum", "udp_checksum",
			Math.min(conf, 0.75),
			"UDP/IP one's complement checksum (16-bit fold + complement)");
	}

	/**
	 * AES round: S-box table lookup, ShiftRows byte permutation,
	 * MixColumns GF(2^8) multiply, AddRoundKey XOR. Minimum 10 rounds.
	 */
	private FunctionType detectAesRound(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 80) return null;
		if (p.xors < 8) return null;
		if (p.loads < 10) return null;

		boolean hasAesConst = p.constants.contains(0x1BL); // GF(2^8) reduction polynomial
		boolean has256 = p.constants.contains(256L) || p.constants.contains(0x100L);
		boolean hasBlockSize = p.constants.contains(16L);

		double xorFrac = p.xors / (double) p.totalOps;

		double conf = 0.35;
		if (hasAesConst) conf += 0.25; // strong AES indicator
		if (xorFrac >= 0.10) conf += 0.10;
		if (has256) conf += 0.05; // S-box size
		if (hasBlockSize) conf += 0.05;
		if (p.hasLoop) conf += 0.05;
		if (p.ands >= 4) conf += 0.05; // byte masking
		if (p.lefts >= 2) conf += 0.05; // ShiftRows/MixColumns shifts

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "aes_round",
			Math.min(conf, 0.75),
			"AES cipher (S-box lookup, MixColumns GF multiply, XOR key)");
	}

	/**
	 * DES round: 8 S-box lookups via table, initial/final permutations,
	 * Feistel network XOR, expansion permutation.
	 */
	private FunctionType detectDesRound(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 60) return null;
		if (p.xors < 4) return null;
		if (p.shifts < 6) return null;

		boolean has0x3F = p.constants.contains(0x3FL); // 6-bit S-box index mask
		boolean has48 = p.constants.contains(48L); // expansion output bits
		boolean has28 = p.constants.contains(28L); // key schedule half size

		double conf = 0.35;
		if (has0x3F) conf += 0.20; // S-box index masking
		if (has48 || has28) conf += 0.10;
		if (p.ands >= 6) conf += 0.10; // bit field extraction
		if (p.loads >= 8) conf += 0.10; // S-box table lookups
		if (p.hasLoop) conf += 0.05; // 16 round iterations
		if (p.rights >= 3 && p.lefts >= 3) conf += 0.10; // permutation shifts

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "des_round",
			Math.min(conf, 0.75),
			"DES cipher (8 S-box lookups, Feistel network, permutations)");
	}

	/**
	 * SHA-256 round: 64 rounds of Ch/Maj/Sigma functions. Heavy on
	 * right-rotates (implemented as shift pairs), XOR, and ADD.
	 */
	private FunctionType detectSha256Round(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 100) return null;
		if (p.adds < 15) return null;
		if (p.xors < 10) return null;
		if (p.shifts < 12) return null;

		// SHA-256 rotation constants
		boolean has2 = p.constants.contains(2L);
		boolean has13 = p.constants.contains(13L);
		boolean has22 = p.constants.contains(22L);
		boolean has6 = p.constants.contains(6L);
		boolean has11 = p.constants.contains(11L);
		boolean has25 = p.constants.contains(25L);

		int rotConsts = (has2 ? 1 : 0) + (has13 ? 1 : 0) + (has22 ? 1 : 0) +
			(has6 ? 1 : 0) + (has11 ? 1 : 0) + (has25 ? 1 : 0);

		if (rotConsts < 3) return null;

		double conf = 0.40;
		if (rotConsts >= 5) conf += 0.25;
		else if (rotConsts >= 4) conf += 0.20;
		else conf += 0.10;
		if (p.ands >= 4) conf += 0.05; // Ch function
		if (p.ors >= 2) conf += 0.05; // rotation combine
		if (p.hasLoop) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "sha256_round",
			Math.min(conf, 0.75),
			"SHA-256 hash (Ch/Maj/Sigma with rotation constants)");
	}

	/**
	 * MD5 round: F/G/H/I auxiliary functions, 64 steps, left-rotate by
	 * per-round constants (7,12,17,22 etc.), additive constants.
	 */
	private FunctionType detectMd5Round(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 80) return null;
		if (p.adds < 10) return null;

		// MD5 rotation amounts
		boolean has7 = p.constants.contains(7L);
		boolean has12 = p.constants.contains(12L);
		boolean has17 = p.constants.contains(17L);
		boolean has22 = p.constants.contains(22L);
		boolean has5 = p.constants.contains(5L);

		// MD5 additive constant (first round constant d76aa478)
		boolean hasMd5Const = p.constants.contains(0xD76AA478L) ||
			p.constants.contains(0xE8C7B756L) || p.constants.contains(0x67452301L);

		int rotConsts = (has7 ? 1 : 0) + (has12 ? 1 : 0) + (has17 ? 1 : 0) +
			(has22 ? 1 : 0) + (has5 ? 1 : 0);

		if (rotConsts < 3 && !hasMd5Const) return null;

		double conf = 0.35;
		if (hasMd5Const) conf += 0.30;
		if (rotConsts >= 4) conf += 0.15;
		else if (rotConsts >= 3) conf += 0.10;
		if (p.ors >= 2) conf += 0.05; // F/G/H/I functions
		if (p.ands >= 2) conf += 0.05;
		if (p.xors >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "md5_round",
			Math.min(conf, 0.75),
			"MD5 hash (F/G/H/I functions, 64 steps with rotation constants)");
	}

	/**
	 * RC4 cipher: KSA phase initializes 256-byte identity permutation
	 * then swaps; PRGA phase swaps and outputs keystream byte.
	 */
	private FunctionType detectRc4Cipher(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 30) return null;
		if (p.loads < 4) return null;
		if (p.stores < 3) return null;

		boolean has256 = p.constants.contains(256L) || p.constants.contains(0x100L);
		boolean has0xFF = p.constants.contains(0xFFL);

		if (!has256 && !has0xFF) return null;

		// RC4: swap pattern (load a[i], load a[j], store a[j]<-a[i], store a[i]<-a[j])
		double memBal = Math.min(p.loads, p.stores) / (double) Math.max(p.loads, p.stores);

		double conf = 0.40;
		if (has256) conf += 0.10;
		if (has0xFF) conf += 0.10;
		if (memBal >= 0.5) conf += 0.10; // balanced load/store for swaps
		if (p.adds >= 2) conf += 0.05; // index arithmetic
		if (p.loadStoreAlternations >= 3) conf += 0.10; // swap pattern
		if (p.loopCount >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "rc4_cipher",
			Math.min(conf, 0.75),
			"RC4 stream cipher (256-byte permutation swap loop)");
	}

	/**
	 * ChaCha20: quarter-round operations consisting of 32-bit add, XOR,
	 * and left-rotate by 16/12/8/7. State is 16 x 32-bit words.
	 */
	private FunctionType detectChaCha20(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 80) return null;
		if (p.adds < 8) return null;
		if (p.xors < 8) return null;
		if (p.shifts < 8) return null;

		boolean has16 = p.constants.contains(16L);
		boolean has12 = p.constants.contains(12L);
		boolean has8 = p.constants.contains(8L);
		boolean has7 = p.constants.contains(7L);

		int qrConsts = (has16 ? 1 : 0) + (has12 ? 1 : 0) + (has8 ? 1 : 0) + (has7 ? 1 : 0);
		if (qrConsts < 3) return null;

		double addXorRatio = Math.min(p.adds, p.xors) / (double) Math.max(p.adds, p.xors);

		double conf = 0.40;
		if (qrConsts == 4) conf += 0.20;
		else conf += 0.10;
		if (addXorRatio >= 0.5) conf += 0.10; // balanced add/xor
		if (p.ors >= 2) conf += 0.05; // rotate combine
		if (p.hasLoop) conf += 0.05; // 20 rounds
		if (p.lefts >= 4) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("crypto", "chacha20",
			Math.min(conf, 0.75),
			"ChaCha20 cipher (quarter-round add/xor/rotate pattern)");
	}

	/**
	 * FIR filter: multiply-accumulate in a loop with coefficient table.
	 * Load coefficient, load sample, multiply, accumulate, advance.
	 */
	private FunctionType detectFirFilter(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 25) return null;
		if (p.mults < 2 && p.floatMults < 2) return null;
		if (p.adds < 2 && p.floatAdds < 2) return null;

		// MAC pattern: load coeff, load sample, multiply, add to accum
		boolean hasMACloop = false;
		for (int i = 0; i < pcode.length - 3; i++) {
			int op0 = pcode[i].getOpcode();
			int op1 = pcode[i+1].getOpcode();
			int op2 = pcode[i+2].getOpcode();
			if (op0 == PcodeOp.LOAD &&
				(op1 == PcodeOp.INT_MULT || op1 == PcodeOp.FLOAT_MULT) &&
				(op2 == PcodeOp.INT_ADD || op2 == PcodeOp.FLOAT_ADD)) {
				hasMACloop = true;
				break;
			}
		}

		double conf = 0.35;
		if (hasMACloop) conf += 0.25;
		if (p.loads >= 4) conf += 0.05; // two arrays: coefficients + samples
		if (p.calls == 0) conf += 0.05; // pure computation
		if (!p.hasNestedLoop) conf += 0.10; // single loop (vs. convolution)
		if (p.stores <= 3) conf += 0.05; // few outputs

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "fir_filter",
			Math.min(conf, 0.75),
			"FIR filter (multiply-accumulate loop with coefficient table)");
	}

	/**
	 * IIR filter: like FIR but with feedback path. Multiply-accumulate
	 * with both input and output history (state variables), more stores.
	 */
	private FunctionType detectIirFilter(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 30) return null;
		if (p.mults < 3 && p.floatMults < 3) return null;
		if (p.adds < 2 && p.floatAdds < 2) return null;
		if (p.stores < 3) return null;

		// IIR: more stores than FIR because state update; subs for feedback
		int totalMults = p.mults + p.floatMults;
		int totalAdds = p.adds + p.subs + p.floatAdds + p.floatSubs;

		double conf = 0.35;
		if (totalMults >= 4) conf += 0.10;
		if (p.subs >= 1 || p.floatSubs >= 1) conf += 0.15; // feedback subtraction
		if (p.stores >= 4) conf += 0.10; // state variable updates
		if (p.loads >= 6) conf += 0.05;
		if (p.calls == 0) conf += 0.05;
		if (totalAdds >= 4) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "iir_filter",
			Math.min(conf, 0.75),
			"IIR filter (multiply-accumulate with feedback state variables)");
	}

	/**
	 * Moving average: circular buffer with modulo index wrapping,
	 * running sum update, divide by window size N.
	 */
	private FunctionType detectMovingAverage(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20) return null;
		if (p.adds < 2) return null;
		if (p.loads < 2) return null;

		boolean hasDivide = p.divs > 0 || p.hasMultThenShift;
		boolean hasModulo = p.rems > 0 || (p.ands >= 1 && p.powerOf2Masks > 0);

		if (!hasDivide) return null;

		double conf = 0.40;
		if (hasDivide) conf += 0.10;
		if (hasModulo) conf += 0.15; // circular buffer wrapping
		if (p.subs >= 1) conf += 0.10; // subtract oldest, add newest
		if (p.stores >= 2) conf += 0.05;
		if (p.calls == 0) conf += 0.05;
		if (p.totalOps < 80) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "moving_average",
			Math.min(conf, 0.75),
			"Moving average filter (circular buffer, divide by window size)");
	}

	/**
	 * Median filter: sorting/comparison network over small window.
	 * Heavy on compares and conditional swaps, few arithmetic ops.
	 */
	private FunctionType detectMedianFilter(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.compares < 5) return null;
		if (p.cbranches < 4) return null;

		// Median: compare-heavy with swap (load/store pairs)
		double compareFrac = p.compares / (double) p.totalOps;
		double arithFrac = (p.adds + p.mults) / (double) p.totalOps;

		if (compareFrac < 0.10) return null;

		double conf = 0.35;
		if (compareFrac >= 0.15) conf += 0.20;
		if (arithFrac < 0.05) conf += 0.10; // mostly compares, little arithmetic
		if (p.loadStoreAlternations >= 3) conf += 0.10; // swap operations
		if (p.loads >= 5 && p.stores >= 3) conf += 0.05;
		if (p.sLesses > 0 || p.lesses > 0) conf += 0.05;
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "median_filter",
			Math.min(conf, 0.75),
			"Median filter (comparison network, conditional swaps)");
	}

	/**
	 * Zero crossing detector: detects sign changes in a signal.
	 * XOR or sign-bit check on consecutive samples, increment counter.
	 */
	private FunctionType detectZeroCrossing(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 20 || p.totalOps > 150) return null;
		if (p.compares < 2) return null;
		if (p.loads < 3) return null;

		// Sign change: compare to zero, or XOR and check sign bit
		boolean hasSignCheck = p.constZeroCompares >= 2 ||
			(p.xors >= 1 && p.rights >= 1); // XOR then shift to get sign
		boolean hasCounter = p.adds >= 1 && p.cbranches >= 2;

		if (!hasSignCheck) return null;

		double conf = 0.40;
		if (hasSignCheck) conf += 0.15;
		if (hasCounter) conf += 0.10;
		if (p.sLesses > 0) conf += 0.10; // signed comparison for sign detect
		if (p.totalOps < 80) conf += 0.05;
		if (p.calls == 0) conf += 0.05;
		if (p.consecutiveLoads >= 2) conf += 0.05; // load consecutive samples

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "zero_crossing",
			Math.min(conf, 0.75),
			"Zero crossing detector (sign change detection, event counter)");
	}

	/**
	 * Convolution: nested loop multiply-accumulate. Outer loop over
	 * output samples, inner loop over kernel.
	 */
	private FunctionType detectConvolution(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasNestedLoop) return null;
		if (p.totalOps < 35) return null;
		if (p.mults < 2 && p.floatMults < 2) return null;
		if (p.adds < 3 && p.floatAdds < 3) return null;
		if (p.loads < 4) return null;

		int totalMults = p.mults + p.floatMults;
		int totalAdds = p.adds + p.floatAdds;

		double conf = 0.40;
		if (p.hasNestedLoop) conf += 0.10;
		if (totalMults >= 3) conf += 0.10;
		if (totalAdds >= 4) conf += 0.05;
		if (p.loads >= 6) conf += 0.05; // kernel + input reads
		if (p.stores >= 2) conf += 0.05; // output writes
		if (p.calls == 0) conf += 0.05;
		if (p.maxLoopDepth >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("dsp", "convolution",
			Math.min(conf, 0.75),
			"Convolution (nested loop multiply-accumulate over kernel)");
	}

	/**
	 * Stepper motor driver: phase sequence table lookup, IO register writes
	 * for coil activation, step delay, direction control.
	 */
	private FunctionType detectStepperMotor(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.stores < 2) return null;
		if (p.ioRegionAccesses < 1) return null;

		// Phase table: small constants for coil patterns (e.g., 0x01,0x02,0x04,0x08)
		boolean hasPhaseConsts = p.constants.contains(0x01L) &&
			(p.constants.contains(0x02L) || p.constants.contains(0x04L) ||
			 p.constants.contains(0x08L));
		boolean hasModulo = p.rems > 0 || (p.ands >= 1 && p.constants.contains(0x03L));

		if (!hasPhaseConsts && p.ioRegionAccesses < 2) return null;

		double conf = 0.35;
		if (hasPhaseConsts) conf += 0.15;
		if (p.ioRegionAccesses >= 2) conf += 0.15;
		if (hasModulo) conf += 0.10; // phase index wrapping
		if (p.hasLoop) conf += 0.05;
		if (p.loads >= 2) conf += 0.05; // table read
		if (p.cbranches >= 1) conf += 0.05; // direction check

		if (conf < 0.55) return null;

		return new FunctionType("hw_control", "stepper_motor",
			Math.min(conf, 0.75),
			"Stepper motor driver (phase sequence, IO coil activation)");
	}

	/**
	 * Bootloader jump: validates application signature/checksum, then
	 * performs indirect branch to application entry point.
	 */
	private FunctionType detectBootloaderJump(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (p.branchInds < 1 && p.callInds < 1) return null;

		// Bootloader: read signature word, compare to magic, jump if valid
		boolean hasMagicCheck = p.compares >= 1 && p.cbranches >= 1;
		boolean hasSignature = p.constants.contains(0xAA55L) ||
			p.constants.contains(0x55AAL) || p.constants.contains(0x5AA5L) ||
			p.constants.contains(0xDEADBEEFL);

		if (!hasMagicCheck) return null;

		double conf = 0.40;
		if (hasSignature) conf += 0.20;
		if (p.branchInds >= 1) conf += 0.10; // jump to app
		if (p.callInds >= 1) conf += 0.10;
		if (p.loads >= 2) conf += 0.05; // read vector table
		if (p.totalOps < 60) conf += 0.05; // bootloader jump is compact
		if (p.calls == 0) conf += 0.05; // no library calls

		if (conf < 0.55) return null;

		return new FunctionType("boot", "bootloader_jump",
			Math.min(conf, 0.75),
			"Bootloader jump to application (signature validate + indirect branch)");
	}

	/**
	 * Flash erase: unlock command sequence (0xAA to 0x555, 0x55 to 0x2AA),
	 * sector erase command, busy-poll status register.
	 */
	private FunctionType detectFlashErase(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.stores < 3) return null;

		boolean hasUnlock1 = p.constants.contains(0x555L) || p.constants.contains(0x5555L);
		boolean hasUnlock2 = p.constants.contains(0x2AAL) || p.constants.contains(0x2AAAL);
		boolean hasAAcmd = p.constants.contains(0xAAL);
		boolean has55cmd = p.constants.contains(0x55L);
		boolean hasEraseCmd = p.constants.contains(0x80L) || p.constants.contains(0x30L);

		int unlockEvidence = (hasUnlock1 ? 1 : 0) + (hasUnlock2 ? 1 : 0) +
			(hasAAcmd ? 1 : 0) + (has55cmd ? 1 : 0);
		if (unlockEvidence < 2) return null;

		// Busy poll: load + AND/compare + CBRANCH in a loop
		boolean hasBusyPoll = p.hasLoop && p.compares >= 1;

		double conf = 0.40;
		if (unlockEvidence >= 3) conf += 0.20;
		else conf += 0.10;
		if (hasEraseCmd) conf += 0.10;
		if (hasBusyPoll) conf += 0.10;
		if (p.consecutiveStores >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("flash", "flash_erase",
			Math.min(conf, 0.75),
			"Flash erase (unlock sequence + sector erase + busy poll)");
	}

	/**
	 * Battery monitor: ADC read from IO region, voltage scaling with
	 * multiply/shift, threshold compare for charge levels.
	 */
	private FunctionType detectBatteryMonitor(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (p.ioRegionAccesses < 1) return null;
		if (p.compares < 2) return null;

		boolean hasScaling = p.mults >= 1 || p.hasMultThenShift ||
			(p.lefts >= 1 && p.rights >= 1);
		boolean hasThresholds = p.cbranches >= 2 && (p.lesses >= 2 || p.sLesses >= 2);

		if (!hasScaling && !hasThresholds) return null;

		double conf = 0.40;
		if (p.ioRegionAccesses >= 1) conf += 0.10; // ADC register read
		if (hasScaling) conf += 0.10;
		if (hasThresholds) conf += 0.15; // multiple voltage thresholds
		if (p.loads >= 2) conf += 0.05;
		if (p.stores >= 1) conf += 0.05;
		if (p.totalOps < 100) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("hw_monitor", "battery_monitor",
			Math.min(conf, 0.75),
			"Battery monitor (ADC read, voltage scaling, threshold compare)");
	}

	/**
	 * Temperature compensation: lookup table indexed by sensor reading,
	 * linear interpolation between table entries, offset/gain adjust.
	 */
	private FunctionType detectTempCompensation(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.loads < 3) return null;
		if (p.mults < 1 && p.floatMults < 1) return null;

		boolean hasInterpolation = (p.subs >= 1 || p.floatSubs >= 1) &&
			(p.mults >= 1 || p.floatMults >= 1);
		boolean hasTableIndex = p.rights >= 1 || p.divs > 0;

		if (!hasInterpolation) return null;

		double conf = 0.40;
		if (hasInterpolation) conf += 0.15;
		if (hasTableIndex) conf += 0.10; // index calculation
		if (p.loads >= 4) conf += 0.05; // table[i] and table[i+1]
		if (p.adds >= 2) conf += 0.05;
		if (p.ioRegionAccesses >= 1) conf += 0.10; // sensor read
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("hw_control", "temp_compensation",
			Math.min(conf, 0.75),
			"Temperature compensation (lookup table + linear interpolation)");
	}

	/**
	 * Sprite scaling: Bresenham-like error accumulator for scaling pixels,
	 * nested loop for row/column, pixel copy with source stepping.
	 */
	private FunctionType detectSpriteScaling(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasNestedLoop) return null;
		if (p.totalOps < 35) return null;
		if (p.loads < 4) return null;
		if (p.stores < 3) return null;
		if (p.adds < 4) return null;

		// Bresenham: error accumulation with conditional source advance
		boolean hasErrorAccum = false;
		for (int i = 0; i < pcode.length - 2; i++) {
			if (pcode[i].getOpcode() == PcodeOp.INT_ADD &&
				(pcode[i+1].getOpcode() == PcodeOp.INT_LESS ||
				 pcode[i+1].getOpcode() == PcodeOp.INT_SLESS) &&
				pcode[i+2].getOpcode() == PcodeOp.CBRANCH) {
				hasErrorAccum = true;
				break;
			}
		}

		double conf = 0.35;
		if (hasErrorAccum) conf += 0.20;
		if (p.maxLoopDepth >= 2) conf += 0.10;
		if (p.subs >= 1) conf += 0.05; // error wrap
		if (p.memory >= 8) conf += 0.05;
		if (p.ands >= 1) conf += 0.05; // pixel masking
		if (p.lefts >= 1 || p.rights >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "sprite_scaling",
			Math.min(conf, 0.75),
			"Sprite scaling (Bresenham-style, nested loop pixel copy)");
	}

	/**
	 * Alpha blending: per-component multiply by alpha, shift right by 8,
	 * combine RGB. Pattern: (a*alpha + b*(255-alpha)) >> 8.
	 */
	private FunctionType detectAlphaBlending(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.mults < 2) return null;
		if (p.rights < 1) return null;

		boolean has0xFF = p.constants.contains(0xFFL);
		boolean hasShift8 = p.constants.contains(8L);
		boolean hasColorMasks = p.constants.contains(0xFF00L) ||
			p.constants.contains(0xFF0000L) || p.constants.contains(0xFF00FFL);

		if (p.mults < 2 || p.rights < 1) return null;

		double conf = 0.35;
		if (has0xFF) conf += 0.10; // alpha mask or 255
		if (hasShift8) conf += 0.10;
		if (hasColorMasks) conf += 0.10;
		if (p.mults >= 3) conf += 0.10; // R, G, B components
		if (p.adds >= 2) conf += 0.05;
		if (p.subs >= 1) conf += 0.05; // 255 - alpha
		if (p.ands >= 2) conf += 0.05; // channel isolation

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "alpha_blending",
			Math.min(conf, 0.75),
			"Alpha blending (per-component multiply, shift right 8, RGB combine)");
	}

	/**
	 * Gamma correction: lookup table with 256 entries or power-law
	 * approximation using multiply chains.
	 */
	private FunctionType detectGammaCorrection(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;

		boolean has256 = p.constants.contains(256L) || p.constants.contains(0x100L);
		boolean has0xFF = p.constants.contains(0xFFL);
		boolean hasTableLookup = p.loads >= 3 && has256;
		boolean hasPowerApprox = p.mults >= 3 && p.rights >= 2; // x*x*x >> shifts

		if (!hasTableLookup && !hasPowerApprox) return null;

		double conf = 0.40;
		if (hasTableLookup) conf += 0.15;
		if (hasPowerApprox) conf += 0.20;
		if (has0xFF) conf += 0.05; // clamp to 8-bit
		if (p.ands >= 1) conf += 0.05;
		if (p.hasLoop && p.loads >= 4) conf += 0.05; // apply to pixel array
		if (p.calls == 0) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "gamma_correction",
			Math.min(conf, 0.75),
			"Gamma correction (" +
			(hasTableLookup ? "256-entry lookup table" : "power-law approximation") + ")");
	}

	/**
	 * Color space conversion (RGB/YUV): 3x3 matrix multiply-add with
	 * fixed-point coefficients, clamp to 0-255.
	 */
	private FunctionType detectColorSpaceConvert(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.mults < 3) return null;
		if (p.adds < 3) return null;

		// YUV coefficients: 66, 129, 25 or 298, 409, 516 (BT.601 fixed-point)
		boolean hasYuvConst = p.constants.contains(66L) || p.constants.contains(129L) ||
			p.constants.contains(298L) || p.constants.contains(409L) ||
			p.constants.contains(516L);
		boolean has0xFF = p.constants.contains(0xFFL);
		boolean hasShift8 = p.constants.contains(8L);

		double conf = 0.35;
		if (hasYuvConst) conf += 0.25;
		if (p.mults >= 6) conf += 0.10; // 3 components * 2 or 3 terms
		else if (p.mults >= 3) conf += 0.05;
		if (p.adds >= 5) conf += 0.05;
		if (has0xFF) conf += 0.05; // clamp
		if (hasShift8) conf += 0.05; // fixed-point descale
		if (p.rights >= 2) conf += 0.05;
		if (p.subs >= 1) conf += 0.05; // offset subtract (e.g., Y-16)

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "colorspace_convert",
			Math.min(conf, 0.75),
			"Color space conversion (RGB/YUV matrix multiply-add)");
	}

	/**
	 * Parallax scrolling: multiple scroll offset values applied to
	 * different background layers, modulo wrapping for tile boundaries.
	 */
	private FunctionType detectParallaxScroll(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.stores < 3) return null;
		if (p.loads < 3) return null;

		boolean hasModulo = p.rems > 0 || p.powerOf2Masks > 0;
		boolean hasMultiOffset = p.adds >= 3 && p.stores >= 4;

		if (!hasModulo && !hasMultiOffset) return null;

		double conf = 0.35;
		if (hasModulo) conf += 0.15; // tile wrap
		if (hasMultiOffset) conf += 0.10;
		if (p.rights >= 1) conf += 0.10; // divide speed by power of 2
		if (p.ioRegionAccesses >= 1) conf += 0.10; // scroll register writes
		if (p.consecutiveStores >= 3) conf += 0.05; // layer registers
		if (p.ands >= 1) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "parallax_scroll",
			Math.min(conf, 0.75),
			"Parallax scrolling (multiple layer offsets, modulo wrapping)");
	}

	/**
	 * Raycasting: trigonometric table lookup, distance calculation
	 * (multiply/divide), column-by-column rendering loop.
	 */
	private FunctionType detectRaycasting(PcodeOp[] pcode, OpcodeProfile p) {
		if (!p.hasLoop) return null;
		if (p.totalOps < 50) return null;
		if (p.mults < 3) return null;
		if (p.loads < 6) return null;

		// Trig lookups (sin/cos table), distance via divide, column store
		boolean hasTrigIndex = p.ands >= 1 && p.loads >= 8; // table index masking
		boolean hasDistCalc = p.divs > 0 || p.hasMultThenShift;

		if (!hasDistCalc) return null;

		double conf = 0.35;
		if (hasTrigIndex) conf += 0.10;
		if (hasDistCalc) conf += 0.15;
		if (p.hasNestedLoop) conf += 0.10; // inner column fill loop
		if (p.stores >= 4) conf += 0.05;
		if (p.compares >= 3) conf += 0.05; // wall hit detection
		if (p.adds >= 4) conf += 0.05;
		if (p.subs >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("graphics", "raycasting",
			Math.min(conf, 0.75),
			"Raycasting renderer (trig lookup, distance calc, column rendering)");
	}

	/**
	 * JSON parser: brace/bracket matching with depth counter, string
	 * delimiter detection, number parsing, whitespace skip.
	 */
	private FunctionType detectJsonParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		if (p.compares < 6) return null;
		if (p.cbranches < 5) return null;

		boolean hasLBrace = p.constants.contains(0x7BL);  // '{'
		boolean hasRBrace = p.constants.contains(0x7DL);  // '}'
		boolean hasLBrack = p.constants.contains(0x5BL);  // '['
		boolean hasRBrack = p.constants.contains(0x5DL);  // ']'
		boolean hasQuote = p.constants.contains(0x22L);   // '"'
		boolean hasColon = p.constants.contains(0x3AL);   // ':'
		boolean hasComma = p.constants.contains(0x2CL);   // ','

		int jsonChars = (hasLBrace ? 1 : 0) + (hasRBrace ? 1 : 0) +
			(hasLBrack ? 1 : 0) + (hasRBrack ? 1 : 0) +
			(hasQuote ? 1 : 0) + (hasColon ? 1 : 0) + (hasComma ? 1 : 0);

		if (jsonChars < 4) return null;

		double conf = 0.35;
		if (jsonChars >= 6) conf += 0.25;
		else if (jsonChars >= 4) conf += 0.15;
		if (p.constAsciiCompares >= 5) conf += 0.10;
		if (p.hasLoop) conf += 0.05;
		if (p.adds >= 1) conf += 0.05; // depth counter
		if (p.subs >= 1) conf += 0.05; // depth decrement

		if (conf < 0.55) return null;

		return new FunctionType("parser", "json_parser",
			Math.min(conf, 0.75),
			"JSON parser (brace/bracket matching, string/number parsing)");
	}

	/**
	 * CSV parser: delimiter scanning (comma/tab), field extraction,
	 * quote handling, line-oriented processing.
	 */
	private FunctionType detectCsvParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.compares < 4) return null;
		if (!p.hasLoop) return null;

		boolean hasComma = p.constants.contains(0x2CL);   // ','
		boolean hasTab = p.constants.contains(0x09L);     // '\t'
		boolean hasQuote = p.constants.contains(0x22L);   // '"'
		boolean hasNewline = p.constants.contains(0x0AL);  // '\n'
		boolean hasCR = p.constants.contains(0x0DL);      // '\r'

		int csvChars = (hasComma ? 1 : 0) + (hasTab ? 1 : 0) +
			(hasQuote ? 1 : 0) + (hasNewline ? 1 : 0) + (hasCR ? 1 : 0);

		if (csvChars < 2 || (!hasComma && !hasTab)) return null;

		double conf = 0.40;
		if (csvChars >= 4) conf += 0.20;
		else if (csvChars >= 2) conf += 0.10;
		if (p.constAsciiCompares >= 3) conf += 0.10;
		if (p.loads >= 4) conf += 0.05;
		if (p.stores >= 2) conf += 0.05;
		if (p.cbranch_eq_runs >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("parser", "csv_parser",
			Math.min(conf, 0.75),
			"CSV parser (delimiter scan, field extraction, quote handling)");
	}

	/**
	 * COFF/PE parser: header magic validation (0x014C, 0x5A4D),
	 * section table walk, field offset reads.
	 */
	private FunctionType detectCoffParser(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.loads < 5) return null;
		if (p.compares < 2) return null;

		boolean hasMZ = p.constants.contains(0x5A4DL);     // "MZ"
		boolean hasPE = p.constants.contains(0x4550L);     // "PE"
		boolean hasCOFF = p.constants.contains(0x014CL);   // i386 COFF machine
		boolean hasARM = p.constants.contains(0x01C0L);    // ARM COFF machine
		boolean has68k = p.constants.contains(0x0268L);    // 68k COFF machine

		int magics = (hasMZ ? 1 : 0) + (hasPE ? 1 : 0) + (hasCOFF ? 1 : 0) +
			(hasARM ? 1 : 0) + (has68k ? 1 : 0);
		if (magics < 1) return null;

		double conf = 0.40;
		if (magics >= 2) conf += 0.20;
		else conf += 0.10;
		if (p.hasLoop) conf += 0.10; // section table iteration
		if (p.adds >= 3) conf += 0.05; // offset calculations
		if (p.loads >= 8) conf += 0.05;
		if (p.cbranches >= 2) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("parser", "coff_parser",
			Math.min(conf, 0.75),
			"COFF/PE object file parser (magic validation, section table walk)");
	}

	/**
	 * BMP image loader: BM header magic (0x4D42), palette loading,
	 * row-by-row pixel data reading, stride padding.
	 */
	private FunctionType detectBmpLoader(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (p.loads < 5) return null;

		boolean hasBM = p.constants.contains(0x4D42L); // "BM" little-endian
		boolean hasHeaderSize = p.constants.contains(40L) || p.constants.contains(54L);
		boolean hasBitsPerPixel = p.constants.contains(24L) || p.constants.contains(32L) ||
			p.constants.contains(8L);
		boolean hasPadding = p.constants.contains(3L) && p.ands >= 1; // 4-byte row alignment

		if (!hasBM && !hasHeaderSize) return null;

		double conf = 0.40;
		if (hasBM) conf += 0.20;
		if (hasHeaderSize) conf += 0.10;
		if (hasBitsPerPixel) conf += 0.05;
		if (hasPadding) conf += 0.05;
		if (p.hasLoop) conf += 0.05; // row iteration
		if (p.stores >= 3) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("parser", "bmp_loader",
			Math.min(conf, 0.75),
			"BMP image loader (0x4D42 header, palette, pixel data)");
	}

	/**
	 * WAV audio loader: RIFF header (0x52494646), chunk-based parsing,
	 * sample rate and channel count extraction.
	 */
	private FunctionType detectWavLoader(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (p.loads < 4) return null;

		boolean hasRIFF = p.constants.contains(0x52494646L);  // "RIFF"
		boolean hasWAVE = p.constants.contains(0x57415645L);  // "WAVE"
		boolean hasFmt = p.constants.contains(0x666D7420L);   // "fmt "
		boolean hasData = p.constants.contains(0x64617461L);  // "data"

		int chunks = (hasRIFF ? 1 : 0) + (hasWAVE ? 1 : 0) +
			(hasFmt ? 1 : 0) + (hasData ? 1 : 0);
		if (chunks < 1) return null;

		double conf = 0.35;
		if (chunks >= 3) conf += 0.30;
		else if (chunks >= 2) conf += 0.20;
		else conf += 0.10;
		if (p.compares >= 2) conf += 0.05; // chunk type checks
		if (p.adds >= 2) conf += 0.05; // chunk size skipping
		if (p.hasLoop) conf += 0.05; // chunk iteration

		if (conf < 0.55) return null;

		return new FunctionType("parser", "wav_loader",
			Math.min(conf, 0.75),
			"WAV audio loader (RIFF header, chunk-based parsing)");
	}

	/**
	 * Syscall dispatch: syscall number in register, table-indexed indirect
	 * branch, range validation, possible privilege transition.
	 */
	private FunctionType detectSyscallDispatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (p.branchInds < 1 && p.callInds < 1) return null;

		boolean hasRangeCheck = p.lesses >= 1 || p.sLesses >= 1;
		boolean hasTableLoad = p.loads >= 2;
		boolean hasPrivOp = p.callOtherCount > 0;

		if (!hasRangeCheck) return null;

		double conf = 0.40;
		if (hasRangeCheck) conf += 0.10;
		if (p.branchInds >= 1 || p.callInds >= 1) conf += 0.10; // dispatch jump
		if (hasTableLoad) conf += 0.05;
		if (hasPrivOp) conf += 0.15; // privilege-related ops
		if (p.lefts >= 1) conf += 0.05; // index * sizeof(ptr)
		if (p.cbranches >= 1) conf += 0.05; // bounds check branch
		if (p.totalOps < 50) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("os_kernel", "syscall_dispatch",
			Math.min(conf, 0.75),
			"Syscall dispatch (number validation, table-indexed indirect call)");
	}

	/**
	 * Thread scheduler: context save/restore (many consecutive stores/loads),
	 * priority comparison, next-thread selection, timer interaction.
	 */
	private FunctionType detectThreadScheduler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 35) return null;
		if (p.loads < 5) return null;
		if (p.stores < 5) return null;
		if (p.compares < 2) return null;

		boolean hasContextSwitch = p.consecutiveStores >= 4 || p.consecutiveLoads >= 4;
		boolean hasPriorityCompare = (p.lesses >= 2 || p.sLesses >= 2) && p.cbranches >= 2;

		if (!hasContextSwitch && !hasPriorityCompare) return null;

		double conf = 0.35;
		if (hasContextSwitch) conf += 0.20;
		if (hasPriorityCompare) conf += 0.10;
		if (p.hasLoop) conf += 0.05; // ready queue scan
		if (p.callOtherCount > 0) conf += 0.10; // privilege ops (interrupt disable)
		if (p.branchInds >= 1 || p.callInds >= 1) conf += 0.05; // jump to next thread
		if (p.loads >= 8 && p.stores >= 8) conf += 0.05;

		if (conf < 0.55) return null;

		return new FunctionType("os_kernel", "thread_scheduler",
			Math.min(conf, 0.75),
			"Thread scheduler (context save/restore, priority queue, dispatch)");
	}

	private FunctionType detectSignalHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Signal handler: save context, check signal number, dispatch
		if (p.consecutiveStores >= 4) conf += 0.15; // context save (push registers)
		if (p.cbranch_eq_runs >= 2) conf += 0.15; // signal number dispatch
		if (p.constSmallInts >= 3) conf += 0.10; // signal numbers (SIGHUP=1, SIGINT=2, etc.)
		if (p.branchInds >= 1 || p.callInds >= 1) conf += 0.10; // handler table dispatch
		if (p.stores >= 5) conf += 0.10; // register save
		if (p.loads >= 3) conf += 0.05; // read signal info struct
		if (p.returns >= 1) conf += 0.05;
		if (p.calls >= 1) conf += 0.05; // call actual handler
		if (conf < 0.55) return null;
		return new FunctionType("signal_handler", "signal_dispatch",
			Math.min(conf, 0.75), "Unix signal handler with context save and dispatch");
	}

	private FunctionType detectPipeIpc(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Pipe IPC: ring buffer with head/tail pointers for read/write
		if (p.powerOf2Masks >= 1) conf += 0.15; // modular wrap for ring buffer
		if (p.loadStoreAlternations >= 2) conf += 0.15; // read data then update pointer
		if (p.adds >= 2) conf += 0.10; // pointer advance
		if (p.compares >= 2) conf += 0.10; // empty/full check
		if (p.constZeroCompares >= 1) conf += 0.10; // check for empty
		if (p.cbranches >= 2) conf += 0.10; // empty/full branch
		if (p.hasLoop) conf += 0.05; // byte-by-byte transfer loop
		if (conf < 0.55) return null;
		return new FunctionType("pipe_ipc", "pipe_read_write",
			Math.min(conf, 0.75), "Pipe IPC with ring buffer head/tail management");
	}

	private FunctionType detectMemoryPool(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Memory pool: fixed-size block allocation from pre-carved arena
		if (p.loads >= 3) conf += 0.10; // read free list head
		if (p.stores >= 2) conf += 0.10; // update free list link
		if (p.constZeroCompares >= 2) conf += 0.15; // null checks (pool exhausted)
		if (p.adds >= 2) conf += 0.10; // pointer arithmetic for block offset
		if (p.ands >= 1) conf += 0.10; // alignment masking
		if (p.cbranches >= 2) conf += 0.10; // exhausted check + alignment check
		if (p.returns >= 2) conf += 0.10; // success/failure paths
		if (p.mults == 0 && p.divs == 0) conf += 0.05; // no complex math
		if (conf < 0.55) return null;
		return new FunctionType("memory_pool", "pool_block_allocate",
			Math.min(conf, 0.75), "Fixed-size memory pool block allocation");
	}

	private FunctionType detectTlbFlush(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// TLB flush: special register writes, memory barrier (CALLOTHER)
		if (p.callOtherCount >= 1) conf += 0.20; // memory barrier / special instruction
		if (p.stores >= 2) conf += 0.10; // write to control registers
		if (p.ioRegionAccesses >= 1) conf += 0.15; // system register region
		if (p.totalOps < 60) conf += 0.10; // typically short
		if (p.loads <= 2) conf += 0.05; // mostly write operations
		if (p.arithmetic < 3) conf += 0.05; // minimal computation
		if (p.hasLoop) conf += 0.10; // iterate over TLB entries
		if (conf < 0.55) return null;
		return new FunctionType("tlb_flush", "tlb_invalidate",
			Math.min(conf, 0.75), "TLB flush/invalidate with memory barrier");
	}

	private FunctionType detectFileDescTable(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// File descriptor table: index into array, validate bounds
		if (p.loads >= 3) conf += 0.10; // read table entry
		if (p.lesses >= 1 || p.sLesses >= 1) conf += 0.15; // bounds check
		if (p.constZeroCompares >= 1) conf += 0.10; // check for invalid fd
		if (p.cbranches >= 2) conf += 0.10; // bounds + validity branches
		if (p.lefts >= 1 || p.mults >= 1) conf += 0.10; // index * struct_size
		if (p.adds >= 2) conf += 0.10; // base + offset
		if (p.returns >= 2) conf += 0.10; // success/error paths
		if (conf < 0.55) return null;
		return new FunctionType("file_desc_table", "fd_table_lookup",
			Math.min(conf, 0.75), "File descriptor table index and bounds validation");
	}

	private FunctionType detectMountHandler(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// Mount handler: device/inode lookup, superblock read, multiple calls
		if (p.calls >= 3) conf += 0.15; // read superblock, lookup device, alloc
		if (p.loads >= 6) conf += 0.10; // read device info, superblock fields
		if (p.stores >= 4) conf += 0.10; // fill mount struct
		if (p.constZeroCompares >= 2) conf += 0.10; // error checks
		if (p.cbranches >= 3) conf += 0.10; // multiple validation branches
		if (p.compares >= 3) conf += 0.10; // type checks, magic number checks
		if (p.returns >= 2) conf += 0.10; // error/success returns
		if (conf < 0.55) return null;
		return new FunctionType("mount_handler", "filesystem_mount",
			Math.min(conf, 0.75), "Filesystem mount with device/inode/superblock handling");
	}

	private FunctionType detectSocketBind(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Socket bind: fill sockaddr struct, byte-swap port (htons)
		if (p.consecutiveStores >= 3) conf += 0.15; // fill address struct fields
		if (p.lefts >= 1 && p.rights >= 1) conf += 0.15; // byte swap (htons)
		if (p.ors >= 1) conf += 0.10; // combine bytes for port number
		if (p.stores >= 4) conf += 0.10; // write family, port, addr fields
		if (p.calls >= 1) conf += 0.10; // call bind() syscall
		if (p.constSmallInts >= 2) conf += 0.10; // AF_INET=2, SOCK_STREAM=1
		if (p.cbranches >= 1) conf += 0.05; // error check after bind
		if (conf < 0.55) return null;
		return new FunctionType("socket_bind", "socket_bind_address",
			Math.min(conf, 0.75), "Socket bind with address struct fill and port byte-swap");
	}

	private FunctionType detectBigIntAdd(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// Big integer add: multi-word carry propagation in loop
		if (p.adds >= 3) conf += 0.15; // add words + carry
		if (p.lesses >= 1) conf += 0.10; // carry detection (result < operand)
		if (p.loads >= 2) conf += 0.10; // load operand words
		if (p.stores >= 2) conf += 0.10; // store result words
		if (p.loopCount == 1) conf += 0.10; // single loop over words
		if (p.mults == 0 && p.divs == 0) conf += 0.10; // no multiply/divide
		if (p.xors == 0 && p.ors <= 1) conf += 0.05; // minimal logic ops
		if (p.totalOps < 80) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("big_int_add", "bigint_add_carry",
			Math.min(conf, 0.75), "Big integer addition with multi-word carry propagation");
	}

	private FunctionType detectBigIntMul(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (!p.hasNestedLoop) return null;
		double conf = 0;
		// Big integer multiply: nested loop over partial products
		if (p.mults >= 1) conf += 0.15; // partial product multiply
		if (p.adds >= 3) conf += 0.15; // accumulate partial products + carry
		if (p.loads >= 3) conf += 0.10; // load operand words
		if (p.stores >= 2) conf += 0.10; // store result words
		if (p.rights >= 1 || p.srights >= 1) conf += 0.10; // extract high word of product
		if (p.loopCount >= 2) conf += 0.10; // nested iteration
		if (p.lesses >= 1) conf += 0.05; // carry/overflow detection
		if (conf < 0.55) return null;
		return new FunctionType("big_int_mul", "bigint_multiply",
			Math.min(conf, 0.75), "Big integer multiply with nested partial products");
	}

	private FunctionType detectPolynomialEval(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Horner's method: multiply-then-add chain
		if (p.mults >= 2) conf += 0.15; // repeated multiply by x
		if (p.adds >= 2) conf += 0.15; // add coefficient each step
		if (p.hasMultThenShift) conf += 0.10; // fixed-point variant
		if (p.loads >= 2) conf += 0.10; // load coefficients from table
		if (p.hasLoop && p.loopCount == 1) conf += 0.10; // single evaluation loop
		if (p.divs == 0) conf += 0.05; // no division in Horner's
		if (p.compares <= 2) conf += 0.05; // minimal branching
		if (p.shifts >= 1) conf += 0.05; // fixed-point scaling
		if (conf < 0.55) return null;
		return new FunctionType("polynomial_eval", "horner_polynomial",
			Math.min(conf, 0.75), "Polynomial evaluation via Horner's method");
	}

	private FunctionType detectLinearInterp(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Linear interpolation: (b-a)*t + a with fixed-point scaling
		if (p.subs >= 1) conf += 0.15; // b - a
		if (p.mults >= 1) conf += 0.15; // * t
		if (p.adds >= 1) conf += 0.10; // + a
		if (p.shifts >= 1) conf += 0.10; // fixed-point scale down
		if (p.hasMultThenShift) conf += 0.15; // multiply then shift = fixed-point
		if (p.totalOps < 60) conf += 0.05; // typically compact
		if (!p.hasLoop) conf += 0.05; // single computation, no loop needed
		if (conf < 0.55) return null;
		return new FunctionType("linear_interp", "lerp_fixed_point",
			Math.min(conf, 0.75), "Linear interpolation (b-a)*t+a with fixed-point");
	}

	private FunctionType detectLogApprox(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Log approximation: extract exponent via right shift, mantissa via table
		if (p.rights >= 2 || p.srights >= 1) conf += 0.15; // exponent extraction
		if (p.ands >= 1) conf += 0.10; // mantissa mask
		if (p.loads >= 2) conf += 0.15; // table lookup for mantissa correction
		if (p.adds >= 1) conf += 0.10; // combine exponent + mantissa part
		if (p.lefts >= 1) conf += 0.10; // index scaling for table access
		if (p.mults <= 2) conf += 0.05; // minimal or no multiply
		if (p.totalOps < 80) conf += 0.05;
		if (p.cbranches >= 1) conf += 0.05; // edge case check (zero input)
		if (conf < 0.55) return null;
		return new FunctionType("log_approx", "log2_approximation",
			Math.min(conf, 0.75), "Logarithm approximation via exponent extract and mantissa table");
	}

	private FunctionType detectExpApprox(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Exp approximation: range reduction then polynomial or table lookup
		if (p.ands >= 1) conf += 0.10; // fractional part mask
		if (p.rights >= 1) conf += 0.10; // integer part extraction
		if (p.lefts >= 1) conf += 0.10; // shift for 2^integer_part
		if (p.mults >= 1) conf += 0.15; // polynomial term or scale
		if (p.adds >= 2) conf += 0.10; // polynomial accumulation
		if (p.loads >= 1) conf += 0.10; // coefficient or table entry
		if (p.subs >= 1) conf += 0.05; // range reduction subtraction
		if (p.totalOps < 100) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("exp_approx", "exp_approximation",
			Math.min(conf, 0.75), "Exponential approximation with range reduction");
	}

	private FunctionType detectReciprocalApprox(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Newton-Raphson reciprocal: x' = x*(2 - d*x)
		if (p.mults >= 2) conf += 0.20; // d*x and x*(2-d*x)
		if (p.subs >= 1) conf += 0.15; // 2 - d*x
		if (p.hasLoop && p.loopCount <= 2) conf += 0.10; // few iterations
		if (p.adds <= 2) conf += 0.05; // minimal adds
		if (p.divs == 0) conf += 0.10; // no hardware divide (that's the point)
		if (p.shifts >= 1) conf += 0.10; // fixed-point scaling
		if (p.totalOps < 80) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("reciprocal_approx", "newton_reciprocal",
			Math.min(conf, 0.75), "Reciprocal approximation via Newton-Raphson iteration");
	}

	private FunctionType detectDivByConstant(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 10) return null;
		double conf = 0;
		// Division by constant: multiply by magic number then shift right
		if (p.hasLargeConstMult) conf += 0.25; // multiply by magic reciprocal
		if (p.hasMultThenShift) conf += 0.25; // mult followed by right shift
		if (p.rights >= 1 || p.srights >= 1) conf += 0.10; // shift to get quotient
		if (p.mults >= 1) conf += 0.10; // the magic multiply
		if (p.divs == 0) conf += 0.05; // no hardware divide instruction
		if (!p.hasLoop) conf += 0.05; // straight-line computation
		if (p.totalOps < 40) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("div_by_constant", "const_division_by_multiply",
			Math.min(conf, 0.75), "Division by constant via multiply-high and shift");
	}

	private FunctionType detectGcdCompute(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// GCD Euclidean algorithm: modulo loop until remainder is zero
		if (p.rems >= 1) conf += 0.20; // modulo operation
		if (p.subs >= 1) conf += 0.10; // subtraction variant of Euclid
		if (p.constZeroCompares >= 1) conf += 0.15; // remainder == 0 termination
		if (p.cbranches >= 1) conf += 0.10; // loop-until-zero branch
		if (p.copies >= 1) conf += 0.05; // swap a and b
		if (p.loopCount == 1) conf += 0.10; // single iteration loop
		if (p.mults == 0) conf += 0.05; // no multiply needed
		if (p.totalOps < 60) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("gcd_compute", "euclidean_gcd",
			Math.min(conf, 0.75), "GCD computation via Euclidean algorithm");
	}

	private FunctionType detectRegexMatch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		double conf = 0;
		// Regex matching: state transitions, character class tests, backtrack
		if (p.cbranch_eq_runs >= 3) conf += 0.15; // character class dispatch
		if (p.constAsciiCompares >= 3) conf += 0.15; // character range tests
		if (p.loads >= 4) conf += 0.10; // read pattern + input characters
		if (p.cbranches >= 4) conf += 0.10; // many conditional branches
		if (p.hasLoop) conf += 0.10; // scan loop
		if (p.sLesses >= 1 || p.lesses >= 2) conf += 0.10; // range comparisons
		if (p.adds >= 2) conf += 0.05; // pointer advance
		if (conf < 0.55) return null;
		return new FunctionType("regex_match", "regex_state_machine",
			Math.min(conf, 0.75), "Regex match with state transitions and character class tests");
	}

	private FunctionType detectStringHash(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// String hash: character-by-character multiply-accumulate
		if (p.mults >= 1 || p.constLargeMultipliers >= 1) conf += 0.20; // hash multiplier
		if (p.adds >= 1) conf += 0.10; // accumulate character value
		if (p.loads >= 1) conf += 0.10; // load characters
		if (p.constZeroCompares >= 1) conf += 0.10; // null terminator check
		if (p.xors >= 1) conf += 0.10; // hash mixing via XOR
		if (p.loopCount == 1) conf += 0.10; // single character loop
		if (p.totalOps < 60) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("string_hash", "string_hash_function",
			Math.min(conf, 0.75), "String hash via character multiply-accumulate loop");
	}

	private FunctionType detectStringTokenize(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Tokenizer: scan for delimiter, advance pointer, return token start
		if (p.hasLoop) conf += 0.10;
		if (p.loads >= 3) conf += 0.10; // load characters
		if (p.constAsciiCompares >= 2) conf += 0.15; // delimiter comparison
		if (p.cbranch_eq_runs >= 2) conf += 0.10; // check multiple delimiters
		if (p.adds >= 2) conf += 0.10; // pointer advance
		if (p.constZeroCompares >= 1) conf += 0.10; // null terminator
		if (p.stores >= 1) conf += 0.10; // write null to split token
		if (p.cbranches >= 2) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("string_tokenize", "strtok_delimit",
			Math.min(conf, 0.75), "String tokenizer with delimiter scan and pointer advance");
	}

	private FunctionType detectAtoi(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// atoi: validate digit, multiply by 10, accumulate
		if (p.mults >= 1) conf += 0.15; // multiply accumulator by 10
		if (p.adds >= 1) conf += 0.10; // add digit value
		if (p.subs >= 1) conf += 0.10; // subtract '0' (0x30)
		if (p.loads >= 1) conf += 0.10; // load next character
		if (p.lesses >= 1 || p.sLesses >= 1) conf += 0.10; // range check 0-9
		if (p.constAsciiCompares >= 1) conf += 0.10; // compare with '0' or '9'
		if (p.constZeroCompares >= 1) conf += 0.05; // null terminator
		if (p.loopCount == 1) conf += 0.05;
		if (p.totalOps < 80) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("atoi", "string_to_integer",
			Math.min(conf, 0.75), "String-to-integer conversion (atoi)");
	}

	private FunctionType detectItoa(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// itoa: divide by 10 loop, store digit, reverse buffer
		if (p.divs >= 1 || p.rems >= 1) conf += 0.20; // divide/mod by 10
		if (p.adds >= 1) conf += 0.10; // add '0' to get ASCII digit
		if (p.stores >= 2) conf += 0.10; // store digit characters
		if (p.constZeroCompares >= 1) conf += 0.10; // quotient == 0 terminates
		if (p.loads >= 1) conf += 0.05; // reverse pass loads
		if (p.subs >= 1) conf += 0.10; // decrement pointer during reverse
		if (p.loopCount >= 1) conf += 0.10; // digit extraction loop
		if (p.totalOps < 100) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("itoa", "integer_to_string",
			Math.min(conf, 0.75), "Integer-to-string conversion (divide by 10 loop)");
	}

	private FunctionType detectStringSearch(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// String search (strstr): nested loop compare, mismatch restart
		if (p.hasNestedLoop) conf += 0.15; // outer scan + inner match
		if (p.loads >= 3) conf += 0.10; // load from haystack and needle
		if (p.equals >= 1 || p.notEquals >= 1) conf += 0.15; // character compare
		if (p.cbranches >= 3) conf += 0.10; // mismatch, end-of-needle, end-of-haystack
		if (p.adds >= 2) conf += 0.10; // advance pointers
		if (p.constZeroCompares >= 1) conf += 0.10; // null terminator check
		if (p.subs >= 1) conf += 0.05; // restart position adjustment
		if (conf < 0.55) return null;
		return new FunctionType("string_search", "strstr_search",
			Math.min(conf, 0.75), "Substring search with nested compare and mismatch restart");
	}

	private FunctionType detectCaseConvert(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Case conversion: range compare A-Z or a-z, add/sub 0x20
		if (p.constAsciiCompares >= 2) conf += 0.20; // compare with 'A','Z' or 'a','z'
		if (p.subs >= 1 || p.adds >= 1) conf += 0.15; // +/- 0x20 for case flip
		if (p.loads >= 1) conf += 0.10; // load character
		if (p.stores >= 1) conf += 0.10; // store converted character
		if (p.cbranches >= 1) conf += 0.10; // branch if in range
		if (p.hasLoop) conf += 0.10; // iterate over string
		if (p.lesses >= 1 || p.sLesses >= 1) conf += 0.05; // range check
		if (conf < 0.55) return null;
		return new FunctionType("case_convert", "toupper_tolower",
			Math.min(conf, 0.75), "Case conversion with A-Z/a-z range check and 0x20 offset");
	}

	private FunctionType detectWhitespaceStrip(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Whitespace strip: scan from both ends, compare space/tab constants
		if (p.constAsciiCompares >= 2) conf += 0.15; // space (0x20), tab (0x09)
		if (p.loads >= 2) conf += 0.10; // load from both ends
		if (p.subs >= 1) conf += 0.10; // decrement end pointer
		if (p.adds >= 1) conf += 0.10; // increment start pointer
		if (p.cbranches >= 2) conf += 0.10; // whitespace continue branches
		if (p.hasLoop) conf += 0.10; // scan loops
		if (p.equals >= 1 || p.lesses >= 1) conf += 0.10; // char comparison
		if (conf < 0.55) return null;
		return new FunctionType("whitespace_strip", "string_trim",
			Math.min(conf, 0.75), "Whitespace trim scanning from both ends of string");
	}

	private FunctionType detectCollisionResponse(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Collision response: velocity reflect (negate), position correction
		if (p.negates >= 1) conf += 0.15; // velocity negate for reflection
		if (p.subs >= 2) conf += 0.15; // penetration depth, position correction
		if (p.loads >= 3) conf += 0.10; // load position, velocity, bounds
		if (p.stores >= 2) conf += 0.10; // write corrected position and velocity
		if (p.compares >= 2) conf += 0.10; // boundary comparison per axis
		if (p.cbranches >= 2) conf += 0.05; // per-axis collision check
		if (p.srights >= 1) conf += 0.05; // fixed-point halving for restitution
		if (p.adds >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("collision_response", "collision_velocity_reflect",
			Math.min(conf, 0.75), "Collision response with velocity reflect and position correct");
	}

	private FunctionType detectGravitySim(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Gravity: constant acceleration added to velocity, velocity to position
		if (p.adds >= 2) conf += 0.15; // vel += accel; pos += vel
		if (p.loads >= 2) conf += 0.10; // load velocity and position
		if (p.stores >= 2) conf += 0.10; // store updated velocity and position
		if (p.sLesses >= 1 || p.lesses >= 1) conf += 0.10; // ground/terminal check
		if (p.cbranches >= 1) conf += 0.10; // ground collision branch
		if (p.subs >= 1) conf += 0.05; // bounce or clamp
		if (p.totalOps < 60) conf += 0.05; // typically short
		if (p.constSmallInts >= 1) conf += 0.10; // gravity constant value
		if (conf < 0.55) return null;
		return new FunctionType("gravity_sim", "gravity_acceleration",
			Math.min(conf, 0.75), "Gravity simulation: acceleration to velocity to position");
	}

	private FunctionType detectJumpPhysics(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// Jump physics: apply gravity + initial velocity, ground check
		if (p.adds >= 2) conf += 0.10; // velocity accumulation + position update
		if (p.subs >= 1) conf += 0.10; // subtract gravity from velocity
		if (p.sLesses >= 1) conf += 0.15; // signed less for ground check
		if (p.cbranches >= 2) conf += 0.10; // ground check + jump initiate
		if (p.loads >= 2) conf += 0.10; // load y-position and velocity
		if (p.stores >= 2) conf += 0.10; // write y-position and velocity
		if (p.constSmallInts >= 1) conf += 0.05; // gravity/jump strength constant
		if (p.constZeroCompares >= 1) conf += 0.05; // on-ground flag check
		if (conf < 0.55) return null;
		return new FunctionType("jump_physics", "jump_gravity_handler",
			Math.min(conf, 0.75), "Jump physics with gravity, initial velocity, and ground check");
	}

	private FunctionType detectHealthDamage(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// Damage: subtract from health, clamp to zero, death check
		if (p.subs >= 1) conf += 0.15; // subtract damage from health
		if (p.constZeroCompares >= 1) conf += 0.15; // health <= 0 check
		if (p.sLesses >= 1) conf += 0.15; // signed less (health < 0 = dead)
		if (p.loads >= 1) conf += 0.10; // load current health
		if (p.stores >= 1) conf += 0.10; // store updated health
		if (p.cbranches >= 1) conf += 0.10; // branch on death
		if (p.calls >= 1) conf += 0.05; // call death/game-over handler
		if (p.totalOps < 50) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("health_damage", "apply_damage_clamp",
			Math.min(conf, 0.75), "Health/damage: subtract, clamp to zero, death check");
	}

	private FunctionType detectInventoryManage(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Inventory: slot array scan, item add/remove, count check
		if (p.hasLoop) conf += 0.10;
		if (p.loads >= 3) conf += 0.10; // read slot data
		if (p.stores >= 2) conf += 0.10; // write to slot
		if (p.equals >= 1) conf += 0.10; // check item ID match
		if (p.cbranches >= 2) conf += 0.10; // empty slot check + found check
		if (p.adds >= 2) conf += 0.10; // index advance + count update
		if (p.lesses >= 1) conf += 0.10; // bounds check (max slots)
		if (p.constZeroCompares >= 1) conf += 0.05; // empty slot == 0
		if (p.constSmallInts >= 2) conf += 0.05; // slot size, max count
		if (conf < 0.55) return null;
		return new FunctionType("inventory_manage", "inventory_slot_op",
			Math.min(conf, 0.75), "Inventory management: slot array add/remove with bounds");
	}

	private FunctionType detectNpcDialog(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 20) return null;
		double conf = 0;
		// NPC dialog: index into text pointer table, advance dialog state
		if (p.loads >= 3) conf += 0.10; // load NPC ID, dialog index, text pointer
		if (p.lefts >= 1 || p.mults >= 1) conf += 0.10; // index * entry_size
		if (p.adds >= 2) conf += 0.10; // table base + offset, state advance
		if (p.stores >= 1) conf += 0.10; // update dialog state
		if (p.cbranch_eq_runs >= 1) conf += 0.10; // end-of-dialog check
		if (p.calls >= 1) conf += 0.10; // call text renderer
		if (p.constSmallInts >= 2) conf += 0.10; // state IDs
		if (p.cbranches >= 1) conf += 0.05;
		if (conf < 0.55) return null;
		return new FunctionType("npc_dialog", "dialog_text_advance",
			Math.min(conf, 0.75), "NPC dialog: text table index and state advance");
	}

	private FunctionType detectEnemyPatrol(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 25) return null;
		double conf = 0;
		// Enemy patrol: waypoint list, direction calc, timer decrement
		if (p.loads >= 3) conf += 0.10; // load waypoint, current pos, timer
		if (p.subs >= 2) conf += 0.15; // direction = target - current, timer--
		if (p.compares >= 2) conf += 0.10; // arrived? timer expired?
		if (p.cbranches >= 2) conf += 0.10; // waypoint-reached, timer branches
		if (p.stores >= 2) conf += 0.10; // update position, waypoint index
		if (p.adds >= 1) conf += 0.10; // advance waypoint index
		if (p.sLesses >= 1) conf += 0.05; // direction sign check
		if (p.constSmallInts >= 1) conf += 0.05; // waypoint count constant
		if (conf < 0.55) return null;
		return new FunctionType("enemy_patrol", "patrol_waypoint_advance",
			Math.min(conf, 0.75), "Enemy patrol with waypoint list, direction, and timer");
	}

	private FunctionType detectBossPattern(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		double conf = 0;
		// Boss pattern: phase check via compare chains, timer-driven attack select
		if (p.cbranch_eq_runs >= 3) conf += 0.15; // phase dispatch table
		if (p.loads >= 4) conf += 0.10; // load phase, timer, health, attack ID
		if (p.compares >= 3) conf += 0.15; // health thresholds for phase changes
		if (p.cbranches >= 3) conf += 0.10; // multi-way phase branching
		if (p.calls >= 2) conf += 0.10; // call attack subroutines
		if (p.subs >= 1) conf += 0.05; // timer decrement
		if (p.stores >= 2) conf += 0.05; // update phase and timer
		if (p.constSmallInts >= 2) conf += 0.05; // phase ID constants
		if (conf < 0.55) return null;
		return new FunctionType("boss_pattern", "boss_phase_attack",
			Math.min(conf, 0.75), "Boss pattern: phase check with timer-driven attack select");
	}

	private FunctionType detectArithmeticCoding(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 30) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// Arithmetic coding: range subdivision, renormalization, bit output
		if (p.mults >= 2) conf += 0.15; // range * probability
		if (p.rights >= 2) conf += 0.10; // range normalization shift
		if (p.subs >= 2) conf += 0.10; // high - low
		if (p.adds >= 1) conf += 0.05; // low + scaled range
		if (p.lesses >= 2) conf += 0.10; // range underflow check
		if (p.lefts >= 1) conf += 0.10; // bit output shift
		if (p.cbranches >= 3) conf += 0.10; // normalization + underflow branches
		if (p.stores >= 2) conf += 0.05; // update low and range state
		if (conf < 0.55) return null;
		return new FunctionType("arithmetic_coding", "arith_range_encode",
			Math.min(conf, 0.75), "Arithmetic coding with range subdivision and bit output");
	}

	private FunctionType detectLzwCodec(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 40) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// LZW: dictionary table build, variable-width code output
		if (p.loads >= 5) conf += 0.10; // dictionary lookups
		if (p.stores >= 3) conf += 0.10; // dictionary inserts
		if (p.lefts >= 1) conf += 0.10; // index scaling for table
		if (p.lesses >= 1) conf += 0.10; // code < table_size check
		if (p.adds >= 3) conf += 0.10; // pointer advance, table index++
		if (p.cbranches >= 3) conf += 0.10; // code-in-table, table-full, input-done
		if (p.hasNestedLoop || p.loopCount >= 2) conf += 0.05; // string output loop
		if (p.compares >= 3) conf += 0.10; // code comparisons
		if (conf < 0.55) return null;
		return new FunctionType("lzw_codec", "lzw_compress_decompress",
			Math.min(conf, 0.75), "LZW codec with dictionary build and code output");
	}

	private FunctionType detectBwtTransform(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 50) return null;
		if (!p.hasNestedLoop) return null;
		double conf = 0;
		// Burrows-Wheeler: suffix sort (nested loop), output last column
		if (p.loads >= 6) conf += 0.10; // character comparisons during sort
		if (p.stores >= 4) conf += 0.10; // index array updates
		if (p.compares >= 4) conf += 0.10; // sort key comparisons
		if (p.cbranches >= 4) conf += 0.10; // sort branching
		if (p.loopCount >= 2) conf += 0.10; // nested sort loops
		if (p.adds >= 4) conf += 0.10; // index arithmetic
		if (p.sLesses >= 2 || p.lesses >= 2) conf += 0.10; // character ordering
		if (p.copies >= 2) conf += 0.05; // swap during sort
		if (conf < 0.55) return null;
		return new FunctionType("bwt_transform", "burrows_wheeler_transform",
			Math.min(conf, 0.75), "Burrows-Wheeler transform with suffix sort");
	}

	private FunctionType detectDeflate(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 60) return null;
		if (!p.hasLoop) return null;
		double conf = 0;
		// DEFLATE: Huffman tree decode + LZ77 back-reference copy
		if (p.loads >= 6) conf += 0.10; // code table lookups
		if (p.ands >= 3) conf += 0.10; // bit extraction masks
		if (p.rights >= 2) conf += 0.10; // bitstream shift right
		if (p.cbranches >= 4) conf += 0.10; // decode branch cascade
		if (p.adds >= 3) conf += 0.05; // pointer advance
		if (p.subs >= 1) conf += 0.05; // distance back-reference
		if (p.hasNestedLoop) conf += 0.10; // inner copy loop for LZ77 match
		if (p.stores >= 3) conf += 0.05; // output decoded bytes
		if (p.lefts >= 1) conf += 0.05; // bit manipulation
		if (p.compares >= 4) conf += 0.05; // length/distance bounds checks
		if (conf < 0.55) return null;
		return new FunctionType("deflate", "deflate_decompress",
			Math.min(conf, 0.75), "DEFLATE decompression (Huffman + LZ77)");
	}

	private FunctionType detectUartInit(PcodeOp[] pcode, OpcodeProfile p) {
		if (p.totalOps < 15) return null;
		double conf = 0;
		// UART init: baud rate divisor write, parity/stop config registers
		if (p.ioRegionAccesses >= 3) conf += 0.20; // UART register writes
		if (p.consecutiveStores >= 3) conf += 0.15; // sequential register config
		if (p.stores >= 4) conf += 0.10; // write LCR, DLL, DLM, etc.
		if (p.divs >= 1 || p.rights >= 1) conf += 0.10; // baud rate divisor calc
		if (p.ands >= 1) conf += 0.05; // register field masking
		if (p.ors >= 1) conf += 0.10; // set configuration bits
		if (p.loads <= p.stores) conf += 0.05; // write-heavy initialization
		if (conf < 0.55) return null;
		return new FunctionType("uart_init", "uart_baud_config",
			Math.min(conf, 0.75), "UART initialization: baud rate divisor and line config");
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

		// Require very high similarity (>0.95) for feature-vector fallback.
		// Lower thresholds produce too many false positives — generic functions
		// on unfamiliar ISAs have similar P-code distributions.
		if (bestSimilarity < 0.95) return null;

		double conf = (bestSimilarity - 0.95) * 10.0; // 0.95->0, 0.98->0.30, 1.0->0.50
		conf = Math.max(0.90, Math.min(0.95, conf + 0.90));

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

		// I2C protocol: IO-heavy, shift for bit assembly, small loop
		new ReferenceSignature("i2c", "i2c_protocol",
			"I2C bus protocol handler",
			new double[]{0.16,0.20,0.06,0.04,0.06,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.50,0.08,0.10,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.20,0.00}),

		// SPI protocol: clock toggle, shift in/out, IO stores
		new ReferenceSignature("spi", "spi_protocol",
			"SPI bus transfer",
			new double[]{0.16,0.18,0.06,0.04,0.08,0.06,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.55,0.08,0.08,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.00}),

		// MIDI handler: status byte dispatch, data byte validation
		new ReferenceSignature("midi", "midi_handler",
			"MIDI message handler",
			new double[]{0.14,0.08,0.06,0.06,0.02,0.16,0.14,0.08,
				0.06,0.02, 0.20,0.08,0.40,0.12,0.15,
				0.00,0.00,0.00,0.00,0.00,0.06,0.04,0.00,0.25,0.06}),

		// Modbus RTU: CRC16 with polynomial, function code dispatch
		new ReferenceSignature("modbus", "modbus_protocol",
			"Modbus RTU protocol handler",
			new double[]{0.14,0.08,0.12,0.06,0.06,0.12,0.12,0.08,
				0.06,0.02, 0.30,0.08,0.40,0.10,0.18,
				0.04,0.06,0.08,0.00,0.00,0.08,0.04,0.00,0.22,0.04}),

		// Huffman decode: bit-by-bit tree traversal
		new ReferenceSignature("huffman", "huffman_decode",
			"Huffman bitstream decoder",
			new double[]{0.18,0.10,0.08,0.06,0.10,0.10,0.12,0.04,
				0.06,0.02, 0.45,0.04,0.50,0.14,0.18,
				0.06,0.06,0.00,0.00,0.00,0.10,0.06,0.04,0.22,0.04}),

		// Base64 encode: 6-bit chunks, shift/mask, table lookup
		new ReferenceSignature("base64enc", "base64_encode",
			"Base64 encoder",
			new double[]{0.16,0.14,0.06,0.06,0.10,0.06,0.08,0.04,
				0.06,0.02, 0.30,0.04,0.60,0.08,0.14,
				0.04,0.04,0.00,0.00,0.00,0.06,0.04,0.00,0.18,0.04}),

		// Base64 decode: reverse lookup, OR assembly
		new ReferenceSignature("base64dec", "base64_decode",
			"Base64 decoder",
			new double[]{0.18,0.12,0.06,0.08,0.08,0.08,0.08,0.04,
				0.06,0.02, 0.30,0.04,0.55,0.08,0.16,
				0.04,0.04,0.00,0.00,0.00,0.08,0.04,0.00,0.18,0.04}),

		// UTF-8 encode: range checks, continuation bytes
		new ReferenceSignature("utf8enc", "utf8_encode",
			"UTF-8 encoder",
			new double[]{0.10,0.12,0.06,0.06,0.06,0.16,0.14,0.04,
				0.06,0.02, 0.15,0.04,0.45,0.12,0.14,
				0.00,0.00,0.00,0.00,0.00,0.04,0.04,0.00,0.12,0.00}),

		// UTF-8 decode: lead byte dispatch, mask and assemble
		new ReferenceSignature("utf8dec", "utf8_decode",
			"UTF-8 decoder",
			new double[]{0.14,0.08,0.06,0.08,0.06,0.16,0.14,0.04,
				0.06,0.02, 0.15,0.04,0.50,0.12,0.16,
				0.00,0.00,0.00,0.00,0.00,0.06,0.04,0.00,0.14,0.00}),

		// Population count: XOR/AND/shift patterns (SWAR or Kernighan)
		new ReferenceSignature("popcount", "population_count",
			"Bit population count (Hamming weight)",
			new double[]{0.06,0.04,0.16,0.08,0.14,0.04,0.08,0.02,
				0.04,0.02, 0.25,0.02,0.40,0.06,0.12,
				0.00,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.12,0.00}),

		// Bitmap blit: nested loop, load/store alternation, stride
		new ReferenceSignature("blit", "bitmap_blit",
			"Bitmap block transfer (blit)",
			new double[]{0.18,0.16,0.08,0.04,0.02,0.06,0.08,0.04,
				0.06,0.04, 0.45,0.04,0.60,0.12,0.12,
				0.08,0.04,0.00,0.00,0.00,0.08,0.00,0.04,0.18,0.04}),

		// Flood fill: pixel read, compare, 4-way neighbor push
		new ReferenceSignature("floodfill", "flood_fill",
			"Flood fill algorithm",
			new double[]{0.16,0.12,0.10,0.04,0.02,0.14,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.55,0.12,0.10,
				0.00,0.04,0.00,0.00,0.00,0.10,0.00,0.02,0.20,0.04}),

		// Circle draw: Bresenham, decision variable, 8-way plot
		new ReferenceSignature("circle", "circle_draw",
			"Circle rasterizer (Bresenham)",
			new double[]{0.08,0.14,0.14,0.04,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.30,0.08,0.08,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.15,0.00}),

		// Polygon fill: edge table, scanline, DDA
		new ReferenceSignature("polygon", "polygon_fill",
			"Polygon scanline fill",
			new double[]{0.14,0.14,0.12,0.04,0.02,0.10,0.10,0.06,
				0.06,0.02, 0.45,0.06,0.50,0.12,0.14,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.20,0.04}),

		// RTC management: IO reads, time constants (60, 24)
		new ReferenceSignature("rtc", "rtc_management",
			"Real-time clock management",
			new double[]{0.18,0.14,0.06,0.04,0.02,0.10,0.10,0.06,
				0.06,0.02, 0.15,0.06,0.55,0.08,0.14,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.15,0.00}),

		// Calendar date: month table, leap year, carry propagation
		new ReferenceSignature("calendar", "calendar_date",
			"Calendar/date arithmetic",
			new double[]{0.14,0.10,0.10,0.04,0.02,0.14,0.12,0.06,
				0.06,0.02, 0.20,0.06,0.55,0.10,0.18,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.00}),

		// CRT init: copy data, zero BSS, consecutive stores
		new ReferenceSignature("crtinit", "crt_init",
			"C runtime initialization",
			new double[]{0.12,0.20,0.06,0.02,0.02,0.06,0.08,0.06,
				0.08,0.04, 0.30,0.06,0.30,0.06,0.06,
				0.06,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.50}),

		// Assert/panic: condition + halt loop or trap
		new ReferenceSignature("panic", "assert_panic",
			"Assertion/panic handler",
			new double[]{0.10,0.06,0.04,0.02,0.00,0.12,0.14,0.10,
				0.06,0.02, 0.10,0.10,0.30,0.10,0.06,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.20,0.04}),

		// Log with severity: level compare, conditional output
		new ReferenceSignature("logprint", "severity_logger",
			"Log output with severity level",
			new double[]{0.14,0.08,0.06,0.04,0.02,0.14,0.12,0.12,
				0.06,0.02, 0.15,0.12,0.40,0.12,0.12,
				0.00,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.18,0.06}),

		// PID controller: error, integral, derivative, 3 multiplies
		new ReferenceSignature("pid", "pid_controller",
			"PID control loop",
			new double[]{0.14,0.14,0.16,0.04,0.02,0.08,0.08,0.04,
				0.06,0.02, 0.15,0.04,0.50,0.06,0.10,
				0.00,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.00}),

		// PWM generation: timer IO, compare with duty cycle
		new ReferenceSignature("pwm", "pwm_generation",
			"PWM signal generation",
			new double[]{0.14,0.16,0.06,0.04,0.02,0.12,0.10,0.04,
				0.06,0.02, 0.10,0.04,0.45,0.08,0.12,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.12,0.00}),

		// FIFO queue: head/tail modular increment
		new ReferenceSignature("fifo", "fifo_queue",
			"FIFO queue push/pop",
			new double[]{0.16,0.14,0.08,0.04,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.15,0.04,0.55,0.08,0.08,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.14,0.00}),

		// Priority queue: binary heap with /2 and *2
		new ReferenceSignature("pqueue", "priority_queue",
			"Binary heap sift operation",
			new double[]{0.16,0.12,0.10,0.04,0.04,0.12,0.10,0.04,
				0.06,0.02, 0.30,0.04,0.55,0.10,0.10,
				0.04,0.04,0.00,0.00,0.04,0.08,0.00,0.02,0.18,0.04}),

		// Hash table: hash + mod + chain traversal
		new ReferenceSignature("hashtable", "hash_table",
			"Hash table lookup/insert",
			new double[]{0.18,0.10,0.10,0.06,0.04,0.12,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.50,0.10,0.16,
				0.04,0.06,0.04,0.00,0.00,0.08,0.00,0.02,0.20,0.04}),

		// Binary search: midpoint, compare, halve range
		new ReferenceSignature("bsearch", "binary_search",
			"Binary search algorithm",
			new double[]{0.14,0.06,0.10,0.04,0.04,0.14,0.14,0.04,
				0.06,0.02, 0.25,0.04,0.35,0.12,0.10,
				0.00,0.04,0.00,0.00,0.04,0.06,0.00,0.00,0.18,0.00}),

		// Hamming ECC: XOR tree at power-of-2 positions
		new ReferenceSignature("hamming", "hamming_ecc",
			"Hamming error correction code",
			new double[]{0.10,0.06,0.08,0.12,0.08,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.40,0.08,0.14,
				0.00,0.04,0.08,0.00,0.00,0.06,0.00,0.00,0.16,0.00}),

		// Galois field multiply: XOR + shift + conditional polynomial reduce
		new ReferenceSignature("galois", "gf_multiply",
			"Galois field GF(2^8) multiplication",
			new double[]{0.06,0.04,0.08,0.06,0.14,0.06,0.10,0.02,
				0.04,0.02, 0.25,0.02,0.30,0.08,0.10,
				0.00,0.04,0.06,0.00,0.00,0.06,0.00,0.00,0.14,0.00}),

		// DMA chaining: build descriptor list, IO writes
		new ReferenceSignature("dmachain", "dma_chaining",
			"DMA descriptor chain setup",
			new double[]{0.10,0.22,0.06,0.04,0.02,0.06,0.08,0.04,
				0.08,0.04, 0.25,0.04,0.25,0.06,0.10,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.02,0.12,0.50}),

		// Timer setup: consecutive IO writes for prescaler/count/control
		new ReferenceSignature("timer", "timer_setup",
			"Timer/counter configuration",
			new double[]{0.10,0.20,0.04,0.04,0.02,0.06,0.06,0.04,
				0.06,0.02, 0.08,0.04,0.25,0.04,0.10,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.08,0.40}),

		// FAT filesystem: cluster chain, sector size 512
		new ReferenceSignature("fat", "fat_filesystem",
			"FAT filesystem operation",
			new double[]{0.16,0.10,0.10,0.06,0.04,0.10,0.12,0.08,
				0.06,0.02, 0.30,0.08,0.50,0.10,0.18,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.02,0.22,0.04}),

		// Disk block IO: sector read/write, CHS/LBA, status poll
		new ReferenceSignature("diskio", "disk_block_io",
			"Disk sector I/O",
			new double[]{0.16,0.12,0.08,0.04,0.04,0.10,0.10,0.08,
				0.06,0.02, 0.25,0.08,0.55,0.08,0.14,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.20,0.04}),

		// Matrix multiply: triple loop, multiply-accumulate
		new ReferenceSignature("matmul", "matrix_multiply",
			"Matrix multiplication",
			new double[]{0.16,0.12,0.14,0.04,0.02,0.06,0.08,0.04,
				0.06,0.02, 0.50,0.04,0.55,0.10,0.10,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.02,0.15,0.04}),

		// FFT butterfly: complex multiply (4 muls), add/subtract pairs
		new ReferenceSignature("fft", "fft_butterfly",
			"FFT butterfly operation",
			new double[]{0.14,0.14,0.18,0.04,0.04,0.06,0.08,0.04,
				0.06,0.02, 0.45,0.04,0.50,0.08,0.12,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.02,0.18,0.04}),

		// Software float add: extract sign/exp/mantissa, align, normalize
		new ReferenceSignature("softfloatadd", "float_emul_add",
			"Software floating-point addition",
			new double[]{0.12,0.10,0.12,0.08,0.12,0.10,0.10,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.08,0.18,
				0.00,0.04,0.00,0.00,0.00,0.06,0.04,0.00,0.15,0.00}),

		// Software float mul: mantissa multiply, exponent add, normalize
		new ReferenceSignature("softfloatmul", "float_emul_mul",
			"Software floating-point multiply",
			new double[]{0.10,0.10,0.16,0.08,0.10,0.08,0.08,0.04,
				0.06,0.02, 0.15,0.04,0.50,0.06,0.18,
				0.00,0.04,0.00,0.00,0.00,0.04,0.04,0.00,0.12,0.00}),

		// Vector table setup: consecutive stores of handler addresses
		new ReferenceSignature("vectable", "vector_table_setup",
			"Exception vector table initialization",
			new double[]{0.06,0.24,0.04,0.02,0.00,0.04,0.06,0.02,
				0.08,0.04, 0.08,0.02,0.12,0.04,0.20,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.06,0.60}),

		// Relocation: read-modify-write loop adding base offset
		new ReferenceSignature("reloc", "relocation",
			"Address relocation/fixup",
			new double[]{0.16,0.16,0.12,0.02,0.02,0.06,0.08,0.04,
				0.06,0.02, 0.30,0.04,0.50,0.06,0.08,
				0.06,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.14,0.04}),

		// SCSI phase handler: IO reads, phase mask, 8-way dispatch
		new ReferenceSignature("scsiphase", "scsi_phase_handler",
			"SCSI bus phase state machine",
			new double[]{0.16,0.10,0.04,0.06,0.02,0.14,0.14,0.10,
				0.06,0.02, 0.20,0.10,0.50,0.12,0.14,
				0.00,0.04,0.00,0.00,0.00,0.08,0.04,0.00,0.25,0.04}),

		// CD-ROM command: opcode dispatch, sector constants
		new ReferenceSignature("cdrom", "cdrom_command",
			"CD-ROM command dispatcher",
			new double[]{0.14,0.08,0.06,0.04,0.02,0.16,0.14,0.12,
				0.06,0.02, 0.20,0.12,0.40,0.12,0.16,
				0.00,0.04,0.00,0.00,0.00,0.10,0.04,0.00,0.25,0.06}),

		// ARP handler: ethertype check, IP/MAC load, cache store
		new ReferenceSignature("arp", "arp_handler",
			"ARP protocol handler",
			new double[]{0.18,0.12,0.04,0.04,0.02,0.14,0.12,0.06,
				0.06,0.02, 0.15,0.06,0.55,0.10,0.16,
				0.00,0.04,0.00,0.00,0.00,0.10,0.00,0.00,0.18,0.04}),

		// TCP state machine: many state+flag branches
		new ReferenceSignature("tcp", "tcp_state_machine",
			"TCP connection state machine",
			new double[]{0.14,0.10,0.06,0.08,0.02,0.16,0.14,0.10,
				0.06,0.02, 0.25,0.10,0.45,0.14,0.18,
				0.00,0.04,0.00,0.00,0.00,0.10,0.06,0.00,0.28,0.04}),

		// VT100 parser: ESC check, CSI dispatch, parameter digits
		new ReferenceSignature("vt100", "vt100_parser",
			"Terminal escape sequence parser",
			new double[]{0.16,0.10,0.06,0.04,0.02,0.16,0.14,0.06,
				0.06,0.02, 0.25,0.06,0.50,0.14,0.16,
				0.00,0.04,0.00,0.00,0.00,0.10,0.04,0.00,0.25,0.04}),

		// Spinlock: tiny loop, load-compare-store
		new ReferenceSignature("spinlock", "mutex_spinlock",
			"Mutex/spinlock acquire",
			new double[]{0.18,0.10,0.04,0.02,0.00,0.14,0.16,0.02,
				0.06,0.02, 0.20,0.02,0.50,0.12,0.04,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.20,0.00}),

		// Coroutine switch: save regs, load regs, minimal arithmetic
		new ReferenceSignature("coroutine", "coroutine_switch",
			"Coroutine/fiber context switch",
			new double[]{0.20,0.20,0.04,0.02,0.00,0.04,0.06,0.02,
				0.08,0.04, 0.08,0.02,0.50,0.04,0.06,
				0.06,0.04,0.00,0.00,0.00,0.02,0.00,0.00,0.08,0.40}),

		// Audio mixer: multiply volumes, accumulate, clip
		new ReferenceSignature("audiomix", "audio_mixer",
			"Multi-channel audio mixer",
			new double[]{0.16,0.10,0.14,0.04,0.04,0.08,0.10,0.04,
				0.06,0.02, 0.35,0.04,0.50,0.08,0.10,
				0.04,0.06,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// ADSR envelope: 4-phase state dispatch, ramp up/down
		new ReferenceSignature("adsr", "adsr_envelope",
			"ADSR sound envelope",
			new double[]{0.14,0.12,0.10,0.04,0.02,0.14,0.12,0.06,
				0.06,0.02, 0.20,0.06,0.55,0.10,0.12,
				0.00,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.20,0.04}),

		// Wavetable synth: phase accumulator, table index, interpolate
		new ReferenceSignature("wavetable", "wavetable_synth",
			"Wavetable synthesis oscillator",
			new double[]{0.16,0.12,0.10,0.06,0.06,0.06,0.08,0.04,
				0.06,0.02, 0.25,0.04,0.55,0.06,0.12,
				0.04,0.06,0.00,0.00,0.00,0.06,0.00,0.02,0.15,0.04}),

		// FM synth: phase + modulation, sine table, envelope multiply
		new ReferenceSignature("fmsynth", "fm_synth_operator",
			"FM synthesis operator",
			new double[]{0.14,0.12,0.12,0.06,0.04,0.06,0.08,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.06,0.12,
				0.04,0.06,0.00,0.00,0.00,0.06,0.00,0.02,0.14,0.04}),

		// Sample rate converter: interpolation weights, fraction tracking
		new ReferenceSignature("src", "sample_rate_convert",
			"Sample rate conversion",
			new double[]{0.16,0.10,0.12,0.06,0.06,0.06,0.08,0.04,
				0.06,0.02, 0.30,0.04,0.50,0.06,0.10,
				0.04,0.06,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// RLE encoder: compare current==previous, count runs
		new ReferenceSignature("rleenc", "rle_encode",
			"Run-length encoder",
			new double[]{0.16,0.12,0.06,0.02,0.02,0.14,0.12,0.04,
				0.06,0.02, 0.30,0.04,0.55,0.10,0.08,
				0.04,0.04,0.00,0.00,0.00,0.10,0.00,0.02,0.18,0.04}),

		// Delta encoder: current - previous
		new ReferenceSignature("deltaenc", "delta_encode",
			"Delta/differential encoder",
			new double[]{0.16,0.14,0.10,0.02,0.02,0.06,0.08,0.02,
				0.06,0.02, 0.25,0.02,0.55,0.06,0.06,
				0.06,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.14,0.04}),

		// Delta decoder: accumulator += delta
		new ReferenceSignature("deltadec", "delta_decode",
			"Delta/differential decoder",
			new double[]{0.16,0.14,0.08,0.02,0.02,0.06,0.08,0.02,
				0.06,0.02, 0.25,0.02,0.55,0.06,0.06,
				0.06,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.14,0.04}),

		// Sensor calibration: offset + scale, clamp
		new ReferenceSignature("sensor", "sensor_calibration",
			"Sensor/ADC calibration",
			new double[]{0.16,0.10,0.12,0.04,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.10,0.04,0.50,0.08,0.10,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.12,0.00}),

		// Power sleep: save context, write sleep register
		new ReferenceSignature("sleep", "power_sleep",
			"Power management sleep entry",
			new double[]{0.10,0.18,0.04,0.04,0.02,0.06,0.08,0.04,
				0.06,0.02, 0.10,0.04,0.30,0.06,0.10,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.08,0.40}),

		// Slab allocator: freelist pop, null check
		new ReferenceSignature("slab", "slab_allocator",
			"Slab/pool allocator",
			new double[]{0.18,0.12,0.06,0.02,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.10,0.04,0.55,0.08,0.08,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.14,0.00}),

		// Bit reverse: shift/mask loop or table lookup
		new ReferenceSignature("bitrev", "bit_reverse",
			"Bit reversal permutation",
			new double[]{0.10,0.06,0.06,0.06,0.14,0.04,0.08,0.02,
				0.04,0.02, 0.20,0.02,0.40,0.06,0.08,
				0.00,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.12,0.00}),

		// XDR encode: shift right 24/16/8, mask 0xFF
		new ReferenceSignature("xdrenc", "xdr_encode",
			"Network byte order encoder",
			new double[]{0.06,0.14,0.04,0.06,0.12,0.04,0.06,0.02,
				0.04,0.02, 0.08,0.02,0.20,0.04,0.10,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.06,0.40}),

		// XDR decode: load 4 bytes, shift left, OR together
		new ReferenceSignature("xdrdec", "xdr_decode",
			"Network byte order decoder",
			new double[]{0.18,0.06,0.04,0.08,0.12,0.04,0.06,0.02,
				0.04,0.02, 0.08,0.02,0.15,0.04,0.10,
				0.06,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.06,0.00}),

		// Page table walk: shift for index, load PTE, check valid
		new ReferenceSignature("pagetable", "page_table_walk",
			"MMU page table walk",
			new double[]{0.18,0.06,0.06,0.08,0.08,0.10,0.10,0.04,
				0.06,0.02, 0.15,0.04,0.40,0.08,0.14,
				0.04,0.04,0.00,0.00,0.00,0.06,0.04,0.00,0.16,0.00}),

		// Cache flush: loop by line size, CALLOTHER for CINV/CPUSH
		new ReferenceSignature("cacheflush", "cache_flush",
			"Cache flush/invalidate",
			new double[]{0.08,0.06,0.08,0.04,0.02,0.10,0.12,0.04,
				0.06,0.02, 0.20,0.04,0.30,0.08,0.08,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.15,0.00}),

		// Event signal: traverse waiter list, set flags
		new ReferenceSignature("eventsig", "event_signal",
			"Event/signal notification",
			new double[]{0.16,0.12,0.04,0.06,0.02,0.10,0.10,0.06,
				0.06,0.02, 0.20,0.06,0.55,0.08,0.08,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.16,0.04}),

		// Pathfinding: nested loop, cost compare, neighbor expansion
		new ReferenceSignature("pathfind", "pathfinding",
			"Pathfinding (A*/BFS/Dijkstra)",
			new double[]{0.16,0.14,0.10,0.04,0.02,0.12,0.12,0.06,
				0.06,0.02, 0.45,0.06,0.55,0.12,0.14,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.22,0.04}),

		// Save/load state: bulk field copy, optional checksum
		new ReferenceSignature("savestate", "save_load_state",
			"State serialization",
			new double[]{0.18,0.16,0.06,0.02,0.02,0.06,0.08,0.06,
				0.06,0.02, 0.25,0.06,0.60,0.06,0.08,
				0.08,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.04}),

		// High score table: compare scores, shift entries
		new ReferenceSignature("hiscore", "high_score_table",
			"High score table insertion",
			new double[]{0.16,0.14,0.08,0.02,0.02,0.12,0.12,0.04,
				0.06,0.02, 0.25,0.04,0.55,0.10,0.08,
				0.06,0.04,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// Demo playback: read input from buffer, advance frame
		new ReferenceSignature("demo", "demo_playback",
			"Demo/attract mode playback",
			new double[]{0.16,0.10,0.06,0.02,0.02,0.10,0.10,0.06,
				0.06,0.02, 0.25,0.06,0.50,0.08,0.10,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// LCD init: sequential IO writes
		new ReferenceSignature("lcdinit", "lcd_init",
			"LCD/display controller init",
			new double[]{0.06,0.22,0.04,0.04,0.02,0.04,0.06,0.06,
				0.06,0.02, 0.08,0.06,0.15,0.04,0.12,
				0.00,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.06,0.50}),

		// Motor control: phase sequence, IO, step delay
		new ReferenceSignature("motor", "motor_control",
			"Motor/stepper driver control",
			new double[]{0.12,0.16,0.06,0.06,0.02,0.08,0.10,0.06,
				0.06,0.02, 0.20,0.06,0.40,0.08,0.10,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.15,0.04}),

		// Keyboard scan: drive rows, read columns, keycode
		new ReferenceSignature("kbdscan", "keyboard_scan",
			"Keyboard matrix scanner",
			new double[]{0.16,0.14,0.06,0.06,0.04,0.10,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.55,0.08,0.10,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// HMAC: ipad/opad XOR, two hash calls
		new ReferenceSignature("hmac", "hmac_compute",
			"HMAC message authentication",
			new double[]{0.14,0.10,0.06,0.10,0.04,0.08,0.10,0.10,
				0.06,0.02, 0.25,0.10,0.45,0.08,0.16,
				0.04,0.06,0.08,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// ELF parser: magic check, section header iteration
		new ReferenceSignature("elfparse", "elf_parser",
			"ELF/COFF section parser",
			new double[]{0.18,0.08,0.06,0.04,0.02,0.12,0.12,0.08,
				0.06,0.02, 0.25,0.08,0.45,0.10,0.18,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.22,0.04}),

		// PS/2 protocol: 11-bit frame, clock/data bit-bang
		new ReferenceSignature("ps2", "ps2_protocol",
			"PS/2 keyboard/mouse protocol",
			new double[]{0.16,0.16,0.06,0.06,0.06,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.50,0.08,0.10,
				0.00,0.04,0.04,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// GC mark: traverse object graph, set mark bits
		new ReferenceSignature("gcmark", "gc_mark",
			"Garbage collector mark phase",
			new double[]{0.18,0.10,0.04,0.08,0.02,0.12,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.50,0.10,0.10,
				0.04,0.04,0.04,0.00,0.00,0.08,0.00,0.02,0.20,0.04}),

		// Framebuffer swap: swap pointers, write display register
		new ReferenceSignature("fbswap", "framebuffer_swap",
			"Double-buffer framebuffer swap",
			new double[]{0.14,0.14,0.06,0.04,0.02,0.06,0.08,0.02,
				0.06,0.02, 0.06,0.02,0.50,0.06,0.08,
				0.04,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.08,0.04}),

		// VRAM clear: tight store loop to graphics memory
		new ReferenceSignature("vramclr", "vram_clear",
			"VRAM fill/clear loop",
			new double[]{0.06,0.22,0.06,0.02,0.02,0.06,0.08,0.02,
				0.06,0.02, 0.20,0.02,0.15,0.06,0.06,
				0.04,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.10,0.40}),

		// EEPROM: IO-heavy, bit-bang or poll, shift for address/data
		new ReferenceSignature("eeprom", "eeprom_access",
			"EEPROM/NVRAM read/write",
			new double[]{0.16,0.16,0.06,0.06,0.06,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.50,0.08,0.10,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// ADC: IO poll, mask result bits
		new ReferenceSignature("adc", "adc_read",
			"ADC conversion read",
			new double[]{0.18,0.08,0.04,0.06,0.02,0.10,0.12,0.04,
				0.06,0.02, 0.20,0.04,0.40,0.08,0.08,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.18,0.00}),

		// DAC: scale + IO write, very short
		new ReferenceSignature("dac", "dac_output",
			"DAC output write",
			new double[]{0.08,0.16,0.06,0.06,0.04,0.04,0.06,0.02,
				0.06,0.02, 0.06,0.02,0.25,0.04,0.08,
				0.00,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.06,0.00}),

		// DIP switch: single IO read, multiple AND extractions
		new ReferenceSignature("dipswitch", "dip_switch_read",
			"DIP switch configuration read",
			new double[]{0.14,0.10,0.04,0.10,0.04,0.06,0.08,0.02,
				0.06,0.02, 0.06,0.02,0.55,0.06,0.10,
				0.00,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.08,0.04}),

		// Coin handler: edge detect, increment, BCD/saturation
		new ReferenceSignature("coin", "coin_handler",
			"Coin/credit insertion handler",
			new double[]{0.14,0.12,0.08,0.06,0.02,0.12,0.12,0.04,
				0.06,0.02, 0.15,0.04,0.55,0.10,0.12,
				0.00,0.04,0.04,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// OSD overlay: conditional pixel blit, nested loop
		new ReferenceSignature("osd", "osd_overlay",
			"On-screen display overlay",
			new double[]{0.18,0.14,0.06,0.04,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.40,0.04,0.55,0.10,0.10,
				0.06,0.04,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// Character generator: char*height, load glyph scanlines
		new ReferenceSignature("chargen", "chargen_lookup",
			"Character generator ROM lookup",
			new double[]{0.18,0.10,0.08,0.04,0.06,0.06,0.08,0.04,
				0.06,0.02, 0.20,0.04,0.50,0.06,0.10,
				0.04,0.06,0.00,0.00,0.00,0.06,0.00,0.02,0.14,0.04}),

		// NAND flash: command+address writes, poll, bulk read
		new ReferenceSignature("nand", "nand_flash_read",
			"NAND flash page read",
			new double[]{0.16,0.16,0.06,0.04,0.02,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.50,0.08,0.12,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.20}),

		// Newton-Raphson: divide + add + shift, convergence loop
		new ReferenceSignature("newton", "newton_raphson",
			"Newton-Raphson iterative solver",
			new double[]{0.10,0.06,0.14,0.04,0.06,0.08,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.40,0.08,0.08,
				0.00,0.06,0.00,0.00,0.04,0.04,0.00,0.00,0.15,0.00}),

		// Euclidean distance: subtract, multiply, add, sqrt
		new ReferenceSignature("euclid", "euclidean_distance",
			"Euclidean distance calculation",
			new double[]{0.12,0.06,0.18,0.04,0.02,0.06,0.08,0.06,
				0.06,0.02, 0.08,0.06,0.40,0.06,0.08,
				0.00,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.10,0.00}),

		// atan2: quadrant dispatch, divide, polynomial
		new ReferenceSignature("atan2", "atan2_approx",
			"atan2 angle approximation",
			new double[]{0.10,0.06,0.16,0.04,0.04,0.14,0.12,0.06,
				0.06,0.02, 0.15,0.06,0.40,0.10,0.12,
				0.00,0.04,0.00,0.00,0.04,0.04,0.00,0.00,0.14,0.00}),

		// Sigmoid: clamp, table index, interpolation
		new ReferenceSignature("sigmoid", "sigmoid_lookup",
			"Sigmoid/activation function",
			new double[]{0.14,0.06,0.10,0.06,0.06,0.10,0.10,0.04,
				0.06,0.02, 0.10,0.04,0.40,0.08,0.12,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.12,0.00}),

		// CAN bus: frame pack, IO writes, arbitration check
		new ReferenceSignature("can", "can_bus_frame",
			"CAN bus frame transmit",
			new double[]{0.12,0.18,0.06,0.06,0.04,0.08,0.10,0.04,
				0.06,0.02, 0.20,0.04,0.40,0.08,0.12,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.16,0.20}),

		// 1-Wire: IO pin toggle, timing, CRC-8
		new ReferenceSignature("onewire", "onewire_protocol",
			"1-Wire protocol handler",
			new double[]{0.14,0.16,0.06,0.06,0.06,0.08,0.10,0.06,
				0.06,0.02, 0.25,0.06,0.45,0.08,0.10,
				0.00,0.04,0.04,0.00,0.00,0.06,0.00,0.00,0.16,0.04}),

		// Manchester: XOR encode, shift in/out
		new ReferenceSignature("manchester", "manchester_codec",
			"Manchester encoding/decoding",
			new double[]{0.10,0.10,0.06,0.10,0.10,0.06,0.08,0.04,
				0.06,0.02, 0.25,0.04,0.40,0.06,0.08,
				0.00,0.04,0.06,0.00,0.00,0.06,0.00,0.00,0.14,0.04}),

		// HDLC: flag/escape bytes, CRC-CCITT
		new ReferenceSignature("hdlc", "hdlc_framing",
			"HDLC frame framing",
			new double[]{0.16,0.12,0.06,0.06,0.04,0.12,0.12,0.04,
				0.06,0.02, 0.25,0.04,0.55,0.10,0.14,
				0.04,0.04,0.04,0.00,0.00,0.08,0.04,0.00,0.20,0.04}),

		// Idle/WFI: nearly empty, halt instruction
		new ReferenceSignature("idle", "idle_wfi",
			"Idle loop / wait-for-interrupt",
			new double[]{0.04,0.02,0.02,0.02,0.00,0.04,0.10,0.02,
				0.02,0.00, 0.10,0.02,0.10,0.06,0.02,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.10,0.00}),

		// IRQ priority dispatch: read status, index vector, indirect call
		new ReferenceSignature("irqdispatch", "irq_priority_dispatch",
			"Interrupt priority dispatch",
			new double[]{0.16,0.06,0.06,0.06,0.06,0.10,0.10,0.08,
				0.06,0.02, 0.10,0.08,0.35,0.08,0.12,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.15,0.00}),

		// Exception frame: consecutive register saves
		new ReferenceSignature("excframe", "exception_frame",
			"Exception frame builder",
			new double[]{0.06,0.24,0.04,0.02,0.00,0.04,0.06,0.04,
				0.08,0.04, 0.06,0.04,0.12,0.04,0.06,
				0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.06,0.50}),

		// POST memory: write pattern, read-verify, nested loops
		new ReferenceSignature("postmem", "post_memory_test",
			"POST memory pattern test",
			new double[]{0.16,0.14,0.06,0.04,0.02,0.12,0.12,0.04,
				0.06,0.02, 0.40,0.04,0.55,0.10,0.12,
				0.06,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.20,0.04}),

		// AI decision tree: many threshold compares, cascading branches
		new ReferenceSignature("ai", "ai_decision_tree",
			"AI behavior decision tree",
			new double[]{0.16,0.06,0.08,0.04,0.02,0.18,0.16,0.08,
				0.06,0.02, 0.15,0.08,0.40,0.14,0.14,
				0.00,0.04,0.00,0.00,0.00,0.10,0.00,0.00,0.28,0.04}),

		// Continue countdown: decrement, zero check, call game-over
		new ReferenceSignature("countdown", "continue_countdown",
			"Continue/game-over countdown",
			new double[]{0.12,0.10,0.08,0.02,0.00,0.14,0.14,0.08,
				0.06,0.02, 0.10,0.08,0.45,0.10,0.08,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// Interlace toggle: XOR field bit, update display register
		new ReferenceSignature("interlace", "interlace_toggle",
			"Interlace field toggle",
			new double[]{0.10,0.12,0.06,0.06,0.02,0.06,0.08,0.02,
				0.06,0.02, 0.06,0.02,0.40,0.06,0.08,
				0.00,0.00,0.04,0.00,0.00,0.02,0.00,0.00,0.08,0.04}),

		// Wear leveling: scan erase counts, find minimum
		new ReferenceSignature("wearlevel", "wear_leveling",
			"Flash wear leveling",
			new double[]{0.16,0.12,0.08,0.04,0.02,0.12,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.55,0.10,0.12,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.02,0.20,0.04}),

		// Bad block scan: iterate blocks, check 0xFF marker
		new ReferenceSignature("badblock", "bad_block_scan",
			"NAND bad block table scan",
			new double[]{0.16,0.10,0.04,0.06,0.02,0.12,0.12,0.04,
				0.06,0.02, 0.25,0.04,0.50,0.10,0.10,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.18,0.04}),

		// Random level gen: RNG, modulo, store to array
		new ReferenceSignature("levelgen", "random_level_gen",
			"Procedural level generator",
			new double[]{0.12,0.14,0.08,0.04,0.02,0.08,0.10,0.08,
				0.06,0.02, 0.30,0.08,0.45,0.08,0.14,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.02,0.18,0.04}),

		// Input recording: read controller, store to ring buffer
		new ReferenceSignature("inputrec", "input_recording",
			"Input recording to ring buffer",
			new double[]{0.16,0.14,0.06,0.04,0.02,0.08,0.08,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.06,0.08,
				0.04,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.14,0.04}),

		// Thermal printer: ESC commands + text data
		new ReferenceSignature("printer", "thermal_printer",
			"Thermal printer command handler",
			new double[]{0.16,0.12,0.04,0.04,0.02,0.12,0.12,0.06,
				0.06,0.02, 0.20,0.06,0.55,0.10,0.12,
				0.00,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.20,0.04}),

		// Weight tare: average ADC readings, store offset
		new ReferenceSignature("tare", "weight_tare",
			"Weight scale tare calibration",
			new double[]{0.14,0.10,0.10,0.04,0.04,0.06,0.08,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.06,0.08,
				0.00,0.06,0.00,0.00,0.04,0.04,0.00,0.00,0.14,0.00}),

		// Fuel injection: sensor reads, multiply/scale, clamp PWM
		new ReferenceSignature("fuel", "fuel_injection",
			"Fuel injection timing",
			new double[]{0.14,0.12,0.14,0.04,0.02,0.10,0.10,0.04,
				0.06,0.02, 0.15,0.04,0.55,0.08,0.12,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.14,0.00}),

		// Barcode decode: bitstream, table lookup, checksum
		new ReferenceSignature("barcode", "barcode_decode",
			"Barcode scanner decode",
			new double[]{0.16,0.08,0.10,0.08,0.06,0.10,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.45,0.10,0.16,
				0.04,0.06,0.00,0.00,0.00,0.08,0.00,0.02,0.22,0.04}),

		// JTAG: TDI/TDO bit-bang, shift register
		new ReferenceSignature("jtag", "jtag_boundary_scan",
			"JTAG boundary scan",
			new double[]{0.14,0.16,0.06,0.08,0.08,0.06,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.45,0.08,0.10,
				0.00,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.16,0.04}),

		// Bus probe: attempt access, catch timeout
		new ReferenceSignature("busprobe", "bus_test",
			"Bus probe/timeout test",
			new double[]{0.12,0.10,0.04,0.06,0.02,0.10,0.12,0.06,
				0.06,0.02, 0.10,0.06,0.40,0.10,0.08,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.00,0.16,0.04}),

		// MPU region config: consecutive IO writes for base/size/perms
		new ReferenceSignature("mpu", "mpu_region_config",
			"MPU/MMU region configuration",
			new double[]{0.06,0.22,0.04,0.06,0.02,0.04,0.06,0.02,
				0.06,0.02, 0.08,0.02,0.15,0.04,0.10,
				0.00,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.06,0.50}),

		// === New signatures: Network protocols ===

		// DNS resolver: loads for packet parsing, compares for labels, loop for domain walk
		new ReferenceSignature("dns", "dns_resolver",
			"DNS packet parser/resolver",
			new double[]{0.20,0.06,0.08,0.10,0.06,0.14,0.12,0.04,
				0.06,0.02, 0.30,0.04,0.30,0.10,0.14,
				0.00,0.04,0.00,0.00,0.00,0.10,0.06,0.00,0.18,0.00}),

		// DHCP client: heavy stores for option building, magic cookie constant
		new ReferenceSignature("dhcp", "dhcp_client",
			"DHCP client option builder",
			new double[]{0.10,0.22,0.06,0.04,0.02,0.08,0.10,0.04,
				0.08,0.02, 0.20,0.04,0.30,0.08,0.16,
				0.00,0.02,0.00,0.00,0.00,0.06,0.00,0.30,0.12,0.00}),

		// HTTP parser: many ASCII compares, string ops, state machine
		new ReferenceSignature("http", "http_parser",
			"HTTP protocol parser",
			new double[]{0.18,0.08,0.04,0.04,0.02,0.18,0.14,0.06,
				0.06,0.02, 0.25,0.06,0.35,0.12,0.20,
				0.00,0.02,0.00,0.00,0.00,0.14,0.00,0.00,0.24,0.00}),

		// SMTP handler: ASCII char compares, state machine branching
		new ReferenceSignature("smtp", "smtp_handler",
			"SMTP protocol handler",
			new double[]{0.16,0.10,0.04,0.04,0.02,0.16,0.14,0.06,
				0.06,0.02, 0.20,0.06,0.40,0.12,0.18,
				0.00,0.02,0.00,0.00,0.00,0.12,0.00,0.00,0.22,0.00}),

		// TFTP client: simple protocol, few states, block-based
		new ReferenceSignature("tftp", "tftp_client",
			"TFTP block transfer client",
			new double[]{0.14,0.12,0.06,0.04,0.02,0.10,0.10,0.06,
				0.06,0.02, 0.20,0.06,0.50,0.08,0.12,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.04,0.14,0.00}),

		// NTP sync: shift ops for timestamp fractions, 48-byte packet
		new ReferenceSignature("ntp", "ntp_time_sync",
			"NTP time synchronization",
			new double[]{0.14,0.10,0.08,0.06,0.10,0.08,0.08,0.04,
				0.06,0.02, 0.10,0.04,0.50,0.06,0.12,
				0.04,0.04,0.00,0.02,0.02,0.06,0.00,0.00,0.10,0.00}),

		// PPP framing: byte stuffing, flag detection, checksum
		new ReferenceSignature("ppp", "ppp_framing",
			"PPP/HDLC byte-stuffing framing",
			new double[]{0.18,0.14,0.06,0.08,0.04,0.10,0.10,0.04,
				0.06,0.02, 0.30,0.04,0.50,0.08,0.12,
				0.04,0.04,0.04,0.00,0.00,0.08,0.04,0.00,0.14,0.00}),

		// Telnet: IAC byte detection, option negotiation
		new ReferenceSignature("telnet", "telnet_protocol",
			"Telnet IAC/option negotiation",
			new double[]{0.16,0.10,0.04,0.06,0.02,0.16,0.14,0.06,
				0.06,0.02, 0.20,0.06,0.40,0.12,0.16,
				0.00,0.02,0.00,0.00,0.00,0.14,0.00,0.00,0.24,0.00}),

		// SNMP agent: ASN.1 BER encoding, OID tree traversal
		new ReferenceSignature("snmp", "snmp_agent",
			"SNMP BER/OID handler",
			new double[]{0.18,0.10,0.06,0.08,0.06,0.12,0.12,0.06,
				0.06,0.02, 0.30,0.06,0.40,0.10,0.16,
				0.00,0.04,0.00,0.02,0.00,0.10,0.04,0.00,0.18,0.00}),

		// UDP checksum: ones-complement sum, pseudo-header
		new ReferenceSignature("udpcksum", "udp_checksum",
			"UDP ones-complement checksum",
			new double[]{0.22,0.04,0.14,0.04,0.04,0.06,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.15,0.06,0.08,
				0.00,0.30,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.00}),

		// === New signatures: Cryptography ===

		// AES round: S-box lookup, ShiftRows, MixColumns
		new ReferenceSignature("aes", "aes_round",
			"AES encryption round",
			new double[]{0.18,0.14,0.06,0.08,0.10,0.04,0.06,0.00,
				0.06,0.04, 0.30,0.00,0.50,0.04,0.18,
				0.04,0.04,0.12,0.00,0.00,0.00,0.04,0.00,0.00,0.00}),

		// DES round: S-box lookups, Feistel XOR
		new ReferenceSignature("des", "des_round",
			"DES Feistel network round",
			new double[]{0.16,0.10,0.04,0.08,0.12,0.04,0.08,0.00,
				0.06,0.04, 0.30,0.00,0.45,0.06,0.20,
				0.04,0.02,0.14,0.00,0.00,0.00,0.04,0.00,0.00,0.00}),

		// SHA-256: 64 rounds, Ch/Maj/Sigma, rotations
		new ReferenceSignature("sha256", "sha256_round",
			"SHA-256 compression round",
			new double[]{0.14,0.10,0.10,0.10,0.14,0.04,0.08,0.00,
				0.06,0.02, 0.40,0.00,0.50,0.06,0.20,
				0.00,0.06,0.10,0.02,0.00,0.00,0.04,0.00,0.00,0.00}),

		// MD5: F/G/H/I functions, 64 steps, rotations
		new ReferenceSignature("md5", "md5_round",
			"MD5 hash computation round",
			new double[]{0.12,0.08,0.12,0.10,0.14,0.04,0.08,0.00,
				0.06,0.02, 0.40,0.00,0.45,0.06,0.22,
				0.00,0.06,0.08,0.02,0.00,0.00,0.04,0.00,0.00,0.00}),

		// RC4: KSA + PRGA swap loop
		new ReferenceSignature("rc4", "rc4_cipher",
			"RC4 stream cipher KSA/PRGA",
			new double[]{0.18,0.16,0.08,0.06,0.02,0.04,0.06,0.00,
				0.08,0.02, 0.40,0.00,0.60,0.04,0.10,
				0.10,0.04,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// ChaCha20: quarter-round add/xor/rotate
		new ReferenceSignature("chacha", "chacha20_quarter_round",
			"ChaCha20 quarter-round",
			new double[]{0.10,0.10,0.14,0.04,0.16,0.02,0.06,0.00,
				0.08,0.02, 0.30,0.00,0.55,0.04,0.14,
				0.00,0.06,0.12,0.04,0.00,0.00,0.00,0.00,0.00,0.00}),

		// === New signatures: DSP / Signal Processing ===

		// FIR filter: multiply-accumulate loop, coefficient table
		new ReferenceSignature("fir", "fir_filter",
			"FIR digital filter",
			new double[]{0.18,0.06,0.16,0.02,0.04,0.04,0.06,0.00,
				0.06,0.02, 0.40,0.00,0.20,0.04,0.12,
				0.00,0.20,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// IIR filter: feedback, multiply-accumulate
		new ReferenceSignature("iir", "iir_filter",
			"IIR recursive digital filter",
			new double[]{0.18,0.10,0.18,0.02,0.04,0.04,0.06,0.00,
				0.06,0.02, 0.35,0.00,0.45,0.04,0.12,
				0.04,0.20,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// Moving average: accumulate in loop, divide by N
		new ReferenceSignature("mavg", "moving_average",
			"Moving average filter",
			new double[]{0.18,0.08,0.14,0.02,0.04,0.04,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.35,0.06,0.08,
				0.00,0.16,0.00,0.00,0.04,0.00,0.00,0.00,0.00,0.00}),

		// Median filter: compare network on small window
		new ReferenceSignature("median", "median_filter",
			"Median filter (compare-swap)",
			new double[]{0.16,0.14,0.06,0.02,0.02,0.16,0.14,0.00,
				0.10,0.02, 0.15,0.00,0.55,0.12,0.08,
				0.04,0.00,0.00,0.00,0.00,0.04,0.00,0.00,0.00,0.00}),

		// Zero crossing: sign change, counter
		new ReferenceSignature("zerocross", "zero_crossing_detect",
			"Zero crossing detector",
			new double[]{0.16,0.08,0.08,0.04,0.04,0.12,0.12,0.00,
				0.06,0.02, 0.30,0.00,0.35,0.10,0.08,
				0.00,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.14,0.00}),

		// Convolution: nested loop multiply-accumulate
		new ReferenceSignature("convolve", "convolution",
			"Discrete convolution (nested loop MAC)",
			new double[]{0.18,0.08,0.18,0.02,0.04,0.06,0.08,0.00,
				0.06,0.02, 0.50,0.00,0.30,0.06,0.10,
				0.00,0.24,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// === New signatures: Hardware / Embedded ===

		// Stepper motor: phase table, IO writes
		new ReferenceSignature("stepper", "stepper_motor",
			"Stepper motor phase driver",
			new double[]{0.12,0.16,0.06,0.06,0.04,0.08,0.10,0.04,
				0.06,0.02, 0.20,0.04,0.40,0.08,0.12,
				0.00,0.02,0.00,0.00,0.00,0.06,0.04,0.00,0.14,0.04}),

		// Bootloader jump: validate signature, jump to app
		new ReferenceSignature("bootjump", "bootloader_jump",
			"Bootloader application handoff",
			new double[]{0.14,0.06,0.04,0.04,0.02,0.14,0.10,0.04,
				0.08,0.02, 0.10,0.04,0.25,0.08,0.14,
				0.00,0.00,0.00,0.00,0.00,0.10,0.00,0.00,0.16,0.06}),

		// Flash erase: unlock sequence, busy poll
		new ReferenceSignature("flasherase", "flash_erase",
			"Flash memory sector erase",
			new double[]{0.12,0.16,0.04,0.06,0.02,0.10,0.12,0.04,
				0.06,0.02, 0.25,0.04,0.40,0.10,0.14,
				0.00,0.00,0.00,0.00,0.00,0.08,0.04,0.06,0.18,0.00}),

		// Battery monitor: ADC read, voltage scale, threshold
		new ReferenceSignature("battery", "battery_monitor",
			"Battery voltage monitoring",
			new double[]{0.14,0.08,0.10,0.04,0.04,0.10,0.10,0.04,
				0.06,0.02, 0.15,0.04,0.40,0.08,0.10,
				0.00,0.04,0.00,0.00,0.02,0.06,0.00,0.00,0.14,0.00}),

		// Temperature compensation: lookup + interpolation
		new ReferenceSignature("tempcomp", "temp_compensation",
			"Temperature compensation lookup/interp",
			new double[]{0.16,0.08,0.12,0.04,0.06,0.08,0.08,0.04,
				0.06,0.02, 0.20,0.04,0.35,0.06,0.14,
				0.04,0.06,0.00,0.00,0.02,0.06,0.00,0.00,0.12,0.00}),

		// === New signatures: Graphics ===

		// Sprite scaling: Bresenham-like, nested loop
		new ReferenceSignature("spritescale", "sprite_scaling",
			"Sprite scaling/stretching",
			new double[]{0.16,0.14,0.10,0.04,0.06,0.06,0.08,0.00,
				0.06,0.02, 0.45,0.00,0.55,0.06,0.10,
				0.06,0.04,0.00,0.02,0.00,0.00,0.00,0.00,0.00,0.00}),

		// Alpha blending: multiply, shift right by 8
		new ReferenceSignature("alphablend", "alpha_blending",
			"Alpha blending (mul + shift)",
			new double[]{0.14,0.12,0.14,0.08,0.08,0.04,0.06,0.00,
				0.06,0.02, 0.20,0.00,0.55,0.04,0.12,
				0.04,0.04,0.00,0.02,0.02,0.00,0.04,0.00,0.00,0.00}),

		// Gamma correction: 256-entry table lookup
		new ReferenceSignature("gamma", "gamma_correction",
			"Gamma correction table lookup",
			new double[]{0.18,0.10,0.06,0.06,0.04,0.06,0.08,0.00,
				0.06,0.04, 0.20,0.00,0.45,0.06,0.10,
				0.04,0.04,0.00,0.00,0.00,0.04,0.00,0.00,0.00,0.00}),

		// Color space convert: RGB/YUV matrix multiply
		new ReferenceSignature("colorspace", "color_space_convert",
			"Color space conversion (matrix mul)",
			new double[]{0.14,0.12,0.16,0.06,0.06,0.04,0.06,0.00,
				0.06,0.02, 0.15,0.00,0.55,0.04,0.14,
				0.04,0.06,0.00,0.04,0.00,0.00,0.04,0.00,0.00,0.00}),

		// Parallax scroll: multiple scroll offsets, modulo
		new ReferenceSignature("parallax", "parallax_scroll",
			"Multi-layer parallax scrolling",
			new double[]{0.14,0.14,0.10,0.06,0.06,0.06,0.08,0.02,
				0.06,0.02, 0.20,0.02,0.55,0.06,0.12,
				0.04,0.04,0.00,0.00,0.00,0.04,0.04,0.04,0.00,0.00}),

		// Raycasting: trig lookup, distance calc
		new ReferenceSignature("raycast", "raycasting",
			"Raycasting column renderer",
			new double[]{0.16,0.12,0.14,0.06,0.08,0.08,0.08,0.02,
				0.06,0.02, 0.40,0.02,0.50,0.06,0.16,
				0.04,0.06,0.00,0.02,0.02,0.04,0.00,0.00,0.00,0.00}),

		// === New signatures: Parsers ===

		// JSON parser: brace/bracket match, string/number parse
		new ReferenceSignature("json", "json_parser",
			"JSON object/array parser",
			new double[]{0.18,0.08,0.04,0.04,0.02,0.18,0.14,0.06,
				0.06,0.02, 0.25,0.06,0.30,0.12,0.22,
				0.00,0.02,0.00,0.00,0.00,0.14,0.00,0.00,0.24,0.00}),

		// CSV parser: delimiter scan, field extraction
		new ReferenceSignature("csv", "csv_parser",
			"CSV delimiter/field parser",
			new double[]{0.18,0.10,0.06,0.04,0.02,0.16,0.12,0.04,
				0.06,0.02, 0.30,0.04,0.40,0.10,0.16,
				0.00,0.02,0.00,0.00,0.00,0.12,0.00,0.00,0.20,0.00}),

		// COFF/PE parser: header magic, section table walk
		new ReferenceSignature("coff", "coff_pe_parser",
			"COFF/PE header parser",
			new double[]{0.18,0.06,0.06,0.04,0.04,0.14,0.12,0.04,
				0.06,0.02, 0.20,0.04,0.20,0.10,0.18,
				0.00,0.04,0.00,0.00,0.00,0.12,0.00,0.00,0.18,0.00}),

		// BMP loader: header parse, palette, pixel data
		new ReferenceSignature("bmp", "bmp_image_loader",
			"BMP image header/pixel loader",
			new double[]{0.18,0.10,0.06,0.06,0.04,0.10,0.10,0.04,
				0.06,0.02, 0.25,0.04,0.45,0.08,0.16,
				0.04,0.04,0.00,0.00,0.00,0.08,0.04,0.00,0.14,0.00}),

		// WAV loader: RIFF header, chunk parsing
		new ReferenceSignature("wav", "wav_audio_loader",
			"WAV/RIFF audio file loader",
			new double[]{0.18,0.08,0.06,0.04,0.02,0.14,0.12,0.04,
				0.06,0.02, 0.20,0.04,0.30,0.10,0.18,
				0.00,0.04,0.00,0.00,0.00,0.12,0.00,0.00,0.20,0.00}),

		// === New signatures: OS / Kernel ===

		// Syscall dispatch: table dispatch, privilege ops
		new ReferenceSignature("syscall", "syscall_dispatch",
			"System call number dispatcher",
			new double[]{0.10,0.06,0.06,0.06,0.04,0.12,0.12,0.06,
				0.08,0.02, 0.10,0.06,0.30,0.10,0.14,
				0.00,0.00,0.00,0.00,0.00,0.08,0.00,0.00,0.14,0.14}),

		// Thread scheduler: context save, priority, next-run
		new ReferenceSignature("threadsched", "thread_scheduler",
			"Thread/task scheduler with priority dispatch",
			new double[]{0.14,0.14,0.06,0.04,0.02,0.10,0.12,0.06,
				0.08,0.02, 0.15,0.06,0.50,0.10,0.12,
				0.04,0.00,0.00,0.00,0.00,0.06,0.00,0.10,0.14,0.00}),

		// Signal handler: context save, dispatch by number
		new ReferenceSignature("signal", "signal_dispatch",
			"Unix signal dispatch handler",
			new double[]{0.10,0.14,0.06,0.04,0.02,0.10,0.12,0.06,
				0.08,0.02, 0.10,0.06,0.35,0.10,0.12,
				0.00,0.00,0.00,0.00,0.00,0.08,0.00,0.10,0.14,0.04}),

		// Pipe IPC: ring buffer head/tail
		new ReferenceSignature("pipe", "pipe_read_write",
			"Pipe IPC ring buffer",
			new double[]{0.16,0.14,0.10,0.06,0.02,0.08,0.10,0.02,
				0.06,0.02, 0.25,0.02,0.55,0.08,0.10,
				0.08,0.04,0.00,0.00,0.00,0.04,0.04,0.00,0.00,0.00}),

		// Memory pool: fixed-size block alloc
		new ReferenceSignature("mempool", "pool_block_allocate",
			"Fixed-size memory pool allocator",
			new double[]{0.14,0.10,0.08,0.06,0.02,0.10,0.10,0.02,
				0.06,0.02, 0.10,0.02,0.50,0.08,0.08,
				0.04,0.00,0.00,0.00,0.00,0.08,0.04,0.00,0.12,0.00}),

		// TLB flush: control register write, barrier
		new ReferenceSignature("tlb", "tlb_invalidate",
			"TLB flush/invalidate",
			new double[]{0.06,0.18,0.04,0.06,0.02,0.04,0.06,0.02,
				0.06,0.02, 0.10,0.02,0.20,0.04,0.08,
				0.00,0.00,0.00,0.00,0.00,0.02,0.00,0.00,0.06,0.40}),

		// File descriptor table: index, bounds check
		new ReferenceSignature("fdtable", "fd_table_lookup",
			"File descriptor table lookup",
			new double[]{0.14,0.06,0.08,0.04,0.04,0.12,0.12,0.04,
				0.06,0.02, 0.10,0.04,0.25,0.10,0.10,
				0.00,0.04,0.00,0.02,0.00,0.08,0.00,0.00,0.16,0.00}),

		// Socket bind: address struct, port swap
		new ReferenceSignature("sockbind", "socket_bind",
			"Socket bind/listen with address setup",
			new double[]{0.10,0.16,0.06,0.06,0.04,0.08,0.10,0.06,
				0.06,0.02, 0.10,0.06,0.35,0.08,0.12,
				0.00,0.00,0.00,0.00,0.00,0.06,0.00,0.10,0.12,0.00}),

		// Mount handler: superblock, device lookup
		new ReferenceSignature("mount", "filesystem_mount",
			"Filesystem mount handler",
			new double[]{0.16,0.12,0.06,0.04,0.02,0.12,0.12,0.08,
				0.06,0.02, 0.10,0.08,0.50,0.10,0.14,
				0.00,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.16,0.00}),

		// UART init: baud rate divisor, parity config
		new ReferenceSignature("uartinit", "uart_init",
			"UART/serial port initialization",
			new double[]{0.06,0.20,0.04,0.08,0.04,0.04,0.06,0.02,
				0.06,0.02, 0.08,0.02,0.15,0.04,0.14,
				0.00,0.00,0.00,0.00,0.00,0.02,0.04,0.16,0.06,0.00}),

		// === New signatures: Math / Algorithms ===

		// Big integer add: multi-word carry propagation
		new ReferenceSignature("bigintadd", "bigint_add",
			"Multi-word big integer addition with carry",
			new double[]{0.16,0.14,0.16,0.04,0.04,0.06,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.55,0.06,0.08,
				0.06,0.10,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00}),

		// Big integer multiply: nested loop, partial products
		new ReferenceSignature("bigintmul", "bigint_multiply",
			"Multi-word big integer multiplication",
			new double[]{0.16,0.14,0.16,0.04,0.06,0.06,0.08,0.00,
				0.06,0.02, 0.45,0.00,0.55,0.06,0.08,
				0.06,0.12,0.00,0.02,0.00,0.00,0.00,0.00,0.00,0.00}),

		// Polynomial eval (Horner): multiply-then-add chain
		new ReferenceSignature("horner", "polynomial_eval",
			"Polynomial evaluation (Horner's method)",
			new double[]{0.14,0.06,0.18,0.02,0.04,0.04,0.06,0.00,
				0.06,0.02, 0.25,0.00,0.20,0.04,0.12,
				0.00,0.14,0.00,0.02,0.00,0.00,0.00,0.00,0.00,0.00}),

		// Linear interpolation: (b-a)*t + a
		new ReferenceSignature("lerp", "linear_interp",
			"Linear interpolation (lerp)",
			new double[]{0.12,0.08,0.16,0.02,0.06,0.04,0.06,0.00,
				0.06,0.02, 0.10,0.00,0.40,0.04,0.08,
				0.00,0.06,0.00,0.02,0.04,0.00,0.00,0.00,0.00,0.00}),

		// Log approximation: exponent extract, mantissa table
		new ReferenceSignature("logapprox", "log_approx",
			"Logarithm approximation",
			new double[]{0.14,0.06,0.10,0.06,0.10,0.06,0.08,0.00,
				0.06,0.02, 0.15,0.00,0.25,0.06,0.12,
				0.04,0.06,0.00,0.02,0.02,0.04,0.04,0.00,0.00,0.00}),

		// Exp approximation: range reduction, polynomial
		new ReferenceSignature("expapprox", "exp_approx",
			"Exponential approximation",
			new double[]{0.12,0.06,0.14,0.04,0.08,0.06,0.08,0.00,
				0.06,0.02, 0.15,0.00,0.25,0.06,0.14,
				0.00,0.08,0.00,0.02,0.02,0.04,0.00,0.00,0.00,0.00}),

		// Reciprocal: Newton iteration, multiply-subtract
		new ReferenceSignature("recip", "reciprocal_approx",
			"Newton-Raphson reciprocal",
			new double[]{0.08,0.06,0.18,0.02,0.04,0.04,0.06,0.00,
				0.06,0.02, 0.20,0.00,0.30,0.04,0.08,
				0.00,0.06,0.00,0.02,0.04,0.00,0.00,0.00,0.00,0.00}),

		// Division by constant: multiply high + shift right
		new ReferenceSignature("divconst", "div_by_constant",
			"Division by constant via multiply-shift",
			new double[]{0.06,0.06,0.12,0.02,0.10,0.02,0.04,0.00,
				0.06,0.02, 0.05,0.00,0.30,0.02,0.08,
				0.00,0.04,0.00,0.02,0.04,0.00,0.00,0.00,0.00,0.00}),

		// GCD: Euclidean algorithm, modulo loop
		new ReferenceSignature("gcd", "gcd_compute",
			"GCD (Euclidean algorithm)",
			new double[]{0.06,0.06,0.10,0.02,0.02,0.06,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.30,0.06,0.06,
				0.00,0.04,0.00,0.00,0.04,0.04,0.00,0.00,0.00,0.00}),

		// === New signatures: String operations ===

		// Regex match: state transitions, char class tests
		new ReferenceSignature("regex", "regex_match",
			"Regular expression matcher",
			new double[]{0.18,0.06,0.04,0.06,0.02,0.18,0.16,0.04,
				0.06,0.02, 0.30,0.04,0.20,0.14,0.20,
				0.00,0.02,0.00,0.00,0.00,0.16,0.00,0.00,0.28,0.00}),

		// String hash: char-by-char multiply-accumulate
		new ReferenceSignature("strhash", "string_hash",
			"String hash (djb2/FNV-style)",
			new double[]{0.18,0.04,0.12,0.02,0.04,0.06,0.08,0.00,
				0.06,0.02, 0.30,0.00,0.10,0.06,0.08,
				0.00,0.14,0.00,0.02,0.00,0.04,0.00,0.00,0.00,0.00}),

		// String tokenize: delimiter scan, pointer advance
		new ReferenceSignature("strtok", "string_tokenize",
			"String tokenizer (delimiter scan)",
			new double[]{0.18,0.08,0.06,0.04,0.02,0.14,0.12,0.04,
				0.06,0.02, 0.30,0.04,0.30,0.10,0.14,
				0.00,0.02,0.00,0.00,0.00,0.12,0.00,0.00,0.18,0.00}),

		// atoi: digit validate, multiply by 10, accumulate
		new ReferenceSignature("atoi", "string_to_int",
			"String to integer conversion (atoi)",
			new double[]{0.16,0.04,0.12,0.04,0.02,0.12,0.10,0.00,
				0.06,0.02, 0.25,0.00,0.10,0.08,0.12,
				0.00,0.10,0.00,0.02,0.00,0.08,0.00,0.00,0.14,0.00}),

		// itoa: divide by 10, digit store, reverse
		new ReferenceSignature("itoa", "int_to_string",
			"Integer to string conversion (itoa)",
			new double[]{0.06,0.14,0.10,0.04,0.02,0.08,0.10,0.00,
				0.06,0.02, 0.25,0.00,0.20,0.08,0.10,
				0.00,0.00,0.00,0.00,0.04,0.04,0.00,0.06,0.14,0.00}),

		// String search: nested compare, mismatch restart
		new ReferenceSignature("strsearch", "string_search",
			"String search (KMP/naive)",
			new double[]{0.20,0.04,0.06,0.02,0.02,0.16,0.14,0.00,
				0.06,0.02, 0.40,0.00,0.10,0.12,0.10,
				0.00,0.02,0.00,0.00,0.00,0.14,0.00,0.00,0.20,0.00}),

		// Case convert: range compare, add/sub 0x20
		new ReferenceSignature("caseconv", "case_convert",
			"Character case conversion (upper/lower)",
			new double[]{0.14,0.10,0.08,0.04,0.02,0.14,0.12,0.00,
				0.06,0.02, 0.25,0.00,0.45,0.10,0.12,
				0.04,0.02,0.00,0.00,0.00,0.10,0.00,0.00,0.16,0.00}),

		// Whitespace strip: scan ends, compare spaces
		new ReferenceSignature("trim", "whitespace_strip",
			"Whitespace trim/strip",
			new double[]{0.14,0.06,0.06,0.04,0.02,0.16,0.14,0.00,
				0.06,0.02, 0.20,0.00,0.20,0.12,0.10,
				0.00,0.02,0.00,0.00,0.00,0.12,0.00,0.00,0.18,0.00}),

		// === New signatures: Game logic ===

		// Collision response: velocity reflect, position correct
		new ReferenceSignature("collresp", "collision_response",
			"Collision response with velocity reflection",
			new double[]{0.14,0.12,0.14,0.04,0.04,0.08,0.08,0.02,
				0.06,0.02, 0.15,0.02,0.55,0.06,0.10,
				0.04,0.06,0.00,0.00,0.02,0.04,0.00,0.00,0.00,0.00}),

		// Gravity sim: constant accel add to velocity
		new ReferenceSignature("gravity", "gravity_sim",
			"Gravity acceleration simulation",
			new double[]{0.12,0.12,0.14,0.02,0.02,0.08,0.08,0.02,
				0.06,0.02, 0.15,0.02,0.55,0.06,0.08,
				0.04,0.06,0.00,0.00,0.00,0.04,0.00,0.00,0.00,0.00}),

		// Jump physics: gravity + initial velocity, ground check
		new ReferenceSignature("jump", "jump_physics",
			"Jump physics (gravity + ground check)",
			new double[]{0.14,0.12,0.12,0.04,0.02,0.10,0.10,0.02,
				0.06,0.02, 0.15,0.02,0.55,0.08,0.10,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.10,0.00}),

		// Health/damage: subtract, clamp, death check
		new ReferenceSignature("damage", "health_damage",
			"Health/damage calculation with clamp",
			new double[]{0.10,0.10,0.10,0.04,0.02,0.14,0.12,0.04,
				0.06,0.02, 0.10,0.04,0.50,0.10,0.08,
				0.00,0.04,0.00,0.00,0.00,0.10,0.00,0.00,0.14,0.00}),

		// Inventory manage: slot array, add/remove
		new ReferenceSignature("inventory", "inventory_manage",
			"Inventory slot management",
			new double[]{0.16,0.14,0.08,0.04,0.02,0.12,0.12,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.10,0.10,
				0.04,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.14,0.00}),

		// NPC dialog: text table index, state advance
		new ReferenceSignature("npcdialog", "npc_dialog",
			"NPC dialog text/state handler",
			new double[]{0.14,0.10,0.06,0.04,0.04,0.10,0.10,0.06,
				0.06,0.02, 0.15,0.06,0.45,0.08,0.14,
				0.04,0.02,0.00,0.00,0.00,0.06,0.00,0.00,0.12,0.04}),

		// Enemy patrol: waypoint list, direction calc
		new ReferenceSignature("patrol", "enemy_patrol",
			"Enemy patrol/waypoint AI",
			new double[]{0.14,0.12,0.10,0.04,0.04,0.10,0.10,0.04,
				0.06,0.02, 0.20,0.04,0.55,0.08,0.12,
				0.04,0.04,0.00,0.00,0.00,0.06,0.00,0.00,0.12,0.00}),

		// Boss pattern: phase check, timer attack select
		new ReferenceSignature("boss", "boss_pattern",
			"Boss phase/attack pattern AI",
			new double[]{0.14,0.12,0.08,0.04,0.02,0.12,0.14,0.06,
				0.06,0.02, 0.15,0.06,0.50,0.12,0.14,
				0.00,0.02,0.00,0.00,0.00,0.08,0.00,0.00,0.20,0.00}),

		// === New signatures: Compression ===

		// Arithmetic coding: range subdivision, bit output
		new ReferenceSignature("arithcode", "arithmetic_coding",
			"Arithmetic coding range encoder/decoder",
			new double[]{0.14,0.10,0.12,0.04,0.10,0.08,0.10,0.00,
				0.06,0.02, 0.30,0.00,0.50,0.08,0.12,
				0.00,0.08,0.00,0.02,0.02,0.04,0.04,0.00,0.00,0.00}),

		// LZW codec: dictionary build, code output
		new ReferenceSignature("lzw", "lzw_codec",
			"LZW dictionary compression",
			new double[]{0.18,0.14,0.08,0.06,0.06,0.10,0.10,0.02,
				0.06,0.02, 0.35,0.02,0.50,0.08,0.16,
				0.06,0.06,0.00,0.00,0.00,0.06,0.04,0.00,0.10,0.00}),

		// BWT: suffix sort, output last column
		new ReferenceSignature("bwt", "bwt_transform",
			"Burrows-Wheeler transform",
			new double[]{0.18,0.14,0.08,0.04,0.04,0.12,0.10,0.02,
				0.06,0.02, 0.45,0.02,0.55,0.08,0.12,
				0.06,0.04,0.00,0.00,0.00,0.08,0.00,0.00,0.10,0.00}),

		// DEFLATE: Huffman + LZ77
		new ReferenceSignature("deflate", "deflate_decompress",
			"DEFLATE (Huffman + LZ77) decompressor",
			new double[]{0.18,0.12,0.08,0.08,0.10,0.08,0.10,0.02,
				0.06,0.02, 0.40,0.02,0.50,0.08,0.18,
				0.04,0.06,0.00,0.02,0.00,0.04,0.04,0.00,0.10,0.00}),
	};
}
