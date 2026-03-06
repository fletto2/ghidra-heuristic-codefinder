# Heuristic Code Finder — Ghidra Extension

**Pre-alpha.** Core pipeline works but heuristic refinements and
functionality will continue to be added. Machine-specific heuristics
(Tier 3) are being tuned alongside automatic platform detection.

Cross-architecture heuristic code/data block identification for Ghidra. Finds
code in flat ROMs and headerless binaries using P-code analysis — works on any
SLEIGH-supported ISA without per-architecture configuration.

## What it does

When Ghidra imports a raw binary (no ELF/PE/Mach-O headers), it has no entry
points to start analysis from. This extension applies 41 proven code/data
heuristics plus 169 function pattern detectors to identify code blocks,
function boundaries, data regions, and algorithmic function types automatically.

The heuristics were developed and validated across three standalone
disassemblers for 68000, Z80, and 6502, then abstracted to operate on Ghidra's
P-code intermediate representation — making them ISA-independent.

### Automatic platform detection

When analyzing a ROM, the extension automatically:

1. **Detects byte-swap issues** — Scans for characteristic instruction opcodes
   (RTS, RTE, NOP, BX LR, etc.) in native vs byte-swapped byte order. If a
   swapped interpretation has significantly more hits, it warns that the ROM
   needs byte-swapping. Supports 68000, SH2, ARM, MIPS, TMS9900, H8, PowerPC,
   and V60. Reports specific swap type (16-bit swap, 32-bit reversal, or
   16-bit pair swap within 32-bit words).

2. **Infers ROM base address** — Analyzes absolute jump/call targets and raw
   pointer values to detect if the ROM is loaded at the wrong address. For
   example, a NeoGeo BIOS loaded at 0x000000 will have code referencing
   0xC00000+, revealing it should be loaded at base 0xC00000.

3. **Identifies the target platform** — Matches P-code memory access patterns
   against a library of 13,500+ machine descriptions (generated from MAME
   source). Shows the top matches ranked by score. The best match is
   automatically used for Tier 3 heuristics (vector tables, memory map
   validation, hardware register identification).

### 10-pass pipeline

1. **Vector table entry points** — Read hardware vectors from platform description
2. **Forward trace** — Recursive descent from seeds with data rejection filters
3. **Reference tracing** — Follow CALL/BRANCH targets iteratively
4. **Jump table resolution** — Detect and follow indirect branches
5. **Orphan recovery** — Entropy + reference coherence on unclaimed regions
6. **Data/code boundaries** — Find code after data regions
7. **Gap filling** — Close small gaps between adjacent code blocks
8. **Overlap resolution** — Ghidra's Listing handles this implicitly
9. **Confidence assignment** — Tag blocks by discovery method (100=vector, 99=call, ..., 78=boundary)
10. **Function classification** — 203 rule-based detectors + 197 feature-vector signatures classify functions by algorithmic purpose (memcpy, checksum, decompression, sprite renderer, I2C, FFT, FAT, TCP, MIDI, HMAC, pathfinding, etc.) and label hardware register accesses

### Heuristic tiers

- **Tier 1** (23 heuristics): Direct P-code properties — block termination, target collection, entropy, density, decode ratio
- **Tier 2** (8 heuristics): P-code pattern matching — prologue/epilogue detection, tail calls, interrupt handlers, callee-save registers
- **Tier 3** (10 heuristics): Platform metadata — vector tables, memory map validation, hardware register patterns
- **Pass 10** (203 detectors + 197 signatures): Function pattern classification via P-code operation distribution analysis

## Install

### Pre-built

Download the latest zip from [Releases](../../releases) or use the one in `dist/`:

1. In Ghidra: **File → Install Extensions**
2. Click the **+** button
3. Select `HeuristicCodeFinder.zip`
4. Restart Ghidra

### Build from source

With Gradle (standard Ghidra extension build):

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

Or without Gradle, using the included build script:

```bash
./build.sh /path/to/ghidra
# optionally: ./build.sh /path/to/ghidra /path/to/java_home
```

Both produce a zip in `dist/`.

## Usage

1. Import a raw binary into Ghidra (File → Import, select "Raw Binary")
2. Open the Code Browser
3. Go to **Analysis → Auto Analyze** (or press 'A')
4. Enable **Heuristic Code Finder** in the analyzer list
5. (Optional) Configure options:

| Option | Default | Description |
|--------|---------|-------------|
| Minimum block size | 8 | Minimum bytes for a code block |
| Byte entropy min/max | 4.0 / 7.0 | Shannon entropy band for code |
| Data run threshold | 5 | Consecutive identical words → data |
| Null/FF density | 0.25 | Max fraction of 0x00/0xFF bytes |
| Valid decode ratio | 0.70 | Min fraction of successfully decoded bytes |
| P-code class entropy | 1.5 | Min entropy over P-code operation classes |
| Redundant op fraction | 0.25 | Max fraction of idempotent P-code ops |
| Gap fill max | 12 | Max gap size (bytes) to fill |
| Orphan min size | 64 | Min undefined region size to scan |
| Platform XML file | (empty) | Path to platform description (auto-detect if empty) |

6. Click **Analyze** — the extension runs after standard analysis

### Headless mode

```bash
analyzeHeadless /project/dir ProjectName -import rom.bin \
  -processor "68000:BE:32:MC68020" \
  -preScript EnableHeuristic.java
```

The analyzer is disabled by default; the pre-script enables it. Copy
`EnableHeuristic.java` to a Ghidra script directory or use `-scriptPath`.

## Platform descriptions

The extension includes 13,500+ platform descriptions auto-generated from
MAME source code, covering arcade, console, and computer systems across
272 manufacturers. These are matched automatically based on CPU type and
memory access patterns.

Hand-crafted platform files with full vector tables and hardware registers
are also included:

| File | Target | CPU |
|------|--------|-----|
| `sega_genesis.xml` | Sega Genesis/Mega Drive | 68000 |
| `nes.xml` | Nintendo NES/Famicom | 6502 |
| `gba.xml` | Game Boy Advance | ARM7 |
| `msx.xml` | MSX home computer | Z80 |
| `mvme162.xml` | Motorola MVME162 VME board | 68040 |
| `saturn_cdb.xml` | Sega Saturn CD Block | SH-1 |
| `plexus_p20.xml` | Plexus P/20 UNIX server | 68010 |
| `agfa9000.xml` | AGFA 9000PS PostScript RIP | 68000 |
| `fps3000.xml` | FPS-3000 Fire Protection Controller | 68000 |
| `gilbarco_pam1000.xml` | Gilbarco PAM 1000 fuel pump controller | 68000 |

### Creating a new platform description

```xml
<platform name="my_board" cpu="68000">
  <memory_map>
    <region start="0x000000" end="0x07FFFF" type="rom" name="flash"/>
    <region start="0x100000" end="0x10FFFF" type="ram" name="sram"/>
    <region start="0xFFF000" end="0xFFF0FF" type="io"  name="uart"/>
  </memory_map>

  <vectors format="abs32_be" base="0x000000">
    <entry index="0" name="initial_ssp"/>
    <entry index="1" name="reset_pc"/>
    <entry index="30" name="vblank" irq="true"/>
  </vectors>

  <hardware_registers>
    <reg addr="0xFFF000" width="1" name="uart_data" access="rw"/>
    <reg addr="0xFFF004" width="1" name="uart_status" access="r"/>
  </hardware_registers>
</platform>
```

Vector formats: `abs32_be`, `abs32_le`, `abs16_be`, `abs16_le`

Memory types: `rom`, `ram`, `io`, `unmapped`

## Byte-swap detection

For 16-bit and 32-bit platforms, ROM dumps are sometimes stored in
non-native byte order (e.g., MAME ROM sets often have byte-swapped
68000 ROMs). The extension detects this by counting characteristic
instruction opcodes in both native and swapped byte orders:

| CPU | Opcodes checked |
|-----|----------------|
| 68000 | RTS (0x4E75), RTE (0x4E73), NOP (0x4E71), JSR (0x4EB9), JMP (0x4EF9) |
| SH2/SH4 | RTS (0x000B), RTE (0x002B), NOP (0x0009) |
| ARM | BX LR (0xE12FFF1E), MOV PC,LR (0xE1A0F00E) |
| MIPS | JR RA (0x03E00008) |
| TMS9900 | B *R11 (0x045B), NOP (0x1000) |
| H8 | RTS (0x5470), RTE (0x5670) |
| PowerPC | BLR (0x4E800020) |

8-bit CPUs (Z80, 6502, 6809, 8080) are not affected by byte-swap issues.

## Heuristic reference

See [HEURISTICS.md](HEURISTICS.md) for the complete catalog of all 41
code/data heuristics, 169 function pattern detectors, and 163 feature-vector
reference signatures, with P-code patterns, ISA-specific forms, and origin
cross-references.

## License

Apache License 2.0 — same as Ghidra.
