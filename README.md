# Heuristic Code Finder — Ghidra Extension

**Pre-alpha.** Core pipeline works but only a handful of platform descriptions
are included. More machine definitions, heuristic refinements, and
functionality will be added in future releases. Machine-specific heuristics
(Tier 3) will be added as soon as automatic platform detection is working.

Cross-architecture heuristic code/data block identification for Ghidra. Finds
code in flat ROMs and headerless binaries using P-code analysis — works on any
SLEIGH-supported ISA without per-architecture configuration.

## What it does

When Ghidra imports a raw binary (no ELF/PE/Mach-O headers), it has no entry
points to start analysis from. This extension applies 41 proven heuristics to
identify code blocks, function boundaries, and data regions automatically.

The heuristics were developed and validated across three standalone
disassemblers for 68000, Z80, and 6502, then abstracted to operate on Ghidra's
P-code intermediate representation — making them ISA-independent.

### 9-pass pipeline

1. **Vector table entry points** — Read hardware vectors from platform description
2. **Forward trace** — Recursive descent from seeds with data rejection filters
3. **Reference tracing** — Follow CALL/BRANCH targets iteratively
4. **Jump table resolution** — Detect and follow indirect branches
5. **Orphan recovery** — Entropy + reference coherence on unclaimed regions
6. **Data/code boundaries** — Find code after data regions
7. **Gap filling** — Close small gaps between adjacent code blocks
8. **Overlap resolution** — Ghidra's Listing handles this implicitly
9. **Confidence assignment** — Tag blocks by discovery method (100=vector, 99=call, ..., 78=boundary)

### Heuristic tiers

- **Tier 1** (23 heuristics): Direct P-code properties — block termination, target collection, entropy, density, decode ratio
- **Tier 2** (8 heuristics): P-code pattern matching — prologue/epilogue detection, tail calls, interrupt handlers, callee-save registers
- **Tier 3** (10 heuristics): Platform metadata — vector tables, memory map validation, hardware register patterns

## Install

### Pre-built

Download the latest zip from [Releases](../../releases) or use the one in `dist/`:

1. In Ghidra: **File → Install Extensions**
2. Click the **+** button
3. Select `ghidra_<version>_PUBLIC_<date>_HeuristicCodeFinder.zip`
4. Restart Ghidra

### Build from source

With Gradle (standard Ghidra extension build):

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC
gradle buildExtension
```

Or without Gradle, using the included build script:

```bash
./build.sh /path/to/ghidra_12.0.3_PUBLIC
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

## Platform descriptions

For best results on embedded/console targets, provide a platform description
XML file that defines the memory map, vector table, and hardware registers.

Included platforms in `data/platforms/`:

| File | Target | CPU |
|------|--------|-----|
| `sega_genesis.xml` | Sega Genesis/Mega Drive | 68000 |
| `nes.xml` | Nintendo NES/Famicom | 6502 |
| `gba.xml` | Game Boy Advance | ARM7 |
| `msx.xml` | MSX home computer | Z80 |
| `mvme162.xml` | Motorola MVME162 VME board | 68040 |
| `saturn_cdb.xml` | Sega Saturn CD Block | SH-1 |

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

## Heuristic reference

See [HEURISTICS.md](HEURISTICS.md) for the complete catalog of all 41
heuristics with P-code patterns, ISA-specific forms, and origin cross-references.

## License

Apache License 2.0 — same as Ghidra.
