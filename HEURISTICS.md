# P-code Heuristic Disassembly Engine

Cross-architecture code/data block identification using Ghidra's SLEIGH P-code
as a universal intermediate representation. Based on heuristics proven across
68000, Z80, and 6502 disassemblers (super68k, superz80, super6502), abstracted
to work on any of the 146 ISA variants supported by SLEIGH.

## Architecture

```
Binary bytes (any ISA)
    |
    v
SLEIGH engine (per-ISA .sla file, 146 variants)
    |
    v
P-code stream (universal micro-ops)
    |
    v
Generic heuristic engine (ONE implementation, all ISAs):
    - Block termination (RETURN, unconditional BRANCH)
    - CALL/BRANCH target collection
    - Prologue/epilogue pattern matching
    - Entropy filtering
    - Gap filling / orphan recovery
    |
    v
Platform metadata (per-system, small):
    - Memory map (ROM/RAM/IO/unmapped ranges)
    - Vector table locations
    - Hardware register addresses
    |
    v
Code blocks / Data blocks / CFG
```

## P-code Operations Reference

SLEIGH normalizes all ISA instructions into these micro-ops:

| P-code Op | Category | Description |
|-----------|----------|-------------|
| `COPY` | Data movement | Register-to-register or immediate-to-register |
| `LOAD` | Memory | Read from memory address |
| `STORE` | Memory | Write to memory address |
| `INT_ADD` | Arithmetic | Integer addition |
| `INT_SUB` | Arithmetic | Integer subtraction |
| `INT_MULT` | Arithmetic | Integer multiply |
| `INT_DIV` | Arithmetic | Unsigned divide |
| `INT_SDIV` | Arithmetic | Signed divide |
| `INT_AND` | Logic | Bitwise AND |
| `INT_OR` | Logic | Bitwise OR |
| `INT_XOR` | Logic | Bitwise XOR |
| `INT_NEGATE` | Logic | Two's complement negate |
| `INT_LEFT` | Shift | Left shift |
| `INT_RIGHT` | Shift | Logical right shift |
| `INT_SRIGHT` | Shift | Arithmetic right shift |
| `INT_EQUAL` | Compare | Equality test |
| `INT_NOTEQUAL` | Compare | Inequality test |
| `INT_LESS` | Compare | Unsigned less-than |
| `INT_SLESS` | Compare | Signed less-than |
| `INT_LESSEQUAL` | Compare | Unsigned less-or-equal |
| `INT_SLESSEQUAL` | Compare | Signed less-or-equal |
| `INT_ZEXT` | Conversion | Zero extend |
| `INT_SEXT` | Conversion | Sign extend |
| `BOOL_AND` | Boolean | Boolean AND |
| `BOOL_OR` | Boolean | Boolean OR |
| `BOOL_NEGATE` | Boolean | Boolean NOT |
| `BRANCH` | Control flow | Unconditional branch |
| `CBRANCH` | Control flow | Conditional branch |
| `BRANCHIND` | Control flow | Indirect branch (computed jump) |
| `CALL` | Control flow | Subroutine call |
| `CALLIND` | Control flow | Indirect subroutine call |
| `RETURN` | Control flow | Return from subroutine |
| `POPCOUNT` | Bitwise | Population count |

Key ISA normalizations:
- 68000 `RTS`, Z80 `RET`, 6502 `RTS`, ARM `BX LR`, x86 `RET` -> P-code `RETURN`
- 68000 `BSR`, Z80 `CALL`, 6502 `JSR`, ARM `BL`, x86 `CALL` -> P-code `CALL`
- 68000 `Bcc`, Z80 `JR cc`, 6502 `Bcc`, ARM `Bcc`, x86 `Jcc` -> P-code `CBRANCH`
- 68000 `BRA`/`JMP`, Z80 `JP`, 6502 `JMP`, ARM `B`, x86 `JMP` -> P-code `BRANCH`

## Heuristic Catalog

### Tier 1: Direct P-code Abstraction (23 heuristics)

These operate on generic P-code properties. One implementation covers all ISAs.

#### H01: Block Termination at RETURN

Terminate a code block when a `RETURN` P-code op is encountered.

- **ISA-specific form**: 68000 `RTS`/`RTE`, Z80 `RET`/`RETI`/`RETN`, 6502 `RTS`/`RTI`
- **P-code form**: Terminate at any instruction producing `RETURN` op
- **Source**: super68k Pass 1, superz80 Pass 1, super6502 Pass 2

#### H02: Block Termination at Unconditional BRANCH

Terminate a code block at an unconditional `BRANCH` not preceded by `CBRANCH`
in the same block (tail call / tail jump pattern).

- **ISA-specific form**: 68000 `BRA`/`JMP` without prior `Bcc`, Z80 `JP nn`/`JR e`, 6502 `JMP`
- **P-code form**: `BRANCH` (not `CBRANCH`) with no `CBRANCH` using same target space in block
- **Source**: super68k Pass 1 tail-call detection, all three disassemblers

#### H03: CALL Target Collection and Tracing

Collect all addresses targeted by `CALL` ops. Each target is a high-confidence
code entry point. Trace forward from each target to discover new code blocks.

- **ISA-specific form**: 68000 `BSR.B`/`BSR.W`/`JSR`, Z80 `CALL nn`, 6502 `JSR abs`
- **P-code form**: Extract target address from any `CALL` op
- **Confidence**: 99.5-99.7% (from super68k precision measurements)
- **Source**: super68k Pass 2, superz80 Pass 2, super6502 Pass 3

#### H04: BRANCH/CBRANCH Target Collection

Collect addresses targeted by `BRANCH` and `CBRANCH` ops. Each target is a
code entry point (lower confidence than CALL targets for unconditional branches,
since some may be data misinterpreted as code).

- **ISA-specific form**: 68000 `Bcc`/`BRA`, Z80 `JR`/`JP`, 6502 `Bcc`/`JMP`
- **P-code form**: Extract target address from `BRANCH`/`CBRANCH` ops
- **Confidence**: 97-99.5% for conditional branches, 95-99% for unconditional
- **Source**: All three disassemblers, reference bitmap construction

#### H05: Entry Point Protection

Prevent instruction decoding from spanning a known entry point. If an
instruction's operand bytes overlap an address in the entry point set,
terminate the current block.

- **ISA-specific form**: Entry point bitmap checked against instruction byte ranges
- **P-code form**: Maintain set of known entry points (from H03, H04, H09). During
  decode, if instruction at addr A has length L, check that no address in
  [A+1, A+L-1] is in the entry point set.
- **Source**: All three disassemblers

#### H06: Gap Filling

Close small gaps (1-12 bytes) between adjacent confirmed code blocks by
attempting to decode the gap bytes. Accept if all bytes decode as valid
instructions producing well-formed P-code.

- **ISA-specific form**: 68000 1-12 bytes, Z80 1-6 bytes, 6502 1-6 bytes
- **P-code form**: Attempt SLEIGH decode of gap bytes. If all produce valid P-code
  (no decode errors), merge into adjacent block.
- **Confidence**: 88 (CONF_GAP_FILL)
- **Source**: super68k gap filling, superz80 Pass 6, super6502 Pass 7

#### H07: Data Run Detection

Reject candidate code blocks containing sequences of repeated identical values.
Data tables, lookup arrays, and padding produce runs that real code does not.

- **P-code form**: Before accepting a block, scan raw bytes for:
  - 5+ consecutive identical 16-bit words (or appropriate ISA word size)
  - 8+ consecutive identical bytes
  - 30%+ of bytes are 0x00 or 0xFF
- **Source**: super68k block_has_data_words / has_data_runs, super6502 data run rejection

#### H08: Byte Entropy Filtering

Compute Shannon entropy over the byte distribution of a candidate block.
Code typically falls in the 4.0-7.0 bits/byte range. Pure data (repeated
values, ASCII text, tile graphics) falls outside this range.

- **Formula**: H = -SUM(p_i * log2(p_i)) for i in 0..255
- **Accept range**: 4.0 <= H <= 7.0
- **Source**: All three disassemblers (orphan detection passes)

#### H09: Orphan Region Recovery — Entropy Classification

Scan unclaimed regions (>= 64 bytes) using multi-channel analysis:
1. Attempt SLEIGH decode — compute valid_ratio (fraction producing valid P-code)
2. Compute byte entropy (H_byte)
3. Compute P-code operation class entropy (H_op) over ~10-15 operation categories
4. Check for periodic structure (32-byte repeats indicate tile/sprite data)

- **Accept criteria**: valid_ratio > 0.70, H_byte in 4.5-6.5, H_op < 4.0
- **Source**: super68k orphan entropy classification, super6502 Pass 5

#### H10: Orphan Region Recovery — Reference Coherence

For orphan regions that pass entropy filtering, resolve all `CALL`/`BRANCH`/
`CBRANCH` targets within the region. Accept if:
- coherent_refs >= 1 (at least one target resolves to a known code block or
  another valid region)
- coherent_ratio >= 0.10 (at least 10% of references are coherent)

- **Source**: super68k orphan code recovery

#### H11: Orphan Region Recovery — Seed-Based Tracing

Use three seed sources for orphan recovery:
1. Post-terminator offsets (address immediately after a `RETURN` or `BRANCH`)
2. Entry point set entries not yet covered by code blocks
3. Prologue pattern matches (H17)

Trace forward from each seed with standard block termination rules.

- **Source**: super68k orphan code recovery

#### H12: Reference Classification

Classify discovered code blocks by how they were found:
- **call-referenced**: Target of a `CALL` op (highest confidence)
- **branch-referenced**: Target of a `BRANCH`/`CBRANCH` op
- **pointer-referenced**: 32-bit (or width-appropriate) address found in data region
- **unreferenced**: Found by structural analysis (sequential scan, orphan recovery)

- **Source**: super68k reference classification

#### H13: Partial Block Saving

When a forward trace encounters an invalid instruction mid-block, save the
valid prefix (>= 8 bytes) as a confirmed code block rather than discarding
the entire trace.

- **Source**: All three disassemblers

#### H14: Overlap Removal

Structural pass to resolve overlapping code blocks. When two blocks overlap:
- Keep the one with higher confidence
- If equal confidence, keep the one referenced by more `CALL`/`BRANCH` ops
- If still tied, keep the longer block

- **Source**: superz80 Pass 3

#### H15: Sequential Scan with Evidence Requirement

Scan forward from known code block boundaries attempting to decode. Accept
a new block only if it has evidence:
- Contains at least one `CALL` or `BRANCH` to a known code address
- Matches a prologue pattern (H17)
- Passes diversity check (H16)

- **Source**: super6502 Pass 2

#### H16: P-code Operation Class Entropy

Map P-code operations into ~10 functional classes and compute entropy over
the class distribution. Reject blocks where class entropy < 1.5 (functionally
monotonous — likely data misinterpreted as instructions).

| Class | P-code Operations |
|-------|-------------------|
| Load | `LOAD` |
| Store | `STORE` |
| Copy | `COPY` |
| Arithmetic | `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_SDIV` |
| Logic | `INT_AND`, `INT_OR`, `INT_XOR`, `INT_NEGATE` |
| Compare | `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_SLESS`, `INT_LESSEQUAL`, `INT_SLESSEQUAL` |
| Shift | `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT` |
| Branch | `BRANCH`, `CBRANCH`, `BRANCHIND` |
| Call/Return | `CALL`, `CALLIND`, `RETURN` |
| Conversion | `INT_ZEXT`, `INT_SEXT`, `BOOL_AND`, `BOOL_OR`, `BOOL_NEGATE` |

- **ISA-specific form**: 68000 uses 22-bin opcode histogram, 6502 uses 10 opcode classes
- **P-code form**: 10 P-code operation classes, uniform across all ISAs
- **Reject threshold**: class_entropy < 1.5 AND valid_ratio < 0.6
- **Source**: super68k opcode entropy, super6502 opcode-class entropy

#### H17: Data/Code Boundary Detection

Identify transitions from data regions to code by scanning for the pattern:
preceding bytes are data-like (>30% zero/0xFF, >40% high-bit bytes, periodic
structure) followed by bytes that decode as valid P-code.

- **Source**: super68k Pass 5, superz80 Pass 5, super6502 Pass 5b

#### H18: Redundant/Idempotent Instruction Detection

Reject blocks where >25% of instructions are consecutive identical idempotent
operations. In P-code terms, detect:
- `COPY rX, rX` (register to itself)
- Back-to-back inverse `COPY` pairs (e.g. `COPY A,B` then `COPY B,A`)
- Repeated flag-setting with no intervening `CBRANCH`

Real code rarely has >25% redundant operations; data misinterpreted as
instructions frequently does.

- **ISA-specific form**: 68000 `MOVE Dn,Dn`, `EXG Dn,Dn`; 6502 `TAX;TXA`, repeated `NOP`
- **P-code form**: `COPY` where output varnode == input varnode
- **Source**: super68k has_redundant_pairs, super6502 redundant instruction detection

#### H19: Jump Table Detection

When a `BRANCHIND` (indirect branch) is encountered:
1. Identify the source of the branch target (typically `LOAD` from a table)
2. Read consecutive pointer-width values from that table address
3. Validate each as a code entry point (within ROM range, decodes as valid P-code)
4. Trace from each valid entry

- **ISA-specific form**: 68000 `JMP (PC,Dn)`, Z80 `JP (HL)`, 6502 `JMP ($xxxx)`
- **P-code form**: `BRANCHIND` op, trace data source for target address
- **Source**: super68k jump table detection, super6502 Pass 4

#### H20: Confidence Tier Assignment

Assign confidence scores to discovered blocks based on discovery method:

| Tier | Confidence | Discovery Method |
|------|-----------|-----------------|
| Vector entry | 100 | Platform vector table (H28) |
| CALL target | 99 | Target of `CALL` op (H03) |
| Direct branch target | 98 | Target of `BRANCH` op (H04) |
| Conditional branch target | 97 | Target of `CBRANCH` op (H04) |
| Indirect target | 95 | Target of `BRANCHIND` via jump table (H19) |
| Pattern match | 93 | Prologue/epilogue detection (H17, H22) |
| Sequential scan | 90 | Forward scan with evidence (H15) |
| Gap fill | 88 | Gap filling (H06) |
| Orphan | 80 | Orphan recovery (H09-H11) |
| Data boundary | 78 | Data/code transition (H17) |

- **Source**: super6502 confidence tier system

#### H21: Byte Density Check

Quick pre-filter: reject candidate regions where >25% of bytes are 0x00 or
0xFF. Code rarely has this density of null/fill bytes; padding, erased flash,
and uninitialized memory regions do.

- **Source**: super6502 byte density check

#### H22: Speculative Forward Decode

When a reference target points to an uncovered offset, speculatively decode
forward up to 64 instructions (or until terminator/invalid). Accept if the
decoded stream meets evidence requirements (H15).

Handle entry point conflicts: if speculative decode overlaps an existing block
by <= 16 bytes, trim the shorter block.

- **Source**: super6502 Pass 6

#### H23: Valid Decode Ratio

Compute the fraction of candidate block bytes that SLEIGH successfully decodes
(no decode errors). Reject blocks with valid_ratio < 0.70.

This is the most fundamental filter: if SLEIGH can't decode the bytes as
instructions for the target ISA, they're not code.

- **Source**: All three disassemblers (implicit in every pass)


### Tier 2: P-code Pattern Abstraction (8 heuristics)

These are currently implemented with ISA-specific opcodes but can be expressed
as P-code operation patterns. Requires pattern matching on P-code sequences
rather than raw byte sequences.

#### H24: Prologue Detection — Stack Frame Setup

Detect function prologues by matching P-code patterns for stack frame creation.

**P-code pattern:**
```
SP = INT_SUB SP, <const>           # Allocate stack frame
STORE [SP + offset_1], reg_1       # Save register 1
STORE [SP + offset_2], reg_2       # Save register 2 (optional, repeated)
...
```

**ISA-specific forms:**

| ISA | Prologue Pattern |
|-----|-----------------|
| 68000 | `LINK An,#disp` (combined SUB + STORE of frame pointer) |
| 68000 | `MOVEM.L regs,-(A7)` (multiple register save) |
| Z80 | `PUSH AF; PUSH BC; PUSH DE; PUSH HL` |
| 6502 | `PHP; PHA` (or `TXA; PHA; TYA; PHA`) |
| ARM | `PUSH {r4-r11, lr}` or `STMFD sp!, {regs}` |
| x86 | `PUSH EBP; MOV EBP,ESP; SUB ESP,imm` |
| x86-64 | `PUSH RBP; MOV RBP,RSP; SUB RSP,imm` |

**P-code unification**: All reduce to `INT_SUB` on stack pointer + `STORE`s
to stack-relative addresses. The pattern matcher needs:
1. Identify the stack pointer register (from .pspec or by convention)
2. Look for `INT_SUB SP, const` followed by `STORE` to `[SP + offset]`
3. Count number of register saves (2+ = high confidence prologue)

- **Source**: super68k Pass 3 (LINK), Pass 4 (MOVEM), superz80 Pass 2.5, super6502 Pass 2

#### H25: Epilogue Detection — Stack Frame Teardown

Detect function epilogues by matching the reverse of H24.

**P-code pattern:**
```
reg_N = LOAD [SP + offset_N]       # Restore register N
...
reg_1 = LOAD [SP + offset_1]       # Restore register 1
SP = INT_ADD SP, <const>           # Deallocate stack frame
RETURN                             # Return
```

**ISA-specific forms:**

| ISA | Epilogue Pattern |
|-----|-----------------|
| 68000 | `UNLK An; RTS` or `MOVEM.L (A7)+,regs; RTS` |
| Z80 | `POP HL; POP DE; POP BC; POP AF; RET` |
| 6502 | `PLA; TAY; PLA; TAX; PLA; PLP; RTS/RTI` |
| ARM | `POP {r4-r11, pc}` or `LDMFD sp!, {regs, pc}` |
| x86 | `MOV ESP,EBP; POP EBP; RET` or `LEAVE; RET` |

**P-code unification**: `LOAD`s from stack-relative addresses + `INT_ADD` on
stack pointer + `RETURN`. Matching prologue/epilogue pairs (same registers
saved/restored) is a strong function boundary signal.

- **Source**: superz80 Pass 2.5 (push/pop pair matching), super6502 Pass 2

#### H26: Tail Call Detection

Detect unconditional `BRANCH` at end of function (no `RETURN`) where the
branch target is a known function entry point. This is a tail call
optimization — the function jumps to another function instead of calling
it and returning.

**P-code pattern:**
```
... (function body, no CBRANCH to addresses after this BRANCH)
BRANCH <known_function_entry>
```

Distinguish from mid-function jumps: a tail call's branch target is typically
in a different function, and there's no conditional branch that could skip it.

- **ISA-specific form**: 68000 `BRA`/`JMP` without prior `Bcc` to beyond it
- **P-code form**: `BRANCH` where target is in entry point set AND no `CBRANCH`
  in same block targets an address after the `BRANCH`
- **Source**: super68k Pass 1 tail-call termination

#### H27: Computed Jump / RTS Trick Detection

Detect computed jump patterns where the target address is loaded from a table
and used for indirect control flow.

**6502 RTS Trick P-code pattern:**
```
reg = LOAD [table + index]         # Load high byte from table
STORE [stack], reg                 # Push to stack
reg = LOAD [table + index]         # Load low byte from table
STORE [stack], reg                 # Push to stack
RETURN                             # RTS pops address from stack -> jump
```

**Generic P-code pattern:**
```
target = LOAD [base + index]       # Load from jump table
BRANCHIND target                   # Indirect branch
```

Both patterns indicate a jump table. Extract the base address, read pointer
entries, and trace each as a code entry point.

- **Source**: super6502 Pass 4 (RTS trick), super68k jump table detection

#### H28: Opcode-Stream Pattern Matching

Match known multi-instruction idioms expressed as P-code operation sequences
rather than raw byte sequences.

**Example patterns (P-code form):**

Interrupt save (NMI/IRQ handler entry):
```
STORE [SP], flags_reg              # Save flags/status
STORE [SP], reg_A                  # Save accumulator
STORE [SP], reg_X                  # Save index registers
STORE [SP], reg_Y
```

System initialization:
```
flags_write: disable_interrupts    # SEI / DI / cli
COPY SP, <const>                   # Set stack pointer
```

16-bit arithmetic on 8-bit ISA:
```
result_lo = INT_ADD op1_lo, op2_lo          # Low byte add
result_hi = INT_ADD_CARRY op1_hi, op2_hi    # High byte add with carry
```

Memory clear loop:
```
STORE [addr], <zero>               # Clear byte/word
addr = INT_ADD addr, <const>       # Advance pointer
CBRANCH <loop_start>, condition    # Loop
```

- **ISA-specific form**: 68000 ~7 patterns, Z80 ~15 patterns, 6502 ~24 opcode patterns + ~40 byte patterns
- **P-code form**: Sequences of P-code operations with varnode constraints
- **Source**: superz80 known pattern matching, super6502 known pattern detection methods 1 & 2

#### H29: Interrupt Handler Prologue Detection

Detect interrupt/exception handler entries: instructions that save processor
state without a preceding `CALL`. Distinct from regular prologues (H24)
because there's no call site — the entry point is reached by hardware
interrupt dispatch.

**P-code pattern:**
```
(no preceding CALL to this address)
STORE [SP], status_flags           # Save flags/condition codes
STORE [SP], reg_1                  # Save registers
STORE [SP], reg_2
...
```

The address is typically in a vector table (H30) or at a fixed hardware address.

- **Source**: super6502 NMI/IRQ save pattern, super68k exception vector handling

#### H30: Stack Pointer Identification

Identify which register is the stack pointer by analyzing P-code patterns:
- The register used with `INT_SUB` before `STORE` and `INT_ADD` before `LOAD`
  in paired prologue/epilogue sequences
- The register that `RETURN` implicitly reads from
- Alternatively, read from .pspec metadata (Ghidra provides this)

This is needed by H24, H25, H27, and H29.

- **Source**: Implicit in all stack-based heuristics; made explicit for cross-ISA use

#### H31: Callee-Save Register Set Detection

Across multiple functions, collect the set of registers saved in prologues (H24)
and restored in epilogues (H25). The intersection is the callee-save register
set for the binary's calling convention. This can then be used to:
- Increase confidence in prologue/epilogue matching
- Reject false prologues that save unusual register sets
- Identify compiler vs hand-written code (compilers are consistent)

- **Source**: Derived from prologue/epilogue analysis across all three disassemblers


### Tier 3: Platform-Specific Heuristics (11 heuristics)

These require hardware/system knowledge that cannot be derived from P-code alone.
They need a platform description file specifying memory maps, vector tables,
and hardware register addresses.

#### H32: Vector Table Entry Points

Read code entry point addresses from hardware vector tables at fixed locations.

| Platform | Vector Location | Entries |
|----------|----------------|---------|
| 68000 (bare) | $000000-$0003FF | 256 vectors (reset SSP, reset PC, bus error, ... TRAP #0-15, IRQ 1-7) |
| Genesis | $000000-$0000FF | Subset: reset, VBlank, HBlank, external |
| NES (6502) | $FFFA-$FFFF | 3 vectors: NMI, RESET, IRQ |
| Z80 (MSX) | $0000, $0038, $0066 | RST 0, RST 38h (IRQ mode 1), NMI |
| ARM | $00000000-$0000001C | 8 vectors: reset, undef, SWI, prefetch abort, data abort, reserved, IRQ, FIQ |
| SH-1/SH-2 | $00000000-$000000FF | Power-on PC/SP, manual reset, ... NMI, IRQ |
| x86 (real) | $0000:0000-$0000:03FF | 256 IVT entries (4 bytes each: offset:segment) |

**Platform description needed**: Vector table base address, entry count, entry format
(pointer width, endianness, absolute vs relative).

- **Source**: super6502 Pass 1, super68k Pass 1

#### H33: Memory Map Validation

Validate that addresses referenced by `LOAD`/`STORE`/`CALL`/`BRANCH` fall
within valid memory regions. Reject code blocks that reference unmapped
address space.

| Platform | ROM | RAM | I/O | Dead Zone |
|----------|-----|-----|-----|-----------|
| Genesis | $000000-$3FFFFF | $FF0000-$FFFFFF | $A00000-$A1FFFF, $C00000-$C0001F | $400000-$9FFFFF |
| NES | $8000-$FFFF (PRG ROM) | $0000-$07FF | $2000-$2007 (PPU), $4000-$4017 (APU) | $0800-$1FFF (mirrors) |
| MSX | $0000-$BFFF (slot-dependent) | $C000-$FFFF | $98-$9B (VDP), $A0-$A2 (PSG) | varies |
| GBA | $08000000-$09FFFFFF | $02000000-$0203FFFF | $04000000-$040003FF | varies |
| Mac 128K | $400000-$43FFFF (ROM) | $000000-$01FFFF | $580000-$5FFFFF (VIA, SCC, IWM) | varies |

**Platform description needed**: List of (start_addr, end_addr, type) tuples where
type is ROM, RAM, IO, or UNMAPPED.

- **Source**: super68k address coherence validation, super6502 NES address validation

#### H34: Hardware Register Pattern Override

Accept otherwise-unreferenced code blocks that contain accesses to known
hardware registers. These indicate initialization routines, interrupt handlers,
or driver code that wouldn't be referenced by normal `CALL`/`BRANCH`.

| Platform | Pattern | Description |
|----------|---------|-------------|
| Genesis | `STORE $A14000, #'SEGA'` | TMSS security handshake |
| Genesis | `STORE $A11100, #$0100` | Z80 bus request |
| Genesis | `STORE $C00004, #$8xxx` | VDP register write |
| Genesis | `LOAD $A10003` | Controller read |
| NES | `LOAD $2002` | PPU status read (VBlank wait) |
| NES | `STORE $4014, #xx` | OAM DMA trigger |
| NES | `STORE $2006` + `STORE $2007` | PPU address + data write |
| MSX | `OUT ($98-$9B)` | VDP access |
| MSX | `OUT ($A0-$A2)` | PSG access |

**Platform description needed**: List of (address, access_type, name) tuples
identifying hardware registers.

- **Source**: super68k Genesis hardware pattern override, super6502 NES PPU/APU patterns

#### H35: ROM Checksum / Security Code Detection

Identify ROM integrity verification and copy protection routines that access
known security addresses or compute checksums over ROM regions.

| Platform | Pattern |
|----------|---------|
| Genesis | Checksum word at $00018E, verification routine reads ROM $000200-end |
| Genesis | TMSS write to $A14000 |
| Saturn | MPEG ROM decryption (Hitachi cipher blocks) |
| NES | Mapper-specific bank verification |

**Platform description needed**: Checksum locations, security register addresses.

- **Source**: super68k ROM verification, Saturn cipher detection

#### H36: Mapper / Bank Switching Detection

Identify bank switch operations where writes to specific addresses change the
memory map. This is critical for multi-bank ROMs where code references may
cross bank boundaries.

| Platform | Pattern |
|----------|---------|
| NES UxROM | `STORE $8000-$FFFF` (bank number) |
| NES MMC1 | 5x serial write to $8000-$FFFF |
| NES MMC3 | `STORE $8000` (select) + `STORE $8001` (bank) |
| Genesis | No mapper (flat 4MB address space) |
| MSX | Slot/page select via I/O ports |
| GBA | Wait state control ($04000204) |

**Platform description needed**: Mapper type, bank switch trigger addresses,
bank size, number of banks.

- **Source**: super6502 mapper detection, super68k (not needed for Genesis)

#### H37: Dual-CPU / Coprocessor Communication

Identify code that communicates with secondary processors. These routines
often look unusual (writes to I/O space, polling loops) and might be rejected
by generic heuristics without platform knowledge.

| Platform | Pattern |
|----------|---------|
| Genesis | 68000 -> Z80: bus request ($A11100), Z80 RAM writes ($A00000-$A01FFF) |
| SNES | 65816 -> SPC700: upload protocol via $2140-$2143 |
| Saturn | SH-2 -> SH-1 CD block commands |

**Platform description needed**: Coprocessor interface addresses, communication protocol.

- **Source**: super68k Z80 bus control patterns, SNES SPC700 upload

#### H38: I/O Port Pattern Detection (Z80-specific generalization)

For architectures with separate I/O address space (Z80, x86), detect I/O
port access patterns that indicate hardware driver code.

- **P-code**: Z80 `IN`/`OUT` instructions produce `LOAD`/`STORE` on the I/O
  address space (distinct from RAM space in P-code). The heuristic matches
  `LOAD`/`STORE` on the I/O space.
- **Platform description needed**: I/O port -> device mapping

- **Source**: superz80 OUT patterns (VDP, PSG, SCC)

#### H39: DMA / Bulk Transfer Detection

Identify DMA setup routines where hardware DMA registers are programmed.
These are code blocks that configure and trigger hardware transfers.

| Platform | Pattern |
|----------|---------|
| Genesis | VDP DMA: writes to $C00004 with DMA source/length/dest |
| SNES | HDMA/GDMA: writes to $420B/$420C |
| GBA | DMA: writes to $040000B0-$040000DF |

**Platform description needed**: DMA register addresses and programming sequences.

- **Source**: super68k VDP DMA code scanning

#### H40: System Call / Trap Detection

Identify operating system or firmware system call interfaces. These produce
`CALLOTHER` P-code ops (for software interrupts/traps) and may not follow
standard calling conventions.

| Platform | Pattern |
|----------|---------|
| 68000 pSOS | `TRAP #11` (pSOS), `TRAP #12` (pREPC+), `TRAP #13` (pHILE+) |
| 68000 Mac | `_Trap` A-line instructions ($Axxx) for Toolbox/OS calls |
| SH-1 | `TRAPA #n` for CD block commands |
| ARM | `SWI #n` (software interrupt) |
| x86 | `INT 21h` (DOS), `INT 80h` (Linux), `SYSCALL` (64-bit) |

**Platform description needed**: Trap/SWI number -> service mapping.

- **Source**: Chyron/Gilbarco pSOS trap interface, Mac A-trap dispatch

#### H41: Stack Initialization Detection

Identify the reset/boot entry point by finding code that initializes the
stack pointer from an immediate value (not from a prior computation).

**P-code pattern:**
```
SP = COPY <const>                  # Load immediate value into stack pointer
```

This typically appears only once in a binary, at the reset entry point, and
is a strong anchor for starting analysis.

| ISA | Form |
|-----|------|
| 68000 | Initial SSP read from vector table $000000 |
| Z80 | `LD SP, nnnn` |
| 6502 | `LDX #$FF; TXS` |
| ARM | Reset handler sets SP |
| x86 | `MOV ESP, imm` or segment:offset setup |

- **Source**: superz80 DI;LD SP;IM 1;EI system init pattern, super6502 reset prologue


## Platform Description File Format

Tier 3 heuristics require a per-platform metadata file. Proposed format:

```xml
<platform name="sega_genesis" cpu="68020">
  <memory_map>
    <region start="0x000000" end="0x3FFFFF" type="rom" name="cartridge"/>
    <region start="0xA00000" end="0xA0FFFF" type="io" name="z80_space"/>
    <region start="0xA10000" end="0xA1001F" type="io" name="io_ports"/>
    <region start="0xC00000" end="0xC0001F" type="io" name="vdp"/>
    <region start="0xFF0000" end="0xFFFFFF" type="ram" name="work_ram"/>
  </memory_map>

  <vectors format="abs32_be" base="0x000000">
    <entry index="0" name="initial_ssp"/>
    <entry index="1" name="reset_pc"/>
    <entry index="25" name="trap0"/>
    <entry index="30" name="vblank" irq="true"/>
    <entry index="28" name="hblank" irq="true"/>
    <entry index="31" name="external" irq="true"/>
  </vectors>

  <hardware_registers>
    <reg addr="0xA14000" width="4" name="tmss" access="w"/>
    <reg addr="0xA11100" width="2" name="z80_busreq" access="w"/>
    <reg addr="0xA11200" width="2" name="z80_reset" access="w"/>
    <reg addr="0xC00000" width="2" name="vdp_data" access="rw"/>
    <reg addr="0xC00004" width="2" name="vdp_ctrl" access="rw"/>
    <reg addr="0xA10003" width="1" name="joypad1_data" access="r"/>
    <reg addr="0xA10009" width="1" name="joypad1_ctrl" access="w"/>
  </hardware_registers>

  <coprocessor name="z80" base="0xA00000" size="0x2000"/>
</platform>
```

This format extends Ghidra's .pspec/.cspec with system-level information
that .pspec doesn't cover (memory map, I/O registers, coprocessor interfaces).


## Multi-Pass Pipeline

Recommended pass ordering for the generic P-code disassembler:

```
Pass 1: Vector table entry points (H32)
         -> guaranteed seeds with confidence 100

Pass 2: Forward trace from seeds (H01, H02, H03, H04, H05)
         -> discover blocks, collect CALL/BRANCH targets
         -> apply data filters (H07, H08, H21, H23)

Pass 3: Reference target tracing (H03, H04, H22)
         -> trace from all collected targets not yet covered
         -> apply prologue detection (H24) for high-confidence acceptance

Pass 4: Jump table resolution (H19, H27)
         -> follow BRANCHIND targets
         -> read pointer tables, validate and trace

Pass 5: Orphan recovery (H09, H10, H11)
         -> scan unclaimed regions >= 64 bytes
         -> multi-channel entropy + reference coherence

Pass 6: Data/code boundary detection (H17)
         -> find code blocks preceded by data patterns

Pass 7: Gap filling (H06)
         -> close 1-12 byte gaps between adjacent blocks

Pass 8: Overlap resolution (H14)
         -> resolve any remaining conflicts

Pass 9: Confidence assignment (H20)
         -> tag all blocks with discovery method confidence
```

Passes 2-4 iterate until no new blocks are discovered (fixed-point).


## Heuristic Origin Cross-Reference

| Heuristic | super68k | superz80 | super6502 | Tier |
|-----------|----------|----------|-----------|------|
| H01 Block termination RETURN | Pass 1 | Pass 1 | Pass 2 | 1 |
| H02 Block termination BRANCH | Pass 1 | Pass 1 | Pass 2 | 1 |
| H03 CALL target tracing | Pass 2 | Pass 2 | Pass 3 | 1 |
| H04 BRANCH/CBRANCH targets | Pass 2 | Pass 2 | Pass 3 | 1 |
| H05 Entry point protection | All passes | All passes | All passes | 1 |
| H06 Gap filling | Gap fill | Pass 6 | Pass 7 | 1 |
| H07 Data run detection | block_has_data_words | Pass 1 pre-check | Pass 2 | 1 |
| H08 Byte entropy filtering | Orphan pass | Pass 4 | Pass 5 | 1 |
| H09 Orphan entropy classification | Orphan pass | Pass 4 | Pass 5 | 1 |
| H10 Orphan reference coherence | Orphan pass | - | - | 1 |
| H11 Orphan seed-based tracing | Orphan pass | - | - | 1 |
| H12 Reference classification | All passes | All passes | All passes | 1 |
| H13 Partial block saving | All passes | All passes | Passes 2,3,5,5b | 1 |
| H14 Overlap removal | Implicit | Pass 3 | Pass 6 | 1 |
| H15 Sequential scan + evidence | Pass 1 | Pass 1 | Pass 2 | 1 |
| H16 P-code class entropy | Entropy score | - | Opcode-class entropy | 1 |
| H17 Data/code boundary | Pass 5 | Pass 5 | Pass 5b | 1 |
| H18 Redundant instruction detect | has_redundant_pairs | - | Redundant detect | 1 |
| H19 Jump table detection | Jump tables | - | Pass 4 | 1 |
| H20 Confidence tiers | Implicit | Implicit | Explicit (10 levels) | 1 |
| H21 Byte density check | block_has_data_words | Pass 1 pre-check | Density check | 1 |
| H22 Speculative forward decode | Orphan pass | - | Pass 6 | 1 |
| H23 Valid decode ratio | All passes | All passes | All passes | 1 |
| H24 Prologue detection | Pass 3, 4 | Pass 2.5 | Pass 2 | 2 |
| H25 Epilogue detection | Pass 3 | Pass 2.5 | Pass 2 | 2 |
| H26 Tail call detection | Pass 1 | Pass 1 | - | 2 |
| H27 Computed jump / RTS trick | Jump tables | - | Pass 4 | 2 |
| H28 Opcode-stream patterns | - | 15 patterns | 24+40 patterns | 2 |
| H29 Interrupt handler prologue | Implicit | Implicit | NMI/IRQ save | 2 |
| H30 Stack pointer identification | Implicit (A7) | Implicit (SP) | Implicit (S) | 2 |
| H31 Callee-save register set | Implicit | Pass 2.5 | Implicit | 2 |
| H32 Vector table entry points | Pass 1 | Known addrs | Pass 1 | 3 |
| H33 Memory map validation | Address coherence | - | NES addr validation | 3 |
| H34 HW register pattern override | Genesis patterns | - | NES PPU/APU | 3 |
| H35 ROM checksum / security | Checksum detect | - | - | 3 |
| H36 Mapper / bank switching | Not needed | Slot select | Mapper detect | 3 |
| H37 Dual-CPU communication | Z80 bus control | - | - | 3 |
| H38 I/O port patterns | - | VDP/PSG/SCC | - | 3 |
| H39 DMA / bulk transfer | VDP DMA scan | - | OAM DMA | 3 |
| H40 System call / trap | - | - | - | 3 |
| H41 Stack initialization | Implicit | DI;LD SP;IM 1;EI | SEI;CLD;LDX;TXS | 3 |


## Pass 10: Function Pattern Detection

After code/data identification (Passes 1-9), Pass 10 classifies discovered functions
by their algorithmic purpose using P-code operation distribution analysis.

### ROM domain classification

Before running detectors, the ROM is classified into a domain based on SHA1
identification or platform heuristics:

| Domain | Description | Example ROMs |
|--------|-------------|-------------|
| `GAME_CONSOLE` | Home console cartridge/BIOS | Genesis, SNES, GBA, Casio Loopy, Jaguar |
| `ARCADE` | Arcade board ROM | CPS1, Neo Geo, Taito |
| `COMPUTER_BOOT` | Workstation/server boot ROM | NeXT, SGI O2, iMac G3, Sony NEWS, MVME162 |
| `TYPESETTER` | Typesetter/RIP firmware | AGFA 9000PS |
| `INDUSTRIAL` | Industrial controller | Gilbarco PAM 1000, FPS-3000 |
| `NETWORK_DEVICE` | Network equipment | Routers, bridges |
| `AUDIO_DEVICE` | Sound processor ROM | YM, SPC audio CPUs |
| `GENERIC` | Unknown — conservative rules only | Unidentified ROMs |

The domain gates which detectors run: game-specific detectors (sprite renderer,
tile decoder, particle system, animation update, collision, physics, pathfinding,
score update, etc.) **only fire for GAME_CONSOLE or ARCADE domains**. This
prevents hundreds of false positives on workstation and server boot ROMs.

### Three-phase classification

1. **Phase 0 — P-code vector database** (primary, 1086 signatures): TF-IDF
   weighted cosine similarity on P-code bigram/trigram n-grams against a reference
   database of known functions. Filtered by ROM domain.

2. **Phase 1 — Rule-based detectors** (280 detectors): Each detector examines the
   P-code operation profile (op-class proportions, structural features, constant
   analysis, IO region tracking) and returns a classification with confidence score
   when specific thresholds are met. Minimum 20 P-code ops per function. Only runs
   as fallback when the vector database finds nothing. ~60 game-specific detectors
   are gated on GAME_CONSOLE/ARCADE domain.

3. **Phase 2 — Feature-vector similarity** (274 reference signatures): Functions that
   don't match any rule are compared against 25-dimensional reference fingerprints
   (10 op-class proportions + 5 structural features + 10 discriminative bigrams)
   using cosine similarity with threshold 0.80.

### Detector categories

| Category | Detectors | Examples |
|----------|-----------|---------|
| Memory operations | 11 | memcpy, memset, memcmp, memmove, heap allocator, bitmap allocator, block mapping, DMA transfer, DMA chaining, slab allocator, cache flush |
| String operations | 14 | strlen, string compare, string copy, printf, sprintf, hex dump, number-to-string, regex matcher, string hash, tokenizer, atoi, itoa, string search, case convert, trim |
| Math / arithmetic | 21 | multiply, divide, fixed-point, square root, trig lookup, dot product, abs value, clamp, coordinate transform, BCD, matrix multiply, FFT butterfly, PID controller, popcount, bit reverse, big integer add/multiply, polynomial eval, linear interpolation, log approximation, exp approximation, reciprocal, divide-by-constant, GCD |
| Checksums / hashing | 9 | checksum, CRC polynomial, CRC table lookup, checksum validation, IP checksum, hash function, Hamming ECC, HMAC, Galois field multiply |
| Compression / encoding | 19 | decompression, RLE decompress/compress, LZ, ADPCM, byte swap, Huffman decode, base64 encode/decode, UTF-8 encode/decode, delta encode/decode, XDR encode/decode, arithmetic coding, LZW, BWT, DEFLATE |
| Crypto | 6 | AES round, DES Feistel, SHA-256 round, MD5 transform, RC4 keystream, ChaCha20 quarter-round |
| Graphics / display | 24 | sprite renderer, tile decoder, tilemap loader, scroll handler, screen fade, palette fade, palette cycle, line drawing, text renderer, image loader, bitmap blit, flood fill, circle draw, polygon fill, LCD init, framebuffer swap, VRAM clear, sprite scaling, alpha blending, gamma correction, color space convert, parallax scroll, raycasting |
| Game logic | 17 | collision detection, velocity physics, animation update, particle system, camera tracking, object spawn, score update, pathfinding, high score table, demo playback, save/load state, collision response, gravity/jump, damage calc, inventory, NPC dialog, patrol AI, boss pattern |
| Input / UI | 6 | controller input, menu navigation, debounce input, wildcard match, keyboard scan, VT100 escape parser |
| System / hardware | 28 | boot init, interrupt handler, interrupt control, serial IO, memory test, watchdog feed, flash program, vblank wait, DMA queue, delay loop, self-test, device driver dispatch, timer setup, PWM generation, CRT init, vector table setup, relocation, assert/panic, sensor calibration, power sleep, motor control, page table walk, event signal, stepper motor, bootloader, flash erase, battery monitor, temp compensation |
| OS / kernel | 17 | task scheduler, semaphore, context save/restore, message passing, file operation, bytecode interpreter, stack interpreter, mutex/spinlock, coroutine switch, syscall dispatcher, thread scheduler, signal handler, pipe read/write, memory pool, TLB flush, fd table, mount handler, socket handler, UART driver |
| Control flow | 5 | jump table dispatch, state machine, busy-wait loop, retry loop, error handler |
| Data structures | 8 | table lookup, bitfield extraction, circular buffer, linked list traversal, FIFO queue, priority queue, hash table, binary search |
| Algorithms | 6 | sort, RNG, encrypt/decrypt, command parser, parity compute, ELF section parser |
| Audio | 7 | sound driver, MIDI handler, audio mixer, ADSR envelope, wavetable synth, FM synth operator, sample rate convert |
| DSP / signal processing | 6 | FIR filter, IIR filter, moving average, median filter, zero-crossing detector, convolution |
| Communication | 5 | I2C protocol, SPI protocol, Modbus RTU, PS/2 protocol, serial IO |
| Network | 14 | network protocol, SCSI command, SCSI phase handler, ARP handler, TCP state machine, CD-ROM command, DNS resolver, DHCP client, HTTP parser, SMTP handler, TFTP handler, NTP sync, PPP framer, Telnet handler, SNMP handler, UDP handler |
| Parsers | 5 | JSON parser, CSV parser, COFF/PE loader, BMP decoder, WAV decoder |
| Filesystem | 2 | FAT filesystem, disk block I/O |
| Float emulation | 2 | softfloat add, softfloat multiply |
| Logging / debug | 2 | severity-level logger, garbage collector mark |

### Hardware register labeling

When a platform description is loaded, Pass 10 also scans all instructions for
LOAD/STORE operations targeting known hardware register addresses and creates:
- Named labels at register addresses
- Cross-references from instructions to registers
- End-of-line comments identifying the register

## Statistics

- **Total code/data heuristics**: 41
- **Tier 1 (direct P-code, zero per-ISA code)**: 23 (56%)
- **Tier 2 (P-code pattern matching)**: 8 (20%)
- **Tier 3 (platform metadata required)**: 10 (24%)
- **Function pattern detectors**: 280 rule-based + 274 reference signatures
- **Coverage with Tier 1 alone**: Sufficient for basic disassembly of any ISA
- **Coverage with Tier 1+2**: High-quality function-level disassembly
- **Coverage with Tier 1+2+3**: Production-quality platform-aware disassembly
- **Coverage with Pass 10**: Automatic function classification and hardware labeling
