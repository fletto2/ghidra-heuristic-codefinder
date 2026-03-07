#!/usr/bin/env python3
"""
Parse MAME source code to generate platform description XML files
for the Ghidra HeuristicCodeFinder extension.

Extracts memory maps, CPU types, and machine names from MAME driver
source files (.cpp) under src/mame/.

Usage:
    ./mame_to_platform.py /path/to/mame/src/mame /output/dir
"""

import sys
import os
import re
from collections import defaultdict
from pathlib import Path

# CPU type -> our canonical cpu name and properties
CPU_MAP = {
    # 68000 family
    'M68000':     ('68000',   'abs32_be', 4, 256),
    'M68010':     ('68010',   'abs32_be', 4, 256),
    'M68020':     ('68020',   'abs32_be', 4, 256),
    'M68EC020':   ('68020',   'abs32_be', 4, 256),
    'M68030':     ('68030',   'abs32_be', 4, 256),
    'M68EC030':   ('68030',   'abs32_be', 4, 256),
    'M68040':     ('68040',   'abs32_be', 4, 256),
    'SCC68070':   ('68070',   'abs32_be', 4, 256),
    # Z80 family
    'Z80':        ('z80',     'abs16_le', 2, 0),
    'Z180':       ('z180',    'abs16_le', 2, 0),
    'Z8000':      ('z8000',   'abs16_be', 2, 0),
    'Z80N':       ('z80n',    'abs16_le', 2, 0),
    'NSC800':     ('z80',     'abs16_le', 2, 0),
    'R800':       ('r800',    'abs16_le', 2, 0),
    'LR35902':    ('lr35902', 'abs16_le', 2, 0),
    # 6502 family
    'M6502':      ('6502',    'abs16_le', 2, 3),
    'N2A03':      ('n2a03',   'abs16_le', 2, 3),
    'R65C02':     ('65c02',   'abs16_le', 2, 3),
    'M65C02':     ('65c02',   'abs16_le', 2, 3),
    'M65SC02':    ('65c02',   'abs16_le', 2, 3),
    'M6510':      ('6510',    'abs16_le', 2, 3),
    'M7501':      ('6510',    'abs16_le', 2, 3),
    'M8502':      ('6510',    'abs16_le', 2, 3),
    'W65C02S':    ('65c02',   'abs16_le', 2, 3),
    'W65C816':    ('65816',   'abs16_le', 2, 0),
    'G65816':     ('65816',   'abs16_le', 2, 0),
    'HUC6280':    ('huc6280', 'abs16_le', 2, 3),
    # 6800/6809 family
    'M6800':      ('6800',    'abs16_be', 2, 0),
    'M6801':      ('6801',    'abs16_be', 2, 0),
    'M6803':      ('6803',    'abs16_be', 2, 0),
    'HD6301':     ('6301',    'abs16_be', 2, 0),
    'M6809':      ('6809',    'abs16_be', 2, 0),
    'M6809E':     ('6809',    'abs16_be', 2, 0),
    'HD6309':     ('6309',    'abs16_be', 2, 0),
    # 8080/8085 family
    'I8080':      ('8080',    'abs16_le', 2, 8),
    'I8080A':     ('8080',    'abs16_le', 2, 8),
    'I8085A':     ('8085',    'abs16_le', 2, 8),
    'I8085':      ('8085',    'abs16_le', 2, 8),
    # x86 family
    'I8086':      ('8086',    'abs16_le', 2, 256),
    'I8088':      ('8088',    'abs16_le', 2, 256),
    'I80186':     ('80186',   'abs16_le', 2, 256),
    'I80286':     ('80286',   'abs16_le', 2, 256),
    'I80386':     ('80386',   'abs32_le', 4, 256),
    'I486':       ('80486',   'abs32_le', 4, 256),
    'PENTIUM':    ('pentium', 'abs32_le', 4, 256),
    # ARM family
    'ARM7':       ('arm7_le', 'abs32_le', 4, 8),
    'ARM7_BE':    ('arm7_be', 'abs32_be', 4, 8),
    'ARM9':       ('arm9',    'abs32_le', 4, 8),
    'ARM920T':    ('arm9',    'abs32_le', 4, 8),
    'ARM946ES':   ('arm9',    'abs32_le', 4, 8),
    # SH family
    'SH2':        ('sh2',     'abs32_be', 4, 64),
    'SH7604':     ('sh2',     'abs32_be', 4, 64),
    'SH2A':       ('sh2a',    'abs32_be', 4, 64),
    'SH4':        ('sh4',     'abs32_le', 4, 64),
    'SH3':        ('sh3',     'abs32_be', 4, 64),
    # MIPS family
    'MIPS1':      ('mips',    'abs32_le', 4, 0),
    'MIPS3':      ('mips3',   'abs32_le', 4, 0),
    'R3000':      ('r3000',   'abs32_le', 4, 0),
    'R3041':      ('r3000',   'abs32_le', 4, 0),
    'R4000':      ('r4000',   'abs32_le', 4, 0),
    'R4600':      ('r4600',   'abs32_le', 4, 0),
    'R5000':      ('r5000',   'abs32_le', 4, 0),
    'TX3927':     ('r3000',   'abs32_le', 4, 0),
    'VR4300':     ('vr4300',  'abs32_le', 4, 0),
    # PowerPC family
    'PPC601':     ('ppc',     'abs32_be', 4, 0),
    'PPC602':     ('ppc',     'abs32_be', 4, 0),
    'PPC603':     ('ppc',     'abs32_be', 4, 0),
    'PPC603E':    ('ppc',     'abs32_be', 4, 0),
    'PPC604':     ('ppc',     'abs32_be', 4, 0),
    'MPC8240':    ('ppc',     'abs32_be', 4, 0),
    # TMS family
    'TMS9900':    ('tms9900', 'abs16_be', 2, 0),
    'TMS9995':    ('tms9995', 'abs16_be', 2, 0),
    'TMS9980A':   ('tms9980', 'abs16_be', 2, 0),
    # Hitachi H8
    'H83002':     ('h8',      'abs32_be', 4, 0),
    'H83006':     ('h8',      'abs32_be', 4, 0),
    'H83007':     ('h8',      'abs32_be', 4, 0),
    'H83044':     ('h8',      'abs32_be', 4, 0),
    'H83048':     ('h8',      'abs32_be', 4, 0),
    'H83337':     ('h8',      'abs32_be', 4, 0),
    'H8325':      ('h8',      'abs32_be', 4, 0),
    # V60/V70
    'V60':        ('v60',     'abs32_le', 4, 0),
    'V70':        ('v70',     'abs32_le', 4, 0),
    # 8048/8051 family
    'I8048':      ('8048',    'abs16_le', 2, 0),
    'I8049':      ('8049',    'abs16_le', 2, 0),
    'I8050':      ('8048',    'abs16_le', 2, 0),
    'I8051':      ('8051',    'abs16_le', 2, 0),
    'I80C51':     ('8051',    'abs16_le', 2, 0),
    'I8751':      ('8051',    'abs16_le', 2, 0),
    'I87C51':     ('8051',    'abs16_le', 2, 0),
    # SPARC
    'MB86901':    ('sparc',   'abs32_be', 4, 0),
    # M6805
    'M6805':      ('6805',    'abs16_be', 2, 0),
    'M68705':     ('68705',   'abs16_be', 2, 0),
    'HD6305':     ('6805',    'abs16_be', 2, 0),
    # M68HC11
    'MC68HC11':   ('68hc11',  'abs16_be', 2, 0),
    'MC68HC11A1': ('68hc11',  'abs16_be', 2, 0),
    # Misc
    'SM510':      ('sm510',   None, 0, 0),
    'SM511':      ('sm511',   None, 0, 0),
    'TLCS90':     ('tlcs90',  'abs16_le', 2, 0),
    'UPD7810':    ('upd7810', 'abs16_le', 2, 0),
    'UPD78C05':   ('upd78c05','abs16_le', 2, 0),
    'DECO_CPU7':  ('6502',    'abs16_le', 2, 3),
    'DECO_CPU6':  ('6502',    'abs16_le', 2, 3),
    'DECO222':    ('6502',    'abs16_le', 2, 3),
    'MC6845':     (None, None, 0, 0),  # not a CPU, skip
}

# 68000 vector table entries
M68K_VECTORS = [
    (0, 'initial_ssp'),
    (1, 'reset_pc'),
    (2, 'bus_error'),
    (3, 'address_error'),
    (4, 'illegal_instr'),
    (5, 'divide_by_zero'),
    (6, 'chk'),
    (7, 'trapv'),
    (8, 'privilege'),
    (9, 'trace'),
    (10, 'line_a'),
    (11, 'line_f'),
    (24, 'spurious_irq'),
    (25, 'autovector_1', True),
    (26, 'autovector_2', True),
    (27, 'autovector_3', True),
    (28, 'autovector_4', True),
    (29, 'autovector_5', True),
    (30, 'autovector_6', True),
    (31, 'autovector_7', True),
    (32, 'trap_0'),
    (33, 'trap_1'),
    (34, 'trap_2'),
    (35, 'trap_3'),
    (36, 'trap_4'),
    (37, 'trap_5'),
    (38, 'trap_6'),
    (39, 'trap_7'),
    (40, 'trap_8'),
    (41, 'trap_9'),
    (42, 'trap_10'),
    (43, 'trap_11'),
    (44, 'trap_12'),
    (45, 'trap_13'),
    (46, 'trap_14'),
    (47, 'trap_15'),
]

# 6502 vector table entries (at top of address space)
M6502_VECTORS = [
    (0, 'nmi', True),
    (1, 'reset'),
    (2, 'irq', True),
]

# ARM7 vector table entries
ARM7_VECTORS = [
    (0, 'reset'),
    (1, 'undef'),
    (2, 'swi'),
    (3, 'prefetch_abort'),
    (4, 'data_abort'),
    (6, 'irq', True),
    (7, 'fiq', True),
]

# SH-2 vector table entries (subset)
SH2_VECTORS = [
    (0, 'power_on_pc'),
    (1, 'power_on_sp'),
    (2, 'manual_reset_pc'),
    (3, 'manual_reset_sp'),
    (4, 'general_illegal'),
    (6, 'slot_illegal'),
    (9, 'cpu_addr_error'),
    (10, 'dma_addr_error'),
    (11, 'nmi', True),
    (12, 'user_break'),
]


def parse_map_function(lines, start_idx):
    """Parse a memory map function starting at start_idx, return list of (start, end, type, name)."""
    regions = []
    brace_depth = 0
    in_func = False

    for i in range(start_idx, min(start_idx + 200, len(lines))):
        line = lines[i]

        if '{' in line:
            brace_depth += line.count('{') - line.count('}')
            in_func = True
        elif '}' in line:
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0 and in_func:
                break
        if not in_func:
            continue

        # Match map(0xNNNN, 0xNNNN)
        m = re.search(r'map\s*\(\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*\)', line)
        if not m:
            continue

        start_addr = int(m.group(1), 16)
        end_addr = int(m.group(2), 16)

        # Determine region type from chained methods
        rest = line[m.end():]
        # Also look at comment for name hints
        comment = ''
        cm = re.search(r'//\s*(.*)', line)
        if cm:
            comment = cm.group(1).strip()

        region_type = 'io'  # default: treat as I/O (has handler functions)
        region_name = ''

        # .rom() and .ram() take priority even if chained with .rw()/.w()/.r()
        if '.rom()' in rest:
            region_type = 'rom'
            region_name = 'rom'
        elif '.ram()' in rest:
            region_type = 'ram'
            region_name = 'ram'
        elif '.writeonly()' in rest:
            region_type = 'ram'
            region_name = 'writeonly'
        elif '.readonly()' in rest:
            region_type = 'rom'
            region_name = 'readonly'
        elif '.bankrw(' in rest or '.bankr(' in rest:
            region_type = 'ram'
            region_name = 'banked'
        elif '.noprw()' in rest or '.unmaprw()' in rest:
            region_type = 'unmapped'
            region_name = 'unmapped'
        elif '.nopw()' in rest and '.nopr()' not in rest and '.r(' not in rest and '.rw(' not in rest:
            region_type = 'unmapped'
            region_name = 'nop_write'
        elif '.nopr()' in rest or '.unmapr()' in rest:
            region_type = 'unmapped'
            region_name = 'nop_read'
        elif '.portr(' in rest or '.portw(' in rest:
            region_type = 'io'
            region_name = 'port'

        # Try to extract a meaningful name from FUNC() or share() or comment
        func_m = re.search(r'FUNC\(\w+::(\w+)\)', rest)
        share_m = re.search(r'\.share\("(\w+)"\)', rest)
        bankr_m = re.search(r'\.bankr\w*\("(\w+)"\)', rest)

        if share_m:
            region_name = share_m.group(1)
        elif bankr_m:
            region_name = bankr_m.group(1)
        elif func_m and region_type == 'io':
            region_name = func_m.group(1)
            # Clean up common prefixes
            for prefix in ['read_', 'write_', 'r_', 'w_', 'rw_']:
                if region_name.startswith(prefix):
                    region_name = region_name[len(prefix):]
                    break
        elif comment and not region_name:
            # Use first few words of comment as name
            region_name = re.sub(r'[^a-zA-Z0-9_ ]', '', comment)[:40].strip().replace(' ', '_').lower()

        if not region_name:
            region_name = f"region_{start_addr:x}"

        regions.append((start_addr, end_addr, region_type, region_name))

    return regions


def parse_file(filepath):
    """Parse a single MAME driver .cpp file, return list of machine descriptions."""
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return []

    machines = []

    # Extract header comment (machine/hardware description)
    header_comment = ''
    in_comment = False
    for line in lines[:100]:  # Only check first 100 lines
        stripped = line.strip()
        if stripped.startswith('/*'):
            in_comment = True
            header_comment += stripped.lstrip('/*').strip() + '\n'
        elif in_comment:
            if stripped.endswith('*/'):
                header_comment += stripped.rstrip('*/').strip() + '\n'
                break
            else:
                # Skip lines that are just ' *'
                text = stripped.lstrip('* ').rstrip()
                if text:
                    header_comment += text + '\n'
    header_comment = header_comment.strip()

    # Extract device list from #include and required_device declarations
    devices = set()
    # Well-known MAME device includes -> device type
    DEVICE_INCLUDES = {
        'wd33c9': 'scsi:wd33c93', 'ncr5380': 'scsi:ncr5380', 'am53cf96': 'scsi:am53cf96',
        'ncr53c9': 'scsi:ncr53c90', 'aic6250': 'scsi:aic6250',
        'ym2151': 'sound:ym2151', 'ym2203': 'sound:ym2203', 'ym2413': 'sound:ym2413',
        'ym2608': 'sound:ym2608', 'ym2610': 'sound:ym2610', 'ym2612': 'sound:ym2612',
        'ym3526': 'sound:ym3526', 'ym3812': 'sound:ym3812',
        'sn76496': 'sound:sn76496', 'sn76489': 'sound:sn76489',
        'ay8910': 'sound:ay8910', 'ay8912': 'sound:ay8912',
        'pokey': 'sound:pokey', 'sid6581': 'sound:sid6581',
        'rf5c68': 'sound:rf5c68', 'rf5c164': 'sound:rf5c164',
        'okim6295': 'sound:okim6295', 'dac': 'sound:dac',
        'tms9918': 'video:tms9918', 'tms9928': 'video:tms9928', 'tms9929': 'video:tms9929',
        'v9938': 'video:v9938', 'v9958': 'video:v9958',
        'mc6845': 'video:mc6845', 'hd6845': 'video:hd6845',
        'dp8573': 'rtc:dp8573', 'dp8572': 'rtc:dp8572',
        'mc146818': 'rtc:mc146818', 'msm6242': 'rtc:msm6242',
        'z80scc': 'serial:z80scc', 'z80sio': 'serial:z80sio',
        'mc68681': 'serial:mc68681', 'scn2681': 'serial:scn2681',
        'ns16550': 'serial:ns16550', '8250': 'serial:8250',
        'acia6850': 'serial:acia6850', 'mc6850': 'serial:mc6850',
        'seeq8003': 'net:seeq8003', 'am7990': 'net:am7990', 'dp8390': 'net:dp8390',
        'i8255': 'io:i8255', 'i8254': 'timer:i8254', 'i8253': 'timer:i8253',
        'i8259': 'irq:i8259', 'i8237': 'dma:i8237',
        'wd_fdc': 'disk:wd_fdc', 'upd765': 'disk:upd765',
        'eeprom': 'storage:eeprom', 'nscsi': 'bus:nscsi',
    }
    for line in lines:
        # Match #include "machine/device.h" or "sound/device.h" etc.
        inc_m = re.search(r'#include\s+"(?:machine|sound|video|bus)/(\w+)\.h"', line)
        if inc_m:
            inc_name = inc_m.group(1).lower()
            for key, dev_type in DEVICE_INCLUDES.items():
                if key in inc_name:
                    devices.add(dev_type)
                    break
        # Match required_device<device_type> declarations
        rd_m = re.search(r'required_device<(\w+)>', line)
        if rd_m:
            dev_name = rd_m.group(1).lower()
            for key, dev_type in DEVICE_INCLUDES.items():
                if key in dev_name:
                    devices.add(dev_type)
                    break

    # Find all memory map functions
    map_functions = {}  # func_name -> [(start, end, type, name), ...]
    for i, line in enumerate(lines):
        m = re.match(r'void\s+(\w+)::(\w+)\s*\(\s*address_map\s*&\s*map\s*\)', line)
        if m:
            class_name = m.group(1)
            func_name = m.group(2)
            regions = parse_map_function(lines, i)
            if regions:
                map_functions[func_name] = regions
                map_functions[f"{class_name}::{func_name}"] = regions

    if not map_functions:
        return []

    # Find CPU type declarations and their map assignments
    # Pattern: CPU_TYPE(config, tag, clock);
    # followed by: tag->set_addrmap(AS_PROGRAM, &class::map_func);
    cpu_declarations = {}  # tag -> cpu_type
    cpu_type_pattern = re.compile(
        r'(' + '|'.join(re.escape(k) for k in CPU_MAP.keys()) + r')\s*\(\s*config\s*,\s*(\w+)',
    )
    for line in lines:
        m = cpu_type_pattern.search(line)
        if m:
            cpu_type = m.group(1)
            tag = m.group(2)
            if CPU_MAP.get(cpu_type, (None,))[0] is not None:
                cpu_declarations[tag] = cpu_type

    # Find set_addrmap calls to connect CPUs to maps
    cpu_map_assignments = {}  # map_func_name -> cpu_tag
    for line in lines:
        m = re.search(r'(\w+)->set_addrmap\s*\(\s*AS_PROGRAM\s*,\s*&\w+::(\w+)\s*\)', line)
        if m:
            tag = m.group(1)
            map_func = m.group(2)
            cpu_map_assignments[map_func] = tag

    # Find machine declarations: GAME(), CONS(), COMP(), SYST()
    # Format: GAME( year, name, parent, machine_config, input, class, init, rot, mfr, desc, flags )
    machine_names = []
    for line in lines:
        m = re.search(r'(?:GAME|CONS|COMP|SYST)\s*\(\s*(\d+)\s*,\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*,', line)
        if m:
            year = m.group(1)
            name = m.group(2)
            config_func = m.group(3)
            machine_names.append((name, year, config_func))

    # If no GAME/CONS/COMP/SYST macros, derive name from filename
    if not machine_names:
        stem = Path(filepath).stem
        # Skip header/utility files
        if stem.endswith('_v') or stem.endswith('_m') or stem.endswith('_a'):
            return []
        machine_names.append((stem, '', ''))

    # Build config_func -> map_func lookup
    # Parse machine_config functions to find which set_addrmap they call
    config_to_map = {}  # config_func_name -> (cpu_type, map_func_name)
    # Find config function definitions and their set_addrmap calls
    for i, line in enumerate(lines):
        # Match: void CLASS::config_func(machine_config &config[, ...])
        cm = re.match(r'void\s+\w+::(\w+)\s*\(\s*machine_config\s*&\s*config\b', line)
        if cm:
            config_name = cm.group(1)
            # Scan the function body for set_addrmap(AS_PROGRAM, ...)
            brace_depth = 0
            in_func = False
            for j in range(i, min(i + 200, len(lines))):
                bl = lines[j]
                if '{' in bl:
                    brace_depth += bl.count('{') - bl.count('}')
                    in_func = True
                elif '}' in bl:
                    brace_depth += bl.count('{') - bl.count('}')
                    if brace_depth <= 0 and in_func:
                        break
                # Find set_addrmap for AS_PROGRAM (the main CPU map)
                am = re.search(r'(\w+)->set_addrmap\s*\(\s*AS_PROGRAM\s*,\s*&\w+::(\w+)\s*\)', bl)
                if am:
                    tag = am.group(1)
                    map_func = am.group(2)
                    # Only record the first AS_PROGRAM mapping (main CPU)
                    if config_name not in config_to_map:
                        config_to_map[config_name] = (tag, map_func)

    # Determine the primary CPU and its memory map per machine_config
    # Default fallback: find a global primary CPU/map
    default_cpu = None
    default_map = None

    for map_func, tag in cpu_map_assignments.items():
        if tag in cpu_declarations:
            cpu_type = cpu_declarations[tag]
            if map_func in map_functions:
                if tag == 'm_maincpu' or default_cpu is None:
                    default_cpu = cpu_type
                    default_map = map_func

    # If no set_addrmap found, try to match by naming convention
    if default_cpu is None:
        for cpu_name in ['M68000', 'Z80', 'M6502', 'N2A03', 'SH2', 'ARM7',
                         'I8080', 'I8085', 'M6809', 'I8086', 'R65C02',
                         'M68020', 'SH4', 'V60', 'HUC6280', 'TMS9900',
                         'M6800', 'LR35902']:
            if re.search(rf'\b{cpu_name}\b', content):
                default_cpu = cpu_name
                break

    if default_cpu is None:
        return []

    # Fallback map selection when no config_func resolution works
    if default_map is None:
        def map_score(name):
            if '::' in name:
                return (100,)
            n = name.lower()
            regions = map_functions.get(name, [])
            rom_ram_count = sum(1 for r in regions if r[2] in ('rom', 'ram'))
            return (
                0 if 'program' in n else 1,
                0 if 'main' in n else 1,
                0 if '_map' in n else 1,
                0 if 'mem' in n else 1,
                -rom_ram_count,
                len(name),
            )
        candidates = [n for n in map_functions.keys() if '::' not in n]
        if candidates:
            default_map = min(candidates, key=map_score)
        elif map_functions:
            default_map = min(map_functions.keys(), key=map_score)

    if default_map is None or default_map not in map_functions:
        return []

    manufacturer = Path(filepath).parent.name

    # Build machine descriptions — resolve per-machine config when possible
    for machine_name, year, config_func in machine_names:
        # Try to resolve this machine's specific map via config_func
        this_cpu = default_cpu
        this_map = default_map

        if config_func and config_func in config_to_map:
            tag, map_func = config_to_map[config_func]
            if map_func in map_functions:
                this_map = map_func
                if tag in cpu_declarations:
                    this_cpu = cpu_declarations[tag]

        regions = map_functions[this_map]
        cpu_info = CPU_MAP.get(this_cpu, ('unknown', None, 0, 0))

        machines.append({
            'name': machine_name,
            'year': year,
            'cpu': this_cpu,
            'cpu_canonical': cpu_info[0],
            'vector_format': cpu_info[1],
            'vector_entry_size': cpu_info[2],
            'vector_count': cpu_info[3],
            'regions': regions,
            'manufacturer': manufacturer,
            'source_file': os.path.basename(filepath),
            'secondary_cpus': {},
            'devices': sorted(devices),
            'header_comment': header_comment,
        })

    return machines


def get_vectors_for_cpu(cpu_canonical, regions):
    """Return appropriate vector entries based on CPU type and memory map."""
    vectors = []
    vector_base = 0

    if cpu_canonical in ('68000', '68010', '68020', '68030', '68040', '68070'):
        # 68000: vectors at 0x000000, but only if ROM starts there
        has_rom_at_zero = any(r[0] == 0 and r[2] == 'rom' for r in regions)
        if has_rom_at_zero:
            vectors = M68K_VECTORS
            vector_base = 0
    elif cpu_canonical in ('6502', '65c02', 'n2a03', '6510', 'huc6280'):
        # 6502: vectors at $FFFA
        has_rom_at_top = any(r[1] >= 0xFFFF and r[2] == 'rom' for r in regions)
        if has_rom_at_top:
            vectors = M6502_VECTORS
            vector_base = 0xFFFA
    elif cpu_canonical in ('arm7_le', 'arm7_be', 'arm9'):
        has_rom_at_zero = any(r[0] == 0 and r[2] == 'rom' for r in regions)
        if has_rom_at_zero:
            vectors = ARM7_VECTORS
            vector_base = 0
    elif cpu_canonical in ('sh2', 'sh2a'):
        has_rom_at_zero = any(r[0] == 0 and r[2] == 'rom' for r in regions)
        if has_rom_at_zero:
            vectors = SH2_VECTORS
            vector_base = 0

    return vectors, vector_base


def merge_adjacent_regions(regions):
    """Merge adjacent regions of the same type."""
    if not regions:
        return regions
    merged = [regions[0]]
    for r in regions[1:]:
        prev = merged[-1]
        if r[2] == prev[2] and r[0] == prev[1] + 1:
            merged[-1] = (prev[0], r[1], prev[2], prev[3])
        else:
            merged.append(r)
    return merged


def generate_xml(machine):
    """Generate platform description XML for a machine."""
    name = machine['name']
    cpu = machine['cpu_canonical']
    regions = machine['regions']
    vector_format = machine['vector_format']

    # Sort and merge regions
    regions = sorted(regions, key=lambda r: r[0])
    regions = merge_adjacent_regions(regions)

    # Filter out very small unmapped regions and duplicates
    seen = set()
    filtered = []
    for r in regions:
        key = (r[0], r[1])
        if key not in seen:
            seen.add(key)
            filtered.append(r)
    regions = filtered

    # Skip machines with too few regions (probably incomplete)
    meaningful = [r for r in regions if r[2] in ('rom', 'ram', 'io')]
    if len(meaningful) < 2:
        return None

    vectors, vector_base = get_vectors_for_cpu(cpu, regions)

    lines = []
    lines.append(f'<platform name="{name}" cpu="{cpu}">')

    # Source info as comment
    lines.append(f'  <!-- source: MAME {machine["manufacturer"]}/{machine["source_file"]} -->')
    if machine['year']:
        lines.append(f'  <!-- year: {machine["year"]} -->')

    # Memory map
    lines.append('  <memory_map>')
    for start, end, rtype, rname in regions:
        # Clean up name for XML
        rname = re.sub(r'[^a-zA-Z0-9_]', '_', rname)[:50]
        if not rname:
            rname = f'{rtype}_{start:x}'
        lines.append(f'    <region start="0x{start:08X}" end="0x{end:08X}" type="{rtype}" name="{rname}"/>')
    lines.append('  </memory_map>')

    # Vectors
    if vectors and vector_format:
        lines.append('')
        lines.append(f'  <vectors format="{vector_format}" base="0x{vector_base:08X}">')
        for entry in vectors:
            idx = entry[0]
            vname = entry[1]
            is_irq = len(entry) > 2 and entry[2]
            irq_attr = ' irq="true"' if is_irq else ''
            lines.append(f'    <entry index="{idx}" name="{vname}"{irq_attr}/>')
        lines.append('  </vectors>')

    # Devices
    if machine.get('devices'):
        lines.append('')
        lines.append('  <devices>')
        for dev in machine['devices']:
            # Format: "category:name" → <device type="category" name="name"/>
            if ':' in dev:
                cat, dname = dev.split(':', 1)
                lines.append(f'    <device type="{cat}" name="{dname}"/>')
            else:
                lines.append(f'    <device name="{dev}"/>')
        lines.append('  </devices>')

    # Header comment (hardware description)
    if machine.get('header_comment'):
        lines.append('')
        comment = machine['header_comment']
        # Escape XML special chars
        comment = comment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        # Truncate to first 500 chars to keep XML manageable
        if len(comment) > 500:
            comment = comment[:500] + '...'
        lines.append(f'  <!-- {comment} -->')

    lines.append('</platform>')
    return '\n'.join(lines) + '\n'


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <mame_src_mame_dir> <output_dir>")
        sys.exit(1)

    mame_dir = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)

    # Find all .cpp files
    cpp_files = sorted(Path(mame_dir).rglob('*.cpp'))
    print(f"Scanning {len(cpp_files)} source files...")

    all_machines = []
    files_with_maps = 0

    for filepath in cpp_files:
        machines = parse_file(str(filepath))
        if machines:
            files_with_maps += 1
            all_machines.extend(machines)

    print(f"Found {len(all_machines)} machines in {files_with_maps} files")

    # Generate XML files
    generated = 0
    skipped = 0
    by_cpu = defaultdict(int)

    for machine in all_machines:
        xml = generate_xml(machine)
        if xml is None:
            skipped += 1
            continue

        # Organize by manufacturer
        mfr_dir = os.path.join(output_dir, machine['manufacturer'])
        os.makedirs(mfr_dir, exist_ok=True)

        outpath = os.path.join(mfr_dir, f"{machine['name']}.xml")
        with open(outpath, 'w') as f:
            f.write(xml)

        generated += 1
        by_cpu[machine['cpu_canonical']] += 1

    print(f"\nGenerated {generated} platform descriptions ({skipped} skipped)")
    print(f"\nBy CPU type:")
    for cpu, count in sorted(by_cpu.items(), key=lambda x: -x[1]):
        print(f"  {cpu:12s}: {count}")


if __name__ == '__main__':
    main()
