
# MachO

A better parser for the MachO file format. 

## Features

- [x] Parse MachO header
- [x] Supports Fat MachO files
- [x] Parse MachO all known load commands
- [x] Parse code signature, chained fixups, dysymtab, and more.
- [x] Tool for dumping MachO header/ load commands
- [x] Tool for extracting thin MachO from fat MachO

## TODO

- [ ] Parse CMS signature in LC_CODE_SIGNATURE
- [ ] Resolve library ordinals across several load commands
- [ ] Make the tools more user-friendly, and make more tools



## Installation

Library:

```bash
cargo add macho2
```

Tooling:

```bash
cargo install macho2
```

## Tools

### MachO

Dumps the header and load commands of a MachO file.

```
→ macho
Usage: macho <file_path>

→ macho /usr/bin/sqlite3   
MhExecute - X86_64 CpuSubTypeX86(All) - MHFlags(MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE)
000: LC_SEGMENT_64  addr=0x000000000-0x100000000 off=0x000000000-0x000000000 sz=0x000000 (---/---) __PAGEZERO
001: LC_SEGMENT_64  addr=0x100000000-0x100142000 off=0x000000000-0x000142000 sz=0x142000 (r-x/r-x) __TEXT
      addr=0x100001550-0x10011d73e off=0x000001550-0x00011d73e sz=0x11c1ee __text
      addr=0x10011d73e-0x10011dc66 off=0x00011d73e-0x00011dc66 sz=0x000528 __stubs
      addr=0x10011dc70-0x100127ba8 off=0x00011dc70-0x000127ba8 sz=0x009f38 __const
      addr=0x100127bb0-0x10013f5d8 off=0x000127bb0-0x00013f5d8 sz=0x017a28 __cstring
      addr=0x10013f5e0-0x10013fc72 off=0x00013f5e0-0x00013fc72 sz=0x000692 __oslogstring
      addr=0x10013fc74-0x100141efc off=0x00013fc74-0x000141efc sz=0x002288 __unwind_info
      addr=0x100141f00-0x100142000 off=0x000141f00-0x000142000 sz=0x000100 __eh_frame
002: LC_SEGMENT_64  addr=0x100142000-0x100147000 off=0x000142000-0x000147000 sz=0x005000 (rw-/rw-) __DATA_CONST
      addr=0x100142000-0x100142748 off=0x000142000-0x000142748 sz=0x000748 __got
      addr=0x100142750-0x1001467e8 off=0x000142750-0x0001467e8 sz=0x004098 __const
003: LC_SEGMENT_64  addr=0x100147000-0x10014f000 off=0x000147000-0x00014c000 sz=0x005000 (rw-/rw-) __DATA
      addr=0x100147000-0x10014b8a0 off=0x000147000-0x00014b8a0 sz=0x0048a0 __data
      addr=0x10014b8a0-0x10014b8e0 off=0x00014b8a0-0x00014b8e0 sz=0x000040 __crash_info
      addr=0x10014b8e0-0x10014e4d0 off=0x000000000-0x000002bf0 sz=0x002bf0 __bss
      addr=0x10014e4d0-0x10014e4e0 off=0x000000000-0x000000010 sz=0x000010 __common
004: LC_SEGMENT_64  addr=0x10014f000-0x10015f000 off=0x00014c000-0x000158b40 sz=0x00cb40 (r--/r--) __LINKEDIT
005: LC_DYLD_CHAINED_FIXUPS  nimports=258 nstarts=2
006: LC_DYLD_EXPORTS_TRIE  nexports=1
007: LC_SYMTAB  off=0x0014f4d0 sz=0x00000104 nsyms=260
008: LC_DYSYMTAB  nlocals=1 nextdefs=1 nundefs=258 nindirects=453
009: LC_LOAD_DYLINKER  /usr/lib/dyld
010: LC_UUID  eef6064e-ab34-3016-b466-bc6cbe36db71
011: LC_BUILD_VERSION  minos=14.6.0 platform=MacOS ntools=1
012: LC_SOURCE_VERSION  351.4.0.0.0
013: LC_MAIN  entry=0x0000da0c
014: LC_LOAD_DYLIB  /usr/lib/libz.1.dylib (1.2.12)
015: LC_LOAD_DYLIB  /usr/lib/libncurses.5.4.dylib (5.4.0)
016: LC_LOAD_DYLIB  /usr/lib/libedit.3.dylib (3.0.0)
017: LC_LOAD_DYLIB  /usr/lib/libSystem.B.dylib (65.120.2)
018: LC_FUNCTION_STARTS  nfuncs=3132
019: LC_DATA_IN_CODE
020: LC_CODE_SIGNATURE  nblobs=3
```

### Thin

Extracts the thin MachO file from a fat MachO file.

```
→ thin
Usage: thin <file_path> <output>

→ file /usr/bin/sqlite3
/usr/bin/sqlite3: Mach-O universal binary with 3 architectures: [x86_64:Mach-O 64-bit executable x86_64] [x86_64h] [arm64e]
/usr/bin/sqlite3 (for architecture x86_64):     Mach-O 64-bit executable x86_64
/usr/bin/sqlite3 (for architecture x86_64h):    Mach-O 64-bit executable x86_64h
/usr/bin/sqlite3 (for architecture arm64e):     Mach-O 64-bit executable arm64e

→ thin /usr/bin/sqlite3 sqlite3.arm64e
0: X86_64 CpuSubTypeX86(All)
1: X86_64 CpuSubTypeX86(X86_64H)
2: Arm64 CpuSubTypeArm64(ARM64E)
> 2

→ file sqlite3.arm64e 
sqlite3.arm64e: Mach-O 64-bit executable arm64e
```

### Exports

Dumps the exports of a MachO file.

```
→ exports
Usage: exports <file_path>
```
