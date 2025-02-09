
# MachO

A better parser for the MachO file format. 

## Features

- [x] Parse MachO header
- [x] Supports Fat MachO files
- [x] Parse MachO all known load commands
- [x] Tool for dumping MachO header/ load commands
- [x] Tool for extracting thin MachO from fat MachO
- [ ] Parse LinkeditDataCommand specific data (CodeSignature, etc.)


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

Dumps an extremely verbose representation of the MachO file.

```
→ macho
Usage: macho <file_path>

→ macho /usr/bin/sqlite3   
This is a fat macho file. Please select an architecture:
0: X86_64 CpuSubTypeX86(All)
1: X86_64 CpuSubTypeX86(X86_64H)
2: Arm64 CpuSubTypeArm64(ARM64E)
> 2
Header64(
    MachHeader64 {
        magic: MhMagic64,
        cputype: Arm64,
        cpusubtype: CpuSubTypeArm64(
            ARM64E,
        ),
        filetype: MhExecute,
        ncmds: 21,
        sizeofcmds: 2088,
        flags: MHFlags(
            MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE,
        ),
        reserved: 0,
    },
)
...load commands...
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
