use macho2::{
    header::MachHeader,
    macho::{FatMachO, LoadCommandResolved, MachO, MachOErr, MachOResult, Resolved},
    segment::Protection,
};
use std::{
    env,
    fs::File,
    io::{stdout, Write},
};

fn main() -> MachOResult<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        return Ok(());
    }

    let file_path = &args[1];
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return Ok(());
        }
    };

    if FatMachO::is_fat_magic(&mut file)? {
        let mut fat_macho = FatMachO::parse(&mut file).unwrap();
        println!("This is a fat macho file. Please select an architecture:");
        for (i, arch) in fat_macho.archs.iter().enumerate() {
            println!("{}: {:?} {:?}", i, arch.cputype(), arch.cpusubtype());
        }
        print!("> ");

        let index = loop {
            let mut input = String::new();
            stdout().flush().unwrap();
            std::io::stdin().read_line(&mut input).unwrap();
            match input.trim().parse::<usize>() {
                Ok(i) if i < fat_macho.archs.len() => break i,
                _ => println!(
                    "Please enter a valid number between 0 and {}",
                    fat_macho.archs.len() - 1
                ),
            }
        };
        let macho = fat_macho
            .macho(fat_macho.archs[index].cputype())
            .map_err(|e| {
                panic!("Failed to extract Mach-O: {}", e);
            })
            .unwrap();
        print_header(macho.header);
        print_load_commands(macho.load_commands());
    } else if MachO::<_, Resolved>::is_macho_magic(&mut file)? {
        let macho = MachO::<_, Resolved>::parse(file).unwrap();
        print_header(macho.header);
        print_load_commands(macho.load_commands());
    } else {
        return Err(MachOErr {
            detail: "Invalid Mach-O file".to_string(),
        });
    };

    Ok(())
}

fn print_header(hdr: MachHeader) {
    println!(
        "{:?} - {} {:?} - {:?}",
        hdr.filetype(),
        hdr.cputype(),
        hdr.cpusubtype(),
        hdr.flags()
    );
}

fn print_load_commands(lcs: &Vec<LoadCommandResolved>) {
    lcs.iter().enumerate().for_each(|(i, lc)| {
        print!("{:03}: ", i);
        print_load_command(lc);
    });
}

fn print_load_command(lc: &LoadCommandResolved) {
    match lc {
        LoadCommandResolved::None => todo!(),
        LoadCommandResolved::Segment32(segment_command32) => {
            println!(
                "LC_SEGMENT  addr=0x{:09x}-0x{:09x} off=0x{:09x}-0x{:09x} sz=0x{:06x} ({}/{}) {}",
                segment_command32.vmaddr,
                segment_command32.vmaddr + segment_command32.vmsize,
                segment_command32.fileoff,
                segment_command32.fileoff + segment_command32.filesize,
                segment_command32.filesize,
                protection_to_string(segment_command32.initprot),
                protection_to_string(segment_command32.maxprot),
                segment_command32.segname,
            );
            for sect in &segment_command32.sects {
                println!(
                    "      addr=0x{:09x}-0x{:09x} off=0x{:09x}-0x{:09x} sz=0x{:06x} {}",
                    sect.addr,
                    sect.addr + sect.size,
                    sect.offset,
                    sect.offset + sect.size,
                    sect.size,
                    sect.sectname,
                );
            }
        }
        LoadCommandResolved::Segment64(segment_command64) => {
            println!(
                "LC_SEGMENT_64  addr=0x{:09x}-0x{:09x} off=0x{:09x}-0x{:09x} sz=0x{:06x} ({}/{}) {}",
                segment_command64.vmaddr,
                segment_command64.vmaddr + segment_command64.vmsize,
                segment_command64.fileoff,
                segment_command64.fileoff + segment_command64.filesize,
                segment_command64.filesize,
                protection_to_string(segment_command64.initprot),
                protection_to_string(segment_command64.maxprot),
                segment_command64.segname,
            );
            for sect in &segment_command64.sections {
                println!(
                    "      addr=0x{:09x}-0x{:09x} off=0x{:09x}-0x{:09x} sz=0x{:06x} {}",
                    sect.addr,
                    sect.addr + sect.size,
                    sect.offset,
                    sect.offset as u64 + sect.size,
                    sect.size,
                    sect.sectname,
                );
            }
        }
        LoadCommandResolved::Symtab(symtab_command) => println!(
            "LC_SYMTAB  off=0x{:08x} sz=0x{:08x} nsyms={}",
            symtab_command.symoff, symtab_command.nsyms, symtab_command.nsyms
        ),
        LoadCommandResolved::Symseg(_) => println!("LC_SYMSEG"),
        LoadCommandResolved::Thread(_) => println!("LC_THREAD"),
        LoadCommandResolved::UnixThread(_) => println!("LC_UNIXTHREAD"),
        LoadCommandResolved::Dysymtab(dysymtab_command) => println!(
            "LC_DYSYMTAB  nlocals={} nextdefs={} nundefs={} nindirects={}",
            dysymtab_command.nlocalsym,
            dysymtab_command.extdefs.len(),
            dysymtab_command.nundefsym,
            dysymtab_command.indirect.len(),
        ),
        LoadCommandResolved::LoadDylib(dylib_command) => {
            println!(
                "LC_LOAD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::DylibId(dylib_command) => {
            println!(
                "LC_ID_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::LoadDylinker(dylinker_command) => {
            println!("LC_LOAD_DYLINKER  {}", dylinker_command.name)
        }
        LoadCommandResolved::IdDylinker(dylinker_command) => {
            println!("LC_ID_DYLINKER  {}", dylinker_command.name)
        }
        LoadCommandResolved::PreboundDylib(prebound_dylib_command) => {
            println!("LC_PREBOUND_DYLIB  {}", prebound_dylib_command.name)
        }
        LoadCommandResolved::Routines(_) => println!("LC_ROUTINES  "),
        LoadCommandResolved::SubFramework(_) => println!("LC_SUB_FRAMEWORK  "),
        LoadCommandResolved::SubUmbrella(_) => println!("LC_SUB_UMBRELLA  "),
        LoadCommandResolved::SubClient(_) => println!("LC_SUB_CLIENT  "),
        LoadCommandResolved::SubLibrary(_) => println!("LC_SUB_LIBRARY  "),
        LoadCommandResolved::TwoLevelHints(two_level_hints_command) => {
            println!(
                "LC_TWOLEVEL_HINTS  nhints={}",
                two_level_hints_command.nhints
            )
        }
        LoadCommandResolved::PrebindCksum(prebind_cksum_command) => {
            println!("LC_PREBIND_CKSUM  cksum={}", prebind_cksum_command.cksum)
        }
        LoadCommandResolved::LoadWeakDylib(dylib_command) => {
            println!(
                "LC_LOAD_WEAK_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::Routines64(_) => println!("LC_ROUTINES_64  "),
        LoadCommandResolved::UUID(uuid_command) => println!("LC_UUID  {}", uuid_command.uuid),
        LoadCommandResolved::Rpath(rpath_command) => println!("LC_RPATH  {}", rpath_command.path),
        LoadCommandResolved::CodeSignature(code_sign_command) => {
            println!(
                "LC_CODE_SIGNATURE  nblobs={}",
                code_sign_command.blobs.len()
            )
        }
        LoadCommandResolved::SegmentSplitInfo(_) => println!("LC_SEGMENT_SPLIT_INFO  "),
        LoadCommandResolved::ReexportDylib(dylib_command) => {
            println!(
                "LC_REEXPORT_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::LazyLoadDylib(dylib_command) => {
            println!(
                "LC_LAZY_LOAD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::EncryptionInfo(encryption_info_command) => println!(
            "LC_ENCRYPTION_INFO  off=0x{:08x} sz=0x{:08x}",
            encryption_info_command.cryptoff, encryption_info_command.cryptsize
        ),
        LoadCommandResolved::DyldInfo(dyld_info_command) => println!(
            "LC_DYLD_INFO  nrebase={} nbind={} nweakbind={} nlazybind={} nexport={}",
            dyld_info_command.rebase_instructions.len(),
            dyld_info_command.bind_instructions.len(),
            dyld_info_command.weak_instructions.len(),
            dyld_info_command.lazy_instructions.len(),
            dyld_info_command.exports.len()
        ),
        LoadCommandResolved::DyldInfoOnly(dyld_info_command) => println!(
            "LC_DYLD_INFO_ONLY  nrebase={} nbind={} nweakbind={} nlazybind={} nexport={}",
            dyld_info_command.rebase_instructions.len(),
            dyld_info_command.bind_instructions.len(),
            dyld_info_command.weak_instructions.len(),
            dyld_info_command.lazy_instructions.len(),
            dyld_info_command.exports.len()
        ),
        LoadCommandResolved::LoadUpwardDylib(dylib_command) => {
            println!(
                "LC_LOAD_UPWARD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommandResolved::VersionMinMacosx(version_min_command) => {
            println!("LC_VERSION_MIN_MACOSX  {}", version_min_command.version)
        }
        LoadCommandResolved::VersionMinIphoneos(version_min_command) => {
            println!("LC_VERSION_MIN_IPHONEOS  {}", version_min_command.version)
        }
        LoadCommandResolved::FunctionStarts(function_starts_command) => {
            println!(
                "LC_FUNCTION_STARTS  nfuncs={}",
                function_starts_command.funcs.len()
            )
        }
        LoadCommandResolved::DyldEnvironment(dylinker_command) => {
            println!("LC_DYLD_ENVIRONMENT  {}", dylinker_command.name)
        }
        LoadCommandResolved::Main(entry_point_command) => {
            println!("LC_MAIN  entry=0x{:08x}", entry_point_command.entryoff)
        }
        LoadCommandResolved::DataInCode(_) => println!("LC_DATA_IN_CODE"),
        LoadCommandResolved::SourceVersion(source_version_command) => {
            println!("LC_SOURCE_VERSION  {}", source_version_command.version)
        }
        LoadCommandResolved::DylibCodeSignDrs(_) => println!("LC_DYLIB_CODE_SIGN_DRS  "),
        LoadCommandResolved::EncryptionInfo64(encryption_info_command64) => println!(
            "LC_ENCRYPTION_INFO_64  off=0x{:08x} sz=0x{:08x}",
            encryption_info_command64.cryptoff, encryption_info_command64.cryptsize
        ),
        LoadCommandResolved::LinkerOption(linker_option_command) => {
            println!(
                "LC_LINKER_OPTION  nopts={}",
                linker_option_command.strings.len()
            )
        }
        LoadCommandResolved::LinkerOptimizationHint(_) => println!("LC_LINKER_OPTIMIZATION_HINT  "),
        LoadCommandResolved::VersionMinTvos(version_min_command) => {
            println!("LC_VERSION_MIN_TVOS  {}", version_min_command.version)
        }
        LoadCommandResolved::VersionMinWatchos(version_min_command) => {
            println!("LC_VERSION_MIN_WATCHOS  {}", version_min_command.version)
        }
        LoadCommandResolved::Note(note_command) => println!(
            "LC_NOTE  owner={} off={}",
            note_command.data_owner, note_command.offset
        ),
        LoadCommandResolved::BuildVersion(build_version_command) => {
            println!(
                "LC_BUILD_VERSION  minos={} platform={} ntools={}",
                build_version_command.minos,
                build_version_command.platform,
                build_version_command.tools.len()
            )
        }
        LoadCommandResolved::DyldExportsTrie(dyld_exports_trie) => {
            println!(
                "LC_DYLD_EXPORTS_TRIE  nexports={}",
                dyld_exports_trie.exports.len()
            )
        }
        LoadCommandResolved::DyldChainedFixups(dyld_chained_fixup_command) => println!(
            "LC_DYLD_CHAINED_FIXUPS  nimports={} nstarts={}",
            dyld_chained_fixup_command.imports.len(),
            dyld_chained_fixup_command.starts.seg_starts.len()
        ),
        LoadCommandResolved::FilesetEntry(fileset_entry_command) => println!(
            "LC_FILESET_ENTRY  {} addr=0x{:08x} off=0x{:08x}",
            fileset_entry_command.entry_id,
            fileset_entry_command.vmaddr,
            fileset_entry_command.fileoff,
        ),
        LoadCommandResolved::AtomInfo(_) => println!("LC_ATOM_INFO  "),
    }
}

fn protection_to_string(prot: Protection) -> String {
    let mut prot_str = String::new();
    if prot.contains(Protection::READ) {
        prot_str.push('r');
    } else {
        prot_str.push('-');
    }
    if prot.contains(Protection::WRITE) {
        prot_str.push('w');
    } else {
        prot_str.push('-');
    }
    if prot.contains(Protection::EXECUTE) {
        prot_str.push('x');
    } else {
        prot_str.push('-');
    }
    prot_str
}
