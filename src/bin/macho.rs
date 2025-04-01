use macho2::{
    command::{segment::Protection, LoadCommand},
    header::MachHeader,
    machine::ThreadState,
    macho::{FatMachO, MachO, MachOErr, MachOResult},
};
use std::{
    env,
    fs::File,
    io::{stdout, Read, Seek, Write},
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

    if FatMachO::<_>::is_fat_magic(&mut file)? {
        let mut fat_macho = FatMachO::<_>::parse(&mut file).unwrap();
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
                panic!("Failed to extract Mach-O: {:?}", e);
            })
            .unwrap();
        print_header(macho.header);
        print_load_commands(macho);
    } else if MachO::<_>::is_macho_magic(&mut file)? {
        let macho = MachO::<_>::parse(file).unwrap();
        print_header(macho.header);
        print_load_commands(macho);
    } else {
        return Err(MachOErr::InvalidValue("Invalid Mach-O file".to_string()));
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

fn print_load_commands<T: Seek + Read>(mut macho: MachO<T>) {
    let exportstrie = macho.resolve_dyldexportstrie();
    let dyldinfo = macho.resolve_dyldinfo();
    let dyldinfoonly = macho.resolve_dyldinfoonly();
    let codesignature = macho.resolve_codesign();
    let functionstarts = macho.resolve_functionstarts();
    let dysymtab = macho.resolve_dysymtab();
    let fixups = macho.resolve_fixups();

    macho.load_commands.iter().for_each(|lc| {
        match lc {
        LoadCommand::None => todo!(),
        LoadCommand::Segment32(segment_command32) => {
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
        LoadCommand::Segment64(segment_command64) => {
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
        LoadCommand::Symtab(symtab_command) => println!(
            "LC_SYMTAB  off=0x{:08x} sz=0x{:08x} nsyms={}",
            symtab_command.symoff, symtab_command.nsyms, symtab_command.nsyms
        ),
        LoadCommand::Symseg(_) => println!("LC_SYMSEG"),
        LoadCommand::Thread(_) => println!("LC_THREAD"),
        LoadCommand::UnixThread(threadcmd) => {
            let thread = threadcmd.threads.get(0);
            if thread.is_some() {
                match thread.unwrap() {
                    ThreadState::X86State64(x86_thread_state64) => {
                        println!(
                            "LC_UNIXTHREAD  rip=0x{:016x} rsp=0x{:016x}", x86_thread_state64.rip, x86_thread_state64.rsp);
                    },
                    ThreadState::Arm64State64(arm64_thread_state64) => {
                        println!(
                            "LC_UNIXTHREAD  pc=0x{:016x} sp=0x{:016x}", arm64_thread_state64.pc, arm64_thread_state64.sp);
                    },
                    ThreadState::X86State32(x86_thread_state32) => {
                        println!(
                            "LC_UNIXTHREAD  eip=0x{:08x} esp=0x{:08x}", x86_thread_state32.eip, x86_thread_state32.esp);
                    },
                }
            }
            else {
                println!("LC_UNIXTHREAD nthreads={}", threadcmd.threads.len());
            }
        }
        LoadCommand::Dysymtab(dysymtab_command) => println!(
            "LC_DYSYMTAB  {}",
            match dysymtab.as_ref() {
                Some(dysymtab) => format!("nlocals={} nextdefs={} nundefs={} nindirects={}", 
                    dysymtab_command.nlocalsym, 
                    dysymtab.extdefs.len(), 
                    dysymtab_command.nundefsym, 
                    dysymtab.indirect.len()),
                None => format!("nlocals={} nundefs={}", dysymtab_command.nlocalsym, dysymtab_command.nundefsym),
            },
        ),
        LoadCommand::LoadDylib(dylib_command) => {
            println!(
                "LC_LOAD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::DylibId(dylib_command) => {
            println!(
                "LC_ID_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::LoadDylinker(dylinker_command) => {
            println!("LC_LOAD_DYLINKER  {}", dylinker_command.name)
        }
        LoadCommand::IdDylinker(dylinker_command) => {
            println!("LC_ID_DYLINKER  {}", dylinker_command.name)
        }
        LoadCommand::PreboundDylib(prebound_dylib_command) => {
            println!("LC_PREBOUND_DYLIB  {}", prebound_dylib_command.name)
        }
        LoadCommand::Routines(_) => println!("LC_ROUTINES  "),
        LoadCommand::SubFramework(_) => println!("LC_SUB_FRAMEWORK  "),
        LoadCommand::SubUmbrella(_) => println!("LC_SUB_UMBRELLA  "),
        LoadCommand::SubClient(_) => println!("LC_SUB_CLIENT  "),
        LoadCommand::SubLibrary(_) => println!("LC_SUB_LIBRARY  "),
        LoadCommand::TwoLevelHints(two_level_hints_command) => {
            println!(
                "LC_TWOLEVEL_HINTS  nhints={}",
                two_level_hints_command.nhints
            )
        }
        LoadCommand::PrebindCksum(prebind_cksum_command) => {
            println!("LC_PREBIND_CKSUM  cksum={}", prebind_cksum_command.cksum)
        }
        LoadCommand::LoadWeakDylib(dylib_command) => {
            println!(
                "LC_LOAD_WEAK_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::Routines64(_) => println!("LC_ROUTINES_64  "),
        LoadCommand::UUID(uuid_command) => println!("LC_UUID  {}", uuid_command.uuid),
        LoadCommand::Rpath(rpath_command) => println!("LC_RPATH  {}", rpath_command.path),
        LoadCommand::CodeSignature(_) => {
            println!(
                "LC_CODE_SIGNATURE  {}",
                match codesignature.as_ref() {
                    Some(codesignature) => format!("nblobs={}", codesignature.blobs.len()),
                    None => "(malformed)".to_string(),
                }
            )
        }
        LoadCommand::SegmentSplitInfo(_) => println!("LC_SEGMENT_SPLIT_INFO  "),
        LoadCommand::ReexportDylib(dylib_command) => {
            println!(
                "LC_REEXPORT_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::LazyLoadDylib(dylib_command) => {
            println!(
                "LC_LAZY_LOAD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::EncryptionInfo(encryption_info_command) => println!(
            "LC_ENCRYPTION_INFO  off=0x{:08x} sz=0x{:08x}",
            encryption_info_command.cryptoff, encryption_info_command.cryptsize
        ),
        LoadCommand::DyldInfo(_) => println!(
            "LC_DYLD_INFO  {}",
            match dyldinfo.as_ref() {
                Some(dyldinfo) => {
                    format!("nrebase={} nbind={} nweakbind={} nlazybind={} nexport={}",
                    dyldinfo.rebase_instructions.len(),
                    dyldinfo.bind_instructions.len(),
                    dyldinfo.weak_instructions.len(),
                    dyldinfo.lazy_instructions.len(),
                    dyldinfo.exports.len())
                }
                None => "(malformed)".to_string(),
            },
        ),
        LoadCommand::DyldInfoOnly(_) => println!(
            "LC_DYLD_INFO_ONLY  {}",
            match dyldinfoonly.as_ref() {
                Some(dyldinfoonly) => {
                    format!(
                        "nrebase={} nbind={} nweakbind={} nlazybind={} nexport={}",
                        dyldinfoonly.rebase_instructions.len(),
                        dyldinfoonly.bind_instructions.len(),
                        dyldinfoonly.weak_instructions.len(),
                        dyldinfoonly.lazy_instructions.len(),
                        dyldinfoonly.exports.len()
                    )
                }
                None => "(malformed)".to_string(),
            }
        ),
        LoadCommand::LoadUpwardDylib(dylib_command) => {
            println!(
                "LC_LOAD_UPWARD_DYLIB  {} ({})",
                dylib_command.name, dylib_command.current_version
            )
        }
        LoadCommand::VersionMinMacosx(version_min_command) => {
            println!("LC_VERSION_MIN_MACOSX  {}", version_min_command.version)
        }
        LoadCommand::VersionMinIphoneos(version_min_command) => {
            println!("LC_VERSION_MIN_IPHONEOS  {}", version_min_command.version)
        }
        LoadCommand::FunctionStarts(_) => {
            println!(
                "LC_FUNCTION_STARTS  {}",
                match functionstarts.as_ref() {
                    Some(functionstarts) => format!(
                        "nfuncs={}",
                        functionstarts.funcs.len()
                    ),
                    None => "(malformed)".to_string(),
                }
            )
        }
        LoadCommand::DyldEnvironment(dylinker_command) => {
            println!("LC_DYLD_ENVIRONMENT  {}", dylinker_command.name)
        }
        LoadCommand::Main(entry_point_command) => {
            println!("LC_MAIN  entry=0x{:08x}", entry_point_command.entryoff)
        }
        LoadCommand::DataInCode(_) => println!("LC_DATA_IN_CODE"),
        LoadCommand::SourceVersion(source_version_command) => {
            println!("LC_SOURCE_VERSION  {}", source_version_command.version)
        }
        LoadCommand::DylibCodeSignDrs(_) => println!("LC_DYLIB_CODE_SIGN_DRS  "),
        LoadCommand::EncryptionInfo64(encryption_info_command64) => println!(
            "LC_ENCRYPTION_INFO_64  off=0x{:08x} sz=0x{:08x}",
            encryption_info_command64.cryptoff, encryption_info_command64.cryptsize
        ),
        LoadCommand::LinkerOption(linker_option_command) => {
            println!(
                "LC_LINKER_OPTION  nopts={}",
                linker_option_command.strings.len()
            )
        }
        LoadCommand::LinkerOptimizationHint(_) => println!("LC_LINKER_OPTIMIZATION_HINT  "),
        LoadCommand::VersionMinTvos(version_min_command) => {
            println!("LC_VERSION_MIN_TVOS  {}", version_min_command.version)
        }
        LoadCommand::VersionMinWatchos(version_min_command) => {
            println!("LC_VERSION_MIN_WATCHOS  {}", version_min_command.version)
        }
        LoadCommand::Note(note_command) => println!(
            "LC_NOTE  owner={} off={}",
            note_command.data_owner, note_command.offset
        ),
        LoadCommand::BuildVersion(build_version_command) => {
            println!(
                "LC_BUILD_VERSION  minos={} platform={} ntools={}",
                build_version_command.minos,
                build_version_command.platform,
                build_version_command.tools.len()
            )
        }
        LoadCommand::DyldExportsTrie(_) => {
            println!(
                "LC_DYLD_EXPORTS_TRIE  {}",
                match exportstrie.as_ref() {
                    Some(exportstrie) => {
                        format!(
                            "nexports={}",
                            exportstrie.exports.len()
                        )
                    }
                    None => "(malformed)".to_string(),
                }
            )
        }
        LoadCommand::DyldChainedFixups(_) => println!(
            "LC_DYLD_CHAINED_FIXUPS  {}",
            match fixups.as_ref() {
                Some(fixups) => format!("nimports={} nstarts={}", fixups.imports.len(), fixups.starts.seg_starts.len()),
                None => "(malformed)".to_string(),
            }
        ),
        LoadCommand::FilesetEntry(fileset_entry_command) => println!(
            "LC_FILESET_ENTRY  {} addr=0x{:08x} off=0x{:08x}",
            fileset_entry_command.entry_id,
            fileset_entry_command.vmaddr,
            fileset_entry_command.fileoff,
        ),
        LoadCommand::AtomInfo(_) => println!("LC_ATOM_INFO  "),
    }
    })
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
